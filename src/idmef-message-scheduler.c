/*****
*
* Copyright (C) 2001-2015 CS-SI. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
*
* This file is part of the Prelude-Manager program.
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2, or (at your option)
* any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
*****/

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <signal.h>
#include <dirent.h>
#include <errno.h>
#include <netinet/in.h> /* required by common.h */
#include <ftw_.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-timer.h>
#include <libprelude/prelude-error.h>

#include "glthread/thread.h"
#include "glthread/lock.h"
#include "glthread/cond.h"

#include "prelude-manager.h"
#include "filter-plugins.h"
#include "decode-plugins.h"
#include "report-plugins.h"
#include "manager-options.h"
#include "reverse-relaying.h"
#include "pmsg-to-idmef.h"
#include "idmef-message-scheduler.h"
#include "bufpool.h"


/*
 * On POSIX systems where clock_gettime() is available, the symbol
 * _POSIX_TIMERS should be defined to a value greater than 0.
 *
 * However, some architecture (example True64), define it as:
 * #define _POSIX_TIMERS
 *
 * This explain the - 0 hack, since we need to test for the explicit
 * case where _POSIX_TIMERS is defined to a value higher than 0.
 *
 * If pthread_condattr_setclock and _POSIX_MONOTONIC_CLOCK are available,
 * CLOCK_MONOTONIC will be used. This avoid possible race problem when
 * calling pthread_cond_timedwait() if the system time is modified.
 *
 * If CLOCK_MONOTONIC is not available, revert to the standard CLOCK_REALTIME
 * way.
 *
 * If neither of the above are available, use gettimeofday().
 */
#if _POSIX_TIMERS - 0 > 0
# if defined(HAVE_PTHREAD_CONDATTR_SETCLOCK) && defined(_POSIX_MONOTONIC_CLOCK) && (_POSIX_MONOTONIC_CLOCK - 0 >= 0)
#  define COND_CLOCK_TYPE CLOCK_MONOTONIC
# else
#  define COND_CLOCK_TYPE CLOCK_REALTIME
# endif
#endif


#ifndef MIN
# define MIN(x, y) (((x) < (y)) ? (x) : (y))
#endif

#define QUEUE_STATE_DESTROYED 0x01


struct idmef_queue {
        prelude_list_t list;

        int state;

        bufpool_t *high;
        bufpool_t *mid;
        bufpool_t *low;
};


static PRELUDE_LIST(message_queue);
static gl_lock_t queue_list_mutex = gl_lock_initializer;

static prelude_bool_t input_available = FALSE;
static gl_cond_t input_cond = gl_cond_initializer;
static gl_lock_t input_mutex = gl_lock_initializer;
static gl_lock_t process_mutex = gl_lock_initializer;

static unsigned int sched_process_high   =  50;
static unsigned int sched_process_medium =  30;
static unsigned int sched_process_low    =  20;
static unsigned int sched_process        = 100;


/*
 * Thread controling stuff.
 */
static gl_thread_t thread;
static volatile sig_atomic_t stop_processing = 0;



static void signal_input_available(void)
{
        gl_lock_lock(input_mutex);

        if ( ! input_available ) {
                input_available = TRUE;
                gl_cond_signal(input_cond);
        }

        gl_lock_unlock(input_mutex);
}



static inline struct timespec *get_timespec(struct timespec *ts)
{
        struct timeval now;

        gettimeofday(&now, NULL);

        ts->tv_sec = now.tv_sec;
        ts->tv_nsec = now.tv_usec * 1000;

        return ts;
}



static int timespec_diff(struct timespec *end, struct timespec *start)
{
        int diff = end->tv_sec - start->tv_sec;

        if ( end->tv_nsec < start->tv_nsec )
                diff -= 1;

        return diff;
}

static prelude_bool_t timespec_expired(struct timespec *end, struct timespec *start)
{
        return ( timespec_diff(end, start) >= 1 ) ? TRUE : FALSE;
}


/*
 * Wait until a message is queued.
 */
static void wait_for_message(struct timespec *last_wakeup)
{
        int ret;
        struct timespec ts;

        gl_lock_lock(input_mutex);

        while ( ! input_available && ! stop_processing ) {

                ts.tv_sec = last_wakeup->tv_sec + 1;
                ts.tv_nsec = last_wakeup->tv_nsec;

                ret = glthread_cond_timedwait(&input_cond, &input_mutex, &ts);
                if ( ret == ETIMEDOUT ) {
                        prelude_timer_wake_up();
                        last_wakeup->tv_sec = ts.tv_sec;
                        last_wakeup->tv_nsec = ts.tv_nsec;
                }
        }

        if ( ! input_available && stop_processing ) {
                gl_lock_unlock(input_mutex);
                gl_thread_exit(NULL);
        }

        /*
         * We are going to process all available data.
         */
        input_available = FALSE;
        gl_lock_unlock(input_mutex);
}



static int process_message(prelude_msg_t *msg)
{
        int ret;
        idmef_message_t *idmef;

        ret = pmsg_to_idmef(&idmef, msg);
        if ( ret < 0 ) {
                prelude_msg_destroy(msg);

                /*
                 * FIXME: need a way to close connection on invalid message.
                 */
                prelude_log(PRELUDE_LOG_ERR, "Invalid message received.\n");
                return ret;
        }

        /*
         * prelude-msg is usefull for report plugin failover.
         * We don't need to call prelude_msg_destroy(), as
         * idmef_message_destroy() will consequently do this for us.
         */
        idmef_message_set_pmsg(idmef, msg);
        idmef_message_process(idmef);

        idmef_message_destroy(idmef);

        return 0;
}



static void queue_destroy(idmef_queue_t *queue)
{
        gl_lock_lock(queue_list_mutex);
        prelude_list_del(&queue->list);
        gl_lock_unlock(queue_list_mutex);

        bufpool_destroy(queue->high);
        bufpool_destroy(queue->mid);
        bufpool_destroy(queue->low);

        free(queue);
}



static int is_queue_dirty(idmef_queue_t *queue)
{
        return bufpool_get_message_count(queue->high) +
               bufpool_get_message_count(queue->mid)  +
               bufpool_get_message_count(queue->low);
}



static size_t read_message_scheduled_from_pool(bufpool_t *pool, size_t count)
{
        size_t proc = 0;
        prelude_msg_t *msg;

        while ( count-- ) {
                prelude_return_val_if_fail(bufpool_get_message(pool, &msg) == 1, proc);

                process_message(msg);
                proc++;
        }

        return proc;
}



static void read_message_scheduled(idmef_queue_t *queue)
{
        unsigned int j;
        int ret, i = 0;
        prelude_msg_t *msg;
        size_t total, hlen, mlen, llen, proc;
        bufpool_t *btbl[] = { queue->high, queue->mid, queue->low };
        const size_t btbl_size = sizeof(btbl) / sizeof(*btbl);

        hlen = bufpool_get_message_count(queue->high);
        mlen = bufpool_get_message_count(queue->mid);
        llen = bufpool_get_message_count(queue->low);

        proc  = read_message_scheduled_from_pool(queue->high, MIN(hlen, sched_process_high));
        proc += read_message_scheduled_from_pool(queue->mid, MIN(mlen, sched_process_medium));
        proc += read_message_scheduled_from_pool(queue->low, MIN(llen, sched_process_low));

        total = MIN(hlen + mlen + llen - proc, sched_process - proc);

        while ( total ) {
                ret = 0;

                for ( j = 0; j < btbl_size; j++ ) {
                        ret = bufpool_get_message(btbl[i++ % btbl_size], &msg);
                        if ( ret == 1 ) {
                                process_message(msg);
                                break;
                        }
                }

                if ( ret != 1 )
                        break;

                total--;
        }

        prelude_return_if_fail(total == 0);
}



static void schedule_queued_message(struct timespec *last_wakeup)
{
        struct timespec end;
        int dirty, any_queue_dirty;
        idmef_queue_t *queue = NULL, *bkp = NULL;

        do {
                any_queue_dirty = 0;

                while ( 1 ) {
                        gl_lock_lock(queue_list_mutex);
                        queue = prelude_list_get_next_safe(&message_queue, queue, bkp, idmef_queue_t, list);
                        gl_lock_unlock(queue_list_mutex);

                        if ( ! queue )
                                break;

                        read_message_scheduled(queue);

                        dirty = is_queue_dirty(queue);
                        any_queue_dirty += dirty;

                        if ( ! dirty && queue->state & QUEUE_STATE_DESTROYED )
                                queue_destroy(queue);
                }

                if ( timespec_expired(get_timespec(&end), last_wakeup) ) {
                        prelude_timer_wake_up();
                        last_wakeup->tv_sec = end.tv_sec;
                        last_wakeup->tv_nsec = end.tv_nsec;
                }
        } while ( any_queue_dirty );
}




/*
 * This is the function responssible for handling queued message.
 */
static void *message_reader(void *arg)
{
        int ret;
        sigset_t set;
        struct timespec last_wakeup;

        sigfillset(&set);

        ret = glthread_sigmask(SIG_SETMASK, &set, NULL);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't set thread signal mask.\n");
                return NULL;
        }

        get_timespec(&last_wakeup);
        last_wakeup.tv_sec--;

        while ( ! stop_processing ) {
                schedule_queued_message(&last_wakeup);
                wait_for_message(&last_wakeup);
        }

        /*
         * make sure we don't miss some.
         */
        schedule_queued_message(&last_wakeup);

        return NULL;
}


int idmef_message_schedule(idmef_queue_t *queue, prelude_msg_t *msg)
{
        int ret;
        bufpool_t *mqueue;

        if ( ! queue )
                return -1;

        switch (prelude_msg_get_priority(msg)) {

        case PRELUDE_MSG_PRIORITY_HIGH:
                mqueue = queue->high;
                break;

        case PRELUDE_MSG_PRIORITY_MID:
                mqueue = queue->mid;
                break;

        default:
                mqueue = queue->low;
                break;
        }

        ret = bufpool_add_message(mqueue, msg);
        signal_input_available();

        return ret;
}



static uint64_t get_unique_id(void)
{
        unsigned int id;
        struct timeval tv;
        static unsigned int global_id = 0, last_sec = 0;

        gettimeofday(&tv, NULL);

        gl_lock_lock(queue_list_mutex);
        if ( tv.tv_sec > last_sec ) {
                last_sec = tv.tv_sec;
                global_id = 0;
        }

        id = global_id++;
        gl_lock_unlock(queue_list_mutex);

        return ((uint64_t) id << 32) | last_sec;
}



idmef_queue_t *idmef_message_scheduler_queue_new(prelude_client_t *client)
{
        int ret;
        uint64_t id;
        idmef_queue_t *queue;
        char buf[PATH_MAX], bdir[PATH_MAX];

        queue = calloc(1, sizeof(*queue));
        if ( ! queue ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        id = get_unique_id();
        prelude_client_profile_get_backup_dirname(prelude_client_get_profile(client), bdir, sizeof(bdir));

        snprintf(buf, sizeof(buf), "%s/high-buffer.%" PRELUDE_PRIu64, bdir, id);
        ret = bufpool_new(&queue->high, buf);
        if ( ret < 0 ) {
                free(queue);
                return NULL;
        }

        snprintf(buf, sizeof(buf), "%s/medium-buffer.%" PRELUDE_PRIu64, bdir, id);
        ret = bufpool_new(&queue->mid, buf);
        if ( ret < 0 ) {
                bufpool_destroy(queue->high);
                free(queue);
                return NULL;
        }

        snprintf(buf, sizeof(buf), "%s/low-buffer.%" PRELUDE_PRIu64, bdir, id);
        ret = bufpool_new(&queue->low, buf);
        if ( ret < 0 ) {
                bufpool_destroy(queue->high);
                bufpool_destroy(queue->mid);
                free(queue);
                return NULL;
        }

        gl_lock_lock(queue_list_mutex);
        prelude_list_add_tail(&message_queue, &queue->list);
        gl_lock_unlock(queue_list_mutex);

        return queue;
}




void idmef_message_scheduler_queue_destroy(idmef_queue_t *queue)
{
        queue->state |= QUEUE_STATE_DESTROYED;
        signal_input_available();
}



#include <libprelude/prelude-failover.h>
extern prelude_client_t *manager_client;


static int flush_failover(prelude_failover_t *failover, const char *name)
{
        int ret;
        prelude_msg_t *msg;
        unsigned long available;

        available = prelude_failover_get_available_msg_count(failover);

        if ( available == 0 )
                return 0;

        prelude_log(PRELUDE_LOG_INFO, "%s: flushing %lu buffered messages from a previous run.\n",
                    name, available);

        do {
                ret = prelude_failover_get_saved_msg(failover, &msg);
                if ( ret <= 0 )
                        break;

                process_message(msg);
        } while ( 1 );

        return ret;
}



static int del_cb(const char *filename, const struct stat *st, int flag)
{
        int ret;

        ret = unlink(filename);
        return ( ret < 0 && errno != EISDIR ) ? prelude_error_from_errno(errno) : 0;
}


static int failover_unlink(const char *dirname)
{
        int ret;

        ret = ftw(dirname, del_cb, 10);
        if ( ret < 0 )
                return prelude_error_from_errno(errno);

        ret = rmdir(dirname);
        return (ret < 0) ? prelude_error_from_errno(errno) : 0;
}



int idmef_message_scheduler_init(void)
{
        int ret;
        DIR *dir;
        struct dirent *de;
        char bdir[PATH_MAX];
        char filename[PATH_MAX];
        prelude_failover_t *failover;

        prelude_client_profile_get_backup_dirname(prelude_client_get_profile(manager_client), bdir, sizeof(bdir));

        dir = opendir(bdir);
        if ( ! dir ) {
                prelude_log(PRELUDE_LOG_ERR, "error opening directory '%s': %s.\n", bdir, strerror(errno));
                return -1;
        }

        while ( (de = readdir(dir)) ) {
                if ( ! strstr(de->d_name, "buffer") )
                        continue;

                snprintf(filename, sizeof(filename), "%s/%s", bdir, de->d_name);

                ret = prelude_failover_new(&failover, filename);
                if ( ret < 0 )
                        return ret;

                flush_failover(failover, de->d_name);
                prelude_failover_destroy(failover);

                ret = failover_unlink(filename);
                if ( ret < 0 )
                        prelude_log(PRELUDE_LOG_ERR, "couldn't remove failover '%s': %s.\n", filename, prelude_strerror(ret));
        }

        closedir(dir);

        ret = glthread_create(&thread, &message_reader, NULL);
        if ( ret < 0 )
                prelude_log(PRELUDE_LOG_ERR, "couldn't create message processing thread.\n");

        return ret;
}




void idmef_message_scheduler_exit(void)
{
        idmef_queue_t *queue;
        prelude_list_t *tmp, *bkp;

        gl_lock_lock(input_mutex);

        stop_processing = 1;
        gl_cond_signal(input_cond);

        gl_lock_unlock(input_mutex);

        prelude_log(PRELUDE_LOG_INFO, "Waiting queued message to be processed.\n");
        gl_thread_join(thread, NULL);

        gl_cond_destroy(input_cond);
        gl_lock_destroy(input_mutex);

        prelude_list_for_each_safe(&message_queue, tmp, bkp) {
                queue = prelude_list_entry(tmp, idmef_queue_t, list);
                queue_destroy(queue);
        }
}




void idmef_message_process(idmef_message_t *idmef)
{
        int ret = 0;
        prelude_bool_t relay_filter_available = 0;

        gl_lock_lock(process_mutex);

        /*
         * run normalization plugin.
         */
        decode_plugins_run(0, NULL, idmef);

        /*
         * run simple reporting plugin.
         */
        report_plugins_run(idmef);

        relay_filter_available = filter_plugins_available(MANAGER_FILTER_CATEGORY_REVERSE_RELAYING);
        if ( relay_filter_available )
                ret = filter_plugins_run_by_category(idmef, MANAGER_FILTER_CATEGORY_REVERSE_RELAYING);

        gl_lock_unlock(process_mutex);

        if ( ret == 0 )
                reverse_relay_send_receiver(idmef);
}



void idmef_message_scheduler_stop_processing(void)
{
        gl_lock_lock(process_mutex);
}



void idmef_message_scheduler_start_processing(void)
{
        gl_lock_unlock(process_mutex);
}



void idmef_message_scheduler_set_priority(unsigned int high, unsigned int medium, unsigned int low)
{
        sched_process_high = high;
        sched_process_medium = medium;
        sched_process_low = low;
        sched_process = high + medium + low;
}
