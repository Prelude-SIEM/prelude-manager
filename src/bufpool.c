/*****
*
* Copyright (C) 2007 PreludeIDS Technologies. All Rights Reserved.
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
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

#include "config.h"
#include "libmissing.h"

#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <assert.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-failover.h>

#include "bufpool.h"

#define DISK_THRESHOLD_DEFAULT 1 * (1024 * 1024)


struct bufpool {
        prelude_list_t list;
        prelude_failover_t *failover;

        prelude_list_t msglist;
        char *filename;

        pthread_mutex_t mutex;

        size_t len;
        size_t count;
};


static PRELUDE_LIST(pool_list);
static size_t on_disk_threshold = DISK_THRESHOLD_DEFAULT;
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

static size_t mem_msglen = 0, mem_msgcount = 0;
static size_t disk_msglen = 0, disk_msgcount = 0;



/*
 * When adding a message to a queue, if the amount of memory used by
 * all queue reach on_disk_threshold, then we find the queue using most
 * memory, and flush it to disk.
 *
 * When the memory usage become normal again (no more EPS than the
 * manager can process, the failover is destroyed.
 */


static inline void inc_dlen(bufpool_t *bp, size_t len)
{
        pthread_mutex_lock(&mutex);
        disk_msglen += len;
        disk_msgcount++;
        pthread_mutex_unlock(&mutex);

        bp->count++;
}


static inline void dec_dlen(bufpool_t *bp, size_t len)
{
        pthread_mutex_lock(&mutex);
        disk_msglen -= len;
        disk_msgcount--;
        pthread_mutex_unlock(&mutex);

        bp->count--;
}

static inline void inc_len(bufpool_t *bp, size_t len)
{
        pthread_mutex_lock(&mutex);
        mem_msglen += len;
        mem_msgcount++;
        pthread_mutex_unlock(&mutex);

        bp->len += len;
        bp->count++;
}



static inline void dec_len(bufpool_t *bp, size_t len)
{
        pthread_mutex_lock(&mutex);
        mem_msglen -= len;
        mem_msgcount--;
        pthread_mutex_unlock(&mutex);

        bp->len -= len;
        bp->count--;
}



static int flush_bufpool_to_disk(bufpool_t *bp)
{
        int ret;
        prelude_msg_t *msg;
        prelude_list_t *tmp, *bkp;

        pthread_mutex_lock(&bp->mutex);

        ret = prelude_failover_new(&bp->failover, bp->filename);
        if ( ret < 0 )
                goto err;

        prelude_list_for_each_safe(&bp->msglist, tmp, bkp) {
                msg = prelude_linked_object_get_object(tmp);
                prelude_linked_object_del((prelude_linked_object_t *) msg);

                ret = prelude_failover_save_msg(bp->failover, msg);
                if ( ret < 0 ) {
                        prelude_log(PRELUDE_LOG_ERR, "failover write failure: %s.\n", prelude_strerror(ret));
                        prelude_msg_destroy(msg);
                        break;
                }

                inc_dlen(bp, prelude_msg_get_len(msg));
                dec_len(bp, prelude_msg_get_len(msg));
                prelude_msg_destroy(msg);
        }

        prelude_list_del_init(&bp->list);

err:
        pthread_mutex_unlock(&bp->mutex);

        return ret;
}


static int evict_from_memory(void)
{
        size_t prev_len = 0;
        prelude_list_t *tmp;
        bufpool_t *bp, *evict = NULL;

        prelude_list_for_each(&pool_list, tmp) {
                bp = prelude_list_entry(tmp, bufpool_t, list);

                if ( bp->failover )
                        continue;

                if ( ! evict )
                        evict = bp;

                if ( bp->len > prev_len ) {
                        evict = bp;
                        prev_len = bp->len;
                }
        }

        return (evict) ? flush_bufpool_to_disk(evict) : 0;
}



int bufpool_add_message(bufpool_t *bp, prelude_msg_t *msg)
{
        int ret = 0;
        size_t total, len = prelude_msg_get_len(msg);

        pthread_mutex_lock(&mutex);
        total = mem_msglen;
        pthread_mutex_unlock(&mutex);

        pthread_mutex_lock(&bp->mutex);

        if ( total + len < on_disk_threshold && ! bp->failover ) {
                prelude_linked_object_add_tail(&bp->msglist, (prelude_linked_object_t *) msg);
                inc_len(bp, len);
                pthread_mutex_unlock(&bp->mutex);
        }

        else if ( bp->failover ) {
                prelude_failover_save_msg(bp->failover, msg);
                inc_dlen(bp, prelude_msg_get_len(msg));
                prelude_msg_destroy(msg);

                pthread_mutex_unlock(&bp->mutex);
        }

        else {
                pthread_mutex_unlock(&bp->mutex);

                evict_from_memory();
                ret = bufpool_add_message(bp, msg);
        }

        return ret;
}


static void failover_destroy(bufpool_t *bp)
{
        prelude_failover_destroy(bp->failover);
        bp->failover = NULL;
        prelude_list_add_tail(&pool_list, &bp->list);
}



int bufpool_get_message(bufpool_t *bp, prelude_msg_t **out)
{
        int ret;
        prelude_list_t *tmp;
        prelude_msg_t *msg = NULL;

        pthread_mutex_lock(&bp->mutex);

        prelude_list_for_each(&bp->msglist, tmp) {
                msg = prelude_linked_object_get_object(tmp);
                prelude_linked_object_del((prelude_linked_object_t *) msg);
                dec_len(bp, prelude_msg_get_len(msg));
                break;
        }

        if ( ! msg && bp->failover ) {
                ret = prelude_failover_get_saved_msg(bp->failover, &msg);
                if ( ret < 0 ) {
                        prelude_log(PRELUDE_LOG_ERR, "could not retrieve message from failover: %s.\n", prelude_strerror(ret));
                        failover_destroy(bp);
                }

                else if ( bp->count - 1 == 0 ) {
                        prelude_msg_t *tmsg;

                        ret = prelude_failover_get_saved_msg(bp->failover, &tmsg);
                        assert(ret == 0);

                        failover_destroy(bp);
                }

                if ( msg )
                        dec_dlen(bp, prelude_msg_get_len(msg));
        }

        assert(msg || bp->count == 0);
        pthread_mutex_unlock(&bp->mutex);

        *out = msg;
        return (msg) ? 1 : 0;
}



int bufpool_new(bufpool_t **bp, const char *filename)
{
        *bp = malloc(sizeof(**bp));
        if ( ! *bp )
                return -1;

        (*bp)->len = 0;
        (*bp)->count = 0;
        (*bp)->failover = NULL;
        prelude_list_init(&(*bp)->msglist);

        (*bp)->filename = strdup(filename);
        if ( ! (*bp)->filename ) {
                free(*bp);
                return prelude_error_from_errno(errno);
        }

        pthread_mutex_init(&(*bp)->mutex, NULL);

        pthread_mutex_lock(&mutex);
        prelude_list_add_tail(&pool_list, &(*bp)->list);
        pthread_mutex_unlock(&mutex);

        return 0;
}


void bufpool_destroy(bufpool_t *bp)
{
        pthread_mutex_lock(&mutex);
        prelude_list_del(&bp->list);
        pthread_mutex_unlock(&mutex);

        if ( bp->failover )
                prelude_failover_destroy(bp->failover);

        pthread_mutex_destroy(&bp->mutex);

        free(bp->filename);
        free(bp);
}


void bufpool_set_disk_threshold(size_t threshold)
{
        on_disk_threshold = threshold;
}


size_t bufpool_get_message_count(bufpool_t *bp)
{
        size_t count;

        pthread_mutex_lock(&bp->mutex);
        count = bp->count;
        pthread_mutex_unlock(&bp->mutex);

        return count;
}



void bufpool_print_stats(void)
{
        uint64_t dl, dc, ml, mc;

        pthread_mutex_lock(&mutex);
        dl = disk_msglen;
        dc = disk_msgcount;
        ml = mem_msglen;
        mc = mem_msgcount;
        pthread_mutex_unlock(&mutex);

        prelude_log(PRELUDE_LOG_INFO, "disk_len=%" PRELUDE_PRIu64 " disk_count=%" PRELUDE_PRIu64 " mem_len=%" PRELUDE_PRIu64 " mem_count=%" PRELUDE_PRIu64 "\n", dl, dc, ml, mc);
}
