/*****
*
* Copyright (C) 2001, 2002, 2003 Yoann Vandoorselaere <yoann@prelude-ids.org>
* All Rights Reserved
*
* This file is part of the Prelude program.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <errno.h>
#include <sys/time.h>
#include <netinet/in.h> /* required by common.h */

#include <libprelude/prelude-log.h>
#include <libprelude/prelude-list.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/plugin-common.h>
#include <libprelude/idmef.h>
#include <libprelude/idmef-message.h>
#include <libprelude/idmef-message-recv.h>
#include <libprelude/idmef-message-id.h>
#include <libprelude/extract.h>
#include <libprelude/threads.h>
#include <libprelude/common.h>
#include <libprelude/prelude-client.h>

#include "plugin-decode.h"
#include "plugin-report.h"
#include "plugin-filter.h"
#include "pconfig.h"
#include "relaying.h"
#include "idmef-message-scheduler.h"

#define MAX_MESSAGE_IN_MEMORY 200

#define MID_PRIORITY_MESSAGE_FILENAME MANAGER_FIFO_DIR "/mid-priority-fifo"
#define LOW_PRIORITY_MESSAGE_FILENAME MANAGER_FIFO_DIR "/low-priority-fifo"


typedef struct {
        uint32_t count;
        FILE *fdp;
        prelude_io_t *fd;
        pthread_mutex_t fd_lock;
} file_output_t;



static LIST_HEAD(message_list);

static unsigned int input_available = 0;
static unsigned int in_memory_count = 0;

static file_output_t mid_priority_output;
static file_output_t low_priority_output;


/*
 * Thread controling stuff.
 */
static pthread_t thread;
static int stop_processing = 0;
static pthread_cond_t input_cond = PTHREAD_COND_INITIALIZER;
static pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t input_mutex = PTHREAD_MUTEX_INITIALIZER;




/*
 * Wait until a message is queued.
 */
static void wait_for_message(void) 
{        
        pthread_mutex_lock(&input_mutex);            
          
        while ( ! input_available && ! stop_processing ) 
                pthread_cond_wait(&input_cond, &input_mutex);
        
        if ( ! input_available && stop_processing ) {
                pthread_mutex_unlock(&input_mutex);
                pthread_exit(NULL);
        }
        
        /*
         * We are going to process all available data.
         */
        input_available = 0;
        pthread_mutex_unlock(&input_mutex);
}



static int clear_fifo(file_output_t *out) 
{
        int ret;
        
        ret = ftruncate(prelude_io_get_fd(out->fd), 0);
        if ( ret < 0 ) {
                log(LOG_ERR, "error truncating fifo to 0.\n");
                return -1;
        }

        rewind(out->fdp);
        
        return 0;
}




/*
 * Get a low / mid priority queued message
 */
static prelude_msg_t *get_message_from_file(file_output_t *out) 
{
        int ret;
        prelude_msg_t *msg = NULL;
        prelude_msg_status_t status;
        
        pthread_mutex_lock(&out->fd_lock);

        if ( ! out->count ) {
                pthread_mutex_unlock(&out->fd_lock);
                return NULL;
        }

        rewind(out->fdp);
                
        status = prelude_msg_read(&msg, out->fd);
        if ( status == prelude_msg_finished ) {
                /*
                 * you have new mail :-)
                 */
                if ( --out->count == 0 ) {
                        ret = clear_fifo(out);
                        if ( ret < 0 )
                                exit(1);
                }
                
                pthread_mutex_unlock(&out->fd_lock);
                return msg;
        }
        
        else {
                
                /*
                 * unfinished and error should never happen 
                 */
                log(LOG_ERR, "on disk message fifo is corrupted (status=%d) (count=%d).\n", status, out->count);
                exit(1);
        }

        pthread_mutex_unlock(&out->fd_lock);
        
        return msg;
}



/*
 * Retrieve a queued mid priority message.
 */
static prelude_msg_t *get_mid_priority_message(void) 
{
        return get_message_from_file(&mid_priority_output);
}




/*
 * Retrieve a qeued low priority message.
 */
static prelude_msg_t *get_low_priority_message(void) 
{
        return get_message_from_file(&low_priority_output);
}



/*
 * Get a high priority message.
 */
static prelude_msg_t *get_high_priority_message(void) 
{
        prelude_msg_t *msg = NULL;
        
        pthread_mutex_lock(&list_mutex);
        
        if ( ! list_empty(&message_list) ) {
                msg = prelude_list_get_object(message_list.next, prelude_msg_t);
                prelude_list_del( (prelude_linked_object_t *) msg);
                in_memory_count--;
        }

        pthread_mutex_unlock(&list_mutex);

        return msg;
}




static idmef_message_t *read_idmef_message(prelude_msg_t *msg) 
{
	int ret;
	void *buf;
	uint8_t tag;
	uint32_t len;
        idmef_message_t *message;
        
	message = idmef_message_new();
	if ( ! message ) {
		log(LOG_ERR, "memory exhausted.\n");
		return NULL;
	}

        while ( (ret = prelude_msg_get(msg, &tag, &len, &buf)) > 0 ) {
                
                if ( tag == MSG_ALERT_TAG ) {
			idmef_alert_t *alert;
                        
			alert = idmef_message_new_alert(message);
			if ( ! alert )
                                break;
                        
                        if ( ! idmef_recv_alert(msg, alert) )
				break;
                        
			manager_idmef_alert_get_ident(alert);
                }

                else if ( tag == MSG_HEARTBEAT_TAG ) {
			idmef_heartbeat_t *heartbeat;

			heartbeat = idmef_message_new_heartbeat(message);
			if ( ! heartbeat )
                                break;

			if ( ! idmef_recv_heartbeat(msg, heartbeat) )
				break;

			manager_idmef_heartbeat_get_ident(heartbeat);
		}

                else if ( tag == MSG_OWN_FORMAT ) {
                        
                        ret = extract_uint8_safe(&tag, buf, len);
			if ( ret < 0 )
                                break;
                        
			ret = decode_plugins_run(tag, msg, message);
			if ( ret < 0 )
                                break;
                }

                else log(LOG_ERR, "unknow tag: %d.\n", tag);
        }
        
        if ( ret == 0 )
                return message;

        log(LOG_ERR, "error reading IDMEF message.\n");
        idmef_message_destroy(message);
                
        return NULL;
}



static int process_message(prelude_msg_t *msg) 
{
        int ret;
        int relay_filter_available = 0;
        idmef_message_t *idmef = NULL;
        
        relay_filter_available = filter_plugins_available(FILTER_CATEGORY_RELAYING);
        if ( relay_filter_available < 0 )
                manager_relay_msg_if_needed(msg);
        
        if ( report_plugins_available() < 0 && relay_filter_available < 0 ) {
                /*
                 * we are probably a simple relaying manager.
                 */
                prelude_msg_destroy(msg);
                return 0;
        }
        
        idmef = read_idmef_message(msg);
        if ( ! idmef ) {
                prelude_msg_destroy(msg);
                return -1;
        }

	ret = idmef_message_enable_cache(idmef);
	if ( ret < 0 )
		log(LOG_ERR, "cannot enable IDMEF cache\n");
		

        if ( relay_filter_available == 0 && filter_plugins_run_by_category(idmef, FILTER_CATEGORY_RELAYING) == 0 )
                manager_relay_msg_if_needed(msg);


        /*
         * run simple reporting plugin.
         */
        report_plugins_run(idmef);

        /*
         * free data.
         */
	idmef_message_destroy(idmef);
	prelude_msg_destroy(msg);
        
        return 0;
}





/*
 * This is the function responssible for handling queued message.
 */
static void *message_reader(void *arg) 
{
        int ret;
        sigset_t set;
        prelude_msg_t *msg;
        
        sigfillset(&set);
        
        ret = pthread_sigmask(SIG_SETMASK, &set, NULL);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't set thread signal mask.\n");
                return NULL;
        }
        
        while ( 1 ) {
                msg = get_high_priority_message();
                if ( ! msg )
                        msg = get_mid_priority_message();
                
                if ( ! msg )
                        msg = get_low_priority_message();

                if ( ! msg ) {                        
                        wait_for_message();
                        continue;
                }
                
                ret = process_message(msg);
                /*
                 * FIXME: need a way to close connection on invalid message.
                 */
        }
}



/*
 * Queue this message to memory.
 */
static int queue_message_to_memory(prelude_msg_t *msg, uint8_t priority) 
{        
        pthread_mutex_lock(&list_mutex);

        if ( priority == PRELUDE_MSG_PRIORITY_HIGH || in_memory_count < MAX_MESSAGE_IN_MEMORY ) {
                prelude_list_add_tail((prelude_linked_object_t *) msg, &message_list);
                in_memory_count++;
        } else {
                pthread_mutex_unlock(&list_mutex);
                return -1;
        }

        pthread_mutex_unlock(&list_mutex);
        
        return 0;
}





static int queue_message_to_fd(file_output_t *out, prelude_msg_t *msg) 
{
        int ret;
        
        pthread_mutex_lock(&out->fd_lock);
                
        ret = prelude_msg_write(msg, out->fd);
        if ( ret <= 0 ) {
                log(LOG_ERR, "couldn't write message to file.\n");
                goto err;
        }
        
        out->count++;

 err:
        pthread_mutex_unlock(&out->fd_lock);

        /*
         * Message was copied to a file,
         * we do not need it anymore.
         */
        prelude_msg_destroy(msg);
        
        return 0;
}




static int flush_existing_fifo(const char *filename, file_output_t *out, off_t size) 
{
        int i = 0, ret;
        prelude_msg_t *msg;
        prelude_msg_status_t status;
        
        log(LOG_INFO, "%s contain unflushed message (%d bytes). Flushing.\n", filename, size);
        
        while ( 1 ) {
                
                msg = NULL;
                status = prelude_msg_read(&msg, out->fd);

                if ( status == prelude_msg_finished ) {
                        ret = process_message(msg);
                        if ( ret < 0 )
                                return -1;
                        i++;
                }
                
                else if ( status == prelude_msg_error || status == prelude_msg_unfinished ) {                        
                        log(LOG_ERR, "error reading message. FIFO may be corrupted.\n");
                        return -1;
                }

                else if ( status == prelude_msg_eof )
                        break;
        }
        
        log(LOG_INFO, "Done - %d messages flushed.\n", i);

        ret = ftruncate(prelude_io_get_fd(out->fd), 0);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't truncate message to 0 byte.\n");
                return -1;
        }

        rewind(out->fdp);
                
        return 0;
}




/*
 * 
 */
static int init_file_output(const char *filename, file_output_t *out) 
{
        int ret, fd;
        struct stat st;

        fd = prelude_open_persistant_tmpfile(filename, O_RDWR, S_IRUSR|S_IWUSR);
        if ( fd < 0 ) {
                log(LOG_ERR, "couldn't open %s in rw mode.\n", filename);
                return -1;
        }
        
        out->fdp = fdopen(fd, "a+");
        if ( ! out->fdp ) {
                log(LOG_ERR, "couldn't open %s in read / write mode.\n", filename);
                close(fd);
                return -1;
        }

        out->fd = prelude_io_new();
        if ( ! out->fd ) {
                log(LOG_ERR, "couldn't associate FD to prelude IO object.\n");
                fclose(out->fdp);
                close(fd);
                return -1;
        }
        
        ret = fstat(fd, &st);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't stats %s.\n", filename);
                fclose(out->fdp);
                close(fd);
                return -1;
        }

        out->count = 0;
        prelude_io_set_file_io(out->fd, out->fdp);
        pthread_mutex_init(&out->fd_lock, NULL);

        rewind(out->fdp);
        
        if ( st.st_size > 0 ) 
                ret = flush_existing_fifo(filename, out, st.st_size);
        else
                ret = 0;
        
        return ret;
}



/*
 *
 */
static void destroy_file_output(file_output_t *out) 
{
        prelude_io_close(out->fd);
        prelude_io_destroy(out->fd);
}




void idmef_message_schedule(prelude_msg_t *msg) 
{
        int ret;
        uint8_t priority;

        priority = prelude_msg_get_priority(msg);
        
        /*
         * First if memory condition are okay,
         * queue the message in memory. If the heuristic fail,
         * it'll return -1.
         */
        ret = queue_message_to_memory(msg, priority);
        if ( ret < 0 ) {
                
                if ( priority == PRELUDE_MSG_PRIORITY_MID ) 
                        queue_message_to_fd(&mid_priority_output, msg);
                
                else if ( priority == PRELUDE_MSG_PRIORITY_LOW )
                        queue_message_to_fd(&low_priority_output, msg);
        }
        
        /*
         * Signal that data is available.
         */
        pthread_mutex_lock(&input_mutex);

        if ( ! input_available ) {
                input_available = 1;
                pthread_cond_signal(&input_cond);
        }

        pthread_mutex_unlock(&input_mutex);
}




int idmef_message_scheduler_init(void) 
{
        int ret;
        
        ret = init_file_output(MID_PRIORITY_MESSAGE_FILENAME, &mid_priority_output);
        if ( ret < 0 )
                return -1;

        ret = init_file_output(LOW_PRIORITY_MESSAGE_FILENAME, &low_priority_output);
        if ( ret < 0 ) {
                destroy_file_output(&mid_priority_output);
                return -1;
        }
                
        ret = pthread_create(&thread, NULL, &message_reader, NULL);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't create message processing thread.\n");
                return -1;
        }
        
        return 0;
}




void idmef_message_scheduler_exit(void) 
{
        pthread_mutex_lock(&input_mutex);

        stop_processing = 1;
        pthread_cond_signal(&input_cond);

        pthread_mutex_unlock(&input_mutex);
        
        log(LOG_INFO, "Waiting for queued message to be processed.\n");
        pthread_join(thread, NULL);
        
        destroy_file_output(&mid_priority_output);
        destroy_file_output(&low_priority_output);
        pthread_cond_destroy(&input_cond);
        pthread_mutex_destroy(&list_mutex);
}










