/*****
*
* Copyright (C) 2001 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>
#include <pthread.h>

#include <libprelude/common.h>
#include <libprelude/prelude-list.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/plugin-common.h>
#include <libprelude/idmef-tree.h>

#include "alert-scheduler.h"
#include "plugin-decode.h"
#include "plugin-report.h"
#include "pconfig.h"
#include "idmef-func.h"
#include "idmef-message-read.h"


#define MAX_ALERT_IN_MEMORY 200

#define MID_PRIORITY_ALERT_FILENAME "/var/lib/prelude/mid-priority-fifo"
#define LOW_PRIORITY_ALERT_FILENAME "/var/lib/prelude/low-priority-fifo"


typedef struct {

        prelude_io_t *fd;
        unsigned int count;
        pthread_mutex_t mutex;
        
} file_output_t;



static LIST_HEAD(alert_list);
static unsigned int in_memory_count;
static pthread_mutex_t list_mutex;

static file_output_t mid_priority_output;
static file_output_t low_priority_output;


/*
 * Thread controling stuff.
 */
static pthread_t thread;
static pthread_cond_t input_cond;




/*
 * Wait until an alert is queued.
 */
static void wait_for_alert(void) 
{
        pthread_mutex_lock(&list_mutex);

        while ( in_memory_count == 0 ) 
                pthread_cond_wait(&input_cond, &list_mutex);
        
        pthread_mutex_unlock(&list_mutex);
}




/*
 * Get a low / mid priority queued alert.
 */
static prelude_msg_t *get_alert_from_file(file_output_t *out) 
{
        int ret;
        prelude_msg_t *msg = NULL;

        pthread_mutex_lock(&out->mutex);

        if ( out->count ) {
                ret = prelude_msg_read(&msg, out->fd);
                if ( ret )
                        out->count--;
        }

        pthread_mutex_unlock(&out->mutex);

        return msg;
}




/*
 * Get a high priority alert.
 */
static prelude_msg_t *get_high_priority_alert(void) 
{
        prelude_msg_t *msg = NULL;
        
        pthread_mutex_lock(&list_mutex);
                
        if ( in_memory_count ) {
                msg = prelude_list_get_object(alert_list.next, prelude_msg_t);
                prelude_list_del( (prelude_linked_object_t *) msg);
                in_memory_count--;
        }

        pthread_mutex_unlock(&list_mutex);

        return msg;
}




/*
 * Retrieve a queued mid priority alert.
 */
static prelude_msg_t *get_mid_priority_alert(void) 
{
        return get_alert_from_file(&mid_priority_output);
}




/*
 * Retrieve a qeued low priority alert.
 */
static prelude_msg_t *get_low_priority_alert(void) 
{
        return get_alert_from_file(&low_priority_output);
}




static void process_message(prelude_msg_t *msg) 
{
        int ret;
        idmef_message_t *idmef;

        manager_relay_msg_if_needed(msg);
                
        idmef = idmef_alert_new();

        ret = idmef_message_read(idmef, msg);
        if ( ret < 0 ) {
                log(LOG_ERR, "error reading IDMEF message.\n");
                return;
        }

        report_plugins_run(idmef->message.alert);
        
        idmef_message_free(idmef);
        
        prelude_msg_destroy(msg);
}




/*
 * This is the function responssible for handling queued alert.
 */
static void *process_alert(void *arg) 
{
        prelude_msg_t *msg;

        while ( 1 ) {
                
                msg = get_high_priority_alert();

                if ( ! msg )
                        msg = get_mid_priority_alert();

                if ( ! msg )
                        msg = get_low_priority_alert();

                
                if ( ! msg ) {
                        wait_for_alert();
                        continue;
                }

                process_message(msg);
        }
}



/*
 * Queue this alert to memory.
 */
static void queue_alert_to_memory(prelude_msg_t *msg) 
{
        pthread_mutex_lock(&list_mutex);
        
        in_memory_count++;
        prelude_list_add_tail((prelude_linked_object_t *) msg, &alert_list);
        
        if ( in_memory_count == 1 )
                pthread_cond_signal(&input_cond);
        
        pthread_mutex_unlock(&list_mutex);
}



/*
 * 
 */
static int init_file_output(const char *filename, file_output_t *out) 
{
        int fd;

        fd = open(filename, O_CREAT, S_IRUSR|S_IWUSR);
        if ( fd < 0 ) {
                log(LOG_ERR, "couldn't open %s for appending.\n", filename);
                return -1;
        }

        out->fd = prelude_io_new();
        if ( ! out->fd ) {
                log(LOG_ERR, "couldn't associate FD to prelude IO object.\n");
                close(fd);
                return -1;
        }

        prelude_io_set_file_io(out->fd, fd);

        out->count = 0;
        pthread_mutex_init(&out->mutex, NULL);

        return 0;
}



/*
 *
 */
static void destroy_file_output(file_output_t *out) 
{
        pthread_mutex_destroy(&out->mutex);
        prelude_io_close(out->fd);
        prelude_io_destroy(out->fd);
}




void alert_schedule(prelude_msg_t *msg, prelude_io_t *src) 
{
        int ret;
        uint8_t priority;

        priority = prelude_msg_get_priority(msg);
        
        if ( in_memory_count < MAX_ALERT_IN_MEMORY || priority == PRELUDE_MSG_PRIORITY_HIGH ) 
                queue_alert_to_memory(msg);

        else if ( priority == PRELUDE_MSG_PRIORITY_MID ) {
                
                ret = prelude_msg_forward(msg, mid_priority_output.fd, src);
                if ( ret )
                        mid_priority_output.count++;
        }

        else if ( priority == PRELUDE_MSG_PRIORITY_LOW ) {

                ret = prelude_msg_forward(msg, low_priority_output.fd, src);
                if ( ret )
                        low_priority_output.count++;
        }
}




int alert_scheduler_init(void) 
{
        int ret;

        ret = init_file_output(MID_PRIORITY_ALERT_FILENAME, &mid_priority_output);
        if ( ret < 0 )
                return -1;

        ret = init_file_output(LOW_PRIORITY_ALERT_FILENAME, &low_priority_output);
        if ( ret < 0 ) {
                destroy_file_output(&mid_priority_output);
                return -1;
        }
        
        pthread_cond_init(&input_cond, NULL);
        pthread_mutex_init(&list_mutex, NULL);

        in_memory_count = 0;
        
        ret = pthread_create(&thread, NULL, &process_alert, NULL);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't create alert processing thread.\n");
                return -1;
        }
        
        return 0;
}




void alert_scheduler_exit(void) 
{
        log(LOG_INFO, "Waiting for queued alert to be processed.\n");
        
        pthread_cancel(thread);
        
        destroy_file_output(&mid_priority_output);
        destroy_file_output(&low_priority_output);

        pthread_cond_destroy(&input_cond);
        pthread_mutex_destroy(&list_mutex);
}










