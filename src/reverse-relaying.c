/*****
*
* Copyright (C) 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-failover.h>
#include <libprelude/prelude-connection-pool.h>

#include "reverse-relaying.h"
#include "server-logic.h"
#include "server-generic.h"
#include "sensor-server.h"
#include "manager-options.h"


#define MESSAGE_FLUSH_MAX 100


typedef struct {
        pthread_mutex_t mutex;
        prelude_connection_pool_t *pool;
} reverse_relay_t;


struct reverse_relay_receiver {        
        prelude_list_t list;
        
        
        uint64_t analyzerid;
        
        unsigned int count;
        pthread_mutex_t mutex;
        prelude_failover_t *failover;
        server_generic_client_t *client;
};


static PRELUDE_LIST(receiver_list);
static prelude_msgbuf_t *msgbuf;
static pthread_mutex_t receiver_mutex = PTHREAD_MUTEX_INITIALIZER;
static reverse_relay_t initiator = { PTHREAD_MUTEX_INITIALIZER, NULL};

extern manager_config_t config;
extern prelude_client_t *manager_client;



static int connection_event_cb(prelude_connection_pool_t *pool,
                               prelude_connection_pool_event_t event, prelude_connection_t *cnx) 
{
        int ret;
        
        if ( ! (event & PRELUDE_CONNECTION_POOL_EVENT_ALIVE) )
                return 0;
        
        prelude_connection_set_data(cnx, &initiator);
        
        ret = sensor_server_add_client(config.server[0], cnx);
        if ( ret < 0 )
                prelude_log(PRELUDE_LOG_WARN, "error adding new client to reverse relay list.\n");

        return 0;
}



static reverse_relay_receiver_t *get_next_receiver(prelude_list_t **iter)
{
        prelude_list_t *tmp;
        reverse_relay_receiver_t *rrr = NULL;
        
        pthread_mutex_lock(&receiver_mutex);

        prelude_list_for_each_continue_safe(&receiver_list, tmp, *iter) {
                rrr = prelude_list_entry(tmp, reverse_relay_receiver_t, list);
                break;
        }
        
        pthread_mutex_unlock(&receiver_mutex);

        return rrr;
}




int reverse_relay_set_receiver_alive(reverse_relay_receiver_t *rrr, server_generic_client_t *client) 
{
        int ret;
        ssize_t size;
        prelude_msg_t *msg;
        prelude_failover_t *failover = rrr->failover;

        do {
                pthread_mutex_lock(&rrr->mutex);

                size = prelude_failover_get_saved_msg(failover, &msg);
                if ( size == 0 ) {
                        rrr->client = client;
                        pthread_mutex_unlock(&rrr->mutex);
                        break;
                }
                pthread_mutex_unlock(&rrr->mutex);
                
                if ( size < 0 ) {
                        prelude_perror((prelude_error_t) size, "could not retrieve saved message from disk");
                        return -1;
                }

                rrr->count++;
                
                ret = sensor_server_write_client(client, msg);
                if ( ret < 0 ) {
                        if ( prelude_error_get_code(ret) == PRELUDE_ERROR_EAGAIN ) {
                                server_generic_client_set_state(client, server_generic_client_get_state(client) |
                                                                SERVER_GENERIC_CLIENT_STATE_FLUSHING);
                                return 0;
                        }
                                                
                        return ret;
                }                
                
        } while ( (rrr->count % MESSAGE_FLUSH_MAX) != 0 );

        if ( size != 0 ) {
                server_logic_notify_write_enable((server_logic_client_t *) client);
                server_generic_client_set_state(client, server_generic_client_get_state(client) |
                                                SERVER_GENERIC_CLIENT_STATE_FLUSHING);
                return 0;
        }

        if ( rrr->count ) {
                server_generic_log_client(client, PRELUDE_LOG_INFO,
                                          "flushed %u messages received while analyzer was offline.\n", rrr->count);
                rrr->count = 0;
        }

        server_generic_client_set_state(client, server_generic_client_get_state(client) & ~SERVER_GENERIC_CLIENT_STATE_FLUSHING);
                
        return 0;
}



int reverse_relay_set_initiator_dead(prelude_connection_t *cnx)
{
        int ret = -1;
        reverse_relay_t *ptr = prelude_connection_get_data(cnx);
        
        pthread_mutex_lock(&ptr->mutex);
        ret = prelude_connection_pool_set_connection_dead(ptr->pool, cnx);
        pthread_mutex_unlock(&ptr->mutex);
        
        return ret;
}



void reverse_relay_set_receiver_dead(reverse_relay_receiver_t *rrr)
{
        pthread_mutex_lock(&rrr->mutex);
        rrr->client = NULL;
        pthread_mutex_unlock(&rrr->mutex);
}



int reverse_relay_new_receiver(reverse_relay_receiver_t **rrr, server_generic_client_t *client, uint64_t analyzerid) 
{
        int ret;
        char buf[512];
        reverse_relay_receiver_t *new;
        
        new = malloc(sizeof(*new));
        if ( ! new )
                return -1;

        new->count = 0;
        new->client = client;
        new->analyzerid = analyzerid;
        
        prelude_client_profile_get_backup_dirname(prelude_client_get_profile(manager_client), buf, sizeof(buf));
        snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "/%" PRELUDE_PRIu64, analyzerid);
        
        ret = prelude_failover_new(&new->failover, buf);
        if ( ret < 0 ) {
                prelude_perror(ret, "could not create failover");
                free(new);
                return -1;
        }
        
        pthread_mutex_init(&new->mutex, NULL);
        
        pthread_mutex_lock(&receiver_mutex);
        prelude_list_add_tail(&receiver_list, &new->list);
        pthread_mutex_unlock(&receiver_mutex);

        *rrr = new;
        
        return 0;
}



reverse_relay_receiver_t *reverse_relay_search_receiver(uint64_t analyzerid) 
{
        prelude_list_t *iter = NULL;
        reverse_relay_receiver_t *item;
        
        while ( (item = get_next_receiver(&iter)) ) {
                
                if ( analyzerid == item->analyzerid )
                        return item;
        }
        
        return NULL;
}


static int send_msgbuf(prelude_msgbuf_t *msgbuf, prelude_msg_t *msg)
{
        int ret;
        reverse_relay_receiver_t *item = prelude_msgbuf_get_data(msgbuf);

        pthread_mutex_lock(&item->mutex);
        
        if ( item->client ) {
                ret = sensor_server_queue_write_client(item->client, msg);
                pthread_mutex_unlock(&item->mutex);
                return ret;
        }

        pthread_mutex_unlock(&item->mutex);
        ret = prelude_failover_save_msg(item->failover, msg);
        if ( ret < 0 )
                prelude_perror(ret, "could not save message to disk");
        
        prelude_msg_destroy(msg);
        
        return 0;
}



static int get_issuer_analyzerid(idmef_message_t *idmef, uint64_t *analyzerid)
{
        idmef_alert_t *alert;
        idmef_message_type_t type;
        idmef_heartbeat_t *heartbeat;
        idmef_analyzer_t *analyzer, *last = NULL;
        
        type = idmef_message_get_type(idmef);
        
        if ( type == IDMEF_MESSAGE_TYPE_ALERT ) {
                alert = idmef_message_get_alert(idmef);
                while ( (analyzer = idmef_alert_get_next_analyzer(alert, last)) )
                        last = analyzer;
        }

        else if ( type == IDMEF_MESSAGE_TYPE_HEARTBEAT ) {
                heartbeat = idmef_message_get_heartbeat(idmef);
                while ( (analyzer = idmef_heartbeat_get_next_analyzer(heartbeat, last)) )
                        last = analyzer;
        }

        else return -1;
        
        if ( last && prelude_string_get_string(idmef_analyzer_get_analyzerid(last)) )
                *analyzerid = strtoull(prelude_string_get_string(idmef_analyzer_get_analyzerid(last)), NULL, 10);
        else
                *analyzerid = 0;
        
        return 0;
}



void reverse_relay_send_receiver(idmef_message_t *idmef) 
{
        int ret;
        uint64_t analyzerid;
        prelude_list_t *iter = NULL;
        reverse_relay_receiver_t *item;

        ret = get_issuer_analyzerid(idmef, &analyzerid);
        if ( ret < 0 )
                return;
        
        /*
         * FIXME: this is dirty since we are encoding
         * the IDMEF message once per receiver.
         *
         * Implement a better scheme where we create an intermediate
         * "linking" object, which share a refcount, a message, and
         * a mutex, but hold it's list member private.
         */
        while ( (item = get_next_receiver(&iter)) ) {

                if ( analyzerid == item->analyzerid )
                        /* we're not an echo server, let's skip the sender */
                        continue;

                prelude_msgbuf_set_data(msgbuf, item);
                idmef_message_write(idmef, msgbuf);
                prelude_msgbuf_mark_end(msgbuf);                
        }
}



int reverse_relay_create_initiator(const char *arg)
{
        int ret;
        prelude_client_profile_t *cp;
        
        cp = prelude_client_get_profile(manager_client);
        
        ret = prelude_connection_pool_new(&initiator.pool, cp, PRELUDE_CONNECTION_PERMISSION_IDMEF_READ);
        if ( ret < 0 )
                return ret;
        
        prelude_connection_pool_set_flags(initiator.pool, PRELUDE_CONNECTION_POOL_FLAGS_RECONNECT);
        prelude_connection_pool_set_event_handler(initiator.pool, PRELUDE_CONNECTION_POOL_EVENT_DEAD |
                                                  PRELUDE_CONNECTION_POOL_EVENT_ALIVE, connection_event_cb);
        
        ret = prelude_connection_pool_set_connection_string(initiator.pool, arg);
        if ( ret < 0 ) {
                prelude_connection_pool_destroy(initiator.pool);
                return ret;
        }

        ret = prelude_connection_pool_init(initiator.pool);
        if ( ret < 0 ) {
                prelude_connection_pool_destroy(initiator.pool);
                return ret;
        }

        return 0;
}



int reverse_relay_init(void)
{
        int ret;
        
        ret = prelude_msgbuf_new(&msgbuf);
        if ( ! msgbuf ) {
                prelude_perror(ret, "error creating reverse relay msgbuf");
                return -1;
        }
        
        prelude_msgbuf_set_callback(msgbuf, send_msgbuf);
        prelude_msgbuf_set_flags(msgbuf, PRELUDE_MSGBUF_FLAGS_ASYNC);

        return 0;
}
