/*****
*
* Copyright (C) 2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <pthread.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-connection-pool.h>

#include "reverse-relaying.h"
#include "server-generic.h"
#include "sensor-server.h"


typedef struct {
        pthread_mutex_t mutex;
        prelude_connection_pool_t *pool;
} reverse_relay_t;


static reverse_relay_t receiver = { PTHREAD_MUTEX_INITIALIZER, NULL};
static reverse_relay_t initiator = { PTHREAD_MUTEX_INITIALIZER, NULL};

extern server_generic_t *sensor_server;
extern prelude_client_t *manager_client;



static int connection_event_cb(prelude_connection_pool_t *pool,
                               prelude_connection_pool_event_t event, prelude_connection_t *cnx) 
{
        int ret;
        
        if ( ! (event & PRELUDE_CONNECTION_POOL_EVENT_ALIVE) )
                return 0;

        prelude_connection_set_data(cnx, &initiator);
        
        ret = sensor_server_add_client(sensor_server, cnx);
        if ( ret < 0 )
                prelude_log(PRELUDE_LOG_WARN, "error adding new client to reverse relay list.\n");

        return 0;
}



int reverse_relay_set_receiver_alive(prelude_connection_t *cnx) 
{
        int ret;

        if ( ! receiver.pool )
                return 0;
        
        pthread_mutex_lock(&receiver.mutex);
        ret = prelude_connection_pool_set_connection_alive(receiver.pool, cnx);
        pthread_mutex_unlock(&receiver.mutex);

        return ret;
}



int reverse_relay_set_dead(prelude_connection_t *cnx)
{
        int ret = -1;
        reverse_relay_t *ptr = prelude_connection_get_data(cnx);
        
        pthread_mutex_lock(&ptr->mutex);
        ret = prelude_connection_pool_set_connection_dead(ptr->pool, cnx);
        pthread_mutex_unlock(&ptr->mutex);
        
        return ret;
}




int reverse_relay_add_receiver(prelude_connection_t *cnx) 
{
        int ret;
        prelude_client_profile_t *cp;

        cp = prelude_client_get_profile(manager_client);
        
        pthread_mutex_lock(&receiver.mutex);

        if ( ! receiver.pool ) {
                ret = prelude_connection_pool_new(&receiver.pool, cp, 0);
                if ( ! receiver.pool ) {
                        prelude_perror(ret, "error creating connection pool");
                        return -1;
                }
                
                prelude_connection_pool_set_flags(receiver.pool, ~PRELUDE_CONNECTION_POOL_FLAGS_RECONNECT);
                prelude_connection_pool_init(receiver.pool);
        }

        prelude_connection_set_data(cnx, &receiver);
        
        ret = prelude_connection_pool_add_connection(receiver.pool, cnx);
        if ( ret < 0 ) 
                prelude_perror(ret, "error adding connection");
                
        pthread_mutex_unlock(&receiver.mutex);
        
        return ret;
}



prelude_connection_t *reverse_relay_search_receiver(uint64_t analyzerid) 
{
        prelude_connection_t *cnx;
        prelude_list_t *head, *tmp;
                
        if ( ! receiver.pool )
                return NULL;
        
        head = prelude_connection_pool_get_connection_list(receiver.pool);
        
        pthread_mutex_lock(&receiver.mutex);
        
        prelude_list_for_each(head, tmp) {
                cnx = prelude_linked_object_get_object(tmp);
                                 
                if ( analyzerid == prelude_connection_get_peer_analyzerid(cnx) ) {
                        pthread_mutex_unlock(&receiver.mutex);
                        return cnx;
                }
        }
        
        pthread_mutex_unlock(&receiver.mutex);

        return NULL;
}



static int send_msgbuf(prelude_msgbuf_t *msgbuf, prelude_msg_t *msg)
{        
        pthread_mutex_lock(&receiver.mutex);
        prelude_connection_pool_broadcast(receiver.pool, msg);
        pthread_mutex_unlock(&receiver.mutex);
                
        return 0;
}



void reverse_relay_send_msg(idmef_message_t *idmef) 
{
        int ret;
        static prelude_msgbuf_t *msgbuf = NULL;
        
        if ( ! receiver.pool )
                return;

        if ( ! msgbuf ) {
                ret = prelude_msgbuf_new(&msgbuf);
                if ( ! msgbuf ) {
                        prelude_perror(ret, "error creating reverse relay msgbuf");
                        return;
                }
                
                prelude_msgbuf_set_callback(msgbuf, send_msgbuf);
        }
        
        idmef_message_write(idmef, msgbuf);
        prelude_msgbuf_mark_end(msgbuf);
}



int reverse_relay_create_initiator(const char *arg)
{
        int ret;
        prelude_client_profile_t *cp;
        
        cp = prelude_client_get_profile(manager_client);
        
        ret = prelude_connection_pool_new(&initiator.pool, cp, PRELUDE_CONNECTION_PERMISSION_IDMEF_READ);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating reverse relay");
                return ret;
        }
        
        prelude_connection_pool_set_flags(initiator.pool, PRELUDE_CONNECTION_POOL_FLAGS_RECONNECT);
        prelude_connection_pool_set_event_handler(initiator.pool, PRELUDE_CONNECTION_POOL_EVENT_DEAD |
                                                  PRELUDE_CONNECTION_POOL_EVENT_ALIVE, connection_event_cb);
        
        ret = prelude_connection_pool_set_connection_string(initiator.pool, arg);
        if ( ret < 0 ) {
                prelude_perror(ret, "error setting reverse relay connection string");
                prelude_connection_pool_destroy(initiator.pool);
                return ret;
        }

        ret = prelude_connection_pool_init(initiator.pool);
        if ( ret < 0 ) {
                prelude_perror(ret, "error initializing reverse relay");
                prelude_connection_pool_destroy(initiator.pool);
                return ret;
        }

        return 0;
}
