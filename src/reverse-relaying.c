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
#include <libprelude/prelude-connection-mgr.h>

#include "reverse-relaying.h"
#include "server-generic.h"
#include "sensor-server.h"


typedef struct {
        pthread_mutex_t mutex;
        prelude_connection_mgr_t *mgr;
} reverse_relay_t;


static reverse_relay_t receiver;
static reverse_relay_t initiator;

extern server_generic_t *sensor_server;
extern prelude_client_t *manager_client;



static int connection_event_cb(prelude_connection_mgr_t *mgr,
                               prelude_connection_mgr_event_t event, prelude_connection_t *cnx) 
{
        int ret;
        
        if ( ! (event & PRELUDE_CONNECTION_MGR_EVENT_ALIVE) )
                return 0;

        prelude_connection_set_data(cnx, &initiator);
        
        ret = sensor_server_add_client(sensor_server, cnx);
        if ( ret < 0 )
                prelude_log(PRELUDE_LOG_WARN, "error adding new client to reverse relay list.\n");

        return 0;
}



int reverse_relay_tell_receiver_alive(prelude_connection_t *cnx) 
{
        int ret;

        if ( ! receiver.mgr )
                return 0;
        
        pthread_mutex_lock(&receiver.mutex);
        ret = prelude_connection_mgr_tell_connection_alive(receiver.mgr, cnx);
        pthread_mutex_unlock(&receiver.mutex);

        return ret;
}



int reverse_relay_tell_dead(prelude_connection_t *cnx, prelude_connection_capability_t capability) 
{
        int ret = -1;
        reverse_relay_t *ptr = prelude_connection_get_data(cnx);
        
        pthread_mutex_lock(&ptr->mutex);
        ret = prelude_connection_mgr_tell_connection_dead(ptr->mgr, cnx);
        pthread_mutex_unlock(&ptr->mutex);
        
        return ret;
}




int reverse_relay_add_receiver(prelude_connection_t *cnx) 
{
        int ret;
        prelude_client_profile_t *cp;

        cp = prelude_client_get_profile(manager_client);
        
        pthread_mutex_lock(&receiver.mutex);

        if ( ! receiver.mgr ) {
                ret = prelude_connection_mgr_new(&receiver.mgr, cp, PRELUDE_CONNECTION_CAPABILITY_NONE);
                if ( ! receiver.mgr ) {
                        prelude_perror(ret, "error creating connection-mgr object");
                        return -1;
                }
                
                prelude_connection_mgr_set_flags(receiver.mgr, ~PRELUDE_CONNECTION_MGR_FLAGS_RECONNECT);
                prelude_connection_mgr_init(receiver.mgr);
        }

        prelude_connection_set_data(cnx, &receiver);
        
        ret = prelude_connection_mgr_add_connection(receiver.mgr, cnx);
        if ( ret < 0 ) 
                prelude_perror(ret, "error adding connection");
                
        pthread_mutex_unlock(&receiver.mutex);
        
        return ret;
}



prelude_connection_t *reverse_relay_search_receiver(uint64_t analyzerid) 
{
        prelude_connection_t *cnx;
        prelude_list_t *head, *tmp;

        if ( ! receiver.mgr )
                return NULL;
        
        head = prelude_connection_mgr_get_connection_list(receiver.mgr);
        
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
        prelude_connection_mgr_broadcast(receiver.mgr, msg);
        pthread_mutex_unlock(&receiver.mutex);
                
        return 0;
}



void reverse_relay_send_msg(idmef_message_t *idmef) 
{
        int ret;
        static prelude_msgbuf_t *msgbuf = NULL;
        
        if ( ! receiver.mgr )
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
        
        ret = prelude_connection_mgr_new(&initiator.mgr, cp, PRELUDE_CONNECTION_CAPABILITY_RECV_IDMEF);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating reverse relay");
                return -1;
        }
        
        prelude_connection_mgr_set_flags(initiator.mgr, PRELUDE_CONNECTION_MGR_FLAGS_RECONNECT);
        prelude_connection_mgr_set_event_handler(initiator.mgr,
                                                 PRELUDE_CONNECTION_MGR_EVENT_DEAD|PRELUDE_CONNECTION_MGR_EVENT_ALIVE,
                                                 connection_event_cb);
        
        ret = prelude_connection_mgr_set_connection_string(initiator.mgr, arg);
        if ( ret < 0 ) {
                prelude_perror(ret, "error setting reverse relay connection string");
                prelude_connection_mgr_destroy(initiator.mgr);
                return -1;
        }

        ret = prelude_connection_mgr_init(initiator.mgr);
        if ( ret < 0 ) {
                prelude_perror(ret, "error initializing reverse relay");
                prelude_connection_mgr_destroy(initiator.mgr);
                return -1;
        }
        
        return 0;
}




int reverse_relay_init(void)
{
        receiver.mgr = NULL;
        pthread_mutex_init(&receiver.mutex, NULL);

        initiator.mgr = NULL;
        pthread_mutex_init(&initiator.mutex, NULL);

        return 0;
}
