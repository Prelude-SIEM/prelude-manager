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

#include <libprelude/prelude-inttypes.h>
#include <libprelude/idmef.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-list.h>
#include <libprelude/prelude-linked-object.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-connection.h>
#include <libprelude/prelude-connection-mgr.h>
#include <libprelude/prelude-async.h>
#include <libprelude/prelude-message-buffered.h>
#include <libprelude/idmef-message-write.h>

#include "reverse-relaying.h"
#include "server-generic.h"
#include "sensor-server.h"


extern server_generic_t *sensor_server;
extern prelude_client_t *manager_client;

static prelude_connection_mgr_t *receiver_managers = NULL;
static prelude_connection_mgr_t *initiator_managers = NULL;
static pthread_mutex_t receiver_managers_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t initiator_managers_lock = PTHREAD_MUTEX_INITIALIZER;



static void reverse_relay_notify_state(prelude_list_t *clist) 
{
        int ret;
        prelude_list_t *tmp;
        prelude_connection_t *cnx;
        
        prelude_list_for_each(tmp, clist) {
                cnx = prelude_linked_object_get_object(tmp, prelude_connection_t);

                if ( prelude_connection_is_alive(cnx) < 0 ) 
                        continue;
                
                ret = sensor_server_add_client(sensor_server, cnx);
                if ( ret < 0 ) {
                        log(LOG_ERR, "error adding new client to reverse relay list.\n");
                        return;
                }
        }
}



int reverse_relay_tell_receiver_alive(prelude_connection_t *cnx) 
{
        int ret;

        if ( ! receiver_managers )
                return 0;
        
        pthread_mutex_lock(&receiver_managers_lock);
        ret = prelude_connection_mgr_tell_connection_alive(receiver_managers, cnx);
        pthread_mutex_unlock(&receiver_managers_lock);

        return ret;
}



int reverse_relay_tell_dead(prelude_connection_t *cnx) 
{
        int ret = -1;
        prelude_client_capability_t capability;
        
        capability = prelude_client_get_capability(prelude_connection_get_client(cnx));
        
        if ( capability & PRELUDE_CLIENT_CAPABILITY_RECV_IDMEF ) {        
                pthread_mutex_lock(&initiator_managers_lock);
                ret = prelude_connection_mgr_tell_connection_dead(initiator_managers, cnx);
                pthread_mutex_unlock(&initiator_managers_lock);
        }

        else if ( capability & PRELUDE_CLIENT_CAPABILITY_SEND_IDMEF ) {        
                pthread_mutex_lock(&receiver_managers_lock);
                ret = prelude_connection_mgr_tell_connection_dead(receiver_managers, cnx);
                pthread_mutex_unlock(&receiver_managers_lock);
        }
        
        return ret;
}




int reverse_relay_add_receiver(prelude_connection_t *cnx) 
{
        int ret;

        pthread_mutex_lock(&receiver_managers_lock);
        ret = prelude_connection_mgr_add_connection(&receiver_managers, cnx, 0);
        pthread_mutex_unlock(&receiver_managers_lock);

        return ret;
}




prelude_connection_t *reverse_relay_search_receiver(const char *addr) 
{
        prelude_connection_t *cnx;

        pthread_mutex_lock(&receiver_managers_lock);
        cnx = prelude_connection_mgr_search_connection(receiver_managers, addr);
        pthread_mutex_unlock(&receiver_managers_lock);

        return cnx;
}



static prelude_msg_t *send_msgbuf(prelude_msgbuf_t *msgbuf)
{
        prelude_msg_t *msg = prelude_msgbuf_get_msg(msgbuf);

        pthread_mutex_lock(&receiver_managers_lock);
        prelude_connection_mgr_broadcast(receiver_managers, msg);
        pthread_mutex_unlock(&receiver_managers_lock);
        
        prelude_msg_recycle(msg);
        
        return msg;
}



void reverse_relay_send_msg(idmef_message_t *idmef) 
{
        static prelude_msgbuf_t *msgbuf = NULL;
        
        if ( ! receiver_managers )
                return;

        if ( ! msgbuf ) {
                msgbuf = prelude_msgbuf_new(manager_client);
                if ( ! msgbuf )
                        return;
                
                prelude_msgbuf_set_callback(msgbuf, send_msgbuf);
        }
        
        idmef_message_write(idmef, msgbuf);
        prelude_msgbuf_mark_end(msgbuf);
}



int reverse_relay_create_initiator(const char *arg)
{
        int ret;
        
        initiator_managers = prelude_connection_mgr_new(manager_client);
        if ( ! initiator_managers )
                return -1;

        ret = prelude_connection_mgr_set_connection_string(initiator_managers, arg);
        if ( ret < 0 ) {
                prelude_connection_mgr_destroy(initiator_managers);
                return -1;
        }

        ret = prelude_connection_mgr_init(initiator_managers);
        if ( ret < 0 ) {
                prelude_connection_mgr_destroy(initiator_managers);
                return -1;
        }
        
        return 0;
}



int reverse_relay_init_initiator(void)
{
        if ( ! initiator_managers )
                return -1;

        prelude_connection_mgr_notify_connection(initiator_managers, reverse_relay_notify_state);
        reverse_relay_notify_state(prelude_connection_mgr_get_connection_list(initiator_managers));

        return 0;
}
