/*****
*
* Copyright (C) 2001, 2002, 2004 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <libprelude/prelude-list.h>
#include <libprelude/prelude-log.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-message-id.h>
#include <libprelude/prelude-ident.h>
#include <libprelude/extract.h>
#include <libprelude/prelude-connection.h>
#include <libprelude/prelude-connection-mgr.h>

#include "server-logic.h"
#include "server-generic.h"
#include "sensor-server.h"
#include "idmef-message-scheduler.h"
#include "pconfig.h"
#include "reverse-relaying.h"


typedef struct {
        SERVER_GENERIC_OBJECT;
        prelude_list_t list;

        idmef_queue_t *queue;
        prelude_connection_t *cnx;
        
        pthread_mutex_t *list_mutex;
        prelude_msg_t *options_list;
} sensor_fd_t;


extern prelude_client_t *manager_client;


static PRELUDE_LIST_HEAD(send_idmef_cnx_list);

static PRELUDE_LIST_HEAD(admins_cnx_list);
static PRELUDE_LIST_HEAD(sensors_cnx_list);
static PRELUDE_LIST_HEAD(managers_cnx_list);
static pthread_mutex_t admins_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t sensors_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t managers_list_mutex = PTHREAD_MUTEX_INITIALIZER;




static sensor_fd_t *search_cnx(prelude_list_t *head, uint64_t analyzerid) 
{
        sensor_fd_t *cnx;
        prelude_list_t *tmp;

        prelude_list_for_each(tmp, head) {
                cnx = prelude_list_entry(tmp, sensor_fd_t, list);

                if ( cnx->ident == analyzerid )
                        return cnx;
        }

        return NULL;
}




static int forward_message_to_all(sensor_fd_t *client, prelude_msg_t *msg,
                                  prelude_list_t *head, pthread_mutex_t *list_mutex) 
{
        sensor_fd_t *cnx;
        prelude_list_t *tmp;

        pthread_mutex_lock(list_mutex);
        
        prelude_list_for_each(tmp, head) {
                cnx = prelude_list_entry(tmp, sensor_fd_t, list);

                if ( cnx->port )
                        log_client(client, "message forwarded to [%s:%d, %s:0x%llx].\n",
                                   cnx->addr, cnx->port, cnx->client_type, cnx->ident);
                else
                        log_client(client, "message forwarded to [unix, %s:0x%llx].\n",
                                   cnx->client_type, cnx->ident);
                
                prelude_msg_write(msg, cnx->fd);
        }
        
        pthread_mutex_unlock(list_mutex);

        return 0;
}




static int forward_option_reply_to_admin(sensor_fd_t *cnx, uint64_t analyzerid, prelude_msg_t *msg) 
{
        int ret;
        sensor_fd_t *admin;
        
        pthread_mutex_lock(&admins_list_mutex);

        admin = search_cnx(&admins_cnx_list, analyzerid);
        if ( ! admin ) {
                pthread_mutex_unlock(&admins_list_mutex);
                return forward_message_to_all(cnx, msg, &managers_cnx_list, &managers_list_mutex);
        }

        if ( admin->port )
                log_client(cnx, "option reply forwarded to [%s:%d, %s:0x%llx].\n",
                           admin->addr, admin->port, admin->client_type, analyzerid);
        else
                log_client(cnx, "option reply forwarded to [unix, %s:0x%llx].\n",
                           admin->client_type, analyzerid);
                
        ret = prelude_msg_write(msg, admin->fd);
        pthread_mutex_unlock(&admins_list_mutex);

        return ret;
}




static int forward_option_request_to_sensor(sensor_fd_t *cnx, uint64_t analyzerid, prelude_msg_t *msg)
{
        int ret;
        sensor_fd_t *sensor;
        
        pthread_mutex_lock(&sensors_list_mutex);

        sensor = search_cnx(&sensors_cnx_list, analyzerid);
        if ( ! sensor ) {
                pthread_mutex_unlock(&sensors_list_mutex);
                return forward_message_to_all(cnx, msg, &managers_cnx_list, &managers_list_mutex);
        }

        if ( sensor->port )
                log_client(cnx, "option request forwarded to [%s:%d, %s:0x%llx].\n",
                           sensor->addr, sensor->port, sensor->client_type, analyzerid);
        else
                log_client(cnx, "option request forwarded to [unix, %s:0x%llx].\n",
                           sensor->client_type, analyzerid);
                
        ret = prelude_msg_write(msg, sensor->fd);
        
        pthread_mutex_unlock(&sensors_list_mutex);

        return ret;
}




static int forward_option_list_to_admin(sensor_fd_t *cnx, prelude_msg_t *msg) 
{
        if ( cnx->options_list )
                prelude_msg_destroy(cnx->options_list);
        
        cnx->options_list = msg;

        return forward_message_to_all(cnx, msg, &admins_cnx_list, &admins_list_mutex);
}





static int request_sensor_option(sensor_fd_t *client, prelude_msg_t *msg) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        uint64_t target_sensor_ident = 0;

        while ( (ret = prelude_msg_get(msg, &tag, &len, &buf)) > 0 ) {

                 /*
                  * We just need the target ident, so that we know
                  * where to forward this message.
                  */
                if ( tag != PRELUDE_MSG_OPTION_TARGET_ID )
                        continue;
                
                ret = extract_uint64_safe(&target_sensor_ident, buf, len);
                if ( ret < 0 )
                        return -1;
        }
        
        if ( ret < 0 ) {
                log(LOG_ERR, "error decoding message.\n");
                return -1;
        }
        
        ret = forward_option_request_to_sensor(client, target_sensor_ident, msg);
        if ( ret < 0 ) {
                log(LOG_ERR, "error broadcasting option to sensor id 0x%llx.\n", target_sensor_ident);
                return -1;
        }
        
        return 0;
}




static int reply_sensor_option(sensor_fd_t *client, prelude_msg_t *msg) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        uint64_t target_admin_ident = 0;

        while ( (ret = prelude_msg_get(msg, &tag, &len, &buf)) > 0 ) {

                 /*
                  * We just need the target ident, so that we know
                  * where to forward this message.
                  */
                if ( tag != PRELUDE_MSG_OPTION_TARGET_ID )
                        continue;
                
                ret = extract_uint64_safe(&target_admin_ident, buf, len);
                if ( ret < 0 )
                        return -1;
        }
        
        if ( ret < 0 ) {
                log(LOG_ERR, "error decoding message.\n");
                return -1;
        }
        
        ret = forward_option_reply_to_admin(client, target_admin_ident, msg);
        if ( ret < 0 ) {
                log(LOG_ERR, "error broadcasting option to sensor id 0x%llx.\n", target_admin_ident);
                return -1;
        }
        
        return 0;
}




static int handle_declare_ident(sensor_fd_t *cnx, void *buf, uint32_t blen) 
{
        int ret;

        ret = extract_uint64_safe(&cnx->ident, buf, blen);
        if ( ret < 0 )
                return -1;
        
        log_client(cnx, "declared ident 0x%llx.\n", cnx->ident);
                
        return 0;
}




static int handle_declare_child_relay(sensor_fd_t *cnx) 
{
        cnx->queue = idmef_message_scheduler_queue_new();
        if ( ! cnx->queue )
                return -1;
        
        /*
         * our client is a relaying Manager.
         * we want relaying Manager to be at the end of our list (see
         * sensor_server_broadcast_admin_command).
         */
        pthread_mutex_lock(&managers_list_mutex);
        prelude_list_add_tail(&cnx->list, &managers_cnx_list);
        pthread_mutex_unlock(&managers_list_mutex);

        cnx->list_mutex = &managers_list_mutex;

        cnx->client_type = "child-manager";
        log_client(cnx, "client declared to be a children relay (relaying to us).\n");

        return 0;
}




static int handle_declare_parent_relay(sensor_fd_t *cnx) 
{
        int state;
        prelude_connection_t *pc;
        
        pc = reverse_relay_search_receiver(cnx->addr);
        if ( pc ) {
                /*
                 * This reverse relay is already known:
                 * Associate the new FD with it, and tell connection-mgr, the connection is alive.
                 */
                prelude_io_close(prelude_connection_get_fd(pc));
                prelude_io_destroy(prelude_connection_get_fd(pc));
                prelude_connection_set_fd(pc, cnx->fd);
        } else {
                /*
                 * First time a child relay with this address connect here.
                 * Add it to the manager list. Type of the created connection is -parent-
                 * because *we* are sending the alert to the child.
                 */
                pc = prelude_connection_new(manager_client, cnx->addr, 0);
                if ( ! pc )
                        return -1;
                
                prelude_connection_set_fd(pc, cnx->fd);
                reverse_relay_add_receiver(pc);
        }
        
        state = prelude_connection_get_state(pc) | PRELUDE_CONNECTION_ESTABLISHED;
        prelude_connection_set_state(pc, state);

        cnx->client_type = "parent-manager";
        log_client(cnx, "client declared to be a parent relay (we relay to him).\n");
        
        reverse_relay_tell_receiver_alive(pc);
        
        /*
         * set fd to NULL so that the client removal, which'll trigger the close callback,
         * won't destroy the fd, that we still reference in order to send data to the
         * remote manager.
         */
        cnx->fd = NULL;
        server_logic_remove_client((server_logic_client_t *) cnx);
        
        return -2;
}




static int handle_declare_sensor(sensor_fd_t *cnx) 
{
        cnx->queue = idmef_message_scheduler_queue_new();
        if ( ! cnx->queue )
                return -1;
        
        cnx->client_type = "sensor";
        
        log_client(cnx, "client declared to be a sensor.\n");

        pthread_mutex_lock(&sensors_list_mutex);
        prelude_list_add_tail(&cnx->list, &sensors_cnx_list);
        pthread_mutex_unlock(&sensors_list_mutex);

        cnx->list_mutex = &sensors_list_mutex;
        
        return 0;
}




static int handle_declare_admin(sensor_fd_t *cnx) 
{
        cnx->client_type = "admin";
        
        log_client(cnx, "client declared to be an administrative client.\n");

        pthread_mutex_lock(&admins_list_mutex);
        prelude_list_add_tail(&cnx->list, &admins_cnx_list);
        pthread_mutex_unlock(&admins_list_mutex);

        cnx->list_mutex = &admins_list_mutex;
        
        return 0;
}




static int read_client_type(sensor_fd_t *cnx, prelude_msg_t *msg) 
{
        int ret;     
        void *buf;
        uint8_t tag;
        uint32_t dlen;
        
        ret = prelude_msg_get(msg, &tag, &dlen, &buf);
        if ( ret < 0 ) {
                log_client(cnx, "error decoding message.\n");
                return -1;
        }
        
        if ( ret == 0 ) 
                return 0;

        prelude_msg_destroy(msg);

        if ( tag & PRELUDE_CLIENT_CAPABILITY_RECV_IDMEF && tag & PRELUDE_CLIENT_CAPABILITY_SEND_IDMEF )
                return handle_declare_child_relay(cnx);
        
        if ( tag & PRELUDE_CLIENT_CAPABILITY_SEND_IDMEF )
                return handle_declare_sensor(cnx);

        if ( tag & PRELUDE_CLIENT_CAPABILITY_RECV_IDMEF )
                return handle_declare_parent_relay(cnx);

        if ( tag & PRELUDE_CLIENT_CAPABILITY_SEND_ADMIN )
                return handle_declare_admin(cnx);
        
        log(LOG_ERR, "- client declared unknow capability: closing connection.\n");
        
        return -1;
}




static int read_ident_message(sensor_fd_t *cnx, prelude_msg_t *msg) 
{
        int ret;        
        void *buf;
        uint8_t tag;
        uint32_t dlen;

        ret = prelude_msg_get(msg, &tag, &dlen, &buf);
        if ( ret < 0 ) {
                log_client(cnx, "error decoding message.\n");
                return -1;
        }

        if ( ret == 0 ) 
                return 0;
        
        switch (tag) {
                
        case PRELUDE_MSG_ID_DECLARE:
                ret = handle_declare_ident(cnx, buf, dlen);
                break;
                
        default:
                log_client(cnx, "unknow ID tag: %d.\n", tag);
                ret = -1;
                break;
        }
        
        return ret;
}




static int read_connection_cb(server_generic_client_t *client)
{
        int ret;
        uint8_t tag;
        prelude_msg_t *msg;
        prelude_msg_status_t status;
        sensor_fd_t *cnx = (sensor_fd_t *) client;
        
        status = prelude_msg_read(&cnx->msg, cnx->fd);
        if ( status == prelude_msg_eof || status == prelude_msg_error ) {
                /*
                 * end of file on read
                 */
                return -1;
        }

        else if ( status == prelude_msg_unfinished )
                /*
                 * We don't have the whole message yet
                 */
                return 0;

        msg = cnx->msg;
        cnx->msg = NULL;

        tag = prelude_msg_get_tag(msg);
        
        /*
         * If we get there, we have a whole message.
         */        
        switch ( tag ) {
        case PRELUDE_MSG_IDMEF:
                ret = idmef_message_schedule(cnx->queue, msg);
                return ret;
                
        case PRELUDE_MSG_ID:
                ret = read_ident_message(cnx, msg);
                break;

        case PRELUDE_MSG_CLIENT_CAPABILITY:
                ret = read_client_type(cnx, msg);
                break;
                
        case PRELUDE_MSG_OPTION_LIST:
                ret = forward_option_list_to_admin(cnx, msg);
                break;

        case PRELUDE_MSG_OPTION_REQUEST:  
                ret = request_sensor_option(cnx, msg);
                break;

        case PRELUDE_MSG_OPTION_REPLY:
                ret = reply_sensor_option(cnx, msg);
                break;

        default:
                log_client(cnx, "unknow message id %d\n", prelude_msg_get_tag(msg));
                ret = 0;
                break;
        }

        if ( tag != PRELUDE_MSG_CLIENT_CAPABILITY && tag != PRELUDE_MSG_OPTION_LIST )
                /*
                 * msg will be destroyed before for this kind of message.
                 */
                prelude_msg_destroy(msg);

        return ret;
}




static void close_connection_cb(server_generic_client_t *ptr) 
{
        sensor_fd_t *cnx = (sensor_fd_t *) ptr;
        
        if ( cnx->cnx )
                reverse_relay_tell_dead(cnx->cnx);

        if ( cnx->list_mutex ) {
                pthread_mutex_lock(cnx->list_mutex);
                prelude_list_del(&cnx->list);
                pthread_mutex_unlock(cnx->list_mutex);
        }

        /*
         * If cnx->msg is not NULL, it mean the sensor
         * closed the connection without finishing to send
         * a message. Destroy the unfinished message.
         */
        if ( cnx->msg )
                prelude_msg_destroy(cnx->msg);

        if ( cnx->queue )
                idmef_message_scheduler_queue_destroy(cnx->queue);
}




static int accept_connection_cb(server_generic_client_t *ptr) 
{
        return 0;
}



server_generic_t *sensor_server_new(const char *addr, uint16_t port) 
{
        int ret;
        server_generic_t *server;
        
        server = server_generic_new(addr, port, sizeof(sensor_fd_t), accept_connection_cb,
                                    read_connection_cb, close_connection_cb);
        if ( ! server ) {
                log(LOG_ERR, "error creating a generic server.\n");
                return NULL;
        }
        
        ret = idmef_message_scheduler_init();
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't initialize alert scheduler.\n");
                return NULL;
        }
        
        return server;
}



void sensor_server_stop(server_generic_t *server) 
{
        server_generic_stop(server);
}




int sensor_server_add_client(server_generic_t *server, prelude_connection_t *cnx) 
{
        sensor_fd_t *cdata;
        
        cdata = calloc(1, sizeof(*cdata));
        if ( ! cdata ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }
        
        cdata->queue = idmef_message_scheduler_queue_new();
        if ( ! cdata->queue ) {
                free(cdata);
                return -1;
        }
        
        cdata->addr = strdup(prelude_connection_get_daddr(cnx));
        cdata->is_authenticated = 1;
        cdata->fd = prelude_connection_get_fd(cnx);
        cdata->cnx = cnx;
        cdata->client_type = "parent-manager";
        
        server_generic_process_requests(server, (server_generic_client_t *) cdata);
        
        return 0;
}
