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
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-message-id.h>
#include <libprelude/prelude-ident.h>
#include <libprelude/prelude-extract.h>
#include <libprelude/prelude-connection.h>
#include <libprelude/prelude-connection-mgr.h>
#include <libprelude/prelude-option-wide.h>

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
        
        prelude_client_capability_t capability;
} sensor_fd_t;


extern prelude_client_t *manager_client;


static PRELUDE_LIST_HEAD(send_idmef_cnx_list);

static PRELUDE_LIST_HEAD(admins_cnx_list);
static PRELUDE_LIST_HEAD(sensors_cnx_list);
static pthread_mutex_t admins_list_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t sensors_list_mutex = PTHREAD_MUTEX_INITIALIZER;




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
        int ret;
        sensor_fd_t *cnx;
        prelude_list_t *tmp;

        pthread_mutex_lock(list_mutex);
        
        prelude_list_for_each(tmp, head) {
                cnx = prelude_list_entry(tmp, sensor_fd_t, list);
                        
                do {
                        ret = prelude_msg_write(msg, cnx->fd);
                } while ( ret == PRELUDE_ERROR_EAGAIN );
        }
        
        pthread_mutex_unlock(list_mutex);

        return 0;
}




static int forward_option_reply_to_admin(sensor_fd_t *cnx, uint64_t analyzerid, prelude_msg_t *msg) 
{
        int ret;
        char buf[128];
        sensor_fd_t *admin;
        
        pthread_mutex_lock(&admins_list_mutex);

        admin = search_cnx(&admins_cnx_list, analyzerid);
        if ( ! admin ) {
                pthread_mutex_unlock(&admins_list_mutex);
                server_generic_log_client((server_generic_client_t *) cnx,
                                          "admin client %llu is not available here.\n", analyzerid);
                return -1;
        }

        server_generic_get_addr_string((server_generic_client_t *) admin, buf, sizeof(buf));
        server_generic_log_client((server_generic_client_t *) cnx,
                                  "option reply forwarded to [%s].\n", buf);
                
        do {
                ret = prelude_msg_write(msg, admin->fd);
        } while ( ret == PRELUDE_ERROR_EAGAIN );
        
        pthread_mutex_unlock(&admins_list_mutex);

        return ret;
}




static int forward_option_request_to_sensor(sensor_fd_t *cnx, uint64_t analyzerid, prelude_msg_t *msg)
{
        int ret;
        char buf[128];
        sensor_fd_t *sensor;
        
        pthread_mutex_lock(&sensors_list_mutex);
        
        sensor = search_cnx(&sensors_cnx_list, analyzerid);        
        if ( ! sensor ) {
                pthread_mutex_unlock(&sensors_list_mutex);
                server_generic_log_client((server_generic_client_t *) cnx,
                                          "client %llu is not available here.\n", analyzerid);
                return -1;
        }
        
        pthread_mutex_unlock(&sensors_list_mutex);

        server_generic_get_addr_string((server_generic_client_t *) sensor, buf, sizeof(buf));
        server_generic_log_client((server_generic_client_t *) cnx,
                                  "option request forwarded to [%s].\n", buf);
        
        do {
                ret = prelude_msg_write(msg, sensor->fd);
        } while ( ret == PRELUDE_ERROR_EAGAIN );
        
        return ret;
}



static int get_msg_target_ident(sensor_fd_t *client, prelude_msg_t *msg, uint64_t *ident, int direction)
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        uint32_t hop = -1, tmp;
        
        while ( prelude_msg_get(msg, &tag, &len, &buf) == 0 ) {

                if ( tag == PRELUDE_MSG_OPTION_HOP ) {
                        ret = prelude_extract_int32_safe(&hop, buf, len);
                        if ( ret < 0 )
                                break;

                        if ( direction == PRELUDE_MSG_OPTION_REQUEST )
                                hop++;
                        else
                                hop--;

                        tmp = htonl(hop);
                        memcpy(buf, &tmp, sizeof(tmp));
                        continue;
                }
                
                 /*
                  * We just need the target ident, so that we know
                  * where to forward this message.
                  */
                if ( tag != PRELUDE_MSG_OPTION_TARGET_ID )
                        continue;
                                
                if ( hop >= (len / sizeof(uint64_t)) ) {
                        if ( (hop - 1) >= (len / sizeof(uint64_t)) )
                                break;
                        else
                                hop--;
                }
                
                return prelude_extract_uint64_safe(ident, ((uint8_t *) buf) + (hop * sizeof(uint64_t)), sizeof(uint64_t));
        }

        server_generic_log_client((server_generic_client_t *) client,
                                  "message does not carry a valid target: closing connection.\n");

        return -1;
}




static int request_sensor_option(sensor_fd_t *client, prelude_msg_t *msg) 
{
        int ret;
        uint64_t target_sensor_ident = 0;

        ret = get_msg_target_ident(client, msg, &target_sensor_ident, PRELUDE_MSG_OPTION_REQUEST);
        if ( ret < 0 )
                return -1;
        
        if ( target_sensor_ident == prelude_client_get_analyzerid(manager_client) ) {
                server_generic_log_client((server_generic_client_t *) client,
                                          "option request forwarded to [local manager].\n");

                prelude_msg_recycle(msg);
                return prelude_option_process_request(manager_client, client->fd, msg);
        }
        
        ret = forward_option_request_to_sensor(client, target_sensor_ident, msg);
        if ( ret < 0 )
                return -1;
        
        return 0;
}




static int reply_sensor_option(sensor_fd_t *client, prelude_msg_t *msg) 
{
        int ret;
        uint64_t target_admin_ident = 0;

        ret = get_msg_target_ident(client, msg, &target_admin_ident, PRELUDE_MSG_OPTION_REPLY);
        if ( ret < 0 ) 
                return -1;

        /*
         * The one replying the option doesn't care about client presence or not.
         */
        forward_option_reply_to_admin(client, target_admin_ident, msg);
        return 0;
}




static int handle_declare_ident(sensor_fd_t *cnx, void *buf, uint32_t blen) 
{
        int ret;

        ret = prelude_extract_uint64_safe(&cnx->ident, buf, blen);
        if ( ret < 0 )
                return -1;
        
        server_generic_log_client((server_generic_client_t *) cnx,
                                  "declared ident 0x%" PRIx64 ".\n", cnx->ident);
                
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
        pthread_mutex_lock(&sensors_list_mutex);
        prelude_list_add_tail(&cnx->list, &sensors_cnx_list);
        pthread_mutex_unlock(&sensors_list_mutex);

        cnx->list_mutex = &sensors_list_mutex;
        cnx->client_type = "child-manager";
        
        server_generic_log_client((server_generic_client_t *) cnx,
                                  "client declared to be a children relay (relaying to us).\n");

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
        
        server_generic_log_client((server_generic_client_t *) cnx,
                                  "client declared to be a parent relay (we relay to him).\n");
        
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
        server_generic_log_client((server_generic_client_t *) cnx,
                                  "client declared to be a sensor.\n");
        
        pthread_mutex_lock(&sensors_list_mutex);
        prelude_list_add_tail(&cnx->list, &sensors_cnx_list);
        pthread_mutex_unlock(&sensors_list_mutex);

        cnx->list_mutex = &sensors_list_mutex;
        
        return 0;
}




static int handle_declare_admin(sensor_fd_t *cnx) 
{
        cnx->client_type = "admin";
        
        server_generic_log_client((server_generic_client_t *) cnx,
                                  "client declared to be an administrative client.\n");

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
                server_generic_log_client((server_generic_client_t *) cnx, "error decoding message - %s: %s.\n",
                                          prelude_strsource(ret), prelude_strerror(ret));
                return -1;
        }

        cnx->capability = tag;

        if ( tag & PRELUDE_CLIENT_CAPABILITY_RECV_IDMEF && tag & PRELUDE_CLIENT_CAPABILITY_SEND_IDMEF )
                return handle_declare_child_relay(cnx);
        
        if ( tag & PRELUDE_CLIENT_CAPABILITY_SEND_IDMEF )
                return handle_declare_sensor(cnx);

        if ( tag & PRELUDE_CLIENT_CAPABILITY_RECV_IDMEF )
                return handle_declare_parent_relay(cnx);

        if ( tag & PRELUDE_CLIENT_CAPABILITY_SEND_ADMIN )
                return handle_declare_admin(cnx);

        server_generic_log_client((server_generic_client_t *) cnx,
                                  "client declared unknow capability: closing connection.\n");
        
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
                server_generic_log_client((server_generic_client_t *) cnx,
                                          "error decoding message - %s:%s.\n",
                                          prelude_strsource(ret), prelude_strerror(ret));
                return -1;
        }
        
        switch (tag) {
                
        case PRELUDE_MSG_ID_DECLARE:
                ret = handle_declare_ident(cnx, buf, dlen);
                break;
                
        default:
                server_generic_log_client((server_generic_client_t *) cnx, "unknow ID tag: %d.\n", tag);
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
        sensor_fd_t *cnx = (sensor_fd_t *) client;
        
        ret = prelude_msg_read(&cnx->msg, cnx->fd);        
        if ( ret < 0 ) {
		if ( prelude_error_get_code(ret) == PRELUDE_ERROR_EAGAIN )
                        return 0;
                
                if ( prelude_error_get_code(ret) != PRELUDE_ERROR_EOF )
                        server_generic_log_client((server_generic_client_t *) cnx, "%s: %s\n",
                                                  prelude_strsource(ret), prelude_strerror(ret));

                return -1;
        }
        
        msg = cnx->msg;
        cnx->msg = NULL;
        
        tag = prelude_msg_get_tag(msg);
        
        /*
         * If we get there, we have a whole message.
         */        
        switch ( tag ) {

        case PRELUDE_MSG_IDMEF:
                ret = idmef_message_schedule(cnx->queue, msg);
                break;
                
        case PRELUDE_MSG_ID:
                ret = (cnx->ident) ? -1 : read_ident_message(cnx, msg);
                break;

        case PRELUDE_MSG_CLIENT_CAPABILITY:
                ret = (cnx->capability) ? -1 : read_client_type(cnx, msg);
                break;
                
        case PRELUDE_MSG_OPTION_REQUEST:
                ret = request_sensor_option(cnx, msg);
                break;

        case PRELUDE_MSG_OPTION_REPLY:
                ret = reply_sensor_option(cnx, msg);
                break;
                
        default:
                ret = -1;
                break;
        }

        if ( ret < 0 ) 
                server_generic_log_client((server_generic_client_t *) cnx,
                                          "invalid message sent by the client.\n");

        if ( tag != PRELUDE_MSG_IDMEF )
                prelude_msg_destroy(msg);

        return (ret < 0) ? ret : read_connection_cb(client);
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
        server_generic_t *server;
        
        server = server_generic_new(addr, port, sizeof(sensor_fd_t), accept_connection_cb,
                                    read_connection_cb, close_connection_cb);
        if ( ! server ) {
                log(LOG_ERR, "error creating a generic server.\n");
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
        cdata->state |= SERVER_GENERIC_CLIENT_STATE_ACCEPTED;
        cdata->fd = prelude_connection_get_fd(cnx);
        cdata->cnx = cnx;
        cdata->client_type = "parent-manager";
        
        server_generic_process_requests(server, (server_generic_client_t *) cdata);
        
        return 0;
}
