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
#include <assert.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-message-id.h>
#include <libprelude/prelude-ident.h>
#include <libprelude/prelude-extract.h>
#include <libprelude/prelude-connection.h>
#include <libprelude/prelude-connection-pool.h>
#include <libprelude/prelude-option-wide.h>

#include "server-logic.h"
#include "server-generic.h"
#include "sensor-server.h"
#include "idmef-message-scheduler.h"
#include "manager-options.h"
#include "reverse-relaying.h"

#define TARGET_UNREACHABLE "Destination agent is unreachable"
#define TARGET_PROHIBITED  "Destination agent is administratively prohibited"


typedef struct {
        SERVER_GENERIC_OBJECT;
        prelude_list_t list;

        pthread_mutex_t mutex;
        idmef_queue_t *queue;
        prelude_connection_t *cnx;
        prelude_bool_t we_connected;
        prelude_list_t write_msg_list;
        reverse_relay_receiver_t *rrr;
} sensor_fd_t;


static int read_connection_cb(server_generic_client_t *client);



extern prelude_client_t *manager_client;

static PRELUDE_LIST(sensors_cnx_list);
static pthread_mutex_t sensors_list_mutex = PTHREAD_MUTEX_INITIALIZER;




static sensor_fd_t *search_client(prelude_list_t *head, uint64_t analyzerid) 
{
        sensor_fd_t *client;
        prelude_list_t *tmp;

        prelude_list_for_each(head, tmp) {
                client = prelude_list_entry(tmp, sensor_fd_t, list);

                if ( client->ident == analyzerid )
                        return client;
        }

        return NULL;
}




static int forward_message_to_analyzerid(sensor_fd_t *client, uint64_t analyzerid, prelude_msg_t *msg) 
{
        int ret = 0;
        sensor_fd_t *target;
        
        pthread_mutex_lock(&sensors_list_mutex);

        target = search_client(&sensors_cnx_list, analyzerid);
        if ( ! target ) {
                pthread_mutex_unlock(&sensors_list_mutex);
                return -1;
        }

        /*
         * if we are connected to the client, we need write permission. If the
         * client connected to us, then read permission need to be set.
         */
        if ( prelude_msg_get_tag(msg) == PRELUDE_MSG_OPTION_REQUEST ) {
                /*
                 * We forward an option request to a client.
                 *
                 * If the client connected to us (->cnx == NULL), we need to check it has READ  permission.
                 * If we connected to the client (->cnx != NULL), we need to check if we have WRITE permission.
                 */
                if ( (! (target->permission & PRELUDE_CONNECTION_PERMISSION_ADMIN_WRITE) && target->we_connected) ||
                     (! (target->permission & PRELUDE_CONNECTION_PERMISSION_ADMIN_READ ) && ! target->we_connected) ) {
                        ret = -2;
                        server_generic_log_client((server_generic_client_t *) client, PRELUDE_LOG_WARN,
                                                  "recipient credentials forbids admin request.\n");
                        goto out;
                }
        }

        ret = sensor_server_write_client((server_generic_client_t *) target, msg);
 out:
        pthread_mutex_unlock(&sensors_list_mutex);
        
        return ret;
}



static int get_msg_target_ident(sensor_fd_t *client, prelude_msg_t *msg,
                                uint64_t **target_ptr, uint32_t *hop_ptr, int direction)
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        uint32_t hop, tmp, target_len = 0;

        *target_ptr = NULL;
        
        while ( prelude_msg_get(msg, &tag, &len, &buf) == 0 ) {

                if ( tag == PRELUDE_MSG_OPTION_TARGET_ID ) {
                                                
                        if ( (len % sizeof(uint64_t)) != 0 || len < 2 * sizeof(uint64_t) )
                                return -1;
                        
                        target_len = len;
                        *target_ptr = buf;
                }

                if ( tag != PRELUDE_MSG_OPTION_HOP )
                        continue;

                if ( ! *target_ptr )
                        return -1;
                        
                ret = prelude_extract_uint32_safe(&hop, buf, len);
                if ( ret < 0 )
                        break;

                hop = (direction == PRELUDE_MSG_OPTION_REQUEST) ? hop + 1 : hop - 1;
                                
                if ( hop == (target_len / sizeof(uint64_t)) ) {                        
                        *hop_ptr = (hop - 1);
                        return 0; /* we are the target */
                }
                
                tmp = htonl(hop);
                memcpy(buf, &tmp, sizeof(tmp));
                                
                if ( hop >= (target_len / sizeof(uint64_t)) )
                        break;

                *hop_ptr = hop;                
                return 0;
        }

        server_generic_log_client((server_generic_client_t *) client, PRELUDE_LOG_WARN,
                                  "message does not carry a valid target: closing connection.\n");

        return -1;
}



static int send_unreachable_message(server_generic_client_t *client, uint64_t *ident_list, uint32_t hop, const char *error, size_t size)
{
        ssize_t ret;
        prelude_msg_t *msg;

        /*
         * cancel the hop increment done previously.
         * this function is only supposed to be called for failed request (not failed reply).
         */
        hop--;
        
        ret = prelude_msg_new(&msg, 3,
                              size +
                              sizeof(uint32_t) +
                              hop * sizeof(uint64_t), PRELUDE_MSG_OPTION_REPLY, 0);
        if ( ret < 0 )
                return -1;

        prelude_msg_set(msg, PRELUDE_MSG_OPTION_ERROR, size, error);
        prelude_msg_set(msg, PRELUDE_MSG_OPTION_TARGET_ID, hop * sizeof(uint64_t), ident_list);
        prelude_msg_set(msg, PRELUDE_MSG_OPTION_HOP, sizeof(hop), &hop);

        return sensor_server_write_client(client, msg);
}


static int request_sensor_option(server_generic_client_t *client, prelude_msg_t *msg) 
{
        int ret;
        uint64_t ident;
        uint32_t target_hop;
        uint64_t *target_route;
        sensor_fd_t *sclient = (sensor_fd_t *) client;
        prelude_client_profile_t *cp = prelude_client_get_profile(manager_client);
        
        ret = get_msg_target_ident(sclient, msg, &target_route,
                                   &target_hop, PRELUDE_MSG_OPTION_REQUEST);
        if ( ret < 0 )
                return -1;
        
        /*
         * We receive an option request from client.
         *
         * If the client connected to us (->cnx == NULL), we need to check it has WRITE  permission.
         * If we connected to the client (->cnx != NULL), we need to check it has READ   permission.
         */
        if ( (! (sclient->permission & PRELUDE_CONNECTION_PERMISSION_ADMIN_WRITE) && ! sclient->we_connected) ||
             (! (sclient->permission & PRELUDE_CONNECTION_PERMISSION_ADMIN_READ ) &&   sclient->we_connected) ) {

                server_generic_log_client(client, PRELUDE_LOG_WARN, "insufficient credentials to emit admin request.\n");
                send_unreachable_message(client, target_route, target_hop, TARGET_PROHIBITED, sizeof(TARGET_PROHIBITED));
                return 0;
        }
        
        ident = prelude_extract_uint64(&target_route[target_hop]);
        if ( ident == prelude_client_profile_get_analyzerid(cp) ) {
                prelude_msg_recycle(msg);
                return prelude_option_process_request(manager_client, sclient->fd, msg);
        }
        
        ret = forward_message_to_analyzerid(sclient, ident, msg);
        if ( ret == -1 )
                send_unreachable_message(client, target_route, target_hop, TARGET_UNREACHABLE, sizeof(TARGET_UNREACHABLE));

        if ( ret == -2 )
                send_unreachable_message(client, target_route, target_hop, TARGET_PROHIBITED, sizeof(TARGET_PROHIBITED));
                
        return 0;
}




static int reply_sensor_option(sensor_fd_t *client, prelude_msg_t *msg) 
{
        int ret;
        uint32_t target_hop;
        uint64_t *target_route, ident;
        
        ret = get_msg_target_ident(client, msg, &target_route, &target_hop, PRELUDE_MSG_OPTION_REPLY);
        if ( ret < 0 ) 
                return -1;

        ident = prelude_extract_uint64(&target_route[target_hop]);
                
        /*
         * The one replying the option doesn't care about client presence or not.
         */
        forward_message_to_analyzerid(client, ident, msg);

        return 0;
}



static int handle_declare_receiver(sensor_fd_t *sclient) 
{
        int ret;
        server_generic_client_t *client = (server_generic_client_t *) sclient;
        
        if ( ! sclient->ident )
                return -1;
        
        sclient->rrr = reverse_relay_search_receiver(sclient->ident);
        if ( ! sclient->rrr ) {
                /*
                 * First time a child relay with this address connect here.
                 * Add it to the manager list. Type of the created connection is -parent-
                 * because *we* are sending the alert to the child.
                 */                                
                ret = reverse_relay_new_receiver(&sclient->rrr, client, sclient->ident);
                if ( ret < 0 )
                        return -1;
        }

        server_generic_log_client(client, PRELUDE_LOG_INFO,
                                  "client requested forward of IDMEF message.\n");

        return reverse_relay_set_receiver_alive(sclient->rrr, client);
}




static int handle_declare_client(sensor_fd_t *cnx) 
{
        cnx->queue = idmef_message_scheduler_queue_new();
        if ( ! cnx->queue )
                return -1;
        
        pthread_mutex_lock(&sensors_list_mutex);
        prelude_list_add_tail(&sensors_cnx_list, &cnx->list);
        pthread_mutex_unlock(&sensors_list_mutex);
        
        return 0;
}




static int read_connection_type(sensor_fd_t *cnx, prelude_msg_t *msg) 
{
        void *buf;
        uint8_t tag;
        int ret = -1;  
        uint32_t dlen;
        
        ret = prelude_msg_get(msg, &tag, &dlen, &buf);
        if ( ret < 0 ) {
                server_generic_log_client((server_generic_client_t *) cnx, PRELUDE_LOG_WARN,
                                          "error decoding message - %s: %s.\n",
                                          prelude_strsource(ret), prelude_strerror(ret));
                return -1;
        }
        
        if ( tag & PRELUDE_CONNECTION_PERMISSION_IDMEF_READ ) {

                if ( ! (cnx->permission & PRELUDE_CONNECTION_PERMISSION_IDMEF_READ) ) {
                        server_generic_log_client((server_generic_client_t *) cnx, PRELUDE_LOG_WARN,
                                                  "insufficient credentials to read IDMEF message: closing connection.\n");
                        return -1;
                }
                
                ret = handle_declare_receiver(cnx);
                if ( ret < 0 )
                        return -1;
        }
        
        ret = handle_declare_client(cnx);
        if ( ret < 0 )
                return -1;
        
        return 0;
}



static int read_after_setup(sensor_fd_t *client, prelude_msg_t *msg, uint8_t tag)
{
        int ret = -1;
        
        if ( tag == PRELUDE_MSG_IDMEF ) {
                /*
                 * We receive a message from a client
                 *
                 * If the client connected to us (->cnx == NULL), we need to check it has WRITE  permission.
                 * If we connected to the client (->cnx != NULL), we need to check we have READ   permission.
                 */
                if ( (! (client->permission & PRELUDE_CONNECTION_PERMISSION_IDMEF_WRITE) && ! client->we_connected) ||
                     (! (client->permission & PRELUDE_CONNECTION_PERMISSION_IDMEF_READ ) &&   client->we_connected) ) {
                        server_generic_log_client((server_generic_client_t *) client, PRELUDE_LOG_WARN,
                                                  "insufficient credentials to write IDMEF message.\n");
                        return -1;
                }
                                
                ret = idmef_message_schedule(client->queue, msg);
                if ( ret == 0 )
                        return 0;
        }
        
        else if ( tag == PRELUDE_MSG_OPTION_REQUEST )
                ret = request_sensor_option((server_generic_client_t *) client, msg);

        else if ( tag == PRELUDE_MSG_OPTION_REPLY )
                ret = reply_sensor_option(client, msg);

        else if ( tag == PRELUDE_MSG_CONNECTION_CAPABILITY )
                ret = read_connection_type(client, msg);
        
        prelude_msg_destroy(msg);
        
        if ( ret < 0 ) {
                server_generic_log_client((server_generic_client_t *) client, PRELUDE_LOG_WARN,
                                          "error processing request.\n");
                return -1;
        }
        
        return read_connection_cb((server_generic_client_t *) client);
}



static int read_prior_setup(sensor_fd_t *cnx, prelude_msg_t *msg, uint8_t tag)
{
        int ret = -1;
        
        if ( tag == PRELUDE_MSG_CONNECTION_CAPABILITY )
                ret = read_connection_type(cnx, msg);
            
        prelude_msg_destroy(msg);
        
        if ( ret < 0 )
                return -1;
        
        return read_connection_cb((server_generic_client_t *) cnx);
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
                        server_generic_log_client((server_generic_client_t *) cnx,
                                                  PRELUDE_LOG_WARN, "message read error %s: %s\n",
                                                  prelude_strsource(ret), prelude_strerror(ret));

                return -1;
        }
        
        msg = cnx->msg;
        cnx->msg = NULL;
        
        tag = prelude_msg_get_tag(msg);

        if ( ! cnx->permission )
                return read_prior_setup(cnx, msg, tag);
        
        return read_after_setup(cnx, msg, tag);
}



static int write_connection_cb(server_generic_client_t *client)
{
        int ret = 0;
        prelude_list_t *tmp;
        prelude_msg_t *cur = NULL;
        sensor_fd_t *sclient = (sensor_fd_t *) client;

        pthread_mutex_lock(&sclient->mutex);
        
        prelude_list_for_each(&sclient->write_msg_list, tmp) {
                cur = prelude_linked_object_get_object(tmp);
                prelude_linked_object_del((prelude_linked_object_t *) cur);
                break;
        }
        
        pthread_mutex_unlock(&sclient->mutex);

        if ( cur ) {
                ret = prelude_msg_write(cur, sclient->fd);        
                if ( ret < 0 && prelude_error_get_code(ret) == PRELUDE_ERROR_EAGAIN )
                        return 0;
        
                prelude_msg_destroy(cur);
        }
        
        pthread_mutex_lock(&sclient->mutex);

        if ( prelude_list_is_empty(&sclient->write_msg_list) ) {
                server_logic_notify_write_disable((server_logic_client_t *) client);

                if ( server_generic_client_get_state(client) & SERVER_GENERIC_CLIENT_STATE_FLUSHING )
                        ret = reverse_relay_set_receiver_alive(sclient->rrr, client);
        }

        pthread_mutex_unlock(&sclient->mutex);
        
        return ret;
}



static int close_connection_cb(server_generic_client_t *ptr) 
{
        int ret;
        prelude_msg_t *msg;
        prelude_list_t *tmp, *bkp;
        sensor_fd_t *cnx = (sensor_fd_t *) ptr;
        
        if ( cnx->rrr )
                reverse_relay_set_receiver_dead(cnx->rrr);
        
        else if ( cnx->cnx ) {
                cnx->fd = NULL;
                reverse_relay_set_initiator_dead(cnx->cnx);
                
                ret = prelude_connection_close(cnx->cnx);
                if ( ret < 0 && prelude_error_get_code(ret) == PRELUDE_ERROR_EAGAIN )
                        return -1;
        }
        
        if ( ! prelude_list_is_empty(&cnx->list) ) {
                pthread_mutex_lock(&sensors_list_mutex);
                prelude_list_del(&cnx->list);
                pthread_mutex_unlock(&sensors_list_mutex);
        }
        
        prelude_list_for_each_safe(&cnx->write_msg_list, tmp, bkp) {
                msg = prelude_linked_object_get_object(tmp);
                prelude_linked_object_del((prelude_linked_object_t *) msg);
                prelude_msg_destroy(msg);
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

        return 0;
}




static int accept_connection_cb(server_generic_client_t *ptr) 
{
        sensor_fd_t *fd = (sensor_fd_t *) ptr;
        
        fd->we_connected = FALSE;
        pthread_mutex_init(&fd->mutex, NULL);
        
        prelude_list_init(&fd->list);
        prelude_list_init(&fd->write_msg_list);
        
        return 0;
}



server_generic_t *sensor_server_new(void) 
{
        server_generic_t *server;
        
        server = server_generic_new(sizeof(sensor_fd_t), accept_connection_cb,
                                    read_connection_cb, write_connection_cb, close_connection_cb);
        if ( ! server ) {
                prelude_log(PRELUDE_LOG_WARN, "error creating a generic server.\n");
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
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }
                
        cdata->addr = strdup(prelude_connection_get_peer_addr(cnx));
        if ( ! cdata->addr ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                free(cdata);
                return -1;
        }
        
        cdata->queue = idmef_message_scheduler_queue_new();
        if ( ! cdata->queue ) {
                free(cdata->addr);
                free(cdata);
                return -1;
        }
        
        cdata->state |= SERVER_GENERIC_CLIENT_STATE_ACCEPTED;
        cdata->fd = prelude_connection_get_fd(cnx);
                
        cdata->cnx = cnx;
        cdata->rrr = NULL;
        cdata->we_connected = TRUE;
        pthread_mutex_init(&cdata->mutex, NULL);
        prelude_list_init(&cdata->write_msg_list);
        cdata->ident = prelude_connection_get_peer_analyzerid(cnx);
        
        server_generic_client_set_permission((server_generic_client_t *)cdata, prelude_connection_get_permission(cnx));
        
        prelude_list_add(&sensors_cnx_list, &cdata->list);
        server_generic_process_requests(server, (server_generic_client_t *) cdata);
        
        return 0;
}



int sensor_server_write_client(server_generic_client_t *client, prelude_msg_t *msg) 
{
        int ret;
        sensor_fd_t *dst = (sensor_fd_t *) client;

        pthread_mutex_lock(&dst->mutex);
        
        if ( ! prelude_list_is_empty(&dst->write_msg_list) ) {
                prelude_linked_object_add_tail(&dst->write_msg_list, (prelude_linked_object_t *) msg);
                pthread_mutex_unlock(&dst->mutex);
                return 0;
        }
        
        ret = prelude_msg_write(msg, dst->fd);        
        if ( ret == 0 )
                prelude_msg_destroy(msg);
        
        else if ( ret < 0 && prelude_error_get_code(ret) == PRELUDE_ERROR_EAGAIN ) {
                pthread_mutex_lock(&dst->mutex);
                prelude_linked_object_add_tail(&dst->write_msg_list, (prelude_linked_object_t *) msg);
                pthread_mutex_unlock(&dst->mutex);
                
                server_logic_notify_write_enable((server_logic_client_t *) dst);
                return ret;
        }
        
        return ret;
}
