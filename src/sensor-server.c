/*****
*
* Copyright (C) 2001, 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <inttypes.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include <libprelude/list.h>
#include <libprelude/prelude-log.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-message-id.h>
#include <libprelude/prelude-getopt-wide.h>
#include <libprelude/prelude-ident.h>
#include <libprelude/extract.h>
#include <libprelude/prelude-client.h>
#include <libprelude/prelude-client-mgr.h>

#include "server-logic.h"
#include "server-generic.h"
#include "sensor-server.h"
#include "idmef-message-scheduler.h"
#include "pconfig.h"
#include "relaying.h"


typedef struct {
        SERVER_GENERIC_OBJECT;
        struct list_head list;
        uint64_t analyzerid;
} sensor_fd_t;


static LIST_HEAD(sensor_cnx_list);
static pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;


static int option_list_to_xml(sensor_fd_t *cnx, prelude_msg_t *msg) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t dlen;
        
        ret = prelude_msg_get(msg, &tag, &dlen, &buf);
        if ( ret < 0 ) {
                log(LOG_ERR, "error decoding message.\n");
                return -1;
        }

        if ( ret == 0 ) 
                return 0;
        
        switch (tag) {
                
        case PRELUDE_OPTION_START:
                //printf("option start\n");
                break;
                
        case PRELUDE_OPTION_NAME:
                //printf("option name = %s\n", (char *) buf);
                break;
                
        case PRELUDE_OPTION_DESC:
                //printf("option desc = %s\n", (char *) buf);
                break;

        case PRELUDE_OPTION_HAS_ARG:
                //printf("option has_arg = %d\n", * (uint8_t *) buf);
                break;

        case PRELUDE_OPTION_HELP:
                //printf("option help = %s\n", (char *) buf);
                break;

        case PRELUDE_OPTION_INPUT_VALIDATION:
                //printf("option input regex = %s\n", (char *) buf);
                break;

        case PRELUDE_OPTION_INPUT_TYPE:
                //printf("option input type = %d\n", * (uint8_t *) buf);
                break;
                
        case PRELUDE_OPTION_END:
                //printf("end option.\n");
                break;
                
        default:
                /*
                 * for compatibility purpose, don't return an error on unknow tag.
                 */
                log(LOG_INFO, "[%s] - unknow option tag %d.\n", cnx->addr, tag);
        }

        return option_list_to_xml(cnx, msg);
}




static int handle_declare_ident(sensor_fd_t *cnx, void *buf, uint32_t blen) 
{
        int ret;

        ret = extract_uint64_safe(&cnx->analyzerid, buf, blen);
        if ( ret < 0 )
                return -1;
                
        if ( cnx->analyzerid != 0 ) {
                log(LOG_INFO, "[%s] - sensor declared ident %llu.\n", cnx->addr, cnx->analyzerid);
                return 0;
        }
        
        /*
         * our client is a relaying Manager.
         * we want relaying Manager to be at the end of our list (see
         * sensor_server_broadcast_admin_command).
         */
        pthread_mutex_lock(&list_mutex);

        list_del(&cnx->list);
        list_add_tail(&cnx->list, &sensor_cnx_list);

        pthread_mutex_unlock(&list_mutex);
                
        return 0;
}




static int handle_declare_child_relay(sensor_fd_t *cnx) 
{
        /*
         * our client is a relaying Manager.
         * we want relaying Manager to be at the end of our list (see
         * sensor_server_broadcast_admin_command).
         */
        pthread_mutex_lock(&list_mutex);

        list_del(&cnx->list);
        list_add_tail(&cnx->list, &sensor_cnx_list);

        pthread_mutex_unlock(&list_mutex);

        log(LOG_INFO, "[%s] - client declared to be a children relay (relaying to us).\n", cnx->addr);

        return 0;
}




static int handle_declare_parent_relay(sensor_fd_t *cnx) 
{
        int state;
        prelude_client_t *client;
        
        client = manager_parent_search_client(cnx->addr, PRELUDE_CLIENT_TYPE_MANAGER_PARENT);
        if ( client ) {
                /*
                 * This reverse relay is already known:
                 * Associate the new FD with it, and tell client-mgr, the client is alive.
                 */
                prelude_io_close(prelude_client_get_fd(client));
                prelude_io_destroy(prelude_client_get_fd(client));
                prelude_client_set_fd(client, cnx->fd);
        } else {
                /*
                 * First time a child relay with this address connect here.
                 * Add it to the manager list. Type of the created client is -parent-
                 * because *we* are sending the alert to the child.
                 */
                client = prelude_client_new(cnx->addr, 0);
                if ( ! client )
                        return -1;

                prelude_client_set_fd(client, cnx->fd);
                prelude_client_set_type(client, PRELUDE_CLIENT_TYPE_MANAGER_PARENT);
                manager_parent_add_client(client);
        }

        state = prelude_client_get_state(client) | PRELUDE_CLIENT_CONNECTED;
        prelude_client_set_state(client, state);
        
        log(LOG_INFO, "[%s] - client declared to be a parent relay (we relay to him).\n", cnx->addr);

        manager_parent_tell_alive(client);

        /*
         * set fd to NULL so that the client removal, which'll trigger the close callback,
         * won't destroy the fd, that we still reference in order to send data to the
         * remote manager.
         */
        cnx->fd = NULL;
        server_logic_remove_client((server_logic_client_t *) cnx);
        
        return 0;
}





static int read_ident_message(sensor_fd_t *cnx, prelude_msg_t *msg) 
{
        int ret;        
        void *buf;
        uint8_t tag;
        uint32_t dlen;

        ret = prelude_msg_get(msg, &tag, &dlen, &buf);
        if ( ret < 0 ) {
                log(LOG_INFO, "[%s] - error decoding message.\n", cnx->addr);
                return -1;
        }

        if ( ret == 0 ) 
                return 0;
        
        switch (tag) {
                
        case PRELUDE_MSG_ID_DECLARE:
                ret = handle_declare_ident(cnx, buf, dlen);
                break;
                
        default:
                log(LOG_INFO, "[%s] - unknow ID tag: %d.\n", cnx->addr, tag);
                ret = -1;
                break;
        }
        
        return ret;
}




static int read_client_type(sensor_fd_t *cnx, prelude_msg_t *msg) 
{
        int ret;        
        void *buf;
        uint8_t tag;
        uint32_t dlen;
        
        ret = prelude_msg_get(msg, &tag, &dlen, &buf);
        if ( ret < 0 ) {
                log(LOG_INFO, "[%s] - error decoding message.\n", cnx->addr);
                return -1;
        }
        
        if ( ret == 0 ) 
                return 0;

        prelude_msg_destroy(msg);
        
        switch (tag) {

        case PRELUDE_CLIENT_TYPE_MANAGER_CHILDREN:
                ret = handle_declare_child_relay(cnx);
                break;
                
        case PRELUDE_CLIENT_TYPE_MANAGER_PARENT:
                ret = handle_declare_parent_relay(cnx);
                break;
                
        default:
                return 0;
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
                idmef_message_schedule(msg);
                return 0;

        case PRELUDE_MSG_ID:
                ret = read_ident_message(cnx, msg);
                break;

        case PRELUDE_MSG_CLIENT_TYPE:
                ret = read_client_type(cnx, msg);
                break;
                
        case PRELUDE_MSG_OPTION_LIST:
                                
                ret = option_list_to_xml(cnx, msg);
                if ( ret == 0 )
                        manager_relay_msg_if_needed(msg);
                break;

        default:
                log(LOG_INFO, "[%s] - unknow message id %d\n", cnx->addr, prelude_msg_get_tag(msg));
                ret = 0;
                break;
        }

        if ( tag != PRELUDE_MSG_CLIENT_TYPE )
                /*
                 * msg will be destroyed before for this kind of message.
                 */
                prelude_msg_destroy(msg);
        
        return ret;
}




static void close_connection_cb(server_generic_client_t *ptr) 
{
        int type;
        sensor_fd_t *cnx = (sensor_fd_t *) ptr;
        
        if ( cnx->client ) {
                /*
                 * We are a parent manager connected to a children
                 * manager. The connection got closed. Notify our subsystem
                 * that connection with the children is dead, so that we try
                 * reconnecting.
                 */
                type = prelude_client_get_type(cnx->client);
        
                if ( type == PRELUDE_CLIENT_TYPE_MANAGER_PARENT ) 
                        manager_children_tell_dead(cnx->client);
        }
        
        pthread_mutex_lock(&list_mutex);
        list_del(&cnx->list);
        pthread_mutex_unlock(&list_mutex);

        /*
         * If cnx->msg is not NULL, it mean the sensor
         * closed the connection without finishing to send
         * a message. Destroy the unfinished message.
         */
        if ( cnx->msg )
                prelude_msg_destroy(cnx->msg);
}




static int accept_connection_cb(server_generic_client_t *ptr) 
{
        sensor_fd_t *client = (sensor_fd_t *) ptr;
        
        /*
         * set the analyzer id to -1, because at this time,
         * the analyzer (or relay manager) didn't declared it's ID.
         * and in case of admin request, we don't want to think it's
         * a relay Manager.
         */
        client->analyzerid = (uint64_t) -1;
        
        pthread_mutex_lock(&list_mutex);
        list_add(&client->list, &sensor_cnx_list);
        pthread_mutex_unlock(&list_mutex);
        
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



void sensor_server_close(server_generic_t *server) 
{
        server_generic_close(server);
}




int sensor_server_broadcast_admin_command(uint64_t *analyzerid, prelude_msg_t *msg) 
{
        int ret, ok = -1;
        sensor_fd_t *cnx;
        struct list_head *tmp;
        
        if ( ! analyzerid )
                return -1;

        /*
         * the list is sorted with :
         * - real analyzer first (analyzerid != 0).
         * - then relay manager (analyzerid == 0).
         */
        pthread_mutex_lock(&list_mutex);
        
        list_for_each(tmp, &sensor_cnx_list) {
                cnx = list_entry(tmp, sensor_fd_t, list);
                
                if ( cnx->analyzerid == *analyzerid ) {
                        ok = 1;
                        ret = prelude_msg_write(msg, cnx->fd);
                        break;
                }

                /*
                 * no luck, the analyzer we want to send admin command to
                 * isn't directly connected here. So we have to broadcast the
                 * message to all there relay being connected to us.
                 */
                if ( cnx->analyzerid == 0 ) {
                        ok = 1;
                        ret = prelude_msg_write(msg, cnx->fd);
                }
        }
        
        pthread_mutex_unlock(&list_mutex);

        if ( ok < 0 )
                log(LOG_ERR, "couldn't find sensor with ID %llu and no relay connected\n", *analyzerid);

        return -1;
}



