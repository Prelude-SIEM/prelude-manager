/*****
*
* Copyright (C) 2001-2020 CS-SI. All Rights Reserved.
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
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
*****/

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <gnutls/gnutls.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-message-id.h>
#include <libprelude/prelude-ident.h>
#include <libprelude/prelude-extract.h>
#include <libprelude/prelude-connection.h>
#include <libprelude/prelude-connection-pool.h>
#include <libprelude/prelude-option-wide.h>

#include "bufpool.h"
#include "server-generic.h"
#include "sensor-server.h"
#include "idmef-message-scheduler.h"
#include "manager-options.h"
#include "reverse-relaying.h"

#define TARGET_UNREACHABLE "Destination agent is unreachable"
#define TARGET_PROHIBITED  "Destination agent is administratively prohibited"


extern prelude_client_t *manager_client;


static prelude_list_t sensors_cnx_list[1024];



static unsigned int get_list_key(uint64_t analyzerid)
{
        return analyzerid & (sizeof(sensors_cnx_list) / sizeof(*sensors_cnx_list) - 1);
}



static int write_client(sensor_fd_t *dst, prelude_msg_t *msg)
{
        int ret;

        ret = prelude_msg_write_r(msg, dst->fd, &dst->write_index);
        if ( ret < 0 && prelude_error_get_code(ret) == PRELUDE_ERROR_EAGAIN ) {
                dst->wmsg = msg;
                server_generic_notify_write_enable((server_generic_client_t *) dst);
                return ret;
        }

        if ( ret != 0 )
                prelude_log(PRELUDE_LOG_ERR, "could not write msg: %s.\n", prelude_strerror(ret));

        dst->write_index = 0;
        dst->wmsg = NULL;

        prelude_msg_destroy(msg);
        return ret;
}



static int handle_declare_receiver(sensor_fd_t *sclient)
{
        server_generic_client_t *client = (server_generic_client_t *) sclient;

        if ( ! sclient->ident )
                return -1;

        return reverse_relay_new_receiver(&sclient->rrr, client, sclient->ident);
}




static int handle_declare_client(sensor_fd_t *cnx)
{
        cnx->queue = idmef_message_scheduler_queue_new(manager_client);
        if ( ! cnx->queue )
                return -1;

        prelude_list_add_tail(&sensors_cnx_list[get_list_key(cnx->ident)], &cnx->list);

        return 0;
}



static int handle_capability(sensor_fd_t *cnx, prelude_msg_t *msg)
{
        int ret;
        void *nul;
        uint32_t len;
        uint8_t permission;

        prelude_msg_get(msg, &permission, &len, &nul);

        if ( permission & PRELUDE_CONNECTION_PERMISSION_IDMEF_READ ) {

                if ( ! (cnx->permission & PRELUDE_CONNECTION_PERMISSION_IDMEF_READ) ) {
                        server_generic_log_client((server_generic_client_t *) cnx, PRELUDE_LOG_WARN,
                                                  "insufficient credentials to read IDMEF message: closing connection.\n");
                        return -1;
                }

                ret = handle_declare_receiver(cnx);
                if ( ret < 0 )
                        return ret;
        }

        prelude_msg_destroy(msg);

        return 0;
}



static int handle_msg(sensor_fd_t *client, prelude_msg_t *msg, uint8_t tag)
{
        int ret;

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
                        prelude_msg_destroy(msg);
                        return -1;
                }

                ret = idmef_message_schedule(client->queue, msg);
        }

        else if ( tag == PRELUDE_MSG_OPTION_REQUEST )
                ret = 0;

        else if ( tag == PRELUDE_MSG_OPTION_REPLY )
                ret = 0;

        else if ( tag == PRELUDE_MSG_CONNECTION_CAPABILITY )
                ret = handle_capability(client, msg);

        else {
                /* unknown message, ignore silently for backward compatibility */
                prelude_msg_destroy(msg);
                return 0;
        }

        if ( ret < 0 ) {
                prelude_msg_destroy(msg);
                server_generic_log_client((server_generic_client_t *) client, PRELUDE_LOG_WARN,
                                          "error processing peer message: %s.\n", prelude_strerror(ret));
                return -1;
        }

        return ret;
}



static int read_connection_cb(server_generic_client_t *client)
{
        int ret;
        prelude_msg_t *msg;
        sensor_fd_t *cnx = (sensor_fd_t *) client;

        ret = prelude_msg_read(&cnx->msg, cnx->fd);
        if ( ret < 0 ) {
                prelude_error_code_t code = prelude_error_get_code(ret);

                if ( code == PRELUDE_ERROR_EAGAIN )
                        return 0;

                cnx->msg = NULL;
                if ( code != PRELUDE_ERROR_EOF )
                        server_generic_log_client((server_generic_client_t *) cnx, PRELUDE_LOG_WARN, "%s.\n", prelude_strerror(ret));

                return -1;
        }

        msg = cnx->msg;
        cnx->msg = NULL;

        ret = handle_msg(cnx, msg, prelude_msg_get_tag(msg));
        if ( ret < 0 )
                return ret;

        return 1;
}



static int write_connection_cb(server_generic_client_t *client)
{
        int ret = 0;
        sensor_fd_t *sclient = (sensor_fd_t *) client;

        if ( sclient->wmsg ) {
                ret = write_client(sclient, sclient->wmsg);
                if ( ret < 0 )
                        return (prelude_error_get_code(ret) == PRELUDE_ERROR_EAGAIN) ? 0 : ret;
        }

        if ( sclient->rrr )
                return reverse_relay_write_possible(sclient->rrr, client);

        return ret;
}



static int do_close_cnx(server_generic_client_t *ptr, sensor_fd_t *cnx)
{
        int ret;
        void *fd_ptr;
        prelude_error_code_t code;

         do {
                 ret = prelude_connection_close(cnx->cnx);
                 if ( ret == 0 )
                         break;

                 code = prelude_error_get_code(ret);
                 if ( code == PRELUDE_ERROR_EAGAIN ) {

                         fd_ptr = prelude_io_get_fdptr(prelude_connection_get_fd(cnx->cnx));
                         if ( fd_ptr && gnutls_record_get_direction(fd_ptr) == 1 )
                                 server_generic_notify_write_enable(ptr);

                         return -1;
                 }

                 server_generic_log_client(ptr, PRELUDE_LOG_WARN, "%s.\n", prelude_strerror(ret));

         } while ( ret < 0 && ! prelude_io_is_error_fatal(prelude_connection_get_fd(cnx->cnx), ret));

         return 0;
}



static int close_connection_cb(server_generic_client_t *ptr)
{
        int ret;
        sensor_fd_t *cnx = (sensor_fd_t *) ptr;

        if ( cnx->cnx ) {
                cnx->fd = NULL;
                reverse_relay_set_initiator_dead(cnx->cnx);

                ret = do_close_cnx(ptr, cnx);
                if ( ret < 0 )
                        return -1;
        }


        if ( ! prelude_list_is_empty(&cnx->list) )
                prelude_list_del(&cnx->list);

        /*
         * If cnx->msg is not NULL, it mean the sensor
         * closed the connection without finishing to read/write
         * a message. Destroy the unfinished message.
         */
        if ( cnx->msg )
                prelude_msg_destroy(cnx->msg);

        if ( cnx->wmsg )
                prelude_msg_destroy(cnx->wmsg);

        if ( cnx->queue )
                idmef_message_scheduler_queue_destroy(cnx->queue);

        return 0;
}




static int accept_connection_cb(server_generic_client_t *ptr)
{
        int ret;
        sensor_fd_t *fd = (sensor_fd_t *) ptr;

        fd->we_connected = FALSE;
        prelude_list_init(&fd->list);

        ret = handle_declare_client(fd);
        if ( ret < 0 )
                return -1;

        return 1; /* more data might be available, the caller shall keep reading */
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



int sensor_server_add_client(server_generic_t *server, server_generic_client_t **client, prelude_connection_t *cnx)
{
        sensor_fd_t *cdata;

        cdata = calloc(1, sizeof(*cdata));
        if ( ! cdata ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        *client = (server_generic_client_t *) cdata;

        cdata->queue = idmef_message_scheduler_queue_new(manager_client);
        if ( ! cdata->queue ) {
                free(cdata);
                return -1;
        }

        cdata->state |= SERVER_GENERIC_CLIENT_STATE_ACCEPTED;
        cdata->fd = prelude_connection_get_fd(cnx);

        cdata->cnx = cnx;
        cdata->we_connected = TRUE;

        cdata->server = server;

        cdata->ident = prelude_connection_get_peer_analyzerid(cnx);

        server_generic_client_set_permission((server_generic_client_t *)cdata, prelude_connection_get_permission(cnx));
        prelude_list_add(&sensors_cnx_list[get_list_key(cdata->ident)], &cdata->list);

        return server_generic_process_requests(server, (server_generic_client_t *) cdata);
}



int sensor_server_write_client(server_generic_client_t *client, prelude_msg_t *msg)
{
        sensor_fd_t *dst = (sensor_fd_t *) client;

        assert(! dst->wmsg);
        return write_client(dst, msg);
}



int sensor_server_init(void)
{
        int i;

        for ( i = 0; i < sizeof(sensors_cnx_list) / sizeof(*sensors_cnx_list); i++ )
                prelude_list_init(&sensors_cnx_list[i]);

        return 0;
}



prelude_list_t *sensor_server_get_list(uint64_t analyzerid)
{
        return &sensors_cnx_list[get_list_key(analyzerid)];
}
