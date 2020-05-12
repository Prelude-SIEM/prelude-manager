/*****
*
* Copyright (C) 2004-2020 CS-SI. All Rights Reserved.
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
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-failover.h>
#include <libprelude/prelude-connection-pool.h>

#include "glthread/lock.h"

#include "bufpool.h"
#include "reverse-relaying.h"
#include "server-generic.h"
#include "sensor-server.h"
#include "manager-options.h"

#include "sensor-server.h"



struct reverse_relay_receiver {
        prelude_list_t list;
        uint64_t analyzerid;
        bufpool_t *failover;
};



static prelude_msgbuf_t *msgbuf;

static prelude_bool_t no_receiver = TRUE;
static prelude_list_t receiver_list[1024];
static gl_lock_t receiver_list_mutex = gl_lock_initializer;

extern manager_config_t config;
extern prelude_client_t *manager_client;
static prelude_connection_pool_t *initiator = NULL;




static unsigned int get_list_key(uint64_t analyzerid)
{
        return analyzerid & (sizeof(receiver_list) / sizeof(*receiver_list) - 1);
}


static int connection_event_cb(prelude_connection_pool_t *pool,
                               prelude_connection_pool_event_t event, prelude_connection_t *cnx)
{
        int ret;
        server_generic_client_t *client;

        if ( ! (event & PRELUDE_CONNECTION_POOL_EVENT_ALIVE) )
                return 0;

#if (defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__
        ret = fcntl(prelude_io_get_fd(prelude_connection_get_fd(cnx)), F_SETFL, O_NONBLOCK);
        if ( ret < 0 )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "could not set non blocking mode for client: %s", strerror(errno));
#endif

        ret = sensor_server_add_client(config.server[0], &client, cnx);
        if ( ret < 0 )
                prelude_log(PRELUDE_LOG_WARN, "error adding new client to reverse relay list.\n");

        prelude_connection_set_data(cnx, client);

        return 0;
}



static reverse_relay_receiver_t *get_next_receiver(prelude_list_t *receiver_list, prelude_list_t **iter)
{
        prelude_list_t *tmp;
        reverse_relay_receiver_t *rrr = NULL;

        /*
         * Locking here is not required since the list is never
         * modified by the worker thread. We only protect writing
         * of the list, and reading it from the worker thread.
         */
        prelude_list_for_each_continue_safe(receiver_list, tmp, *iter) {
                rrr = prelude_list_entry(tmp, reverse_relay_receiver_t, list);
                break;
        }

        return rrr;
}



static sensor_fd_t *find_client(reverse_relay_receiver_t *rrr)
{
        sensor_fd_t *client;
        prelude_list_t *tmp;

        prelude_list_for_each(sensor_server_get_list(rrr->analyzerid), tmp) {
                client = prelude_list_entry(tmp, sensor_fd_t, list);
                if ( client->ident == rrr->analyzerid )
                        return client;
        }

        return NULL;
}



static int write_client(sensor_fd_t *client, prelude_msg_t *msg)
{
        int ret;

        ret = sensor_server_write_client((server_generic_client_t *) client, msg);
        if ( ret < 0 ) {
                if ( prelude_error_get_code(ret) != PRELUDE_ERROR_EAGAIN ) {
                        prelude_perror(ret, "write client close cnx");
                        server_generic_client_close((server_generic_client_t *) client);

                } else {
                        assert(client->wmsg);
                        server_generic_notify_write_enable((server_generic_client_t *) client);
                }
        }

        return ret;
}



int reverse_relay_write_possible(reverse_relay_receiver_t *rrr, server_generic_client_t *client)
{
        prelude_msg_t *msg;
        int ret, limit = 1024;
        sensor_fd_t *sclient = (sensor_fd_t *) client;

        while ( --limit > 0 && (ret = bufpool_get_message(rrr->failover, &msg)) > 0 ) {
                ret = write_client(sclient, msg);
                if ( ret < 0 ) {
                        if ( prelude_error_get_code(ret) == PRELUDE_ERROR_EAGAIN ) {
                                ret = 0;
                                break;
                        }

                        return ret;
                }
        }

        if ( ! sclient->wmsg && bufpool_get_message_count(rrr->failover) == 0 )
                server_generic_notify_write_disable(client);

        else if ( ! limit )
                server_generic_notify_write_enable(client);

        return ret;
}



int reverse_relay_set_receiver_alive(reverse_relay_receiver_t *rrr, server_generic_client_t *client)
{
        ssize_t count = bufpool_get_message_count(rrr->failover);

        if ( count )
                server_generic_log_client((server_generic_client_t *) client, PRELUDE_LOG_INFO,
                                          "flushing %lu messages received while analyzer was offline.\n", count);

        /*
         * It is possible that reverse_relay_send_prepared() has been called before we enter this callback.
         * In this case, wmsg might be set.
         */
        if ( ((sensor_fd_t *) client)->wmsg )
                return 0;

        return reverse_relay_write_possible(rrr, client);
}



int reverse_relay_set_initiator_dead(prelude_connection_t *cnx)
{
        int ret = -1;

        if ( initiator )
                ret = prelude_connection_pool_set_connection_dead(initiator, cnx);

        return ret;
}



static reverse_relay_receiver_t *reverse_relay_search_receiver(uint64_t analyzerid)
{
        prelude_list_t *iter = NULL;
        reverse_relay_receiver_t *item;

        while ( (item = get_next_receiver(&receiver_list[get_list_key(analyzerid)], &iter)) ) {

                if ( item->analyzerid == analyzerid )
                        return item;
        }

        return NULL;
}



int reverse_relay_new_receiver(reverse_relay_receiver_t **rrr, server_generic_client_t *client, uint64_t analyzerid)
{
        int ret;
        char bdir[PATH_MAX], fname[PATH_MAX];
        reverse_relay_receiver_t *new;

        new = reverse_relay_search_receiver(analyzerid);
        if ( new )
                goto out;

        new = malloc(sizeof(*new));
        if ( ! new )
                return -1;

        prelude_client_profile_get_backup_dirname(prelude_client_get_profile(manager_client), bdir, sizeof(bdir));
        snprintf(fname, sizeof(fname), "%s/send-failover.%" PRELUDE_PRIu64, bdir, analyzerid);

        ret = bufpool_new(&new->failover, fname);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating reverse relay failover");
                return -1;
        }

        new->analyzerid = analyzerid;

        gl_lock_lock(receiver_list_mutex);
        no_receiver = FALSE;
        prelude_list_add_tail(&receiver_list[get_list_key(analyzerid)], &new->list);
        gl_lock_unlock(receiver_list_mutex);

    out:
        *rrr = new;
        return reverse_relay_set_receiver_alive(new, client);
}



static int send_msgbuf(prelude_msgbuf_t *msgbuf, prelude_msg_t *msg)
{
        int i, ret;
        prelude_list_t *tmp;
        prelude_msg_t *clone;
        reverse_relay_receiver_t *receiver, *sender = prelude_msgbuf_get_data(msgbuf);

        for ( i = 0; i < sizeof(receiver_list) / sizeof(*receiver_list); i++ ) {
                prelude_list_for_each(&receiver_list[i], tmp) {
                        receiver = prelude_list_entry(tmp, reverse_relay_receiver_t, list);
                        if ( sender == receiver )
                                continue;

                        ret = prelude_msg_clone(&clone, msg);
                        if ( ret < 0 )
                                break;

                        bufpool_add_message(receiver->failover, clone);
                        continue;
                }
        }

        prelude_msg_destroy(msg);
        return 1;
}



static int get_issuer_analyzerid(idmef_message_t *idmef, uint64_t *analyzerid)
{
        idmef_alert_t *alert;
        idmef_message_type_t type;
        idmef_heartbeat_t *heartbeat;
        idmef_analyzer_t *analyzer = NULL;
        prelude_string_t *id, *last = NULL;

        type = idmef_message_get_type(idmef);

        if ( type == IDMEF_MESSAGE_TYPE_ALERT ) {
                alert = idmef_message_get_alert(idmef);

                while ( (analyzer = idmef_alert_get_next_analyzer(alert, analyzer)) ) {
                        id = idmef_analyzer_get_analyzerid(analyzer);
                        if ( id )
                                last = id;
                }
        }

        else if ( type == IDMEF_MESSAGE_TYPE_HEARTBEAT ) {
                heartbeat = idmef_message_get_heartbeat(idmef);

                while ( (analyzer = idmef_heartbeat_get_next_analyzer(heartbeat, analyzer)) ) {
                        id = idmef_analyzer_get_analyzerid(analyzer);
                        if ( id )
                                last = id;
                }

        }

        else return -1;

        if ( last && prelude_string_get_string(last) )
                *analyzerid = strtoull(prelude_string_get_string(last), NULL, 10);
        else
                *analyzerid = 0;

        return 0;
}



void reverse_relay_send_receiver(idmef_message_t *idmef)
{
        int ret;
        uint64_t analyzerid;
        reverse_relay_receiver_t *rrr;

        /*
         * If there is no receiver, no need to queue the message.
         */
        if ( no_receiver )
                return;

        /*
         * Create a new item in the message queue, containing
         * the message to be sent, as well as the analyzerid of the
         * emitter.
         */
        ret = get_issuer_analyzerid(idmef, &analyzerid);
        if ( ret < 0 )
                return;

        rrr = reverse_relay_search_receiver(analyzerid);
        prelude_msgbuf_set_data(msgbuf, rrr);


        /*
         * Convert from idmef_message_t to prelude_msg_t, this will
         * trigger the msgbuf callback where the message will be attached
         * to the list of message to be emited.
         */
        idmef_message_write(idmef, msgbuf);
        prelude_msgbuf_mark_end(msgbuf);

        /*
         * Finally, restart the main server event loop so that it
         * take into account the event to be written, and call
         * reverse_relay_send_prepared().
         */
        server_generic_notify_event();
}



void reverse_relay_send_prepared(void)
{

        int i;
        prelude_list_t *tmp;
        reverse_relay_receiver_t *receiver;
        sensor_fd_t *client;

        for ( i = 0; i < sizeof(receiver_list) / sizeof(*receiver_list); i++ ) {
                prelude_list_for_each(&receiver_list[i], tmp) {
                        receiver = prelude_list_entry(tmp, reverse_relay_receiver_t, list);
                        if ( ! receiver->failover || bufpool_get_message_count(receiver->failover) < 1 )
                                continue;

                        client = find_client(receiver);
                        if ( ! client || client->wmsg )
                                continue;

                        reverse_relay_write_possible(receiver, (server_generic_client_t *) client);
                }
        }
}


static void destroy_current_initiator(void)
{
        sensor_fd_t *client;
        prelude_list_t *tmp;
        prelude_connection_t *cnx;

        prelude_list_for_each(prelude_connection_pool_get_connection_list(initiator), tmp) {
                cnx = prelude_linked_object_get_object(tmp);

                client = prelude_connection_get_data(cnx);
                if ( client ) {
                        client->cnx = NULL;
                        client->fd = NULL;
                        server_generic_remove_client(config.server[0], (server_generic_client_t *) client);
                }
        }

        prelude_connection_pool_destroy(initiator);
        initiator = NULL;
}



int reverse_relay_create_initiator(const char *arg)
{
        int ret;
        prelude_client_profile_t *cp;

        cp = prelude_client_get_profile(manager_client);

        if ( initiator )
                destroy_current_initiator();

        ret = prelude_connection_pool_new(&initiator, cp, PRELUDE_CONNECTION_PERMISSION_IDMEF_READ);
        if ( ret < 0 )
                goto out;

        prelude_connection_pool_set_flags(initiator, PRELUDE_CONNECTION_POOL_FLAGS_RECONNECT);
        prelude_connection_pool_set_event_handler(initiator, PRELUDE_CONNECTION_POOL_EVENT_DEAD |
                                                  PRELUDE_CONNECTION_POOL_EVENT_ALIVE, connection_event_cb);

        ret = prelude_connection_pool_set_connection_string(initiator, arg);
        if ( ret < 0 ) {
                prelude_connection_pool_destroy(initiator);
                goto out;
        }

        ret = prelude_connection_pool_init(initiator);
        if ( ret < 0 ) {
                prelude_connection_pool_destroy(initiator);
                goto out;
        }

 out:
        return ret;
}



int reverse_relay_init(void)
{
        int ret, i;

        for ( i = 0; i < sizeof(receiver_list) / sizeof(*receiver_list); i++ )
                prelude_list_init(&receiver_list[i]);

        ret = prelude_msgbuf_new(&msgbuf);
        if ( ! msgbuf ) {
                prelude_perror(ret, "error creating reverse relay msgbuf");
                return -1;
        }

        prelude_msgbuf_set_callback(msgbuf, send_msgbuf);
        prelude_msgbuf_set_flags(msgbuf, PRELUDE_MSGBUF_FLAGS_ASYNC);

        return 0;
}
