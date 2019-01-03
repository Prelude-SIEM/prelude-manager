/*****
*
* Copyright (C) 2004-2019 CS-SI. All Rights Reserved.
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

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-failover.h>
#include <libprelude/prelude-connection-pool.h>

#include "glthread/lock.h"

#include "reverse-relaying.h"
#include "server-generic.h"
#include "sensor-server.h"
#include "manager-options.h"

#include "sensor-server.h"



struct reverse_relay_receiver {
        prelude_list_t list;
        uint64_t analyzerid;
        prelude_failover_t *failover;
};



static prelude_msgbuf_t *msgbuf;
static PRELUDE_LIST(mqueue_list);
static gl_lock_t mqueue_mutex = gl_lock_initializer;

static prelude_bool_t no_receiver = TRUE;
static prelude_list_t receiver_list[1024];
static gl_lock_t receiver_list_mutex = gl_lock_initializer;

extern manager_config_t config;
extern prelude_client_t *manager_client;



static unsigned int get_list_key(uint64_t analyzerid)
{
        return analyzerid & (sizeof(receiver_list) / sizeof(*receiver_list) - 1);
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



static int write_all_client(reverse_relay_receiver_t *rrr, prelude_msg_t *msg, unsigned long count)
{
        int i = 0, ret;
        sensor_fd_t *client;
        prelude_list_t *tmp, *bkp;

        prelude_list_for_each_safe(sensor_server_get_list(rrr->analyzerid), tmp, bkp) {
                client = prelude_list_entry(tmp, sensor_fd_t, list);

                if ( client->ident != rrr->analyzerid )
                        continue;

                i++;
                if ( count )
                        server_generic_log_client((server_generic_client_t *) client, PRELUDE_LOG_INFO,
                                                  "flushing %lu messages received while analyzer was offline.\n", count);

                ret = sensor_server_write_client((server_generic_client_t *) client, prelude_msg_ref(msg));
                if ( ret < 0 && prelude_error_get_code(ret) != PRELUDE_ERROR_EAGAIN )
                         server_generic_client_close((server_generic_client_t *) client);
        }

        return i;
}



int reverse_relay_set_receiver_alive(reverse_relay_receiver_t *rrr)
{
        ssize_t size;
        prelude_msg_t *msg;
        prelude_failover_t *failover = rrr->failover;
        unsigned long avail = prelude_failover_get_available_msg_count(failover);

        while ( (size = prelude_failover_get_saved_msg(failover, &msg)) > 0 ) {
                write_all_client(rrr, msg, avail);
                prelude_msg_destroy(msg);

                avail = 0;
        }

        if ( size < 0 ) {
                prelude_perror((prelude_error_t) size, "could not retrieve saved message from disk");
                return -1;
        }

        return 0;
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
        char fname[PATH_MAX];
        reverse_relay_receiver_t *new;

        new = reverse_relay_search_receiver(analyzerid);
        if ( new )
                goto out;

        new = malloc(sizeof(*new));
        if ( ! new )
                return -1;

        new->analyzerid = analyzerid;
        prelude_client_profile_get_backup_dirname(prelude_client_get_profile(manager_client), fname, sizeof(fname));
        snprintf(fname + strlen(fname), sizeof(fname) - strlen(fname), "/%" PRELUDE_PRIu64, analyzerid);

        ret = prelude_failover_new(&new->failover, fname);
        if ( ret < 0 ) {
                prelude_perror(ret, "could not create failover");
                free(new);
                return -1;
        }

        gl_lock_lock(receiver_list_mutex);
        no_receiver = FALSE;
        prelude_list_add_tail(&receiver_list[get_list_key(analyzerid)], &new->list);
        gl_lock_unlock(receiver_list_mutex);
        *rrr = new;

    out:
        return reverse_relay_set_receiver_alive(new);
}



static int send_msgbuf(prelude_msgbuf_t *msgbuf, prelude_msg_t *msg)
{
        prelude_msg_set_data(msg, prelude_msgbuf_get_data(msgbuf));

        gl_lock_lock(mqueue_mutex);
        prelude_linked_object_add_tail(&mqueue_list, (prelude_linked_object_t *) msg);
        gl_lock_unlock(mqueue_mutex);

        return 0;
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



static prelude_msg_t *mqueue_get_next(void)
{
        prelude_msg_t *m = NULL;

        gl_lock_lock(mqueue_mutex);

        if ( prelude_list_is_empty(&mqueue_list) )
                goto out;

        m = prelude_linked_object_get_object(mqueue_list.next);
        prelude_linked_object_del((prelude_linked_object_t *) m);

out:
        gl_lock_unlock(mqueue_mutex);
        return m;
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
        int ret, i;
        prelude_msg_t *m;
        prelude_list_t *tmp;
        reverse_relay_receiver_t *receiver;

        while ( (m = mqueue_get_next()) ) {

                for ( i = 0; i < sizeof(receiver_list) / sizeof(*receiver_list); i++ ) {
                        prelude_list_for_each(&receiver_list[i], tmp) {
                                receiver = prelude_list_entry(tmp, reverse_relay_receiver_t, list);

                                if ( prelude_msg_get_data(m) == receiver )
                                        continue;

                                ret = write_all_client(receiver, m, 0);
                                if ( ! ret ) {
                                        ret = prelude_failover_save_msg(receiver->failover, m);
                                        if ( ret < 0 )
                                                prelude_perror(ret, "could not save message to disk");
                                }
                        }
                }

                prelude_msg_destroy(m);
        }
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
