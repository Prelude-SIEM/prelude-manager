/*****
*
* Copyright (C) 2001 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <string.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <pthread.h>

#include <libprelude/list.h>
#include <libprelude/common.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-message-id.h>
#include <libprelude/prelude-getopt-wide.h>

#include "server-logic.h"
#include "server-generic.h"
#include "admin-server.h"
#include "sensor-server.h"


typedef struct {
        SERVER_GENERIC_OBJECT;
        struct list_head list;
} admin_client_t;


static server_generic_t *server;
static LIST_HEAD(admin_client_list);
static pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;


static int get_option(prelude_msg_t *msg) 
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

        if ( ret == 0 ) {
                log(LOG_ERR, "end of message without end of option tag.\n");
                return -1;
        }

        switch (tag) {

        case PRELUDE_OPTION_NAME:
                printf("option name = %s\n", (char *) buf);

        case PRELUDE_OPTION_END:
                printf("end option.\n");
                return 0;
                
        default:
                log(LOG_ERR, "Unknow option tag %d.\n", tag);
                return -1;
        }

        return get_option(msg);
}



static int optlist_to_xml(prelude_msg_t *msg) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t dlen;
        
        /*
         * Convert the Prelude option list to XML here.
         */
        ret = prelude_msg_get(msg, &tag, &dlen, &buf);
        if ( ret < 0 ) {
                log(LOG_ERR, "error decoding message.\n");
                return -1;
        }

        if ( ret == 0 ) {
                prelude_msg_destroy(msg);
                return 0; /* end of message do DTD validation here */
        }
        
        switch (tag) {

        case PRELUDE_OPTION_START:
                printf("new option.\n");

                ret = get_option(msg);
                if ( ret < 0 ) {
                        prelude_msg_destroy(msg);
                        return -1;
                }
                
                break;

        default:
                log(LOG_ERR, "Unknow option tag %d.\n", tag);
                return -1;
        }

        return optlist_to_xml(msg);
}




static int read_connection_cb(server_generic_client_t *ptr)
{
        int ret;
        prelude_msg_t *msg;

        /*
         *
         * admin_client_t *client = (admin_client_t *) ptr;
         *
         * Handle XML stream here. And convert it to prelude message.
         * use prelude_io_read_nowait() for reading the message.
         */
        msg = NULL;
        if ( ! msg ) {
                log(LOG_ERR, "couldn't generate message from XML string.\n");
                return -1;
        }

        ret = sensor_server_broadcast_admin_command(NULL /* sensor id here */, msg);
        prelude_msg_destroy(msg);
        
        return ret;
}




static void close_connection_cb(server_generic_client_t *ptr) 
{
        admin_client_t *client = (admin_client_t *) ptr;

        /*
         * Kill an eventual unfinished message remaining
         * at close() time.
         */
        if ( client->msg )
                prelude_msg_destroy(client->msg);
        
        pthread_mutex_lock(&list_mutex);
        list_del(&client->list);
        pthread_mutex_unlock(&list_mutex);
}




static int accept_connection_cb(server_generic_client_t *ptr) 
{
        admin_client_t *client = (admin_client_t *) ptr;
        
        pthread_mutex_lock(&list_mutex);
        list_add(&client->list, &admin_client_list);
        pthread_mutex_unlock(&list_mutex);
        
        return 0;
}



int admin_server_new(const char *addr, uint16_t port) 
{
        server = server_generic_new(addr, port, sizeof(admin_client_t),
                                    accept_connection_cb, read_connection_cb, close_connection_cb);
        if ( ! server ) {
                log(LOG_ERR, "error creating a generic server.\n");
                return -1;
        }

        return 0;
}




void admin_server_start(void) 
{        
        server_generic_start(server); /* Never return */
}




int admin_server_broadcast_sensor_optlist(prelude_msg_t *msg) 
{
        int len;
        char *xml;
        struct list_head *tmp;
        admin_client_t *client;

        /*
         * 
         * Call optlist_to_xml() here,
         * and send the returned XML string
         */
        xml = NULL;
        if ( ! xml ) {
                log(LOG_ERR, "couldn't convert option message to XML string.\n");
                return -1;
        }

        len = strlen(xml) + 1;
     
        msg = prelude_msg_new(1, len, 0, 0);
        if ( ! msg )
                return -1;

        prelude_msg_set(msg, 0, len, xml);
     
        list_for_each(tmp, &admin_client_list) {
                client = list_entry(tmp, admin_client_t, list);
                prelude_msg_write(msg, client->fd);
        }
        
        return 0;
}
