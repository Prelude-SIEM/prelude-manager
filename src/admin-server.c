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
#include <inttypes.h>

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
        prelude_io_t *fd;
        prelude_msg_t *msg;
        struct list_head list;
} admin_cnx_t;



static server_generic_t *server;
static LIST_HEAD(admin_cnx_list);



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




static int read_connection_cb(void *sdata, prelude_io_t *src, void **clientdata) 
{
        int ret;
        prelude_msg_t *msg;
        admin_cnx_t *client = *clientdata;
                 
        /*
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




static void close_connection_cb(void *clientdata) 
{
        admin_cnx_t *cnx = clientdata;

        if ( cnx->msg )
                prelude_msg_destroy(cnx->msg);
        
        free(cnx);
}




static int accept_connection_cb(prelude_io_t *fd, void **cdata) 
{
        admin_cnx_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }
        
        new->fd = fd;
        *cdata = new;
        list_add(&new->list, &admin_cnx_list);
        
        return 0;
}



int admin_server_new(const char *addr, uint16_t port) 
{
        server = server_generic_new(addr, port, accept_connection_cb,
                                    read_connection_cb, close_connection_cb);
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
        admin_cnx_t *cnx;
        struct list_head *tmp;
        
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
        
        list_for_each(tmp, &admin_cnx_list) {
                cnx = list_entry(tmp, admin_cnx_t, list);
                prelude_io_write(cnx->fd, xml, len);
        }
                
        return 0;
}








