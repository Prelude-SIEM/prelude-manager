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
#include <sys/types.h>
#include <netinet/in.h>
#include <pthread.h>

#include <libprelude/list.h>
#include <libprelude/common.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-message-id.h>
#include <libprelude/prelude-getopt-wide.h>
#include <libprelude/prelude-ident.h>
#include <libprelude/extract.h>

#include "server-logic.h"
#include "server-generic.h"
#include "sensor-server.h"
#include "idmef-message-scheduler.h"



typedef struct {        
        struct list_head list;
        uint64_t analyzerid;
        prelude_msg_t *msg;
        prelude_io_t *fd;
} sensor_cnx_t;


static server_generic_t *server;
static LIST_HEAD(sensor_cnx_list);
static prelude_ident_t *analyzer_ident;
static pthread_mutex_t list_mutex = PTHREAD_MUTEX_INITIALIZER;


static int option_list_to_xml(prelude_msg_t *msg) 
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
                printf("option start\n");
                ret = option_list_to_xml(msg);
                if ( ret < 0 )
                        return -1;
                break;
                
        case PRELUDE_OPTION_NAME:
                printf("option name = %s\n", (char *) buf);
                break;

        case PRELUDE_OPTION_DESC:
                printf("option desc = %s\n", (char *) buf);
                break;

        case PRELUDE_OPTION_HAS_ARG:
                printf("option has_arg = %d\n", * (uint8_t *) buf);
                break;

        case PRELUDE_OPTION_HELP:
                printf("option help = %s\n", (char *) buf);
                break;

        case PRELUDE_OPTION_INPUT_VALIDATION:
                printf("option input regex = %s\n", (char *) buf);
                break;

        case PRELUDE_OPTION_INPUT_TYPE:
                printf("option input type = %d\n", * (uint8_t *) buf);
                break;
                
        case PRELUDE_OPTION_END:
                printf("end option.\n");
                return 0;
                
        default:
                log(LOG_ERR, "Unknow option tag %d.\n", tag);
                return -1;
        }

        return option_list_to_xml(msg);
}




static int handle_request_ident(sensor_cnx_t *cnx)
{
        uint64_t nident;
        prelude_msg_t *msg;
        
        msg = prelude_msg_new(1, sizeof(uint64_t), PRELUDE_MSG_ID, 0);
        if ( ! msg )
                return -1;
        
        cnx->analyzerid = prelude_ident_inc(analyzer_ident);

        /*
         * Put in network byte order
         */
        ((uint32_t *) &nident)[0] = htonl(((uint32_t *) &cnx->analyzerid)[1]);
        ((uint32_t *) &nident)[1] = htonl(((uint32_t *) &cnx->analyzerid)[0]);

        /*
         * send the message
         */
        prelude_msg_set(msg, PRELUDE_MSG_ID_REPLY, sizeof(nident), &nident);
        prelude_msg_write(msg, cnx->fd);
        prelude_msg_destroy(msg);

        log(LOG_INFO, "- Allocated ident %llu on sensor request.\n", cnx->analyzerid);
        
        return 0;
}




static int handle_declare_ident(sensor_cnx_t *cnx, void *buf, uint32_t blen) 
{
        int ret;
        
        ret = extract_uint64(&cnx->analyzerid, buf, blen);
        log(LOG_INFO, "- Sensor declared ident %llu.\n", cnx->analyzerid);
        return ret;
}





static int read_ident_message(sensor_cnx_t *cnx, prelude_msg_t *msg) 
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
                
        case PRELUDE_MSG_ID_DECLARE:
                ret = handle_declare_ident(cnx, buf, dlen);
                break;
                
        case PRELUDE_MSG_ID_REQUEST:
                ret = handle_request_ident(cnx);
                break;
                
        default:
                log(LOG_ERR, "Unknow ID tag: %d.\n", tag);
                ret = -1;
        }

        prelude_msg_destroy(msg);
        
        return ret;
}






static int read_connection_cb(void *sdata, prelude_io_t *src, void **clientdata) 
{
        int ret;
        prelude_msg_t *msg;
        prelude_msg_status_t status;
        sensor_cnx_t *cnx = *clientdata;
        
        status = prelude_msg_read(&cnx->msg, src);        
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
        
        /*
         * If we get there, we have a whole message.
         */
        switch ( prelude_msg_get_tag(msg) ) {
                
        case PRELUDE_MSG_IDMEF:
                idmef_message_schedule(msg);
                break;

        case PRELUDE_MSG_ID:
                return read_ident_message(cnx, msg);
                
        case PRELUDE_MSG_OPTION_LIST:
                ret = option_list_to_xml(msg);
                prelude_msg_destroy(msg);
                if ( ret < 0 )
                        return -1;
                break;

        default:
                log(LOG_ERR, "Unknow message id %d\n", prelude_msg_get_tag(cnx->msg));
                prelude_msg_destroy(msg);
                return -1;
        }
                
        return 0;
}




static void close_connection_cb(void *clientdata) 
{
        sensor_cnx_t *cnx = clientdata;

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

        free(cnx);
}




static int accept_connection_cb(prelude_io_t *cfd, void **cdata) 
{
        sensor_cnx_t *new;
        
        new = malloc(sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }
        
        *cdata = new;
        new->fd = cfd;
        new->msg = NULL;

        pthread_mutex_lock(&list_mutex);
        list_add(&new->list, &sensor_cnx_list);
        pthread_mutex_unlock(&list_mutex);
        
        return 0;
}



int sensor_server_new(const char *addr, uint16_t port) 
{
        int ret;

        analyzer_ident = prelude_ident_new(CONFIG_DIR"/analyzer.ident");
        if ( ! analyzer_ident )
                return -1;
        
        server = server_generic_new(addr, port, accept_connection_cb,
                                 read_connection_cb, close_connection_cb);
        if ( ! server ) {
                log(LOG_ERR, "error creating a generic server.\n");
                return -1;
        }
        
        ret = idmef_message_scheduler_init();
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't initialize alert scheduler.\n");
                return -1;
        }
        
        return 0;
}



void sensor_server_start(void) 
{    
        server_generic_start(server); /* Never return */
}




int sensor_server_broadcast_admin_command(uint64_t *analyzerid, prelude_msg_t *msg) 
{
        int ret;
        sensor_cnx_t *cnx;
        struct list_head *tmp;
        
        if ( ! analyzerid )
                return -1;

        pthread_mutex_lock(&list_mutex);
        
        list_for_each(tmp, &sensor_cnx_list) {
                cnx = list_entry(tmp, sensor_cnx_t, list);

                if ( cnx->analyzerid == *analyzerid ) {
                        ret = prelude_msg_write(msg, cnx->fd);
                        pthread_mutex_unlock(&list_mutex);
                        return ret;
                }
        }
        
        pthread_mutex_unlock(&list_mutex);

        log(LOG_ERR, "couldn't find sensor with ID %s\n", *analyzerid);

        return -1;
}





