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
#include "alert-scheduler.h"


typedef struct {
        struct list_head list;
        prelude_msg_t *msg;
        prelude_io_t *fd;
        idmef_analyzer_t analyzer;
} sensor_cnx_t;



server_generic_t *server;
static LIST_HEAD(sensor_cnx_list);



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
        sensor_cnx_t *sensor = *clientdata;
        
        ret = prelude_msg_read(&sensor->msg, src);
        if ( ret < 0 ) 
                return -1; /* an error occured */
        
        if ( ret == 0 )
                return 0;  /* message not fully read yet */
                
        /*
         * If we get there, we have a whole message.
         */
        switch ( prelude_msg_get_tag(sensor->msg) ) {
                
        case PRELUDE_MSG_IDMEF:
                alert_schedule(sensor->msg, src);
                break;
                
        case PRELUDE_MSG_OPTION_LIST:
                
                ret = optlist_to_xml(sensor->msg);
                if ( ret < 0 )
                        return -1;
                break;
        }
        
        sensor->msg = NULL;
        
        return 0;
}




static void close_connection_cb(void *clientdata) 
{
        sensor_cnx_t *cnx = clientdata;

        if ( cnx->msg )
                prelude_msg_destroy(cnx->msg);
        
        free((sensor_cnx_t *)clientdata);
}




static int accept_connection_cb(prelude_io_t *cfd, void **cdata) 
{
        sensor_cnx_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        new->msg = NULL;
        new->fd = cfd;
        list_add(&new->list, &sensor_cnx_list);

        *cdata = new;
        
        return 0;
}




int sensors_server_start(const char *addr, uint16_t port) 
{
        int ret;
        server_generic_t *new;
        
        ret = alert_scheduler_init();
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't initialize alert scheduler.\n");
                return -1;
        }
        
        new = server_generic_new(addr, port, accept_connection_cb,
                                 read_connection_cb, close_connection_cb);
        if ( ! new ) {
                log(LOG_ERR, "error creating a generic server.\n");
                return -1;
        }
        
        return server_generic_start(new);
}




int sensor_server_broadcast_admin_command(const char *sensorid, prelude_msg_t *msg) 
{
        sensor_cnx_t *cnx;
        struct list_head *tmp;
        
        if ( ! sensorid )
                return -1;

        list_for_each(tmp, &sensor_cnx_list) {

                cnx = list_entry(tmp, sensor_cnx_t, list);

                if ( cnx->analyzer.analyzerid && strcmp(cnx->analyzer.analyzerid, sensorid) == 0 ) 
                        return prelude_msg_write(msg, cnx->fd);
        }

        log(LOG_ERR, "couldn't find sensor with ID %s\n", sensorid);

        return -1;
}







