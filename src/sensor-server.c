#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
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
#include "sensor-server.h"
#include "idmef-message-scheduler.h"



typedef struct {        
        struct list_head list;
        prelude_msg_t *msg;
        prelude_io_t *fd;
} sensor_cnx_t;


static server_generic_t *server;
static LIST_HEAD(sensor_cnx_list);
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
                        
        /*
         * If we get there, we have a whole message.
         */
        switch ( prelude_msg_get_tag(cnx->msg) ) {
                
        case PRELUDE_MSG_IDMEF:
                idmef_message_schedule(cnx->msg);
                break;
                
        case PRELUDE_MSG_OPTION_LIST:
                ret = optlist_to_xml(cnx->msg);
                if ( ret < 0 )
                        return -1;
                break;

        default:
                log(LOG_ERR, "Unknow message id %d\n", prelude_msg_get_tag(cnx->msg));
                prelude_msg_destroy(cnx->msg);
                return -1;
        }
        
        cnx->msg = NULL;
        
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




int sensor_server_broadcast_admin_command(const char *sensorid, prelude_msg_t *msg) 
{
        sensor_cnx_t *cnx;
        struct list_head *tmp;
        
        if ( ! sensorid )
                return -1;

        pthread_mutex_lock(&list_mutex);
        
        list_for_each(tmp, &sensor_cnx_list) {
                cnx = list_entry(tmp, sensor_cnx_t, list);

#if 0
                if ( cnx->analyzer.analyzerid && strcmp(cnx->analyzer.analyzerid, sensorid) == 0 ) {
                        ret = prelude_msg_write(msg, cnx->fd);
                        pthread_mutex_unlock(&list_mutex);
                        return ret;
                }
#endif
                
        }
        
        pthread_mutex_unlock(&list_mutex);

        log(LOG_ERR, "couldn't find sensor with ID %s\n", sensorid);

        return -1;
}





