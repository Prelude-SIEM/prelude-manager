#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <inttypes.h>

#include <libprelude/idmef.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-list.h>
#include <libprelude/prelude-linked-object.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-client.h>
#include <libprelude/prelude-client-mgr.h>
#include <libprelude/prelude-async.h>
#include <libprelude/prelude-message-buffered.h>
#include <libprelude/idmef-message-write.h>

#include "reverse-relaying.h"
#include "server-generic.h"
#include "sensor-server.h"


#define PRELUDE_CLIENT_TYPE_MANAGER_RECEIVER PRELUDE_CLIENT_TYPE_MANAGER_PARENT
#define PRELUDE_CLIENT_TYPE_MANAGER_INITIATOR PRELUDE_CLIENT_TYPE_MANAGER_CHILDREN


extern server_generic_t *sensor_server;


static prelude_client_mgr_t *receiver_managers = NULL;
static prelude_client_mgr_t *initiator_managers = NULL;
static pthread_mutex_t receiver_managers_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t initiator_managers_lock = PTHREAD_MUTEX_INITIALIZER;



static void reverse_relay_notify_state(prelude_list_t *clist) 
{
        int ret;
        prelude_list_t *tmp;
        prelude_client_t *client;
        
        prelude_list_for_each(tmp, clist) {
                client = prelude_linked_object_get_object(tmp, prelude_client_t);

                if ( prelude_client_is_alive(client) < 0 ) 
                        continue;
                
                ret = sensor_server_add_client(sensor_server, client);
                if ( ret < 0 ) {
                        log(LOG_ERR, "error adding new client to reverse relay list.\n");
                        return;
                }
        }
}



int reverse_relay_tell_receiver_alive(prelude_client_t *client) 
{
        int ret;

        if ( ! receiver_managers )
                return 0;
        
        pthread_mutex_lock(&receiver_managers_lock);
        ret = prelude_client_mgr_tell_client_alive(receiver_managers, client);
        pthread_mutex_unlock(&receiver_managers_lock);

        return ret;
}



int reverse_relay_tell_dead(prelude_client_t *client) 
{
        int ret = -1, type;

        type = prelude_client_get_type(client);

        if ( type == PRELUDE_CLIENT_TYPE_MANAGER_RECEIVER ) {        
                pthread_mutex_lock(&initiator_managers_lock);
                ret = prelude_client_mgr_tell_client_dead(initiator_managers, client);
                pthread_mutex_unlock(&initiator_managers_lock);
        }

        else if ( type == PRELUDE_CLIENT_TYPE_MANAGER_INITIATOR ) {        
                pthread_mutex_lock(&receiver_managers_lock);
                ret = prelude_client_mgr_tell_client_dead(receiver_managers, client);
                pthread_mutex_unlock(&receiver_managers_lock);
        }
        
        return ret;
}




int reverse_relay_add_receiver(prelude_client_t *client) 
{
        int ret;
        
        pthread_mutex_lock(&receiver_managers_lock);
        ret = prelude_client_mgr_add_client(&receiver_managers, client, 0);
        pthread_mutex_unlock(&receiver_managers_lock);

        return ret;
}




prelude_client_t *reverse_relay_search_receiver(const char *addr) 
{
        prelude_client_t *client;

        pthread_mutex_lock(&receiver_managers_lock);
        client = prelude_client_mgr_search_client(receiver_managers, addr, PRELUDE_CLIENT_TYPE_MANAGER_RECEIVER);
        pthread_mutex_unlock(&receiver_managers_lock);

        return client;
}



static prelude_msg_t *send_msgbuf(prelude_msgbuf_t *msgbuf)
{
        prelude_msg_t *msg = prelude_msgbuf_get_msg(msgbuf);

        pthread_mutex_lock(&receiver_managers_lock);
        prelude_client_mgr_broadcast(receiver_managers, msg);
        pthread_mutex_unlock(&receiver_managers_lock);
        
        prelude_msg_recycle(msg);
        
        return msg;
}



void reverse_relay_send_msg(idmef_message_t *idmef) 
{
        static prelude_msgbuf_t *msgbuf = NULL;
        
        if ( ! receiver_managers )
                return;

        if ( ! msgbuf ) {
                msgbuf = prelude_msgbuf_new(0);
                if ( ! msgbuf )
                        return;
                
                prelude_msgbuf_set_callback(msgbuf, send_msgbuf);
        }
        
        idmef_write_message(msgbuf, idmef);
        prelude_msgbuf_mark_end(msgbuf);
}



int reverse_relay_create_initiator(const char *arg)
{
        initiator_managers = prelude_client_mgr_new(PRELUDE_CLIENT_TYPE_MANAGER_RECEIVER, arg);
        if ( ! initiator_managers )
                return -1;

        return 0;
}



int reverse_relay_init_initiator(void)
{
        if ( ! initiator_managers )
                return -1;
        
        prelude_client_mgr_notify_connection(initiator_managers, reverse_relay_notify_state);
        reverse_relay_notify_state(prelude_client_mgr_get_client_list(initiator_managers));

        return 0;
}
