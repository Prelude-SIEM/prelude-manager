#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>
#include <inttypes.h>

#include <libprelude/prelude-log.h>
#include <libprelude/prelude-list.h>
#include <libprelude/prelude-linked-object.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-client.h>
#include <libprelude/prelude-client-mgr.h>
#include <libprelude/prelude-async.h>

#include "relaying.h"


/*
 * parent manager: manager we forward alerts to
 * child  manager: manager we receive alerts from
 *
 * parent manager are added to the parent_managers list throught
 * the prelude-client-mgr API. In this context, we are a client of
 * a "parent manager".
 *
 * child relay are added to the child_managers list. 
 */


static prelude_client_mgr_t *child_managers = NULL;
static pthread_mutex_t child_managers_lock = PTHREAD_MUTEX_INITIALIZER;

static prelude_client_mgr_t *parent_managers = NULL;
static pthread_mutex_t parent_managers_lock = PTHREAD_MUTEX_INITIALIZER;



int manager_parent_tell_alive(prelude_client_t *client) 
{
        int ret;

        if ( ! parent_managers )
                return 0;
        
        pthread_mutex_lock(&parent_managers_lock);
        ret = prelude_client_mgr_tell_client_alive(parent_managers, client);
        pthread_mutex_unlock(&parent_managers_lock);

        return ret;
}




int manager_parent_tell_dead(prelude_client_t *client) 
{
        int ret;

        if ( ! parent_managers )
                return 0;
        
        pthread_mutex_lock(&parent_managers_lock);
        ret = prelude_client_mgr_tell_client_dead(parent_managers, client);
        pthread_mutex_unlock(&parent_managers_lock);

        return ret;
}




int manager_children_tell_dead(prelude_client_t *client) 
{
        int ret;

        if ( ! child_managers )
                return 0;
        
        pthread_mutex_lock(&child_managers_lock);
        ret = prelude_client_mgr_tell_client_dead(child_managers, client);
        pthread_mutex_unlock(&child_managers_lock);

        return ret;
}




int manager_parent_add_client(prelude_client_t *client) 
{
        int ret;
        
        pthread_mutex_lock(&parent_managers_lock);
        ret = prelude_client_mgr_add_client(&parent_managers, client, 0);
        pthread_mutex_unlock(&parent_managers_lock);

        return ret;
}




prelude_client_t *manager_parent_search_client(const char *addr, int type) 
{
        prelude_client_t *client;

        pthread_mutex_lock(&parent_managers_lock);
        client = prelude_client_mgr_search_client(parent_managers, addr, type);
        pthread_mutex_unlock(&parent_managers_lock);

        return client;
}



void manager_relay_msg_if_needed(prelude_msg_t *msg) 
{
        if ( ! parent_managers )
                return;
        
        pthread_mutex_lock(&parent_managers_lock);
        prelude_client_mgr_broadcast(parent_managers, msg);
        pthread_mutex_unlock(&parent_managers_lock);
}




int manager_children_setup_from_cfgline(const char *cfgline) 
{
        /*
         * Declare our client as parent of the remote child manager.
         */
        pthread_mutex_lock(&child_managers_lock);
        child_managers = prelude_client_mgr_new(PRELUDE_CLIENT_TYPE_MANAGER_PARENT, cfgline);
        pthread_mutex_unlock(&child_managers_lock);
        
        if ( ! child_managers )
                return -1;
        
        return 0;
}




int manager_parent_setup_from_cfgline(const char *cfgline)
{
        /*
         * Declare our client as children of the remote parent manager.
         */
        pthread_mutex_lock(&parent_managers_lock);
        parent_managers = prelude_client_mgr_new(PRELUDE_CLIENT_TYPE_MANAGER_CHILDREN, cfgline);
        pthread_mutex_unlock(&parent_managers_lock);
                
        if ( ! parent_managers )
                return -1;

        return 0;
}


#include "server-generic.h"
extern server_generic_t *sensor_server;

static void notify(prelude_list_t *clist) 
{
        int ret;
        prelude_list_t *tmp;
        prelude_client_t *client;
        
        prelude_list_for_each(tmp, clist) {
                client = prelude_linked_object_get_object(tmp, prelude_client_t);

                if ( prelude_client_is_alive(client) < 0 ) 
                        continue;
                
                ret = server_generic_add_client(sensor_server, client);
                if ( ret < 0 ) {
                        log(LOG_ERR, "error adding new client to reverse relay list.\n");
                        return;
                }
        }
}


void manager_relay_init(void) 
{
        if ( child_managers || parent_managers )
                prelude_async_init();
        
        if ( ! child_managers )
                return;
        
        notify(prelude_client_mgr_get_client_list(child_managers));
        prelude_client_mgr_notify_connection(child_managers, notify);
}


