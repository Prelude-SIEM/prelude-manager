/*****
*
* Copyright (C) 2001, 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

#include "config.h"

#include <stdio.h>
#include <unistd.h>
#include <errno.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>

#include "prelude-manager.h"
#include "decode-plugins.h"


#define MANAGER_PLUGIN_SYMBOL "manager_plugin_init"


static PRELUDE_LIST(decode_plugins_instance);


/*
 *
 */
static int subscribe(prelude_plugin_instance_t *pi) 
{
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);

        prelude_log(PRELUDE_LOG_INFO, "- Subscribing %s to active decoding plugins.\n", plugin->name);

        return prelude_plugin_instance_add(pi, &decode_plugins_instance);
}


static void unsubscribe(prelude_plugin_instance_t *pi) 
{        
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);

        prelude_log(PRELUDE_LOG_INFO, "- Un-subscribing %s from active decoding plugins.\n", plugin->name);

        prelude_plugin_instance_del(pi);
}



/*
 *
 */
int decode_plugins_run(unsigned int plugin_id, prelude_msg_t *msg, idmef_message_t *idmef) 
{
        int ret;
        manager_decode_plugin_t *p;
        prelude_list_t *tmp;
        prelude_plugin_instance_t *pi;
        
        prelude_list_for_each(&decode_plugins_instance, tmp) {

                pi = prelude_linked_object_get_object(tmp);
                                
                p = (manager_decode_plugin_t *) prelude_plugin_instance_get_plugin(pi);
                if ( p->decode_id != plugin_id )
                        continue;

                ret = prelude_plugin_run(pi, manager_decode_plugin_t, run, msg, idmef);
                if ( ret < 0 ) {
                        prelude_log(PRELUDE_LOG_WARN, "%s couldn't decode sensor data.\n", p->name);
                        return -1;
                }
                
                return 0;
        }
        
        prelude_log(PRELUDE_LOG_WARN, "No decode plugin for handling sensor id %u.\n", plugin_id);
        
        return -1;
}




/*
 *
 */
int decode_plugins_init(const char *dirname, void *data) 
{
        int ret;

	ret = access(dirname, F_OK);
	if ( ret < 0 ) {
		if ( errno == ENOENT )
			return 0;
                
		prelude_log(PRELUDE_LOG_ERR, "can't access %s.\n", dirname);
		return -1;
	}

        ret = prelude_plugin_load_from_dir(NULL, dirname, MANAGER_PLUGIN_SYMBOL, data, subscribe, unsubscribe);
        if ( ret < 0 )
                prelude_log(PRELUDE_LOG_WARN, "couldn't load plugin subsystem.\n");
        
        return ret;
}








