/*****
*
* Copyright (C) 2001, 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <unistd.h>
#include <sys/time.h>
#include <inttypes.h>

#include <libprelude/prelude-log.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>

#include "plugin-decode.h"


static LIST_HEAD(decode_plugins_list);
static LIST_HEAD(used_decode_plugins);


/*
 *
 */
static int subscribe(plugin_container_t *pc) 
{
        log(LOG_INFO, "- Subscribing %s to active decoding plugins.\n", pc->plugin->name);
        return plugin_add(pc, &decode_plugins_list, NULL);
}


static void unsubscribe(plugin_container_t *pc) 
{
        log(LOG_INFO, "- Un-subscribing %s from active decoding plugins.\n", pc->plugin->name);
        plugin_del(pc);
}



/*
 *
 */
int decode_plugins_run(uint8_t plugin_id, prelude_msg_t *msg, idmef_message_t *idmef) 
{
        int ret;
        plugin_decode_t *p;
        struct list_head *tmp;
        plugin_container_t *pc;
        
        list_for_each(tmp, &decode_plugins_list) {
            
                pc = list_entry(tmp, plugin_container_t, ext_list);

                p = (plugin_decode_t *) pc->plugin;
                if ( p->decode_id != plugin_id )
                        continue;

                plugin_run_with_return_value(pc, plugin_decode_t, run, ret, msg, idmef);
                if ( ret < 0 ) {
                        log(LOG_ERR, "%s couldn't decode sensor data.\n", p->name);
                        return -1;
                }

                /*
                 * put the used plugin into the used_decode_plugins list, so
                 * that we know which plugin may have data to release.
                 */
                list_del(&pc->ext_list);
                list_add(&pc->ext_list, &used_decode_plugins);
                
                return 0;
        }
        
        log(LOG_ERR, "No decode plugin for handling sensor id %d.\n", plugin_id);
        
        return -1;
}




void decode_plugins_free_data(void) 
{
        plugin_decode_t *p;
        struct list_head *tmp;
        plugin_container_t *pc;

        for ( tmp = used_decode_plugins.next; tmp != &used_decode_plugins; ) {
            
                pc = list_entry(tmp, plugin_container_t, ext_list);
                p = (plugin_decode_t *) pc->plugin;

                plugin_run(pc, plugin_decode_t, free);

                tmp = tmp->next;

                /*
                 * put back the plugin in the main plugins list.
                 */
                list_del(&pc->ext_list);
                list_add(&pc->ext_list, &decode_plugins_list);
        }
}



/*
 *
 */
int decode_plugins_init(const char *dirname, int argc, char **argv) 
{
        int ret;

	ret = access(dirname, F_OK);
	if ( ret < 0 ) {
		if ( errno == ENOENT )
			return 0;
		log(LOG_ERR, "can't access %s.\n", dirname);
		return -1;
	}

        ret = plugin_load_from_dir(dirname, argc, argv, subscribe, unsubscribe);
        if ( ret < 0 )
                log(LOG_ERR, "couldn't load plugin subsystem.\n");
        
        return ret;
}


