/*****
*
* Copyright (C) 2002 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/time.h>
#include <inttypes.h>
#include <assert.h>

#include <libprelude/list.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/prelude-log.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>

#include "plugin-filter.h"


typedef struct {
        struct list_head list;
        
        void *private_data;
        plugin_container_t *filter;
        plugin_generic_t *filtered_plugin;

} filter_plugin_entry_t;



static struct list_head filter_category_list[FILTER_CATEGORY_END];



static int add_filter_entry(plugin_container_t *filter, filter_category_t cat, plugin_generic_t *filtered_plugin, void *data) 
{
        filter_plugin_entry_t *new;

        new = malloc(sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        new->filter = filter;
        new->private_data = data;
        new->filtered_plugin = filtered_plugin;
        
        list_add_tail(&new->list, &filter_category_list[cat]);

        if ( filtered_plugin )
                log(LOG_INFO, "- Subscribing %s to filtering plugins with plugin hook %s.\n",
                    filter->plugin->name, filtered_plugin->name);
        else
                log(LOG_INFO, "- Subscribing %s to filtering plugins with category hook %d.\n",
                    filter->plugin->name, cat);
        
        return 0;
}




/*
 *
 */
static int subscribe(plugin_container_t *pc) 
{
        filter_entry_t *entry;
        plugin_filter_t *filter = (plugin_filter_t *) pc->plugin;

        for ( entry = filter->category; entry->category != FILTER_CATEGORY_END; entry++ ) {
                
                if ( entry->plugin )
                        add_filter_entry(pc, FILTER_CATEGORY_PLUGIN, entry->plugin, entry->private_data);
                else
                        add_filter_entry(pc, entry->category, NULL, entry->private_data);
        }

        return 0;
}


static void unsubscribe(plugin_container_t *pc) 
{
        log(LOG_INFO, "- Un-subscribing %s from active reporting plugins.\n", pc->plugin->name);
        plugin_del(pc);
}




int filter_plugins_run_by_category(const idmef_message_t *msg, filter_category_t cat) 
{
        int ret;
        struct list_head *tmp;
        filter_plugin_entry_t *entry;
        
        list_for_each(tmp, &filter_category_list[cat]) {
                entry = list_entry(tmp, filter_plugin_entry_t, list);
                
                plugin_run_with_return_value(entry->filter, plugin_filter_t, run, ret, msg, entry->private_data);
                if ( ret < 0 )
                        return -1;
        }

        return 0;
}




int filter_plugins_run_by_plugin(const idmef_message_t *msg, plugin_generic_t *plugin) 
{
        int ret;
        struct list_head *tmp;
        filter_plugin_entry_t *entry;
        
        list_for_each(tmp, &filter_category_list[FILTER_CATEGORY_PLUGIN]) {
                
                entry = list_entry(tmp, filter_plugin_entry_t, list);

                if ( entry->filtered_plugin != plugin )
                        continue;
                
                plugin_run_with_return_value(entry->filter, plugin_filter_t, run, ret, msg, entry->private_data);
                if ( ret < 0 )
                        return -1;
        }

        return 0;
}




/*
 * Open the plugin directory (dirname),
 * and try to load all plugins located in it.
 */
int filter_plugins_init(const char *dirname, int argc, char **argv)
{
        int ret, i;
        
        for (i = 0; i < FILTER_CATEGORY_END; i++ )
                INIT_LIST_HEAD(&filter_category_list[i]);
        
	ret = access(dirname, F_OK);        
        if ( ret < 0 ) {
		if ( errno == ENOENT )
			return 0;

                log(LOG_ERR, "can't access %s.\n", dirname);
		return -1;
	}
        
        ret = plugin_load_from_dir(dirname, argc, argv, subscribe, unsubscribe);

        /*
         * don't return an error if the report directory doesn't exist.
         * this could happen as it's normal to not use report plugins on
         * certain system.
         */
        if ( ret < 0 && errno != ENOENT ) {
                log(LOG_ERR, "couldn't load plugin subsystem.\n");
                return -1;
        }
        
        return ret;
}




int filter_plugins_available(filter_category_t cat) 
{
        return list_empty(&filter_category_list[cat]) ? -1 : 0;
}

