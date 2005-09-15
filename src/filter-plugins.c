/*****
*
* Copyright (C) 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/time.h>
#include <assert.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>

#include "prelude-manager.h"
#include "filter-plugins.h"


#define MANAGER_PLUGIN_SYMBOL "manager_plugin_init"


struct manager_filter_hook {
        prelude_list_t list;

        void *data;
        prelude_plugin_instance_t *filter;
        prelude_plugin_instance_t *filtered_plugin;
        
};


static prelude_list_t filter_category_list[MANAGER_FILTER_CATEGORY_END];



static int add_filter_entry(manager_filter_hook_t **entry,
                            prelude_plugin_instance_t *filter, manager_filter_category_t cat,
                            prelude_plugin_instance_t *filtered_plugin_instance, void *data) 
{
        manager_filter_hook_t *new;
        prelude_plugin_generic_t *plugin, *filtered_plugin;
        
        new = malloc(sizeof(*new));
        if ( ! new ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        new->data = data;
        new->filter = filter;
        new->filtered_plugin = filtered_plugin_instance;

        prelude_list_add_tail(&filter_category_list[cat], &new->list);

        plugin = prelude_plugin_instance_get_plugin(filter);
        
        if ( filtered_plugin_instance ) {
                filtered_plugin = prelude_plugin_instance_get_plugin(filtered_plugin_instance);
                prelude_log(PRELUDE_LOG_WARN, "- Subscribing %s to filtering plugin with plugin hook %s[%s].\n",
                            plugin->name, filtered_plugin->name, prelude_plugin_instance_get_name(filtered_plugin_instance));
        } else
                prelude_log(PRELUDE_LOG_WARN, "- Subscribing %s to filtering plugin with category hook %d.\n",
                            plugin->name, cat);

        *entry = new;
        
        return 0;
}



static void unsubscribe(prelude_plugin_instance_t *pi) 
{
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);       
        prelude_log(PRELUDE_LOG_WARN, "- Un-subscribing %s from active reporting plugins.\n", plugin->name);
}



void manager_filter_destroy_hook(manager_filter_hook_t *entry)
{
        prelude_list_del(&entry->list);
        free(entry);
}



int manager_filter_new_hook(manager_filter_hook_t **entry,
                            prelude_plugin_instance_t *pi,
                            manager_filter_category_t filtered_category,
                            prelude_plugin_instance_t *filtered_plugin, void *data)
{
        return add_filter_entry(entry, pi, filtered_category, filtered_plugin, data);
}




int filter_plugins_run_by_category(idmef_message_t *msg, manager_filter_category_t cat) 
{
        int ret;
        prelude_list_t *tmp;
        manager_filter_hook_t *entry;
        
        prelude_list_for_each(&filter_category_list[cat], tmp) {
                entry = prelude_list_entry(tmp, manager_filter_hook_t, list);
                
                ret = prelude_plugin_run(entry->filter, manager_filter_plugin_t, run, msg, entry->data);
                if ( ret < 0 )
                        return -1;
        }
        
        return 0;
}




int filter_plugins_run_by_plugin(idmef_message_t *msg, prelude_plugin_instance_t *plugin) 
{
        int ret;
        prelude_list_t *tmp;
        manager_filter_hook_t *entry;
        
        prelude_list_for_each(&filter_category_list[MANAGER_FILTER_CATEGORY_PLUGIN], tmp) {
                
                entry = prelude_list_entry(tmp, manager_filter_hook_t, list);

                if ( entry->filtered_plugin != plugin )
                        continue;
                
                ret = prelude_plugin_run(entry->filter, manager_filter_plugin_t, run, msg, entry->data);
                if ( ret < 0 )
                        return -1;
        }

        return 0;
}




/*
 * Open the plugin directory (dirname),
 * and try to load all plugins located in it.
 */
int filter_plugins_init(const char *dirname, void *data)
{
        int ret, i;
        
        for (i = 0; i < MANAGER_FILTER_CATEGORY_END; i++ )
                prelude_list_init(&filter_category_list[i]);
        
	ret = access(dirname, F_OK);        
        if ( ret < 0 ) {
		if ( errno == ENOENT )
			return 0;

                prelude_log(PRELUDE_LOG_ERR, "can't access %s.\n", dirname);
		return -1;
	}
        
        ret = prelude_plugin_load_from_dir(NULL, dirname, MANAGER_PLUGIN_SYMBOL, data, NULL, unsubscribe);

        /*
         * don't return an error if the report directory doesn't exist.
         * this could happen as it's normal to not use report plugins on
         * certain system.
         */
        if ( ret < 0 && errno != ENOENT ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't load plugin subsystem.\n");
                return -1;
        }
        
        return ret;
}




prelude_bool_t filter_plugins_available(manager_filter_category_t cat) 
{
        return prelude_list_is_empty(&filter_category_list[cat]);
}

