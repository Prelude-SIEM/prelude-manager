/*****
*
* Copyright (C) 2002-2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>

#include "plugin-filter.h"


typedef struct {
        struct list_head list;

        void *data;
        prelude_plugin_instance_t *filter;
        prelude_plugin_instance_t *filtered_plugin;
        
} filter_plugin_entry_t;



static struct list_head filter_category_list[FILTER_CATEGORY_END];



static filter_plugin_entry_t *new_filter_entry(prelude_plugin_instance_t *filter,
                                               prelude_plugin_instance_t *plugin, void *data) 
{
        filter_plugin_entry_t *new;
        
        new = malloc(sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->data = data;
        new->filter = filter;
        new->filtered_plugin = plugin;
        
        return new;
}




/*
 *
 */
static int subscribe(prelude_plugin_instance_t *pi) 
{
        return 0;
}


static void unsubscribe(prelude_plugin_instance_t *pi) 
{
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);
        
        log(LOG_INFO, "- Un-subscribing %s from active reporting plugins.\n", plugin->name);
        prelude_plugin_del(pi);
}



int filter_plugins_add_plugin(prelude_plugin_instance_t *filter,
                              prelude_plugin_instance_t *plugin, void *data)
{
        filter_plugin_entry_t *new;
        prelude_plugin_generic_t *pf, *pp;

        new = new_filter_entry(filter, plugin, data);
        if ( ! new )
                return -1;
        
        pf = prelude_plugin_instance_get_plugin(filter);
        pp = prelude_plugin_instance_get_plugin(plugin);

        log(LOG_INFO, "- Subscribing %s[%s] to filtering plugin with plugin hook %s[%s].\n",
            pf->name, prelude_plugin_instance_get_name(filter),
            pp->name, prelude_plugin_instance_get_name(plugin));
        
        list_add_tail(&new->list, &filter_category_list[FILTER_CATEGORY_PLUGIN]);
        
        return 0;
}



int filter_plugins_add_category(prelude_plugin_instance_t *filter, filter_category_t cat, void *data)
{
        filter_plugin_entry_t *new;
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(filter);

        new = new_filter_entry(filter, NULL, data);
        if ( ! new )
                return -1;
        
        log(LOG_INFO, "- Subscribing %s to filtering plugin with category hook %d.\n", plugin->name, cat);

        list_add_tail(&new->list, &filter_category_list[cat]);
        
        return 0;
}



int filter_plugins_run_by_category(idmef_message_t *msg, filter_category_t cat) 
{
        int ret;
        struct list_head *tmp;
        filter_plugin_entry_t *entry;

        list_for_each(tmp, &filter_category_list[cat]) {
                entry = list_entry(tmp, filter_plugin_entry_t, list);
                
                ret = prelude_plugin_run(entry->filter, plugin_filter_t, run, msg, entry->data);
                if ( ret < 0 )
                        return -1;
        }
        
        return 0;
}




int filter_plugins_run_by_plugin(idmef_message_t *msg, prelude_plugin_instance_t *plugin) 
{
        int ret;
        struct list_head *tmp;
        filter_plugin_entry_t *entry;
        
        list_for_each(tmp, &filter_category_list[FILTER_CATEGORY_PLUGIN]) {
                
                entry = list_entry(tmp, filter_plugin_entry_t, list);

                if ( entry->filtered_plugin != plugin )
                        continue;
                
                ret = prelude_plugin_run(entry->filter, plugin_filter_t, run, msg, entry->data);
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
        
        ret = prelude_plugin_load_from_dir(dirname, subscribe, unsubscribe);

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

