/*****
*
* Copyright (C) 1998-2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

#include <libprelude/list.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/prelude-log.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>

#include "plugin-report.h"
#include "plugin-filter.h"


static LIST_HEAD(report_plugins_list);


/*
 *
 */
static int subscribe(plugin_container_t *pc) 
{
        log(LOG_INFO, "- Subscribing %s to active reporting plugins.\n", pc->plugin->name);
        return plugin_add(pc, &report_plugins_list, NULL);
}


static void unsubscribe(plugin_container_t *pc) 
{
        log(LOG_INFO, "- Un-subscribing %s from active reporting plugins.\n", pc->plugin->name);
        plugin_del(pc);
}




/*
 * Start all plugins of kind 'list'.
 */
void report_plugins_run(idmef_message_t *msg)
{
        int ret;
        struct list_head *tmp;
        plugin_container_t *pc;

        ret = filter_plugins_run_by_category(msg, FILTER_CATEGORY_REPORTING);
        if ( ret < 0 ) {
                log(LOG_INFO, "reporting filtered.\n");
                return;
        }
        
        list_for_each(tmp, &report_plugins_list) {
                pc = list_entry(tmp, plugin_container_t, ext_list);

                ret = filter_plugins_run_by_plugin(msg, pc->plugin);
                if ( ret < 0 ) {
                        log(LOG_INFO, "reporting filtered for %s.\n", pc->plugin->name);
                        continue;
                }
                
                plugin_run(pc, plugin_report_t, run, msg);
        }
}




/*
 * Close all report plugins.
 */
void report_plugins_close(void)
{
        struct list_head *tmp;
        plugin_container_t *pc;
        plugin_report_t *plugin;

        list_for_each(tmp, &report_plugins_list) {
                
                pc = list_entry(tmp, plugin_container_t, ext_list);

                plugin = (plugin_report_t *) pc->plugin;
                if ( plugin_close_func(plugin) )
                        plugin_close_func(plugin)();
        }
}



/*
 * Open the plugin directory (dirname),
 * and try to load all plugins located in it.
 */
int report_plugins_init(const char *dirname, int argc, char **argv)
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




/**
 * report_plugins_available:
 *
 * Returns: 0 if there is active REPORT plugins, -1 otherwise.
 */
int report_plugins_available(void) 
{
        return list_empty(&report_plugins_list) ? -1 : 0;
}






