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

#include <libprelude/idmef-tree.h>
#include <libprelude/prelude-list.h>
#include <libprelude/prelude-linked-object.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-getopt.h>

#include "plugin-report.h"
#include "plugin-filter.h"


static PRELUDE_LIST_HEAD(report_plugins_instance);


/*
 *
 */
static int subscribe(prelude_plugin_instance_t *pi) 
{
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);
        
        log(LOG_INFO, "- Subscribing %s[%s] to active reporting plugins.\n",
            plugin->name, prelude_plugin_instance_get_name(pi));

        return prelude_plugin_add(pi, &report_plugins_instance, NULL);
}


static void unsubscribe(prelude_plugin_instance_t *pi) 
{
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);
        
        log(LOG_INFO, "- Un-subscribing %s[%s] from active reporting plugins.\n",
            plugin->name, prelude_plugin_instance_get_name(pi));

        prelude_plugin_del(pi);
}




/*
 * Start all plugins of kind 'list'.
 */
void report_plugins_run(idmef_message_t *msg)
{
        int ret;
        prelude_list_t *tmp;
        prelude_plugin_generic_t *pg;
        prelude_plugin_instance_t *pi;

        ret = filter_plugins_run_by_category(msg, FILTER_CATEGORY_REPORTING);
        if ( ret < 0 ) {
                log(LOG_INFO, "reporting filtered.\n");
                return;
        }
        
        prelude_list_for_each(tmp, &report_plugins_instance) {
                pi = prelude_linked_object_get_object(tmp, prelude_plugin_instance_t);
                pg = prelude_plugin_instance_get_plugin(pi);
                
                ret = filter_plugins_run_by_plugin(msg, pi);
                if ( ret < 0 ) {
                        log(LOG_INFO, "reporting filtered for %s.\n", pg->name);
                        continue;
                }
                
                prelude_plugin_run(pi, plugin_report_t, run, pi, msg);
        }
}




/*
 * Close all report plugins.
 */
void report_plugins_close(void)
{
        prelude_list_t *tmp;
        plugin_report_t *plugin;
        prelude_plugin_instance_t *pi;

        
        prelude_list_for_each(tmp, &report_plugins_instance) {
                pi = prelude_linked_object_get_object(tmp, prelude_plugin_instance_t);
                
                plugin = (plugin_report_t *) prelude_plugin_instance_get_plugin(pi);
                
                if ( plugin->close )
                        plugin->close(pi);
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




/**
 * report_plugins_available:
 *
 * Returns: 0 if there is active REPORT plugins, -1 otherwise.
 */
int report_plugins_available(void) 
{
        return prelude_list_empty(&report_plugins_instance) ? -1 : 0;
}






