/*****
*
* Copyright (C) 1998 - 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/time.h>
#include <inttypes.h>

#include <libprelude/list.h>
#include <libprelude/common.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>

#include "plugin-report.h"


static LIST_HEAD(report_plugins_list);


/*
 *
 */
static int report_plugin_register(plugin_container_t *pc) 
{
        log(LOG_INFO, "\tInitialized %s.\n", pc->plugin->name);

        return plugin_register_for_use(pc, &report_plugins_list, NULL);
}



/*
 * Start all plugins of kind 'list'.
 */
void report_plugins_run(idmef_alert_t *alert)
{
        struct list_head *tmp;
        plugin_container_t *pc;

        list_for_each(tmp, &report_plugins_list) {
                pc = list_entry(tmp, plugin_container_t, ext_list);
                plugin_run(pc, plugin_report_t, run, alert);
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
int report_plugins_init(const char *dirname) {
        int ret;
        
        ret = plugin_load_from_dir(dirname, report_plugin_register);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't load plugin subsystem.\n");
                return -1;
        }
        
        return 0;
}











