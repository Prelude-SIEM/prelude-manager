/*****
*
* Copyright (C) 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <libprelude/prelude-log.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>

#include "plugin-filter.h"


static struct list_head filter_plugins_list[FILTER_CATEGORY_END];


/*
 *
 */
static int subscribe(plugin_container_t *pc) 
{
        filter_category_t *cat;
        plugin_filter_t *filter = (plugin_filter_t *) pc->plugin;

        for ( cat = filter->category; *cat != FILTER_CATEGORY_END; cat++ ) {

                assert(*cat < FILTER_CATEGORY_END);
                
                log(LOG_INFO, "- Subscribing %s to filtering plugins with hook %d.\n", filter->name, *cat);
                plugin_add(pc, &filter_plugins_list[*cat], NULL);
        }

        return 0;
}


static void unsubscribe(plugin_container_t *pc) 
{
        log(LOG_INFO, "- Un-subscribing %s from active reporting plugins.\n", pc->plugin->name);
        plugin_del(pc);
}



int filter_plugins_run(const idmef_message_t *msg, filter_category_t cat) 
{
        int ret;
        struct list_head *tmp;
        plugin_container_t *pc;

        if ( cat > FILTER_CATEGORY_END )
                ;
        
                
        list_for_each(tmp, &filter_plugins_list[cat]) {
                pc = list_entry(tmp, plugin_container_t, ext_list);
                
                plugin_run_with_return_value(pc, plugin_filter_t, run, ret, msg);
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
                INIT_LIST_HEAD(&filter_plugins_list[i]);
        
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




