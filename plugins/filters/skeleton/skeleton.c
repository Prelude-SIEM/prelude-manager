/*****
*
* Copyright (C) 2002-2020 CS GROUP - France. All Rights Reserved.
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
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
*****/

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include <libprelude/list.h>
#include <libprelude/idmef-tree.h>

#include "report.h"

#include "plugin-filter.h"
#include "idmef-util.h"


static plugin_filter_t plugin;

static int tbl_index = 0;
static filter_entry_t tbl[256];
static void *filter_rule = NULL;



static int process_message(const idmef_message_t *msg, void *priv) 
{
        log(LOG_INFO, "filter running with rule at %s\n", priv);

        if ( priv )
                return -1;
        else
                return 0;
}



static void add_category(plugin_generic_t *filtered_plugin, filter_category_t cat) 
{
        assert(tbl_index + 1 < sizeof(tbl) / sizeof(filter_entry_t));
        
        tbl[tbl_index].category = cat;
        tbl[tbl_index].plugin = filtered_plugin;
        tbl[tbl_index].private_data = filter_rule;
        tbl[++tbl_index].category = FILTER_CATEGORY_END;
        
        filter_rule = NULL;
}



static int set_skeleton_hook(prelude_option_t *opt, const char *arg) 
{
        int i, ret;
        plugin_generic_t *ptr;
        struct {
                const char *hook;
                filter_category_t cat;
        } tbl[] = {
                { "database", FILTER_CATEGORY_DATABASE   },
                { "reporting", FILTER_CATEGORY_REPORTING },
                { "relaying", FILTER_CATEGORY_RELAYING   },
                { NULL, 0                                },
        };

        for ( i = 0; tbl[i].hook != NULL; i++ ) {
                ret = strcasecmp(arg, tbl[i].hook);
                if ( ret == 0 ) {
                        add_category(NULL, tbl[i].cat);
                        return prelude_option_success;
                }
        }

        /*
         * not a known category, the user may want to filter a
         * specific plugin.
         */

        ptr = plugin_search_by_name(arg);
        if ( ! ptr ) {
                log(LOG_ERR, "category '%s' doesn't exist, or a plugin of that name is not loaded.\n", arg);
                return prelude_option_error;
        }

        add_category(ptr, FILTER_CATEGORY_PLUGIN);
        
        return prelude_option_success;
}




static int set_skeleton_rule(prelude_option_t *opt, const char *arg) 
{
        filter_rule = strdup(arg);
        return prelude_option_success;
}




static int enable_skeleton(prelude_option_t *opt, const char *arg) 
{
        if ( ! tbl_index )
                return prelude_option_success;

        filter_rule = NULL;
        plugin.category = tbl;
        tbl_index = 0;
        
        return plugin_subscribe((plugin_generic_t *) &plugin);
}




plugin_generic_t *plugin_init(int argc, char **argv)
{
        prelude_option_t *opt;
        
        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 0, "skeleton",
                                 "Option for the skeleton plugin", no_argument,
                                 enable_skeleton, NULL);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'r', "rule",
                                 "Filtering rule", required_argument,
                                 set_skeleton_rule, NULL);
        
        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'h', "hook",
                           "Where the filter should be hooked (reporting|database|relaying|plugin name)",
                           required_argument, set_skeleton_hook, NULL);
        
        plugin_set_name(&plugin, "Skeleton");
        plugin_set_author(&plugin, "Prelude Team");
        plugin_set_contact(&plugin, "support.prelude@csgroup.eu");
        plugin_set_desc(&plugin, "Write alert to a file, or to stderr if requested");
	plugin_set_running_func(&plugin, process_message);
                
	return (plugin_generic_t *) &plugin;
}

