/*****
*
* Copyright (C) 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
* Copyright (C) 2003 Krzysztof Zaraska  <kzaraska@student.uci.agh.edu.pl>
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

/* Adapted Yoann's reference filtering plugin code (skeleton.c) */

#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include <libprelude/list.h>
#include <libprelude/idmef.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>

#include "report.h"

#include "plugin-filter.h"


static plugin_filter_t plugin;

static int tbl_index = 0;
static filter_entry_t tbl[256];
static idmef_criterion_t *filter_rule = NULL;



static int process_message(const idmef_message_t *msg, void *priv) 
{
	int ret;
	
	ret = idmef_criterion_match(msg, (idmef_criterion_t *) priv);
	if ( ret < 0 ) {
		log(LOG_ERR, "criteria matching error: assuming positive match\n");
		ret = 1;
	}

        return ( ret > 0 ) ? 0 : -1;
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



static int set_filter_hook(prelude_option_t *opt, const char *arg) 
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




static int set_filter_rule(prelude_option_t *opt, const char *arg) 
{
        filter_rule = idmef_criterion_new_string(arg);
        return filter_rule ? prelude_option_success : prelude_option_error ;
}




static int enable_filter(prelude_option_t *opt, const char *arg) 
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
        
        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 0, "filter",
                                 "Option for the filter plugin", no_argument,
                                 enable_filter, NULL);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'r', "rule",
                                 "Filtering rule", required_argument,
                                 set_filter_rule, NULL);
        
        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'h', "hook",
                           "Where the filter should be hooked (reporting|database|relaying|plugin name)",
                           required_argument, set_filter_hook, NULL);
        
        plugin_set_name(&plugin, "Filter");
        plugin_set_author(&plugin, "Krzysztof Zaraska");
        plugin_set_contact(&plugin, "kzaraska@student.uci.agh.edu.pl");
        plugin_set_desc(&plugin, "Match alert against IDMEF criteria");
	plugin_set_running_func(&plugin, process_message);
                
	return (plugin_generic_t *) &plugin;
}

