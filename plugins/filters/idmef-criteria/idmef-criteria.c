/*****
*
* Copyright (C) 2002-2005 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <stdarg.h>
#include <assert.h>

#include "prelude-manager.h"


int idmef_criteria_LTX_manager_plugin_init(prelude_plugin_generic_t **plugin, void *data);


static manager_filter_plugin_t filter_plugin;


typedef struct {
        idmef_criteria_t *criteria;
        prelude_plugin_instance_t *pi;
} filter_plugin_t;



static int process_message(idmef_message_t *msg, void *priv) 
{
	filter_plugin_t *plugin = priv;
        
        if ( ! plugin->criteria )
                return 0;
        
	return idmef_criteria_match(plugin->criteria, msg);
}



static int set_filter_hook(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context) 
{
        int i, ret;
        filter_plugin_t *plugin;
        char pname[256], iname[256];
        prelude_plugin_instance_t *ptr;
        struct {
                const char *hook;
                manager_filter_category_t cat;
        } tbl[] = {
                { "reporting",         MANAGER_FILTER_CATEGORY_REPORTING        },
                { "reverse-relaying",  MANAGER_FILTER_CATEGORY_REVERSE_RELAYING },
                { NULL,                0                                },
        };

        plugin = prelude_plugin_instance_get_data(context);
        
        for ( i = 0; tbl[i].hook != NULL; i++ ) {
                ret = strcasecmp(optarg, tbl[i].hook);
                if ( ret == 0 ) {
                        manager_filter_plugins_add_filter(context, tbl[i].cat, NULL, plugin);
                        return 0;
                }
        }

        ret = sscanf(optarg, "%255[^[][%255[^]]", pname, iname);
        if ( ret == 0 ) {
                prelude_string_sprintf(err, "error parsing value: '%s'", optarg);
                return -1;
        }
        
        ptr = prelude_plugin_search_instance_by_name(pname, (ret == 2) ? iname : NULL);
        if ( ! ptr ) {
                prelude_string_sprintf(err, "Unknown hook '%s'", optarg);
                return -1;
        }

        manager_filter_plugins_add_filter(context, MANAGER_FILTER_CATEGORY_PLUGIN, ptr, plugin);
        
        return 0;
}




static int set_filter_rule(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context) 
{
	int ret;
        idmef_criteria_t *new;
        filter_plugin_t *plugin = prelude_plugin_instance_get_data(context);

        ret = idmef_criteria_new_from_string(&new, optarg);
        if ( ret < 0 ) 
                return ret;
        
        if ( ! plugin->criteria )
                plugin->criteria = new;
        else
                idmef_criteria_or_criteria(plugin->criteria, new);
        
        return 0;
}




static int get_filter_rule(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        filter_plugin_t *plugin = prelude_plugin_instance_get_data(context);       
        return idmef_criteria_to_string(plugin->criteria, out);
}




static int filter_activate(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context) 
{
        filter_plugin_t *new;
        
        new = malloc(sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);
        
        new->criteria = NULL;
        prelude_plugin_instance_set_data(context, new);
        
        return 0;
}




int idmef_criteria_LTX_manager_plugin_init(prelude_plugin_generic_t **plugin, void *root_opt)
{
        int ret;
        prelude_option_t *opt;
        
        ret = prelude_option_add(root_opt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG
                                 |PRELUDE_OPTION_TYPE_WIDE, 0, "idmef-criteria-filter",
                                 "Filter message based on IDMEF criteria", PRELUDE_OPTION_ARGUMENT_OPTIONAL,
                                 filter_activate, NULL);
        if ( ret < 0 )
                return ret;
        
        prelude_plugin_set_activation_option((void *) &filter_plugin, opt, NULL);
        
        ret = prelude_option_add(opt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG
                                 |PRELUDE_OPTION_TYPE_WIDE, 'r', "rule",
                                 "Filtering rule", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                                 set_filter_rule, get_filter_rule);
        if ( ret < 0 )
                return ret;
        
        ret = prelude_option_add(opt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG
                                 |PRELUDE_OPTION_TYPE_WIDE, 'h', "hook",
                                 "Where the filter should be hooked (reporting|reverse-relaying|plugin name)",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, set_filter_hook, NULL);
        if ( ret < 0 )
                return ret;
        
        prelude_plugin_set_name(&filter_plugin, "Filter");
        prelude_plugin_set_author(&filter_plugin, "Yoann Vandoorselaere");
        prelude_plugin_set_contact(&filter_plugin, "yoann@prelude-ids.org");
        prelude_plugin_set_desc(&filter_plugin, "Match alert against IDMEF criteria");

        manager_filter_plugin_set_running_func(&filter_plugin, process_message);

        *plugin = (void *) &filter_plugin;

        return 0;
}

