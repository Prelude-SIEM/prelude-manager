/*****
*
* Copyright (C) 2002-2004 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include <libprelude/idmef.h>
#include <libprelude/prelude-log.h>
#include <libprelude/idmef-criteria.h>

#include "plugin-filter.h"


prelude_plugin_generic_t *filter_LTX_prelude_plugin_init(void);


static plugin_filter_t filter_plugin;


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



static int set_filter_hook(void *context, prelude_option_t *opt, const char *arg) 
{
        int i, ret;
        filter_plugin_t *plugin;
        char pname[256], iname[256];
        prelude_plugin_instance_t *ptr;
        struct {
                const char *hook;
                filter_category_t cat;
        } tbl[] = {
                { "reporting",         FILTER_CATEGORY_REPORTING        },
                { "reverse-relaying",  FILTER_CATEGORY_REVERSE_RELAYING },
                { NULL,                0                                },
        };

        plugin = prelude_plugin_instance_get_data(context);
        
        for ( i = 0; tbl[i].hook != NULL; i++ ) {
                ret = strcasecmp(arg, tbl[i].hook);
                if ( ret == 0 ) {
                        filter_plugins_add_category(context, tbl[i].cat, NULL, plugin);
                        return 0;
                }
        }

        ret = sscanf(arg, "%255[^[][%255[^]]", pname, iname);
        if ( ret == 0 ) {
                log(LOG_ERR, "error parsing value: '%s'.\n", arg);
                return -1;
        }
        
        ptr = prelude_plugin_search_instance_by_name(pname, (ret == 2) ? iname : NULL);
        if ( ! ptr ) {
                log(LOG_ERR, "category '%s' doesn't exist, or a plugin of that name is not loaded.\n", arg);
                return -1;
        }

        filter_plugins_add_category(context, FILTER_CATEGORY_PLUGIN, ptr, plugin);
        
        return 0;
}




static int set_filter_rule(void *context, prelude_option_t *opt, const char *arg) 
{
        idmef_criteria_t *new;
        filter_plugin_t *plugin = prelude_plugin_instance_get_data(context);

        new = idmef_criteria_new_string(arg);
        if ( ! new ) 
                return -1;
        
        if ( ! plugin->criteria )
                plugin->criteria = new;
        else
                idmef_criteria_or_criteria(plugin->criteria, new);
        
        return 0;
}




static int get_filter_rule(void *context, prelude_option_t *opt, char *buf, size_t size)
{
        int ret;
        prelude_string_t *out;
        filter_plugin_t *plugin = prelude_plugin_instance_get_data(context);

        out = prelude_string_new();
        if ( ! out )
                return -1;
        
        ret = idmef_criteria_to_string(plugin->criteria, out);
        if ( ret < 0 ) {
                prelude_string_destroy(out);
                return -1;
        }

        snprintf(buf, size, "%s", prelude_string_get_string(out));
        prelude_string_destroy(out);

        return 0;
}




static int filter_activate(void *context, prelude_option_t *opt, const char *arg) 
{
        filter_plugin_t *new;
        
        new = malloc(sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }
        
        new->criteria = NULL;
        prelude_plugin_instance_set_data(context, new);
        
        return 0;
}




prelude_plugin_generic_t *filter_LTX_prelude_plugin_init(void)
{
        prelude_option_t *opt;
        
        opt = prelude_option_add(NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG
                                 |PRELUDE_OPTION_TYPE_WIDE, 0, "filter",
                                 "Option for the filter plugin", PRELUDE_OPTION_ARGUMENT_OPTIONAL,
                                 filter_activate, NULL);

        prelude_plugin_set_activation_option((void *) &filter_plugin, opt, NULL);
        
        prelude_option_add(opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG
                           |PRELUDE_OPTION_TYPE_WIDE, 'r', "rule",
                           "Filtering rule", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_filter_rule, get_filter_rule);
        
        prelude_option_add(opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG
                           |PRELUDE_OPTION_TYPE_WIDE, 'h', "hook",
                           "Where the filter should be hooked (reporting|reverse-relaying|plugin name)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_filter_hook, NULL);
        
        prelude_plugin_set_name(&filter_plugin, "Filter");
        prelude_plugin_set_author(&filter_plugin, "Krzysztof Zaraska");
        prelude_plugin_set_contact(&filter_plugin, "kzaraska@student.uci.agh.edu.pl");
        prelude_plugin_set_desc(&filter_plugin, "Match alert against IDMEF criteria");

        filter_plugin_set_running_func(&filter_plugin, process_message);
        
	return (void *) &filter_plugin;
}

