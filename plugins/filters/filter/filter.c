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

#include <libprelude/list.h>
#include <libprelude/idmef.h>
#include <libprelude/prelude-log.h>
#include <libprelude/idmef-criteria.h>

#include "plugin-filter.h"


static plugin_filter_t filter_plugin;


typedef struct {
        void *data;
        idmef_criteria_t *criteria;
} filter_plugin_t;



static int process_message(idmef_message_t *msg, void *priv) 
{
	int ret;
	filter_plugin_t *plugin = priv;
        
        if ( ! plugin->criteria )
                return 0;
        
	ret = idmef_criteria_match(plugin->criteria, msg);
	if ( ret < 0 ) {
		log(LOG_ERR, "criteria matching error: assuming positive match\n");
		ret = 1;
	}

        return (ret > 0) ? 0 : -1;
}




static int parse_plugin_name(const char *buf, char **pname, char **iname)
{
        char *s, *e;
        
        s = strchr(buf, '[');
        if ( ! s ) {
                *pname = strdup(buf);
                if ( ! *pname ) {
                        log(LOG_ERR, "memory exhausted.\n");
                        return -1;
                }

                return 0;
        }
        
        e = strchr(buf, ']');
        if ( ! e ) {
                *s = '[';
                log(LOG_ERR, "invalid plugin instance name: %s.\n", buf);
                return -1;
        }
        
        *s = *e = 0;
        
        *pname = strdup(buf);
        *iname = strdup(s + 1);
        
        *s = '[';
        *e = ']';
        
        return 0;
}




static int set_filter_hook(void **context, prelude_option_t *opt, const char *arg) 
{
        int i, ret;
        char *pname, *iname;
        filter_plugin_t *plugin;
        prelude_plugin_instance_t *ptr;
        struct {
                const char *hook;
                filter_category_t cat;
        } tbl[] = {
                { "reporting", FILTER_CATEGORY_REPORTING },
                { "relaying", FILTER_CATEGORY_RELAYING   },
                { NULL, 0                                },
        };

        plugin = prelude_plugin_instance_get_data(*context);
        
        for ( i = 0; tbl[i].hook != NULL; i++ ) {
                ret = strcasecmp(arg, tbl[i].hook);
                if ( ret == 0 ) {
                        filter_plugins_add_category(*context, tbl[i].cat, plugin);
                        return prelude_option_success;
                }
        }

        ret = parse_plugin_name(arg, &pname, &iname);
        if ( ret < 0 )
                return -1;
        
        ptr = prelude_plugin_search_instance_by_name(pname, iname);
        if ( ! ptr ) {
                log(LOG_ERR, "category '%s' doesn't exist, or a plugin of that name is not loaded.\n", arg);
                return prelude_option_error;
        }

        free(pname);
        free(iname);
        
        filter_plugins_add_plugin(*context, ptr, plugin);
        
        return prelude_option_success;
}




static int set_filter_rule(void **context, prelude_option_t *opt, const char *arg) 
{
        idmef_criteria_t *new;
        filter_plugin_t *plugin = prelude_plugin_instance_get_data(*context);

        new = idmef_criteria_new_string(arg);
        if ( ! new )
                return prelude_option_error;
        
        if ( ! plugin->criteria ) {
                plugin->criteria = idmef_criteria_new();
                if ( ! plugin->criteria ) {
                        idmef_criteria_destroy(new);
                        return prelude_option_error;
                }
        }

        idmef_criteria_add_criteria(plugin->criteria, new, operator_or);
        
        return prelude_option_success;
}




static int filter_activate(void **context, prelude_option_t *opt, const char *arg) 
{
        filter_plugin_t *new;

        new = malloc(sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return prelude_option_error;
        }
        
        new->criteria = NULL;

        *context = prelude_plugin_subscribe((void *) &filter_plugin, opt, arg, new);
        if ( ! *context ) {
                free(new);
                return prelude_option_error;
        }
        
        return prelude_option_success;
}




prelude_plugin_generic_t *prelude_plugin_init(void)
{
        prelude_option_t *opt;
        
        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 0, "filter",
                                 "Option for the filter plugin", optionnal_argument,
                                 filter_activate, NULL);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'r', "rule",
                                 "Filtering rule", required_argument,
                                 set_filter_rule, NULL);
        
        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'h', "hook",
                           "Where the filter should be hooked (reporting|relaying|plugin name)",
                           required_argument, set_filter_hook, NULL);
        
        prelude_plugin_set_name(&filter_plugin, "Filter");
        prelude_plugin_set_author(&filter_plugin, "Krzysztof Zaraska");
        prelude_plugin_set_contact(&filter_plugin, "kzaraska@student.uci.agh.edu.pl");
        prelude_plugin_set_desc(&filter_plugin, "Match alert against IDMEF criteria");
	prelude_plugin_set_running_func(&filter_plugin, process_message);
                
	return (void *) &filter_plugin;
}

