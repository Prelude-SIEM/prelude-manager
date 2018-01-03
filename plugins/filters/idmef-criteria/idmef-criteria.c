/*****
*
* Copyright (C) 2002-2018 CS-SI. All Rights Reserved.
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "prelude-manager.h"


int idmef_criteria_LTX_prelude_plugin_version(void);
int idmef_criteria_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *data);


static manager_filter_plugin_t filter_plugin;


typedef struct {
        idmef_criteria_t *criteria;

        char *hook_str;
        manager_filter_hook_t *hook;
} filter_plugin_t;



static int process_message(idmef_message_t *msg, void *priv)
{
        filter_plugin_t *plugin = priv;
        int ret;

        if ( ! plugin->criteria )
                return 0;

        ret = idmef_criteria_match(plugin->criteria, msg);
        if ( ret < 0 )
                prelude_perror(ret, "error matching criteria");

        return (ret > 0) ? 0 : -1;
}


static int get_filter_hook(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        int ret = 0;
        filter_plugin_t *plugin;

        plugin = prelude_plugin_instance_get_plugin_data(context);

        if ( plugin->hook_str )
                ret = prelude_string_set_ref(out, plugin->hook_str);

        return ret;
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

        plugin = prelude_plugin_instance_get_plugin_data(context);

        for ( i = 0; tbl[i].hook != NULL; i++ ) {
                ret = strcasecmp(optarg, tbl[i].hook);
                if ( ret == 0 ) {
                        manager_filter_new_hook(&plugin->hook, context, tbl[i].cat, NULL, plugin);
                        goto success;
                }
        }

        ret = sscanf(optarg, "%255[^[][%255[^]]", pname, iname);
        if ( ret == 0 ) {
                prelude_string_sprintf(err, "error parsing value: '%s'", optarg);
                return -1;
        }

        ptr = prelude_plugin_search_instance_by_name(NULL, pname, (ret == 2) ? iname : NULL);
        if ( ! ptr ) {
                prelude_string_sprintf(err, "Unknown hook '%s'", optarg);
                return -1;
        }

        manager_filter_new_hook(&plugin->hook, context, MANAGER_FILTER_CATEGORY_PLUGIN, ptr, plugin);

 success:
        if ( plugin->hook_str )
                free(plugin->hook_str);

        plugin->hook_str = strdup(optarg);
        if ( ! plugin->hook_str )
                return -1;

        return 0;
}



static int add_criteria(filter_plugin_t *plugin, const char *criteria)
{
        int ret;
        idmef_criteria_t *new;

        ret = idmef_criteria_new_from_string(&new, criteria);
        if ( ret < 0 )
                return ret;

        if ( plugin->criteria )
                idmef_criteria_destroy(plugin->criteria);

        plugin->criteria = new;

        return 0;
}



static int read_criteria_from_filename(filter_plugin_t *plugin, const char *filename, prelude_string_t *err)
{
        int ret;
        FILE *fd;
        prelude_string_t *out;
        unsigned int line = 0;
        idmef_criteria_t *new, *criteria = NULL;

        fd = fopen(filename, "r");
        if ( ! fd ) {
                prelude_string_sprintf(err, "error opening '%s' for reading: %s (%d)", filename, strerror(errno), errno);
                return -1;
        }

        ret = prelude_string_new(&out);
        if ( ret < 0 )
                return ret;

        while ( (ret = prelude_read_multiline2(fd, &line, out)) == 0 ) {
                ret = idmef_criteria_new_from_string(&new, prelude_string_get_string(out));
                if ( ret < 0 ) {
                        prelude_string_sprintf(err, "%s:%u: %s", filename, line, prelude_strerror(ret));
                        goto err;
                }

                if ( criteria )
                        idmef_criteria_or_criteria(criteria, new);
                else
                        criteria = new;
        }

        if ( ret < 0 && prelude_error_get_code(ret) != PRELUDE_ERROR_EOF ) {
                prelude_string_sprintf(err, "error reading '%s': %s", filename, prelude_strerror(ret));
                return ret;
        }

        ret = 0;

err:
        prelude_string_destroy(out);
        fclose(fd);

        if ( plugin->criteria )
                idmef_criteria_destroy(plugin->criteria);

        plugin->criteria = criteria;

        return ret;
}



static int set_filter_rule(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        int ret;
        filter_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);

        ret = access(optarg, R_OK);
        if ( ret == 0 )
                return read_criteria_from_filename(plugin, optarg, err);

        return add_criteria(plugin, optarg);
}




static int get_filter_rule(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        filter_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        return idmef_criteria_to_string(plugin->criteria, out);
}




static int filter_activate(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        filter_plugin_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);

        new->criteria = NULL;
        prelude_plugin_instance_set_plugin_data(context, new);

        return 0;
}



static void filter_destroy(prelude_plugin_instance_t *pi, prelude_string_t *out)
{
        filter_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        if ( plugin->criteria )
                idmef_criteria_destroy(plugin->criteria);

        if ( plugin->hook )
                manager_filter_destroy_hook(plugin->hook);

        if ( plugin->hook_str )
                free(plugin->hook_str);

        free(plugin);
}




int idmef_criteria_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *root_opt)
{
        int ret;
        prelude_option_t *opt;

        ret = prelude_option_add(root_opt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG
                                 |PRELUDE_OPTION_TYPE_WIDE, 0, "idmef-criteria",
                                 "Filter message based on IDMEF criteria", PRELUDE_OPTION_ARGUMENT_OPTIONAL,
                                 filter_activate, NULL);
        if ( ret < 0 )
                return ret;

        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_LAST);
        prelude_plugin_set_activation_option(pe, opt, NULL);

        ret = prelude_option_add(opt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG
                                 |PRELUDE_OPTION_TYPE_WIDE, 'r', "rule",
                                 "Filter rule, or filename containing rule", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                                 set_filter_rule, get_filter_rule);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG
                                 |PRELUDE_OPTION_TYPE_WIDE, 0, "hook",
                                 "Where the filter should be hooked (reporting|reverse-relaying|plugin name)",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, set_filter_hook, get_filter_hook);
        if ( ret < 0 )
                return ret;

        prelude_plugin_set_name(&filter_plugin, "IDMEF-Criteria");
        prelude_plugin_set_destroy_func(&filter_plugin, filter_destroy);
        manager_filter_plugin_set_running_func(&filter_plugin, process_message);

        prelude_plugin_entry_set_plugin(pe, (void *) &filter_plugin);

        return 0;
}



int idmef_criteria_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}

