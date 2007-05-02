/*****
*
* Copyright (C) 2007 PreludeIDS Technologies. All Rights Reserved.
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
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

#include "config.h"
#include "libmissing.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "prelude-manager.h"
#include <libprelude/prelude-hash.h>


int thresholding_LTX_prelude_plugin_version(void);
int thresholding_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *data);


typedef struct {
        prelude_list_t list;
        idmef_path_t *path;
} path_elem_t;


typedef struct {
        int count; 
        char *key;
        prelude_timer_t timer;
} hash_elem_t;


typedef struct {
        prelude_list_t path_list;
        int threshold;
        int limit;
        int block;
        char *hook_str;
        manager_filter_hook_t *hook;
} filter_plugin_t;


static int plugin_instance_no = 0;
static prelude_hash_t *path_value_hash;
static manager_filter_plugin_t filter_plugin;



static int iter_cb(idmef_value_t *value, void *str)
{
        int ret;
        
        if ( idmef_value_is_list(value) )
                return idmef_value_iterate(value, iter_cb, str);
                
        ret = idmef_value_to_string(value, str);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "could not convert value to string: %s.\n", prelude_strerror(ret));
                return ret;
        }
        
        return 0;
}


static int get_value_from_path(idmef_path_t *path, idmef_message_t *message, prelude_string_t *str)
{
        int ret;
        idmef_value_t *value;
        
        /*
         * Lookup path in message.
         */
        ret = idmef_path_get(path, message, &value);
        if ( ret <= 0 )
               return 0;
       
        ret = idmef_value_iterate(value, iter_cb, str);
        idmef_value_destroy(value);
        
        return ret;
}



static void hash_entry_destroy(void *data)
{
        hash_elem_t *helem = data;
        
        prelude_timer_destroy(&helem->timer);
        free(helem->key);
        free(helem);        
}



static void destroy_filter_path(filter_plugin_t *plugin)
{
        path_elem_t *item;
        prelude_list_t *tmp, *bkp;
        
        prelude_list_for_each_safe(&plugin->path_list, tmp, bkp) {
                item = prelude_list_entry(tmp, path_elem_t, list);

                idmef_path_destroy(item->path);
                           
                prelude_list_del(&item->list);
                free(item);                
        }
}



static void hash_entry_expire_cb(void *data)
{
        hash_elem_t *helem = data;
        
        prelude_log_debug(3, "[%s]: release suppression.\n", helem->key);
        prelude_hash_elem_destroy(path_value_hash, helem->key);
}


static int check_filter(filter_plugin_t *plugin, const char *key)
{
        int ret;
        hash_elem_t *helem;
                
        helem = prelude_hash_get(path_value_hash, key);
        if ( ! helem ) {
                helem = malloc(sizeof(*helem));
                if ( ! helem )
                        return -1;

                helem->count = 0;
                helem->key = strdup(key);                        

                prelude_timer_init_list(&helem->timer);                
                prelude_timer_set_expire(&helem->timer, plugin->block);
                prelude_timer_set_data(&helem->timer, helem);
                prelude_timer_set_callback(&helem->timer, hash_entry_expire_cb);

                ret = prelude_hash_set(path_value_hash, helem->key, helem);
        }

        helem->count++;
            
        /*
         * Check threshold: event with KEY can be reported THRESHOLD time in Y seconds.
         */
        if ( plugin->threshold ) {
                if ( helem->count == 1 )
                        prelude_timer_init(&helem->timer);
                        
                if ( helem->count == plugin->threshold )
                        prelude_log_debug(3, "[%s]: %d events in %d seconds reached - thresholding.\n", 
                                          key, helem->count, plugin->block);
                
                return (helem->count > plugin->threshold) ? -1 : 0;
        }
        
        /*
         * Check limit: event with KEY can be reported LIMIT time, then is blocked until Y seconds are elapsed.
         */
        else if ( plugin->limit ) {
                if ( helem->count == plugin->limit ) {
                        prelude_timer_init(&helem->timer);
                        prelude_log_debug(3, "[%s]: limit of %d events per %d seconds reached - will drop upcoming events.\n", 
                                          key, helem->count, plugin->block); 
                }
                
                return (helem->count > plugin->limit) ? -1 : 0;
        }
        
        return 0;
}


static int process_message(idmef_message_t *msg, void *priv) 
{
        int ret;
	path_elem_t *pelem;
        prelude_list_t *tmp;
        prelude_string_t *key;
	filter_plugin_t *plugin = priv;
        
        ret = prelude_string_new(&key);
        if ( ret < 0 )
                return 0;
                
        prelude_list_for_each(&plugin->path_list, tmp) {
                pelem = prelude_list_entry(tmp, path_elem_t, list);
                
                ret = get_value_from_path(pelem->path, msg, key);                  
                if ( ret < 0 )
                        return 0;
        }
                
        if ( ! prelude_string_is_empty(key) )
                ret = check_filter(plugin, prelude_string_get_string(key));

        prelude_string_destroy(key);
        
        return ret;
}


static int get_filter_threshold(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        filter_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        return prelude_string_sprintf(out, "%d", plugin->threshold);
}



static int set_filter_threshold(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context) 
{
        filter_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        plugin->threshold = atoi(optarg);
        return 0;
}



static int get_filter_limit(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        filter_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        return prelude_string_sprintf(out, "%d", plugin->limit);
}



static int set_filter_limit(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context) 
{
        filter_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        plugin->limit = atoi(optarg);
        return 0;
}



static int get_filter_block(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        filter_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        return prelude_string_sprintf(out, "%d", plugin->block);
}



static int set_filter_block(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context) 
{
        filter_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        plugin->block = atoi(optarg);
        return 0;
}


static int get_filter_path(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        path_elem_t *item;
        prelude_list_t *tmp;
        filter_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        
        prelude_list_for_each(&plugin->path_list, tmp) {
                item = prelude_list_entry(tmp, path_elem_t, list);
                
                if ( ! prelude_string_is_empty(out) )
                        prelude_string_cat(out, ", ");
                        
                prelude_string_cat(out, idmef_path_get_name(item->path, -1));
        }
        
        return 0;
}


static int set_filter_path(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context) 
{
        int ret = 0;
        path_elem_t *elem;
        char *ptr, *start, *dup = strdup(optarg);
        filter_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        
        destroy_filter_path(plugin);
        start = dup;
        
        while ( (ptr = strsep(&dup, ", ")) ) {
                if ( *ptr == '\0' )
                        continue;

                elem = malloc(sizeof(*elem));
                if ( ! elem ) {
                        ret = prelude_error_from_errno(errno);
                        break;
                }
                         
                ret = idmef_path_new_fast(&elem->path, ptr);
                if ( ret < 0 ) {
                        free(elem);
                        break;
                }
        
                prelude_list_add_tail(&plugin->path_list, &elem->list);
        }

        free(start);
        return ret;
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



static int filter_activate(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context) 
{
        int ret;
        filter_plugin_t *new;
        
        if ( plugin_instance_no++ == 0 ) {
                ret = prelude_hash_new(&path_value_hash, NULL, NULL, NULL, hash_entry_destroy);
                if ( ret < 0 )
                        return ret;
        }
        
        new = calloc(1, sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);
        
        prelude_list_init(&new->path_list);
        prelude_plugin_instance_set_plugin_data(context, new);
        
        return 0;
}



static void filter_destroy(prelude_plugin_instance_t *pi, prelude_string_t *out)
{
        filter_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);
        
        destroy_filter_path(plugin);
                
        if ( plugin->hook )
                manager_filter_destroy_hook(plugin->hook);

        if ( plugin->hook_str )
                free(plugin->hook_str);

        if ( --plugin_instance_no == 0 )
                prelude_hash_destroy(path_value_hash);
        
        free(plugin);
}




int thresholding_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *root_opt)
{
        int ret;
        prelude_option_t *opt;

        ret = prelude_option_add(root_opt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG
                                 |PRELUDE_OPTION_TYPE_WIDE, 0, "thresholding",
                                 "Filter message based on path+value limit", PRELUDE_OPTION_ARGUMENT_OPTIONAL,
                                 filter_activate, NULL);
        if ( ret < 0 )
                return ret;

        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_LAST);
        prelude_plugin_set_activation_option(pe, opt, NULL);
        
        ret = prelude_option_add(opt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG
                                 |PRELUDE_OPTION_TYPE_WIDE, 'p', "path",
                                 "Comma separated path to apply limit or threshold", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                                 set_filter_path, get_filter_path);
        if ( ret < 0 )
                return ret;
        
        ret = prelude_option_add(opt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG
                                 |PRELUDE_OPTION_TYPE_WIDE, 't', "threshold",
                                 "Number of events per suppression window", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                                 set_filter_threshold, get_filter_threshold);
        if ( ret < 0 )
                return ret;
                
        ret = prelude_option_add(opt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG
                                 |PRELUDE_OPTION_TYPE_WIDE, 'l', "limit",
                                 "Number of events to report before suppressing for '#' of seconds", 
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, set_filter_limit, get_filter_limit);
        if ( ret < 0 )
                return ret;
                
        ret = prelude_option_add(opt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG
                                 |PRELUDE_OPTION_TYPE_WIDE, 's', "seconds",
                                 "Number of seconds the suppression should remain", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                                 set_filter_block, get_filter_block);
        if ( ret < 0 )
                return ret;
                
                        
        ret = prelude_option_add(opt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG
                                 |PRELUDE_OPTION_TYPE_WIDE, 0, "hook",
                                 "Where the filter should be hooked (reporting|reverse-relaying|plugin name)",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, set_filter_hook, get_filter_hook);
        if ( ret < 0 )
                return ret;
        
        prelude_plugin_set_name(&filter_plugin, "Thresholding");
        prelude_plugin_set_destroy_func(&filter_plugin, filter_destroy);
        manager_filter_plugin_set_running_func(&filter_plugin, process_message);

        prelude_plugin_entry_set_plugin(pe, (void *) &filter_plugin);

        return 0;
}



int thresholding_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}

