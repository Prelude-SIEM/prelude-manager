/*****
*
* Copyright (C) 2004-2005 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>


/*
 * Report plugin entry structure.
 */
typedef struct {
        PRELUDE_PLUGIN_GENERIC;
        int (*run)(prelude_plugin_instance_t *pi, idmef_message_t *message);
        void (*close)(prelude_plugin_instance_t *pi);
} manager_report_plugin_t;

#define report_plugin_set_running_func(p, f) (p)->run = (f)
#define report_plugin_set_closing_func(p, f) (p)->close = (f)


/*
 * Decode plugin entry structure
 */
typedef struct {
        PRELUDE_PLUGIN_GENERIC;
        uint8_t decode_id;
        int (*run)(prelude_msg_t *ac, idmef_message_t *idmef);
} manager_decode_plugin_t;


#define decode_plugin_set_running_func(p, f) (p)->run = (f)



/*
 * Filter plugin entry structure.
 */
typedef enum {
        MANAGER_FILTER_CATEGORY_REPORTING         = 0,
        MANAGER_FILTER_CATEGORY_REVERSE_RELAYING  = 1,
        MANAGER_FILTER_CATEGORY_PLUGIN            = 2,
        MANAGER_FILTER_CATEGORY_END               = 3, /* should be the latest, do not remove */
} manager_filter_category_t;



typedef struct {
        /*
         * What category/plugin should this entry be hooked at.
         */
        manager_filter_category_t category;
        prelude_plugin_generic_t *plugin;
        
        /*
         * private data associated with an entry.
         */
        void *private_data;
} manager_filter_entry_t;


typedef struct {
        PRELUDE_PLUGIN_GENERIC;
        manager_filter_entry_t *category;
        int (*run)(idmef_message_t *message, void *data);
} manager_filter_plugin_t;


#define filter_plugin_set_running_func(p, f) (p)->run = (f)


int manager_filter_plugins_add_filter(prelude_plugin_instance_t *pi,
                                      manager_filter_category_t filtered_category,
                                      prelude_plugin_instance_t *filtered_plugin, void *data);
