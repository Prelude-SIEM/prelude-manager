/*****
*
* Copyright (C) 2002-2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

#ifndef _MANAGER_PLUGIN_FILTER_H
#define _MANAGER_PLUGIN_FILTER_H


#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-getopt.h>
#include <libprelude/prelude-plugin.h>


typedef enum {
        FILTER_CATEGORY_REPORTING         = 0,
        FILTER_CATEGORY_REVERSE_RELAYING  = 1,
        FILTER_CATEGORY_PLUGIN            = 2,
        FILTER_CATEGORY_END               = 3, /* should be the latest, do not remove */
} filter_category_t;



typedef struct {
        /*
         * What category/plugin should this entry be hooked at.
         */
        filter_category_t category;
        prelude_plugin_generic_t *plugin;
        
        /*
         * private data associated with an entry.
         */
        void *private_data;
} filter_entry_t;



typedef struct {
        PRELUDE_PLUGIN_GENERIC;
        filter_entry_t *category;
        int (*run)(idmef_message_t *message, void *data);
} plugin_filter_t;


#define filter_plugin_set_running_func(p, f) (p)->run = (f)


int filter_plugins_available(filter_category_t type);

int filter_plugins_init(const char *dirname, int argc, char **argv);

int filter_plugins_run_by_category(idmef_message_t *msg, filter_category_t cat);

int filter_plugins_run_by_plugin(idmef_message_t *message, prelude_plugin_instance_t *plugin);

int filter_plugins_add_category(prelude_plugin_instance_t *pi, filter_category_t cat,
                                prelude_plugin_instance_t *filtered_plugin, void *data);


#endif /* _MANAGER_PLUGIN_FILTER_H */


