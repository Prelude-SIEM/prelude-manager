/*****
*
* Copyright (C) 2002 Krzysztof Zaraska <kzaraska@student.uci.agh.edu.pl>
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
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <inttypes.h>
#include <sys/types.h>

#include <libprelude/list.h>
#include <libprelude/idmef.h>

#include <libpreludedb/db-type.h>
#include <libpreludedb/db.h>
#include <libpreludedb/db-connection-data.h>
#include <libpreludedb/db-connection.h>
#include <libpreludedb/db-object-selection.h>
#include <libpreludedb/db-message-ident.h>
#include <libpreludedb/db-interface.h>
#include <libpreludedb/db-interface-string.h>

#include "report.h"
#include "idmef-util.h"

typedef struct {
	struct list_head list;

	const char *config;
	prelude_db_interface_t *interface;
} interface_t;

static plugin_report_t plugin;
static int enabled = 0;

static LIST_HEAD(db_interfaces);



static int interface_init(interface_t *interface)
{
	prelude_db_interface_t *db_interface;
	int ret;
	
	if ( ! interface )
		return -1;
	
	db_interface = prelude_db_interface_new_string(interface->config);
	if ( ! db_interface ) 
		return -2;

	ret = prelude_db_interface_connect(db_interface);
	if ( ret < 0 )
		return -3;
		
	interface->interface = db_interface;
	
	return 0;
}

static void init_interfaces(void)
{
	struct list_head *tmp;
	interface_t *interface;
	
	list_for_each(tmp, &db_interfaces) {
		interface = list_entry(tmp, interface_t, list);

		if ( !interface->interface ) 
			interface_init(interface);
	}
	
}

static int shutdown_interfaces(void)
{
	int ret;
	struct list_head *tmp, *n;
	interface_t *interface;

	ret = 0;
	list_for_each_safe(tmp, n, &db_interfaces) {
                
		interface = list_entry(tmp, interface_t, list);

                ret = prelude_db_interface_disconnect(interface->interface);
		if ( ret < 0 ) {
			log(LOG_ERR, "could not disconnect interface %s\n", 
				prelude_db_interface_get_name(interface->interface));
			ret--;
		}
		
		prelude_db_interface_destroy(interface->interface);
	}
	
	return ret;
}




static int write_idmef_message(const idmef_message_t *msg)
{
	struct list_head *tmp;
	interface_t *interface;
	int ret;
	char *name;
	
	list_for_each(tmp, &db_interfaces) {
		interface = list_entry(tmp, interface_t, list);

		if ( interface->interface ) {
			name = prelude_db_interface_get_name(interface->interface);
                	log(LOG_INFO, "writing message on DB interface %s\n", name);

			ret = prelude_db_interface_insert_idmef_message(
				interface->interface, msg);
			if ( ret < 0 )
				log(LOG_ERR, "error on interface %s, code %d\n",
					name, ret);
		}
	}
	
	return 0;
	
}


static void process_message(const idmef_message_t *msg)
{
	if ( enabled )
		write_idmef_message(msg);
}

static int set_db_state(prelude_option_t *opt, const char *arg) 
{
        int ret;
        
        if ( enabled == 1 ) {
		shutdown_interfaces();
		
                ret = plugin_unsubscribe((plugin_generic_t *) &plugin);
                if ( ret < 0 )
                        return prelude_option_error;
                enabled = 0;
        } else {
		ret = prelude_db_init();
		if (ret < 0) {
			log(LOG_ERR, "db_init() failed, DB plugin not registered!\n");
			return prelude_option_error;
		}

		init_interfaces();
        	
                ret = plugin_subscribe((plugin_generic_t *) &plugin);
                if ( ret < 0 )
                        return prelude_option_error;
                
                enabled = 1;
        }
	
        return prelude_option_success;
}



static int get_db_state(char *buf, size_t size) 
{
        snprintf(buf, size, "%s", (enabled == 1) ? "enabled" : "disabled");
        return prelude_option_success;
}

static int new_interface(prelude_option_t *opt, const char *arg)
{
	interface_t *interface;
	
	interface = calloc(1, sizeof(*interface));
	if ( !interface ) {
		log(LOG_ERR, "memory exhausted.\n");
		return prelude_option_error;
	}
	
	interface->config = strdup(arg);
	if ( ! interface->config ) {
		log(LOG_ERR, "memory exhausted.\n");
		free(interface);
		return prelude_option_error;
	}
	
	list_add(&interface->list, &db_interfaces);
	
	return prelude_option_success;
}

plugin_generic_t *plugin_init(int argc, char **argv)
{
	prelude_option_t *opt;
        
        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 0, "db",
                                 "Option for the db plugin", no_argument,
                                 set_db_state, get_db_state);
                                 
        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'i', "interface",
                           "DB interface specification, see libpreludedb docs", 
                           required_argument, new_interface, NULL);

        plugin_set_name(&plugin, "DB");
        plugin_set_author(&plugin, "Krzysztof Zaraska");
        plugin_set_contact(&plugin, "kzaraska@student.uci.agh.edu.pl");
        plugin_set_desc(&plugin, "Interface for writing alerts via libpreludeDB library");
	plugin_set_running_func(&plugin, process_message);
     
	return (plugin_generic_t *) &plugin;
}

