/*****
*
* Copyright (C) 2002 Krzysztof Zaraska <kzaraska@student.uci.agh.edu.pl>
* Copyright (C) 2003 Nicolas Delon <delon.nicolas@wanadoo.fr>
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

#include <libprelude/idmef.h>

#include <libpreludedb/db-type.h>
#include <libpreludedb/db.h>
#include <libpreludedb/db-connection-data.h>
#include <libpreludedb/sql-connection-data.h>
#include <libpreludedb/sql.h>
#include <libpreludedb/db-connection.h>
#include <libpreludedb/db-object-selection.h>
#include <libpreludedb/db-message-ident.h>
#include <libpreludedb/db-interface.h>
#include <libpreludedb/db-interface-string.h>

#include "report.h"


#define param_value(param) (param ? param : "")


typedef struct {
        char *format;
        char *type;
        char *host;
        char *port;
        char *name;
        char *user;
        char *pass;
        prelude_db_interface_t *interface;
} db_plugin_t;



static plugin_report_t plugin;



PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, type)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, host)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, port)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, name)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, user)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, pass)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, format)



static int db_run(prelude_plugin_instance_t *pi, idmef_message_t *message)
{
        int ret;
        db_plugin_t *plugin = prelude_plugin_instance_get_data(pi);

        ret = prelude_db_interface_insert_idmef_message(plugin->interface, message);
	if ( ret < 0 ) 
		log(LOG_ERR, "could not write message using libpreludedb.\n");

        return ret;
}



static void db_destroy(prelude_plugin_instance_t *pi)
{
        db_plugin_t *db = prelude_plugin_instance_get_data(pi);

        if ( db->interface )
                prelude_db_interface_destroy(db->interface);

        if ( db->name )
                free(db->name);

        if ( db->type )
                free(db->type);
        
        if ( db->user )
                free(db->user);

        if ( db->pass )
                free(db->pass);

        if ( db->port )
                free(db->port);
        
        if ( db->format )
                free(db->format);
        
        free(db);
}



static int db_init(prelude_plugin_instance_t *pi)
{
        int ret;
        char conn_string[256];
        prelude_db_interface_t *interface;
        db_plugin_t *db = prelude_plugin_instance_get_data(pi);
        
        snprintf(conn_string, sizeof(conn_string),
                 "interface=iface1 class=sql type=%s format=%s host=%s port=%s name=%s user=%s pass=%s",
                 param_value(db->type), param_value(db->format),
                 param_value(db->host), param_value(db->port),
                 param_value(db->name), param_value(db->user), param_value(db->pass));

        interface = prelude_db_interface_new_string(conn_string);
        if ( ! interface ) {
                log(LOG_ERR, "could not create libpreludedb interface.\n");
                return -1;
        }
        
        ret = prelude_db_interface_connect(interface);
        if ( ret < 0 ) {                
                log(LOG_ERR, "could not connect libpreludedb.\n");
                prelude_db_interface_destroy(interface);
                return -1;
        }
        
        if ( db->interface )
                prelude_db_interface_destroy(db->interface);

        db->interface = interface;

        return 0;
}



static int db_activate(prelude_plugin_instance_t *pi, prelude_option_t *opt, const char *arg) 
{
        db_plugin_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        prelude_plugin_instance_set_data(pi, new);
        
        return prelude_option_success;
}




prelude_plugin_generic_t *prelude_plugin_init(void)
{
        int ret;
	prelude_option_t *opt;

        ret = prelude_db_init();
        if ( ret < 0 ) {
                log(LOG_ERR, "libpreludedb initialisation failed, DB plugin not registered!\n");
                return NULL;
        }
                
        opt = prelude_plugin_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 0, "db",
                                        "Option for the db plugin", optionnal_argument,
                                        db_activate, NULL);

        prelude_plugin_set_activation_option((void *) &plugin, opt, db_init);
        
	prelude_plugin_option_add(opt, CLI_HOOK|CFG_HOOK, 'f', "format",
                                  "Format of the database", required_argument,
                                  db_set_format, db_get_format);

	prelude_plugin_option_add(opt, CLI_HOOK|CFG_HOOK, 't', "type",
                                  "Type of database (mysql/pgsql)", required_argument,
                                  db_set_type, db_get_type);

	prelude_plugin_option_add(opt, CLI_HOOK|CFG_HOOK, 'h', "host",
                                  "The host where the database is running", required_argument,
                                  db_set_host, db_get_host);
        
        prelude_plugin_option_add(opt, CLI_HOOK|CFG_HOOK, 'p', "port",
                                  "The port where the database is running", required_argument,
                                  db_set_port, db_get_port);
        
	prelude_plugin_option_add(opt, CLI_HOOK|CFG_HOOK, 'd', "name",
                                  "The name of the database where the alerts will be stored", required_argument,
                                  db_set_name, db_get_name);

	prelude_plugin_option_add(opt, CLI_HOOK|CFG_HOOK, 'u', "user",
                                  "User of the database", required_argument,
                                  db_set_user, db_get_user);

	prelude_plugin_option_add(opt, CLI_HOOK|CFG_HOOK, 'P', "pass",
                                  "Password for the user", required_argument,
                                  db_set_pass, db_get_pass);
        
        prelude_plugin_set_name(&plugin, "db");
        prelude_plugin_set_author(&plugin, "Krzysztof Zaraska");
        prelude_plugin_set_contact(&plugin, "kzaraska@student.uci.agh.edu.pl");
        prelude_plugin_set_desc(&plugin, "Interface for writing alerts via libpreludedb library");
        prelude_plugin_set_destroy_func(&plugin, db_destroy);

        report_plugin_set_running_func(&plugin, db_run);
        
	return (void *) &plugin;
}
