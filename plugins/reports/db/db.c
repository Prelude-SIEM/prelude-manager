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
#include <sys/types.h>

#include <libprelude/prelude-inttypes.h>
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

#include "libmissing.h"
#include "report.h"


prelude_plugin_generic_t *db_LTX_prelude_plugin_init(void);


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
extern prelude_option_t *manager_root_optlist;



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



static void db_destroy(prelude_plugin_instance_t *pi, prelude_string_t *out)
{
        db_plugin_t *db = prelude_plugin_instance_get_data(pi);

        if ( db->interface )
                prelude_db_interface_destroy(db->interface);

        if ( db->host )
                free(db->host);
        
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



static int db_init(prelude_plugin_instance_t *pi, prelude_string_t *out)
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
        if ( ! interface )
                return -1;
        
        ret = prelude_db_interface_connect(interface);
        if ( ret < 0 ) {
                prelude_db_interface_destroy(interface);
                return ret;
        }
        
        if ( db->interface )
                prelude_db_interface_destroy(db->interface);

        db->interface = interface;

        return 0;
}



static int db_activate(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err) 
{
        db_plugin_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);

        prelude_plugin_instance_set_data(context, new);
        
        return 0;
}




prelude_plugin_generic_t *db_LTX_prelude_plugin_init(void)
{
        int ret;
	prelude_option_t *opt;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;
        
        ret = prelude_db_init();
        if ( ret < 0 ) {
                log(LOG_ERR, "libpreludedb initialisation failed, DB plugin not registered!\n");
                return NULL;
        }
                
        opt = prelude_option_add(manager_root_optlist, hook, 0, "db", "Option for the db plugin",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, db_activate, NULL);

        prelude_plugin_set_activation_option((void *) &plugin, opt, db_init);
        
	prelude_option_add(opt, hook, 'f', "format", "Format of the database",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_format, db_get_format);

	prelude_option_add(opt, hook, 't', "type", "Type of database (mysql/pgsql)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_type, db_get_type);

	prelude_option_add(opt, hook, 'h', "host", "The host where the database is running",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED,  db_set_host, db_get_host);
        
        prelude_option_add(opt, hook, 'p', "port", "The port where the database is running",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_port, db_get_port);
        
	prelude_option_add(opt, hook, 'd', "name",
                           "The name of the database where the alerts will be stored",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_name, db_get_name);

	prelude_option_add(opt, hook, 'u', "user", "User of the database",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_user, db_get_user);

	prelude_option_add(opt, hook, 'P', "pass", "Password for the user",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_pass, db_get_pass);
        
        prelude_plugin_set_name(&plugin, "db");
        prelude_plugin_set_author(&plugin, "Krzysztof Zaraska");
        prelude_plugin_set_contact(&plugin, "kzaraska@student.uci.agh.edu.pl");
        prelude_plugin_set_desc(&plugin, "Interface for writing alerts via libpreludedb library");
        prelude_plugin_set_destroy_func(&plugin, db_destroy);

        report_plugin_set_running_func(&plugin, db_run);
        
	return (void *) &plugin;
}
