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

#include <libprelude/list.h>
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
#include "idmef-util.h"

static char *dbformat = NULL;
static char *dbtype = NULL;
static char *dbhost = NULL;
static char *dbport = NULL;
static char *dbname = NULL;
static char *dbuser = NULL;
static char *dbpass = NULL;

static plugin_report_t plugin;
static int enabled = 0;

static prelude_db_interface_t *db_interface = NULL;


#define param_value(param) (param ? param : "")



static void write_idmef_message(const idmef_message_t *message)
{
	if ( prelude_db_interface_insert_idmef_message(db_interface, message) < 0 ) {
		log(LOG_ERR, "could not write message using libpreludedb.\n");
		return;
	}

#ifdef DEBUG
	log(LOG_INFO, "wrote message %llu:%llu using libpreludedb.\n",
	    idmef_alert_get_ident(idmef_message_get_alert(message)),
	    idmef_analyzer_get_ident(idmef_alert_get_analyzer(idmef_message_get_alert(message))));
#endif /* DEBUG */
}



static void process_message(idmef_message_t *message)
{
        write_idmef_message(message);
}



static int set_db_state(prelude_option_t *opt, const char *arg) 
{
        if ( enabled ) {
		prelude_db_interface_destroy(db_interface);

                if ( plugin_unsubscribe((plugin_generic_t *) &plugin) < 0 )
                        return prelude_option_error;

                enabled = 0;

        } else {
		char conn_string[256];

		if ( prelude_db_init() < 0 ) {
			log(LOG_ERR, "db_init() failed, DB plugin not registered!\n");
			return prelude_option_error;
		}

		snprintf(conn_string, sizeof (conn_string),
			 "interface=iface1 class=sql type=%s format=%s host=%s port=%s name=%s user=%s pass=%s",
			 param_value(dbtype), param_value(dbformat), param_value(dbhost),
                         param_value(dbport), param_value(dbname), param_value(dbuser), param_value(dbpass));

		db_interface = prelude_db_interface_new_string(conn_string);
		if ( ! db_interface ) {
			log(LOG_ERR, "could not create libpreludedb interface.\n");
			return prelude_option_error;
		}

		if ( prelude_db_interface_connect(db_interface) < 0 ) {
			log(LOG_ERR, "could not connect libpreludedb.\n");
			prelude_db_interface_destroy(db_interface);
			return prelude_option_success;
		}

                if ( plugin_subscribe((plugin_generic_t *) &plugin) < 0 ) {
			prelude_db_interface_destroy(db_interface);
                        return prelude_option_error;
		}

                enabled = 1;
        }

        return prelude_option_success;
}



#define set_db(name)	 						\
static int set_db_ ## name(prelude_option_t *opt, const char *arg)	\
{									\
	if ( db ## name )						\
		free(db ## name);					\
									\
	db ## name = strdup(arg);					\
	if ( ! db ## name ) {						\
		log(LOG_ERR, "memory exhausted.\n");			\
		return prelude_option_error;				\
	}								\
									\
	return prelude_option_success;					\
}

set_db(format)
set_db(type)
set_db(host)
set_db(port)
set_db(name)
set_db(user)
set_db(pass)



static int get_db_state(char *buf, size_t size) 
{
        snprintf(buf, size, "%s", enabled ? "enabled" : "disabled");

        return prelude_option_success;
}



plugin_generic_t *plugin_init(int argc, char **argv)
{
	prelude_option_t *opt;

        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 0, "db",
                                 "Option for the db plugin", no_argument,
                                 set_db_state, get_db_state);

	prelude_option_add(opt, CLI_HOOK|CFG_HOOK, 'f', "format",
			   "Format of the database", required_argument,
			   set_db_format, NULL);

	prelude_option_add(opt, CLI_HOOK|CFG_HOOK, 't', "type",
			   "Type of database (mysql/pgsql)", required_argument,
			   set_db_type, NULL);

	prelude_option_add(opt, CLI_HOOK|CFG_HOOK, 'h', "host",
			   "The host where the database is running", required_argument,
			   set_db_host, NULL);
        
        prelude_option_add(opt, CLI_HOOK|CFG_HOOK, 'p', "port",
			   "The port where the database is running", required_argument,
			   set_db_port, NULL);
        
	prelude_option_add(opt, CLI_HOOK|CFG_HOOK, 'd', "name",
			   "The name of the database where the alerts will be stored", required_argument,
			   set_db_name, NULL);

	prelude_option_add(opt, CLI_HOOK|CFG_HOOK, 'u', "user",
			   "User of the database", required_argument,
			   set_db_user, NULL);

	prelude_option_add(opt, CLI_HOOK|CFG_HOOK, 'P', "pass",
			   "Password for the user", required_argument,
			   set_db_pass, NULL);

        plugin_set_name(&plugin, "DB");
        plugin_set_author(&plugin, "Krzysztof Zaraska");
        plugin_set_contact(&plugin, "kzaraska@student.uci.agh.edu.pl");
        plugin_set_desc(&plugin, "Interface for writing alerts via libpreludedb library");
	plugin_set_running_func(&plugin, process_message);

	return (plugin_generic_t *) &plugin;
}
