/*****
*
* Copyright (C) 2002 Krzysztof Zaraska <kzaraska@student.uci.agh.edu.pl>
* Copyright (C) 2003-2005 Nicolas Delon <nicolas@prelude-ids.org>
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
#include <libprelude/prelude-error.h>
#include <libprelude/idmef.h>
#include <libprelude/prelude-error.h>

#include <libpreludedb/preludedb-sql-settings.h>
#include <libpreludedb/preludedb-sql.h>
#include <libpreludedb/preludedb-error.h>
#include <libpreludedb/preludedb-object-selection.h>
#include <libpreludedb/preludedb.h>


#include "libmissing.h"
#include "report.h"


prelude_plugin_generic_t *db_LTX_prelude_plugin_init(void);


#define param_value(param) (param ? param : "")


typedef struct {
        char *type;
	char *log;
        char *host;
        char *port;
        char *name;
        char *user;
        char *pass;
        preludedb_t *db;
} db_plugin_t;



static plugin_report_t plugin;
extern prelude_option_t *manager_root_optlist;



PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, type)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, log)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, host)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, port)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, name)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, user)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, pass)



static int db_run(prelude_plugin_instance_t *pi, idmef_message_t *message)
{
        db_plugin_t *plugin = prelude_plugin_instance_get_data(pi);
        int ret;

        ret = preludedb_insert_message(plugin->db, message);
	if ( ret < 0 ) {
		char *error;
		int ret2;

		ret2 = preludedb_get_error(plugin->db, ret, &error);
		if ( ret2 < 0 )
			log(LOG_ERR, "could not insert message into database: %s.\n",
			    preludedb_strerror(ret));
		else {
			log(LOG_ERR, "could not insert message into database: %s.\n", error);
			free(error);
		}
	}

        return ret;
}



static void db_destroy(prelude_plugin_instance_t *pi, prelude_string_t *out)
{
        db_plugin_t *plugin = prelude_plugin_instance_get_data(pi);

        if ( plugin->type )
                free(plugin->type);

	if ( plugin->host )
                free(plugin->host);

        if ( plugin->name )
                free(plugin->name);

        if ( plugin->user )
                free(plugin->user);

        if ( plugin->pass )
                free(plugin->pass);

        if ( plugin->port )
                free(plugin->port);

	preludedb_destroy(plugin->db);
	free(plugin);
}



static int db_init(prelude_plugin_instance_t *pi, prelude_string_t *out)
{
        db_plugin_t *plugin = prelude_plugin_instance_get_data(pi);
	preludedb_sql_settings_t *settings;

	settings = preludedb_sql_settings_new();
	if ( ! settings )
		return -1;

	if ( plugin->host )
		preludedb_sql_settings_set_host(settings, plugin->host);

	if ( plugin->port )
		preludedb_sql_settings_set_port(settings, plugin->port);

	if ( plugin->user )
		preludedb_sql_settings_set_user(settings, plugin->user);

	if ( plugin->pass )
		preludedb_sql_settings_set_pass(settings, plugin->pass);

	if ( plugin->name )
		preludedb_sql_settings_set_name(settings, plugin->name);

	plugin->db = preludedb_new(plugin->type, settings, NULL);
	preludedb_sql_settings_destroy(settings);
	if ( ! plugin->db ) {
		log(LOG_ERR, "could not initialize libpreludedb.\n");
		return -1;
	}

	if ( plugin->log ) {
		preludedb_sql_t *sql;
		int ret;

		sql = preludedb_get_sql(plugin->db);
		ret = preludedb_sql_enable_query_logging(sql, plugin->log);
		if ( ret < 0 ) {
			preludedb_destroy(plugin->db);
			return ret;
		}
	}

        return 0;
}



static int db_activate(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err) 
{
        db_plugin_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);

	new->type = strdup("mysql");
	if ( ! new->type ) {
		free(new);
		return prelude_error_from_errno(errno);
	}

        prelude_plugin_instance_set_data(context, new);
        
        return 0;
}




prelude_plugin_generic_t *db_LTX_prelude_plugin_init(void)
{
	prelude_option_t *opt;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;

        opt = prelude_option_add(manager_root_optlist, hook, 0, "db", "Options for the libpreludedb plugin",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, db_activate, NULL);

        prelude_plugin_set_activation_option((void *) &plugin, opt, db_init);

	prelude_option_add(opt, hook, 't', "type", "Type of database (mysql/pgsql)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_type, db_get_type);

	prelude_option_add(opt, hook, 'l', "log", "Log all queries in a file, should be only used for debugging purpose",
			   PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_log, db_get_log);

	prelude_option_add(opt, hook, 'h', PRELUDEDB_SQL_SETTING_HOST,
			   "The host where the database server is running (in case of client/server database)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED,  db_set_host, db_get_host);
        
        prelude_option_add(opt, hook, 'p', PRELUDEDB_SQL_SETTING_PORT,
			   "The port where the database server is listening (in case of client/server database)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_port, db_get_port);
        
	prelude_option_add(opt, hook, 'd', PRELUDEDB_SQL_SETTING_NAME,
                           "The name of the database where the alerts will be stored",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_name, db_get_name);

	prelude_option_add(opt, hook, 'u', PRELUDEDB_SQL_SETTING_USER,
			   "User of the database (in case of client/server database)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_user, db_get_user);

	prelude_option_add(opt, hook, 'P', PRELUDEDB_SQL_SETTING_PASS,
			   "Password for the user (in case of client/server database)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_pass, db_get_pass);
        
        prelude_plugin_set_name(&plugin, "db");
        prelude_plugin_set_author(&plugin, "Nicolas Delon");
        prelude_plugin_set_contact(&plugin, "nicolas@prelude-ids.org");
        prelude_plugin_set_desc(&plugin, "Write IDMEF messages in a database using libpreludedb");
        prelude_plugin_set_destroy_func(&plugin, db_destroy);

        report_plugin_set_running_func(&plugin, db_run);
        
	return (void *) &plugin;
}
