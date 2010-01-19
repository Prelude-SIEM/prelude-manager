/*****
*
* Copyright (C) 2002-2005,2006,2007 PreludeIDS Technologies. All Rights Reserved.
* Author: Nicolas Delon <nicolas.delon@prelude-ids.com>
* Author: Krzysztof Zaraska <kzaraska@student.uci.agh.edu.pl>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>

#include <libprelude/idmef.h>
#include <libprelude/prelude-inttypes.h>
#include <libprelude/prelude-error.h>
#include <libprelude/idmef.h>
#include <libprelude/prelude-error.h>

#include <libpreludedb/preludedb-sql-settings.h>
#include <libpreludedb/preludedb-sql.h>
#include <libpreludedb/preludedb-error.h>
#include <libpreludedb/preludedb-path-selection.h>
#include <libpreludedb/preludedb.h>

#include "prelude-manager.h"


#define DEFAULT_DATABASE_TYPE "mysql"


int db_LTX_prelude_plugin_version(void);
int db_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *rootopt);


#define param_value(param) (param ? param : "")


typedef struct {
        char *type;
        char *log;
        char *host;
        char *file;
        char *port;
        char *name;
        char *user;
        char *pass;
        preludedb_t *db;
} db_plugin_t;



PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, type)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, log)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, host)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, port)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, name)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, user)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, pass)
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(db, db_plugin_t, file)


static int db_run(prelude_plugin_instance_t *pi, idmef_message_t *message)
{
        int ret;
        db_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        ret = preludedb_insert_message(plugin->db, message);
        if ( ret < 0 )
                prelude_log(PRELUDE_LOG_WARN, "could not insert message into database: %s.\n", preludedb_strerror(ret));

        if ( prelude_error_get_code(ret) == PRELUDEDB_ERROR_CONNECTION )
                ret = MANAGER_REPORT_PLUGIN_FAILURE_GLOBAL;
        else
                ret = MANAGER_REPORT_PLUGIN_FAILURE_SINGLE;

        return ret;
}



static void db_destroy(prelude_plugin_instance_t *pi, prelude_string_t *out)
{
        db_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        if ( plugin->type )
                free(plugin->type);

        if ( plugin->host )
                free(plugin->host);

        if ( plugin->file )
                free(plugin->file);

        if ( plugin->name )
                free(plugin->name);

        if ( plugin->user )
                free(plugin->user);

        if ( plugin->pass )
                free(plugin->pass);

        if ( plugin->port )
                free(plugin->port);

        if ( plugin->log )
                free(plugin->log);

        if ( plugin->db )
                preludedb_destroy(plugin->db);

        free(plugin);

        preludedb_deinit();
}



static int db_init(prelude_plugin_instance_t *pi, prelude_string_t *out)
{
        int ret;
        preludedb_t *db;
        preludedb_sql_t *sql;
        preludedb_sql_settings_t *settings;
        db_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        ret = preludedb_sql_settings_new(&settings);
        if ( ret < 0 )
                return ret;

        if ( plugin->host )
                preludedb_sql_settings_set_host(settings, plugin->host);

        if ( plugin->file )
                preludedb_sql_settings_set_file(settings, plugin->file);

        if ( plugin->port )
                preludedb_sql_settings_set_port(settings, plugin->port);

        if ( plugin->user )
                preludedb_sql_settings_set_user(settings, plugin->user);

        if ( plugin->pass )
                preludedb_sql_settings_set_pass(settings, plugin->pass);

        if ( plugin->name )
                preludedb_sql_settings_set_name(settings, plugin->name);

        ret = preludedb_sql_new(&sql, plugin->type, settings);
        if ( ret < 0 ) {
                prelude_string_sprintf(out, "error initializing libpreludedb SQL interface: %s", preludedb_strerror(ret));
                preludedb_sql_settings_destroy(settings);
                return ret;
        }

        if ( ! plugin->log )
                preludedb_sql_disable_query_logging(sql);
        else {
                ret = preludedb_sql_enable_query_logging(sql, (strcmp(plugin->log, "-") == 0) ? NULL : plugin->log);
                if ( ret < 0 ) {
                        preludedb_sql_destroy(sql);
                        prelude_string_sprintf(out, "could not enable queries logging with log file '%s': %s",
                                               plugin->log, preludedb_strerror(ret));
                        return ret;
                }
        }

        ret = preludedb_new(&db, sql, NULL, NULL, 0);
        if ( ret < 0 ) {
                preludedb_sql_destroy(sql);
                prelude_string_sprintf(out, "could not initialize libpreludedb: %s", preludedb_strerror(ret));
                return ret;
        }

        if ( plugin->db )
                preludedb_destroy(plugin->db);

        plugin->db = db;

        return 0;
}



static int db_activate(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        int ret;
        db_plugin_t *new;

        ret = preludedb_init();
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error initializing libpreludedb: %s", preludedb_strerror(ret));
                return ret;
        }

        new = calloc(1, sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);

        new->type = strdup(DEFAULT_DATABASE_TYPE);
        if ( ! new->type ) {
                free(new);
                return prelude_error_from_errno(errno);
        }

        prelude_plugin_instance_set_plugin_data(context, new);

        return 0;
}




int db_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *rootopt)
{
        int ret;
        prelude_option_t *opt;
        static manager_report_plugin_t db_plugin;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;

        ret = prelude_option_add(rootopt, &opt, hook, 0, "db", "Options for the libpreludedb plugin",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, db_activate, NULL);
        if ( ret < 0 )
                return ret;

        prelude_plugin_set_activation_option(pe, opt, db_init);

        ret = prelude_option_add(opt, NULL, hook, 't', "type", "Type of database (mysql/pgsql)",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_type, db_get_type);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 'l', "log",
                                 "Log all queries in a file, should be only used for debugging purpose",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, db_set_log, db_get_log);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 'h', PRELUDEDB_SQL_SETTING_HOST,
                                 "The host where the database server is running (in case of client/server database)",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED,  db_set_host, db_get_host);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 'f', PRELUDEDB_SQL_SETTING_FILE,
                                 "The file where the database is stored (in case of file based database)",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED,  db_set_file, db_get_file);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 'p', PRELUDEDB_SQL_SETTING_PORT,
                                 "The port where the database server is listening (in case of client/server database)",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_port, db_get_port);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 'd', PRELUDEDB_SQL_SETTING_NAME,
                                 "The name of the database where the alerts will be stored",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_name, db_get_name);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 'u', PRELUDEDB_SQL_SETTING_USER,
                                 "User of the database (in case of client/server database)",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_user, db_get_user);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 'P', PRELUDEDB_SQL_SETTING_PASS,
                                 "Password for the user (in case of client/server database)",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, db_set_pass, db_get_pass);
        if ( ret < 0 )
                return ret;

        prelude_plugin_set_name(&db_plugin, "db");
        prelude_plugin_set_destroy_func(&db_plugin, db_destroy);
        manager_report_plugin_set_running_func(&db_plugin, db_run);

        prelude_plugin_entry_set_plugin(pe, (void *) &db_plugin);

        return 0;
}



int db_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}
