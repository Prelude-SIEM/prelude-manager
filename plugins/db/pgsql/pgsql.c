/*****
*
* Copyright (C) 2001, 2002 Vandoorselaere Yoann <yoann@mandrakesoft.com>
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
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <libpq-fe.h>

#include "config.h"
#include "db.h"


#define MAX_QUERY_LENGTH 8192


static int is_enabled = 0;
static plugin_db_t plugin;
static char *dbhost = NULL;
static char *dbport = "5432";
static char *dbname = NULL;
static char *dbuser = NULL;
static char *dbpass = NULL;
static PGconn *pgsql = NULL;




/*
 * Escape single quote characher with a backslash.
 */
static char *db_escape(const char *str)
{
        char *ptr;
        int i, ok, len = strlen(str);

        ptr = malloc((len * 2) + 1);
        if ( ! ptr ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        for ( i = 0, ok = 0; i < len; i++ ) {

                if ( str[i] == '\'' ) {
                        ptr[ok++] = '\\';
                        ptr[ok++] = str[i];
                } else
                        ptr[ok++] = str[i];
        }

        ptr[ok] = '\0';
        
        return ptr;
}



/*
 * insert the given values into the given db table.
 */
static int db_insert(const char *query)
{
        PGresult *ret;
        
        ret = PQexec(pgsql, query);
        if ( ! ret || PQresultStatus(ret) != PGRES_COMMAND_OK ) {
        	PQclear(ret);
                log(LOG_ERR, "Query \"%s\" failed : %s.\n", query, PQerrorMessage(pgsql));
                return -1;
        }

	PQclear(ret);

        return 0;
}



/*
 * closes the DB connection.
 */
static void db_close(void)
{
        PQfinish(pgsql);
        log(LOG_INFO, "PostgreSQL connection closed.\n");
}



/*
 * Connect to the MySQL database
 */
static int db_connect(void)
{        
        /*
         * Connect to the PostgreSQL database.
         */
        pgsql = PQsetdbLogin(dbhost, dbport, NULL, NULL, dbname, dbuser, dbpass);


        if ( PQstatus(pgsql) == CONNECTION_BAD) {
                log(LOG_INFO, "PgSQL connection failed: %s", PQerrorMessage(pgsql));
                PQfinish(pgsql);
                return -1;
        }
        
        return 0;
}


static int set_dbhost(prelude_option_t *opt, const char *optarg) 
{
        dbhost = strdup(optarg);
        return prelude_option_success;
}


static int set_dbport(prelude_option_t *opt, const char *optarg) 
{
	dbport = strdup(optarg);
	return prelude_option_success;
}


static int set_dbname(prelude_option_t *opt, const char *optarg) 
{
        dbname = strdup(optarg);
        return prelude_option_success;
}


static int set_dbuser(prelude_option_t *opt, const char *optarg) 
{
        dbuser = strdup(optarg);
        return prelude_option_success;
}


static int set_dbpass(prelude_option_t *opt, const char *optarg) 
{
        dbpass = strdup(optarg);
        return prelude_option_success;
}


static int set_pgsql_state(prelude_option_t *opt, const char *arg) 
{
        int ret;
        
        if ( is_enabled == 1 ) {
                db_close();
                
                ret = plugin_unsubscribe((plugin_generic_t *) &plugin);
                if ( ret < 0 )
                        return prelude_option_error;
                is_enabled = 0;
        }

        else {
                ret = db_connect();
                if ( ret < 0 ) 
                        return -1;
                
                ret = plugin_subscribe((plugin_generic_t *) &plugin);
                if ( ret < 0 )
                        return prelude_option_error;
                
                is_enabled = 1;
        }
        
        return prelude_option_success;
}



static int get_pgsql_state(char *buf, size_t size) 
{
        snprintf(buf, size, "%s", (is_enabled == 1) ? "enabled" : "disabled");
        return prelude_option_success;
}




plugin_generic_t *plugin_init(int argc, char **argv)
{
        prelude_option_t *opt;

        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 0, "pgsql",
                                 "Option for the PgSQL plugin", no_argument,
                                 set_pgsql_state, get_pgsql_state);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'd', "dbhost",
                           "Tell the host where the PgSQL DB is located", required_argument,
                           set_dbhost, NULL);

	prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'P', "dbport",
				"Tell what port the PgSQL DB is listening to", required_argument,
				set_dbport, NULL);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'n', "dbname",
                           "Tell the name of the database to use", required_argument,
                           set_dbname, NULL);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'u', "dbuser",
                           "Username to use for database login", required_argument,
                           set_dbuser, NULL);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'p', "dbpass",
                           "Password to use for database login", required_argument,
                           set_dbpass, NULL);
        
        plugin_set_name(&plugin, "PgSQL");
        plugin_set_desc(&plugin, "Will log all alert to a PostgreSQL database.");
        plugin_set_escape_func(&plugin, db_escape);
        plugin_set_insert_func(&plugin, db_insert);
        plugin_set_closing_func(&plugin, db_close);
       
	return (plugin_generic_t *) &plugin;
}




