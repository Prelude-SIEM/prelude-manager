/*****
*
* Copyright (C) 2001 Vandoorselaere Yoann <yoann@mandrakesoft.com>
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


static char *dbhost = NULL;
static char *dbport = NULL;
static char *dbname = NULL;
static char *dbuser = NULL;
static char *dbpass = NULL;
static PGconn *pgsql;




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
static int db_insert(char *table, char *fields, char *values)
{
        PGresult *ret;
        char query[8192];

        snprintf(query, sizeof(query), "INSERT INTO %s (%s) VALUES(%s)", table, fields, values);
        
        ret = PQexec(pgsql, query);
        if ( ! ret || PQresultStatus(ret) != PGRES_COMMAND_OK ) {
                log(LOG_ERR, "Query \"%s\" failed : %s.\n", query, PQerrorMessage(pgsql));
                return -1;
        }

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



static void set_dbhost(const char *optarg) 
{
        dbhost = strdup(optarg);
}



static void set_dbname(const char *optarg) 
{
        dbname = strdup(optarg);
}


static void set_dbuser(const char *optarg) 
{
        dbuser = strdup(optarg);
}


static void set_dbpass(const char *optarg) 
{
        dbpass = strdup(optarg);
}



static void print_help(const char *optarg) 
{
        fprintf(stderr, "Usage for PgSQL :\n");
        fprintf(stderr, "-d --dbhost Tell the host where the MySQL DB is located.\n");
        fprintf(stderr, "-n --dbname Tell the name of the database to use.\n");
        fprintf(stderr, "-u --dbuser Username to use for database login.\n");
        fprintf(stderr, "-p --dbpass Password to use for database login.\n");
}




int plugin_init(unsigned int id)
{
        int ret;
        static plugin_db_t plugin;
        plugin_option_t opts[] = {
                { "dbhost", required_argument, NULL, 'd', set_dbhost },
                { "dbname", required_argument, NULL, 'n', set_dbname },
                { "dbuser", required_argument, NULL, 'u', set_dbuser },
                { "dbpass", required_argument, NULL, 'p', set_dbpass },
                { "help", no_argument, NULL, 'h', print_help         },
                { 0, 0, 0, 0 },
        };

        plugin_set_name(&plugin, "PgSQL");
        plugin_set_desc(&plugin, "Will log all alert to a PostgreSQL database.");
        plugin_set_escape_func(&plugin, db_escape);
        plugin_set_insert_func(&plugin, db_insert);
        plugin_set_closing_func(&plugin, db_close);
        
        plugin_config_get((plugin_generic_t *)&plugin, opts, PRELUDE_MANAGER_CONF);
        
        /*
         * connect to db or exit
         */
        ret = db_connect();
        if ( ret < 0 ) 
                return -1;
       
	return plugin_register((plugin_generic_t *)&plugin);
}




