/*****
*
* Copyright (C) 2001 Vandoorselaere Yoann <yoann@mandrakesoft.com>
* Copyright (C) 2001 Sylvain GIL <prelude@tootella.org>
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

#include <mysql/mysql.h>

#include "config.h"
#include "db.h"


#define MAX_QUERY_LENGTH 8192


static char *dbhost = NULL;
static char *dbname = NULL;
static char *dbuser = NULL;
static char *dbpass = NULL;
static MYSQL *connection, mysql;



/*
 * Takes a string and create a legal SQL string from it.
 * returns the escaped string.
 */
static char *db_escape(const char *string)
{
        char *escaped;

        if ( ! string )
                string = "";
        
        /*
         * MySQL documentation say :
         * The string pointed to by from must be length bytes long. You must
         * allocate the to buffer to be at least length*2+1 bytes long. (In the
         * worse case, each character may need to be encoded as using two bytes,
         * and you need room for the terminating null byte.)
         */
        escaped = malloc(strlen(string) * 2 + 1);
        if (! escaped) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        mysql_real_escape_string(&mysql, escaped, string, strlen(string));

        return escaped;
}


static int db_query(char * query)
{
        int ret = -1;

        ret = mysql_query(&mysql, query);

        return ret;
}



/*
 * insert the given values into the given db table.
 */
static int db_insert(char *table, char *fields, char *values)
{
        int ret = 0;
        char query[MAX_QUERY_LENGTH];

        snprintf(query, sizeof(query),
                 "INSERT INTO %s (%s) VALUES(%s)", table, fields, values);

                
        ret = db_query(query);
        if ( ret ) {
                log(LOG_ERR, "db_query \"%s\" returned %d\n", query, ret);
                ret = -1;
        }

        return ret;
}




/*
 * closes the DB connection.
 */
static void db_close(void)
{
        mysql_close(connection);
        log(LOG_INFO, "mysql connection closed.\n");
}



/*
 * Connect to the MySQL database
 */
static int db_connect(void)
{
        int state;

        /*
         * connect to the mySQL database
         */
        connection = mysql_connect(&mysql, dbhost, dbuser, dbpass);        
        if ( ! connection ) {
                log(LOG_INFO, "%s\n", mysql_error(&mysql));
                return -1;
        }

        /*
         * select which database to use on the server
         */
        state = mysql_select_db(connection, dbname);

        /* -1 means an error occurred */
        if (state == -1) {
                log(LOG_INFO, "%s\n", mysql_error(connection));
                mysql_close(connection);
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
        fprintf(stderr, "Usage for MySQL :\n");
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

        plugin_set_name(&plugin, "MySQL");
        plugin_set_desc(&plugin, "Will log all alert to a MySQL database.");
        plugin_set_running_func(&plugin, db_insert);
        plugin_set_closing_func(&plugin, db_close);
        
        plugin_config_get((plugin_generic_t *)&plugin, opts, PRELUDE_MANAGER_CONF);
        if ( ! dbhost || ! dbname ) {
                log(LOG_INFO, "MySQL logging not enabled because dbhost / dbname information missing.\n");
                return -1;
        }
        
        /*
         * connect to db or exit
         */
        ret = db_connect();
        if ( ret < 0 ) 
                return -1;
       
	return plugin_register((plugin_generic_t *)&plugin);
}




