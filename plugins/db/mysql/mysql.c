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


static int is_enabled = 0;
static plugin_db_t plugin;
static char *dbhost = NULL;
static char *dbname = NULL;
static char *dbuser = NULL;
static char *dbpass = NULL;
static MYSQL *connection = NULL, mysql;



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




/*
 * insert the given values into the given db table.
 */
static int db_insert(char *table, char *fields, char *values)
{
        int ret = 0;
        char query[MAX_QUERY_LENGTH];
        
        snprintf(query, sizeof(query),
                 "INSERT INTO %s (%s) VALUES(%s)", table, fields, values);
                
        ret = mysql_query(&mysql, query);
        if ( ret ) {
                log(LOG_ERR, "Query \"%s\" returned %d\n", query, ret);
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

        if ( ! dbhost || ! dbname ) {
                log(LOG_INFO, "MySQL logging not enabled because dbhost / dbname information missing.\n");
                return -1;
        }
        
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



static int set_dbhost(const char *optarg) 
{
        dbhost = strdup(optarg);
        return prelude_option_success;
}



static int set_dbname(const char *optarg) 
{
        dbname = strdup(optarg);
        return prelude_option_success;
}


static int set_dbuser(const char *optarg) 
{
        dbuser = strdup(optarg);
        return prelude_option_success;
}


static int set_dbpass(const char *optarg) 
{
        dbpass = strdup(optarg);
        return prelude_option_success;
}


static int set_mysql_state(const char *arg) 
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



static int get_mysql_state(char *buf, size_t size) 
{
        snprintf(buf, size, "%s", (is_enabled == 1) ? "enabled" : "disabled");
        return prelude_option_success;
}



plugin_generic_t *plugin_init(int argc, char **argv)
{
        int ret;
        prelude_option_t *opt;
        
        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 0, "mysql",
                                 "Option for the MySQL plugin", no_argument,
                                 set_mysql_state, get_mysql_state);
        
        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'd', "dbhost",
                           "Tell the host where the MySQL DB is located", required_argument,
                           set_dbhost, NULL);
        
        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'n', "dbname",
                           "Tell the name of the database to use", required_argument,
                           set_dbname, NULL);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'u', "dbuser",
                           "Username to use for database login", required_argument,
                           set_dbuser, NULL);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'p', "dbpass",
                           "Password to use for database login", required_argument,
                           set_dbpass, NULL);
        
        plugin_set_name(&plugin, "MySQL");
        plugin_set_desc(&plugin, "Will log all alert to a MySQL database.");
        plugin_set_escape_func(&plugin, db_escape);
        plugin_set_insert_func(&plugin, db_insert);
        plugin_set_closing_func(&plugin, db_close);
       
	return (plugin_generic_t *) &plugin;
}




