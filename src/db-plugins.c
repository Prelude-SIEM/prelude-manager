/*****
*
* Copyright (C) 2001, 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <stdarg.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/time.h>
#include <inttypes.h>
#include <assert.h>

#include <libprelude/list.h>
#include <libprelude/prelude-log.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>

#include "plugin-db.h"
#include "idmef-db-output.h"

/*
 * define what we believe should be enough for most of our query.
 */
#define DB_REQUEST_LENGTH 16384

/*
 * Maximum value of a dynamically allocated buffer in case
 * DB_REQUEST_LENGTH isn't enough (the length is computed taking
 * prelude_string_to_hex() function into account).
 * 1024 : "INSERT INTO table_name (field_names ...)
 * 65536 * (3+21/16) + 1 : a 2^16 length segment logged with its hexa dump based on prelude_string_to_hex()
 * 1 : the ')' at the end of an SQL request
 */
#define DB_MAX_INSERT_QUERY_LENGTH (1024 + 65536 * (3+21/16) + 1 + 1)


static plugin_db_t *db = NULL;
static LIST_HEAD(db_plugins_list);



/*
 *
 */
static int subscribe(plugin_container_t *pc) 
{
        log(LOG_INFO, "- Subscribing %s to active database plugins.\n", pc->plugin->name);
        db = (plugin_db_t *) pc->plugin;
        return plugin_add(pc, &db_plugins_list, NULL);
}


static void unsubscribe(plugin_container_t *pc) 
{
        log(LOG_INFO, "- Un-subscribing %s from active database plugins.\n", pc->plugin->name);
        db = NULL;
        plugin_del(pc);
}




static char *generate_dynamic_query(const char *old, size_t olen,
                                    int *nlen, const char *fmt, va_list ap) 
{
        int ret;
        char *query;

        assert(olen < *nlen);
        
        query = malloc(*nlen);
        if ( ! query ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }
                
        strncpy(query, old, olen);
        ret = vsnprintf(query + olen, *nlen - olen, fmt, ap);
        
        if ( (ret + 2) > (*nlen - olen) || ret < 0 ) {
                log(LOG_ERR, "query %s doesn't fit in %d bytes.\n", query, *nlen);
                free(query);
                return NULL;
        }

        *nlen = ret + olen;
        
        return query;
}



int db_plugin_insert(const char *table, const char *fields, const char *fmt, ...)
{
        
        va_list ap;
        int len, query_length;
        char *query_dynamic = NULL;
        char query_static[DB_REQUEST_LENGTH], *query;
        
        query = query_static;
        
	len = snprintf(query_static, sizeof(query_static), "INSERT INTO %s (%s) VALUES(", table, fields);
	if ( (len + 1) > sizeof(query_static) || len < 0 ) {
                log(LOG_ERR, "start of query (%s) doesn't fit in %d bytes.\n", query, sizeof(query_static));
                return -1;
        }
        
        /*
         * These  functions  return  the number of characters printed
         * (not including the trailing `\0' used  to  end  output  to
         * strings).   snprintf  and vsnprintf do not write more than
         * size bytes (including the trailing '\0'), and return -1 if
         * the  output  was truncated due to this limit.
         */
        va_start(ap, fmt);
        query_length = vsnprintf(query_static + len, sizeof(query_static) - len, fmt, ap);
        va_end(ap);
        
        if ( (query_length + 2) > (sizeof(query_static) - len) || query_length < 0 ) {
                
                if ( query_length < 0 )
                        query_length = DB_MAX_INSERT_QUERY_LENGTH;
                else 
                        query_length += len + 2;

                va_start(ap, fmt);
                query_dynamic = generate_dynamic_query(query_static, len, &query_length, fmt, ap);
                va_end(ap);
                
                if ( ! query_dynamic )
                        return -1;

                len = 0;
                query = query_dynamic;
        }

        query[query_length + len] = ')';
	query[query_length + len + 1] = '\0';
	
        db->db_insert(query);

	if ( query_dynamic )
                free(query_dynamic);

        return 0;
}





char *db_plugin_escape(const char *string) 
{                
        if ( ! string )
                string = "NULL";
        
        return db->db_escape(string);
}




/**
 * db_plugins_run:
 * @idmef: Pointer to an IDMEF message.
 *
 * Will output the IDMEF message to all active database.
 */
void db_plugins_run(idmef_message_t *idmef) 
{
        if ( ! db )
                return;

        idmef_db_output(idmef);
}




void db_plugins_close(void)
{        
        if ( plugin_close_func(db) )
                plugin_close_func(db)();
}




/**
 * db_plugins_init:
 * @dirname: Pointer to a directory string.
 * @argc: Number of command line argument.
 * @argv: Array containing the command line arguments.
 *
 * Tell the DB plugins subsystem to load DB plugins from @dirname.
 *
 * Returns: 0 on success, -1 if an error occured.
 */
int db_plugins_init(const char *dirname, int argc, char **argv)
{
        int ret;
	
	ret = access(dirname, F_OK);
	if ( ret < 0 ) {
		if ( errno == ENOENT )
			return 0;
		log(LOG_ERR, "can't access %s.\n", dirname);
		return -1;
	}

        ret = plugin_load_from_dir(dirname, argc, argv, subscribe, unsubscribe);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't load plugin subsystem.\n");
                return -1;
        }

        return ret;
}



/**
 * db_plugins_available:
 *
 * Returns: 0 if there is active DB plugins, -1 otherwise.
 */
int db_plugins_available(void) 
{
        return list_empty(&db_plugins_list) ? -1 : 0;
}

