/*****
*
* Copyright (C) 2001 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/time.h>
#include <inttypes.h>

#include <libprelude/list.h>
#include <libprelude/common.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>

#include "plugin-db.h"
#include "idmef-db-output.h"


static LIST_HEAD(db_plugins_list);



/*
 *
 */
static int db_plugin_register(plugin_container_t *pc) 
{
        log(LOG_INFO, "\tInitialized %s.\n", pc->plugin->name);

        return plugin_register_for_use(pc, &db_plugins_list, NULL);
}




/**
 * db_plugins_insert:
 * @table: Pointer to string defining the database table.
 * @fields: Pointer to string defining the database fields.
 * @...: An undefined number of arguments to be escaped before insertion.
 *
 * This function insert all the provided argument into all active database,
 * in the table @table, and in the fields @fields (separated by a ',').
 *
 * The last argument of this function should alway be %DB_INSERT_END, to tell
 * the function about the end of the variable arguments lists.
 */
void db_plugins_insert(char *table, char *fields, ...)
{
        va_list ap;
        int ret, len;
        struct list_head *tmp;
        plugin_container_t *pc;
        char query[8192], *str, *next;
        
        va_start(ap, fields);
        
        list_for_each(tmp, &db_plugins_list) {

                pc = list_entry(tmp, plugin_container_t, ext_list);

                len = 0;

                next = va_arg(ap, char *);
                while ( next != DB_INSERT_END ) {
                        
                        str = next;
                        if ( ! str )
                                str = "";
                        
                        plugin_run_with_return_value(pc, plugin_db_t, db_escape, str, str);
                        
                        next = va_arg(ap, char *);
                        if ( next != DB_INSERT_END )
                                len += snprintf(query + len, sizeof(query) - len, "\"%s\",", str);
                        else
                                len += snprintf(query + len, sizeof(query) - len, "\"%s\"", str);
                                                
                        free(str);
                }
                
                plugin_run_with_return_value(pc, plugin_db_t, db_insert, ret, table, fields, query);
        }
        
        va_end(ap);
}



/**
 * db_plugins_insert_id:
 * @table: Pointer to string defining the database table.
 * @fields: Pointer to string defining the database fields.
 * @id: Pointer to an unsigned long.
 *
 * This function insert @id, in all active databases, in the specified table and field.
 * If id is set to %DB_INSERT_AUTOINC_ID, the database backend will automatically
 * generate a new id, which will be set in the unsigned long pointed by @id.
 */
void db_plugins_insert_id(char *table, char *field, unsigned long *id)
{
        int ret;
        struct list_head *tmp;
        plugin_container_t *pc;

        list_for_each(tmp, &db_plugins_list) {
                pc = list_entry(tmp, plugin_container_t, ext_list);
                plugin_run_with_return_value(pc, plugin_db_t,
                                             db_insert_id, ret, table, fields, id);
        }
}



/**
 * db_plugins_run:
 * @alert: Pointer to an IDMEF alert.
 *
 * Will output the IDMEF alert to all active database.
 */
void db_plugins_run(idmef_alert_t *alert) 
{
        if ( list_empty(&db_plugins_list) )
                return;

        idmef_db_output(alert);
}



/**
 * db_plugins_close:
 *
 * Tell all the active DB plugins to close connection with their
 * database.
 */
void db_plugins_close(void)
{
        plugin_db_t *plugin;
        struct list_head *tmp;
        plugin_container_t *pc;
        

        list_for_each(tmp, &db_plugins_list) {
                
                pc = list_entry(tmp, plugin_container_t, ext_list);

                plugin = (plugin_db_t *) pc->plugin;
                if ( plugin_close_func(plugin) )
                        plugin_close_func(plugin)();
        }
}



/**
 * db_plugins_init:
 * @dirname: Pointer to a directory string.
 *
 * Tell the DB plugins subsystem to load DB plugins from @dirname.
 *
 * Returns: 0 on success, -1 if an error occured.
 */
int db_plugins_init(const char *dirname) {
        int ret;
        
        ret = plugin_load_from_dir(dirname, db_plugin_register);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't load plugin subsystem.\n");
                return -1;
        }

        return 0;
}


