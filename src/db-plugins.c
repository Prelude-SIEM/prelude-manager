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
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/time.h>
#include <inttypes.h>

#include <libprelude/list.h>
#include <libprelude/prelude-log.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>

#include "plugin-db.h"
#include "idmef-db-output.h"


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




char *db_plugin_escape(const char *string) 
{                
        if ( ! string )
                string = "NULL";
        
        return db->db_escape(string);
}




void db_plugin_insert(const char *table, const char *fields, const char *fmt, ...)
{
        va_list ap;
        char query[8192];

        
        va_start(ap, fmt);
        vsnprintf(query, sizeof(query), fmt, ap);
        va_end(ap);
        
        db->db_insert(table, fields, query);
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

