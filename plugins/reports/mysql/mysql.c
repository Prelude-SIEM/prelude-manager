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
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include <mysql/mysql.h>

#include "config.h"
#include "report.h"


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
                return;
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
        char insert_query[MAX_QUERY_LENGTH];

        snprintf(insert_query, MAX_QUERY_LENGTH,
                 "INSERT INTO %s (%s) VALUES(%s)",
                 table, fields, values);

        if ( (ret = db_query(insert_query)) ) {
                printf("db_query returned %d\n", ret);
                ret = -1;
        }
        
        return ret;
}




static void print_address(idmef_address_t *addr) 
{
        printf("   Address information:\n");
        printf("    - ident: %s\n", addr->ident);
        printf("    - category: %d\n", addr->category);
        printf("    - vlan-name: %s\n", addr->vlan_name);
        printf("    - vlan-num: %d\n", addr->vlan_num);
        printf("    - Address: %s\n", addr->address);
        printf("    - Netmask: %s\n", addr->netmask);
}



static void print_node(idmef_node_t *node) 
{
        struct list_head *tmp;
        idmef_address_t *addr;
        
        printf("  Node information :\n");
        printf("   - ident: %s\n", node->ident);
        printf("   - category: %d\n", node->category);
        printf("   - location: %s\n", node->location);
        printf("   - name: %s\n", node->name);

        list_for_each(tmp, &node->address_list) {
                addr = list_entry(tmp, idmef_address_t, list);
                print_address(addr);
        }
}




static void print_userid(idmef_userid_t *uid) 
{
        printf(" Userid information\n");
        printf("  - ident: %s\n", uid->ident);
        printf("  - type: %d\n", uid->type);
        printf("  - name: %s\n", uid->name);
        printf("  - number: %s\n", uid->number);
}




static void print_user(idmef_user_t *user) 
{
        idmef_userid_t *uid;
        struct list_head *tmp;

        printf("  User information\n");
        printf("   - ident: %s\n", user->ident);
        printf("   - category: %d\n", user->category);

        list_for_each(tmp, &user->userid_list) {
                uid = list_entry(tmp, idmef_userid_t, list);
                print_userid(uid);
        }
}



static void print_process(idmef_process_t *process) 
{
        printf("  Process information\n");
        printf("   - ident: %s\n", process->ident);
        printf("   - name: %s\n", process->name);
        printf("   - pid: %s\n", process->pid);
        printf("   - path: %s\n", process->path);

        /*
         * Print arg and env.
         */
}



static void print_service(idmef_service_t *service) 
{
        printf("  Service information\n");
        printf("   - ident: %s\n", service->ident);
        printf("   - name: %s\n", service->name);
        printf("   - port: %d\n", service->port);
        printf("   - portlist: %s\n", service->portlist);
        printf("   - protocol: %s\n", service->protocol);

        /*
         * Wev / Snmp service.
         */
}


static void print_source(idmef_source_t *source, const char *str) 
{
        struct list_head *tmp;
        idmef_address_t *addr;

        printf(" %s information :\n", str);
        printf("  - ident: %s\n", source->ident);
        printf("  - spoofed: %d\n", source->spoofed);
        printf("  - interface: %s\n", source->interface);

        print_node(&source->node);
        print_user(&source->user);
        print_process(&source->process);
        print_service(&source->service);
}



static void print_analyzer(idmef_analyzer_t *analyzer) 
{
        printf(" Analyzer Informations :\n");
        printf("  id: %s\n", analyzer->analyzerid);
        printf("  manufacturer: %s\n", analyzer->manufacturer);
        printf("  model: %s\n", analyzer->model);
        printf("  version: %s\n", analyzer->version);
        printf("  class: %s\n", analyzer->class);
}


static void print_classification(idmef_classification_t *class) 
{
        printf(" Classification Informations :\n");
        printf("  - origin: %d\n", class->origin);
        printf("  - name: %s\n", class->name);
        printf("  - url: %s\n", class->url);
}



static void print_alert(idmef_alert_t *alert) 
{
        char values[MAX_QUERY_LENGTH];
        char * ident; char * impact; char * action;

        struct list_head *tmp;
        idmef_source_t *source;
        idmef_classification_t *class;
        
        /* escape SQL special chars */
        ident = db_escape(alert->ident);
        impact = db_escape(alert->impact);
        action = db_escape(alert->action);

        /* prepare values */
        snprintf(values, MAX_QUERY_LENGTH,
                 "%s, %s, %s", ident, impact, action);

        /* insert into DB */
        db_insert("Prelude_Alert", "ident, impact, action", values);

        /* free memory allocated by db_escape() */
        free(ident);
        free(impact);
        free(action);

        print_analyzer(&alert->analyzer);
        
        list_for_each(tmp, &alert->source_list) {
                source = list_entry(tmp, idmef_source_t, list);
                print_source(source, "Source");
        }

        list_for_each(tmp, &alert->target_list) {
                source = list_entry(tmp, idmef_source_t, list);
                print_source(source, "Target");
        }

        list_for_each(tmp, &alert->classification_list) {
                class = list_entry(tmp, idmef_classification_t, list);
                print_classification(class);
        }
}




/*
 * plugin callback
 */
static void db_run(idmef_alert_t *alert)
{
        print_alert(alert);
}




/*
 * closes the DB connection.
 */
static void db_close(void)
{
        mysql_close(connection);
        printf("mysql connection closed\n");
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
                log(LOG_INFO, "%s", mysql_error(&mysql));
                return -1;
        }

        /*
         * select which database to use on the server
         */
        state = mysql_select_db(connection, dbname);

        /* -1 means an error occurred */
        if (state == -1) {
                log(LOG_INFO, "%s", mysql_error(connection));
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
        static plugin_report_t plugin;
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
        plugin_set_running_func(&plugin, db_run);
        plugin_set_closing_func(&plugin, db_close);
        
        plugin_config_get((plugin_generic_t *)&plugin, opts, PRELUDE_REPORT_CONF);
        
        if ( !dbhost || !dbname || !dbuser || !dbpass )
                return -1;
        
        /* connect to db or exit */
        ret = db_connect();
        if ( ! ret ) {
                printf("db_connect returned %d\n", ret);
                return -1;
        }
       
	return plugin_register((plugin_generic_t *)&plugin);
}
