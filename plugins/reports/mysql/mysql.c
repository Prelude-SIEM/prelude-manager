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




static void print_address(const char *alert_ident, const char *parent_ident,
                          const char parent_type, const char *node_ident,
                          const idmef_address_t *addr) 
{
        char query[MAX_QUERY_LENGTH];
        char *ident, *vlan_name, *address, *netmask, *category;
                
        ident = db_escape(addr->ident);
        vlan_name = db_escape(addr->vlan_name);
        address = db_escape(addr->address);
        netmask = db_escape(addr->netmask);
        category = db_escape(idmef_address_category_to_string(addr->category));
        
        /*
         * prepare values
         */
        snprintf(query, sizeof(query), "\"%s\", \"%c\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%d\", \"%s\", \"%s\"",
                 alert_ident, parent_type, parent_ident, node_ident, ident,
                 category, vlan_name, addr->vlan_num, address, netmask);

        db_insert("Prelude_Address",
                  "alert_ident, parent_type, parent_ident, node_ident, ident, "
                  "category, vlan_name, vlan_num, address, netmask", query);
        
        /*
         * free memory allocated by db_escape()
         */
        free(ident);
        free(vlan_name);
        free(address);
        free(netmask);
        free(category);
}




static void print_node(const char *alert_ident, const char *parent_ident,
                       const char parent_type, const idmef_node_t *node) 
{
        struct list_head *tmp;
        idmef_address_t *addr;
        char query[MAX_QUERY_LENGTH];
        char *ident, *location, *name, *category;
        
        name = db_escape(node->name);
        ident = db_escape(node->ident);
        location = db_escape(node->location);
        category = db_escape(idmef_node_category_to_string(node->category));        
        
        /*
         * prepare query
         */
        snprintf(query, sizeof(query), "\"%s\", \"%c\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"",
                 alert_ident, parent_type, parent_ident, ident, category, location, name);

        db_insert("Prelude_Node",
                  "alert_ident, parent_type, parent_ident, ident, category, location, name", query);
        
        /*
         * free memory allocated by db_escape()
         */
        free(name);
        free(ident);
        free(location);
        free(category);
        
        list_for_each(tmp, &node->address_list) {
                addr = list_entry(tmp, idmef_address_t, list);
                print_address(alert_ident, parent_ident, parent_type, ident, addr);
        }
}




static void print_userid(const char *parent_ident, const idmef_userid_t *uid) 
{
        char query[MAX_QUERY_LENGTH];
        char *ident, *name, *number, *type;
        
        name = db_escape(uid->name);
        ident = db_escape(uid->ident);
        number = db_escape(uid->number);
        type = db_escape(idmef_userid_type_to_string(uid->type));
        
        /*
         * prepare query
         */
        snprintf(query, sizeof(query), "\"%s\", \"%s\", \"%s\", \"%s\", \"%s\"",
                 parent_ident, ident, type, name, number);

        db_insert("Prelude_UserId", "parent_ident, ident, type, name, number", query);

        /*
         * free memory allocated by db_escape()
         */
        free(name);
        free(type);
        free(ident);
        free(number);
        
        
}




static void print_user(const char *alert_ident, const char *parent_ident,
                       const char parent_type, const idmef_user_t *user) 
{
        idmef_userid_t *uid;
        struct list_head *tmp;
        char query[MAX_QUERY_LENGTH], *ident, *category;
        
        ident = db_escape(user->ident);
        category = db_escape(idmef_user_category_to_string(user->category));
        
        /*
         * prepare query
         */
        snprintf(query, sizeof(query), "\"%s\", \"%c\", \"%s\", \"%s\", \"%s\"",
                 alert_ident, parent_type, parent_ident, ident, category);

        db_insert("Prelude_User", "alert_ident, parent_type, parent_ident, ident, category", query);
        
        /*
         * free memory allocated by db_escape()
         */
        free(ident);
        free(category);
        
        list_for_each(tmp, &user->userid_list) {
                uid = list_entry(tmp, idmef_userid_t, list);
                print_userid(alert_ident, uid);
        }
}



static void print_process(const char *alert_ident, const char *parent_ident,
                          const char parent_type, const idmef_process_t *process) 
{
        char query[MAX_QUERY_LENGTH], *ident, *name, *path;
        
        ident = db_escape(process->ident);
        name = db_escape(process->name);
        path = db_escape(process->path);

        /*
         * prepare query
         */
        snprintf(query, sizeof(query), "\"%s\", \"%c\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"",
                 alert_ident, parent_type, parent_ident, ident, name, process->pid, path);

        db_insert("Prelude_Process", "alert_ident, parent_type, parent_ident, ident, name, pid, path",
                  query);

        /*
         * free memory allocated by db_escape()
         */
        free(ident);
        free(name);
        free(path);
}



static void print_service(const char *alert_ident, const char *parent_ident,
                          const char parent_type, const idmef_service_t *service) 
{
        char query[MAX_QUERY_LENGTH];
        char *ident, *name, *protocol;

        /* TODO: 
         *       insert portlist into Prelude_ServicePortList
         */
        name = db_escape(service->name);
        ident = db_escape(service->ident);
        protocol = db_escape(service->protocol);

        /*
         * prepare query
         */
        snprintf(query, sizeof(query), "\"%s\", \"%c\", \"%s\", \"%s\", \"%s\", \"%d\", \"%s\"", alert_ident,
                 parent_type, parent_ident, ident, name, service->port, protocol);

        db_insert("Prelude_Service", "alert_ident, parent_type, parent_ident, ident, "
                  "name, port, protocol", query);

        /*
         * free memory allocated by db_escape()
         */
        free(name);
        free(ident);
        free(protocol);
}




static void print_source(const char *alert_ident, const idmef_source_t *source)
{
        char query[MAX_QUERY_LENGTH], *ident, *interface, *spoofed;

        /*
         * escape SQL special chars
         */
        ident = db_escape(source->ident);
        interface = db_escape(source->interface);
        spoofed = db_escape(idmef_source_spoofed_to_string(source->spoofed));
        
        /*
         * prepare query
         */
        snprintf(query, sizeof(query), "\"%s\", \"%s\", \"%s\", \"%s\"",
                 alert_ident, ident, spoofed, interface);
        
        db_insert("Prelude_Source", "alert_ident, ident, spoofed, interface", query);

        /*
         * free memory allocated by db_escape()
         */
        free(spoofed);
        free(interface);

        print_node(alert_ident, ident, 'S', &source->node);
        print_user(alert_ident, ident, 'S', &source->user);
        print_process(alert_ident, ident, 'S', &source->process);
        print_service(alert_ident, ident, 'S', &source->service);

        free(ident);
}



static void print_target(const char *alert_ident, const idmef_target_t *target)
{
        char query[MAX_QUERY_LENGTH], *ident, *interface, *decoy;

        /*
         * escape SQL special chars
         */
        ident = db_escape(target->ident);
        interface = db_escape(target->interface);
        decoy = db_escape(idmef_target_decoy_to_string(target->decoy));
        
        /*
         * prepare query
         */
        snprintf(query, sizeof(query), "\"%s\", \"%s\", \"%s\", \"%s\"",
                 alert_ident, ident, decoy, interface);
        
        db_insert("Prelude_Source", "alert_ident, ident, spoofed, interface", query);

        /* free memory allocated by db_escape() */
        free(decoy);
        free(interface);

        print_node(alert_ident, ident, 'T', &target->node);
        print_user(alert_ident, ident, 'T', &target->user);
        print_process(alert_ident, ident, 'T', &target->process);
        print_service(alert_ident, ident, 'T', &target->service);

        free(ident);
}



static void print_analyzer(const char *parent_ident, const idmef_analyzer_t *analyzer) 
{
        char query[MAX_QUERY_LENGTH], parent_type;
        char *analyzerid, *manufacturer, *model, *version, *class;

        parent_type = 'A';
        
        /*
         * escape SQL special chars
         */
        analyzerid = db_escape(analyzer->analyzerid);
        manufacturer = db_escape(analyzer->manufacturer);
        model = db_escape(analyzer->model);
        version = db_escape(analyzer->version);
        class = db_escape(analyzer->class);

        /*
         * prepare query
         */ 
        snprintf(query, sizeof(query), "\"%s\", \"%c\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"",
                 parent_ident, parent_type, analyzerid, manufacturer, model, version, class);

        db_insert("Prelude_Analyzer", "parent_ident, parent_type, analyzerid, "
                  "manufacturer, model, version, class", query);
        
        print_node(parent_ident, analyzerid, 'A', &analyzer->node);
        print_process(parent_ident, analyzerid, 'A', &analyzer->process);
        
        /*
         * free memory allocated by db_escape()
         */
        free(analyzerid);
        free(manufacturer);
        free(model);
        free(version);
        free(class);
}




static void print_classification(const char *alert_ident, const idmef_classification_t *class) 
{
        char *name, *url, *origin;
        char query[MAX_QUERY_LENGTH];
        

        /*
         * escape SQL special chars
         */
        url = db_escape(class->url);
        name = db_escape(class->name);
        origin = db_escape(idmef_classification_origin_to_string(class->origin));
        
        /*
         * prepare query
         */
        snprintf(query, sizeof(query), "\"%s\", \"%s\", \"%s\", \"%s\"",
                 alert_ident, origin, name, url);

        /*
         * insert into DB
         */
        db_insert("Prelude_Classification", "alert_ident, origin, name, url", query);

        /*
         * free memory allocated by db_escape()
         */
        free(url);
        free(name);
        free(origin);
}



static void print_data(const char *parent_ident, const idmef_additional_data_t *ad) 
{
        char query[MAX_QUERY_LENGTH];
        char parent_type, *meaning, *data, *type;
        
        /*
         * should be A (alert) or H (heartbeat). 
         */
        parent_type = 'A';

        data = db_escape(ad->data);
        meaning = db_escape(ad->meaning);
        type = db_escape(idmef_additional_data_type_to_string(ad->type));
        
        snprintf(query, sizeof(query), "\"%s\", \"%c\", \"%s\", \"%s\", \"%s\"",
                 parent_ident, parent_type, type, meaning, data);

        db_insert("Prelude_AdditionalData", "parent_ident, parent_type, type, meaning, data", query);

        free(data);
        free(meaning);
}




static void print_alert(idmef_alert_t *alert) 
{
        struct list_head *tmp;
        idmef_source_t *source;
        idmef_target_t *target;

        char query[MAX_QUERY_LENGTH];
        char *ident, *impact, *action;

        idmef_classification_t *class;
        idmef_additional_data_t *data;
        
        /*
         * escape SQL special chars
         */
        ident = db_escape(alert->ident);
        impact = db_escape(alert->impact);
        action = db_escape(alert->action);

        /*
         * prepare query
         */
        snprintf(query, sizeof(query),
                 "\"%s\", \"%s\", \"%s\"", ident, impact, action);

        /* insert into DB */
        db_insert("Prelude_Alert", "ident, impact, action", query);

        /* free memory allocated by db_escape() */
        free(impact);
        free(action);

        print_analyzer(ident, &alert->analyzer);
        
        list_for_each(tmp, &alert->source_list) {
                source = list_entry(tmp, idmef_source_t, list);
                print_source(ident, source);
        }

        list_for_each(tmp, &alert->target_list) {
                target = list_entry(tmp, idmef_target_t, list);
                print_target(ident, target);
        }

        list_for_each(tmp, &alert->classification_list) {
                class = list_entry(tmp, idmef_classification_t, list);
                print_classification(ident, class);
        }
        

        list_for_each(tmp, &alert->additional_data_list) {
                data = list_entry(tmp, idmef_additional_data_t, list);
                print_data(ident, data);
        }

        /* free memory allocated by db_escape() */
        free(ident);
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
        
        plugin_config_get((plugin_generic_t *)&plugin, opts, PRELUDE_MANAGER_CONF);
        if ( ! dbhost || ! dbname )
                return -1;
        
        /*
         * connect to db or exit
         */
        ret = db_connect();
        if ( ret < 0 ) 
                return -1;
       
	return plugin_register((plugin_generic_t *)&plugin);
}
