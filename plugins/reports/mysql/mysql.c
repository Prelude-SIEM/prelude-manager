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

/*
 * Temporary hack.
 */
#define dprintf(comment, string) if ( string ) printf(comment, string)

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
                return;
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


static void print_address(char * alert_ident, idmef_address_t *addr) 
{
        char values[MAX_QUERY_LENGTH];
        char * ident; char * vlan_name; char * vlan_num; char * address;
        char * netmask;

        static char * category_names[] = { "unknown", "atm", "e-mail",
                                           "lotus-notes", "mac", "sna", "vm",
                                           "ipv4-addr", "ipv4-addr-hex",
                                           "ipv4-net", "ipv4-net-mask",
                                           "ipv6-addr", "ipv6-addr-hex",
                                           "ipv6-net", "ipv6-net-mask" };

        /* TODO: parent_type */
        ident = db_escape(addr->ident);
        vlan_name = db_escape(addr->vlan_name);
        address = db_escape(addr->address);
        netmask = db_escape(addr->netmask);

        /* prepare values */
        snprintf(values, MAX_QUERY_LENGTH, "%s, %s, %s, %d, %s, %s",
                 alert_ident, ident, category_names[addr->category], vlan_name,
                 vlan_num, address, netmask);

        /* free memory allocated by db_escape() */
        free(ident);
        free(vlan_name);
        free(address);
        free(netmask);
}



static void print_node(char * alert_ident, idmef_node_t *node) 
{
        struct list_head *tmp;
        idmef_address_t *addr;
        char values[MAX_QUERY_LENGTH];
        char * ident; char * location; char * name;

        static char * category_names[] = { "unknown", "ads", "afs", "coda",
                                           "dfs", "dns", "kerberos", "nds",
                                           "nis", "nisplus", "nt", "wfw" };

        /* TODO: parent_type */
        ident = db_escape(node->ident);
        location = db_escape(node->location);
        name = db_escape(node->name);

        /* prepare values */
        snprintf(values, MAX_QUERY_LENGTH, "%s, %s, %s",
                 alert_ident, ident, category_names[node->category], location,
                 name);

        db_insert("Prelude_Node",
                  "alert_ident, ident, category, location, name", values);

        /* free memory allocated by db_escape() */
        free(ident);
        free(location);
        free(name);

        list_for_each(tmp, &node->address_list) {
                addr = list_entry(tmp, idmef_address_t, list);
                print_address(alert_ident, addr);
        }
}




static void print_userid(char * alert_ident, idmef_userid_t *uid) 
{
        char values[MAX_QUERY_LENGTH];
        char * ident; char * name; char * number;

        static char * type_names[] = { "current-user", "original-user",
                                       "target-user", "user-privs",
                                       "current-group", "group-privs" };

        /* TODO: parent_type */
        ident = db_escape(uid->ident);
        name = db_escape(uid->name);
        number = db_escape(uid->number);

        /* prepare values */
        snprintf(values, MAX_QUERY_LENGTH, "%s, %s, %s",
                 alert_ident, ident, type_names[uid->type], name, number);

        db_insert("Prelude_UserId", "alert_ident, ident, type, name, number",
                  values);

        /* free memory allocated by db_escape() */
        free(ident);
        free(name);
        free(number);
}




static void print_user(char * alert_ident, idmef_user_t *user) 
{
        idmef_userid_t *uid;
        struct list_head *tmp;
        char values[MAX_QUERY_LENGTH];
        char * ident;

        static char * category_names[] = { "unknown", "applicatioin",
                                           "os-device" };

        /* TODO: parent_type */
        ident = db_escape(user->ident);

        /* prepare values */
        snprintf(values, MAX_QUERY_LENGTH, "%s, %s, %s",
                 alert_ident, ident, category_names[user->category]);

        /* free memory allocated by db_escape() */
        free(ident);

        list_for_each(tmp, &user->userid_list) {
                uid = list_entry(tmp, idmef_userid_t, list);
                print_userid(alert_ident, uid);
        }
}



static void print_process(char * alert_ident, idmef_process_t *process) 
{
        char values[MAX_QUERY_LENGTH];
        char * ident; char * name; char * path;

        /* TODO: parent_type */
        ident = db_escape(process->ident);
        name = db_escape(process->name);
        path = db_escape(process->path);

        /* prepare values */
        snprintf(values, MAX_QUERY_LENGTH, "%s, %s, %d, %s",
                 alert_ident, ident, name, process->pid, path);

        db_insert("Prelude_Process", "alert_ident, ident, name, pid, path",
                  values);

        /* free memory allocated by db_escape() */
        free(ident);
        free(name);
        free(path);

        /*
         * Print arg and env.
         */
}



static void print_service(char * alert_ident, idmef_service_t *service) 
{
        char values[MAX_QUERY_LENGTH];
        char * ident; char * name;
        char * portlist; char * protocol;

        /* TODO: parent_type
         *       inset portlist into Prelude_ServicePortList
         */
        ident = db_escape(service->ident);
        name = db_escape(service->name);
        protocol = db_escape(service->protocol);

        /* prepare values */
        snprintf(values, MAX_QUERY_LENGTH, "%s, %s, %s, %d, %s",
                 alert_ident, ident, name, service->port, protocol);

        db_insert("Prelude_Service", "alert_ident, ident, "
                                     "name, port, protocol", values);

        /* free memory allocated by db_escape() */
        free(ident);
        free(name);
        free(protocol);

        /*
         * Wev / Snmp service.
         */
}


static void print_source(char * alert_ident,
                         idmef_source_t *source,
                         const char *str) 
{
        struct list_head *tmp;
        idmef_address_t *addr;
        char values[MAX_QUERY_LENGTH];
        char * ident; char * interface;

        static char * spoofed_names[] = { "unknown", "yes", "no" };

        /* escape SQL special chars */
        ident = db_escape(source->ident);
        interface = db_escape(source->interface);

        /* prepare values */
        snprintf(values, MAX_QUERY_LENGTH, "%s, %s, %s, %s",
                 alert_ident, ident, spoofed_names[source->spoofed],
                 interface);
        
        db_insert("Prelude_Source", "alert_ident, ident, spoofed, interface",
                  values);

        /* free memory allocated by db_escape() */
        free(ident);
        free(interface);

        print_node(alert_ident, &source->node);
        print_user(alert_ident, &source->user);
        print_process(alert_ident, &source->process);

        /* TODO: give info about prelude_type */
        print_service(alert_ident, &source->service);
}

static void print_analyzer(char * parent_ident,
                           idmef_analyzer_t *analyzer) 
{
        char values[MAX_QUERY_LENGTH];
        char * analyzerid; char * manufacturer; char * model;
        char * version; char * class;

        /* escape SQL special chars */
        analyzerid = db_escape(analyzer->analyzerid);
        manufacturer = db_escape(analyzer->manufacturer);
        model = db_escape(analyzer->model);
        version = db_escape(analyzer->version);
        class = db_escape(analyzer->class);

        /* prepare values */
        /* TODO: fill the parent_type value */
        snprintf(values, MAX_QUERY_LENGTH,
                 "%s, %s, %s, %s, %s, %s",
                 parent_ident, analyzerid, manufacturer, model, version, class);

        db_insert("Prelude_Analyzer",
                  "parent_ident, analyzerid, manufacturer, "
                  "model, version, class",
                  values);

        /* free memory allocated by db_escape() */
        free(analyzerid);
        free(manufacturer);
        free(model);
        free(version);
        free(class);
}


static void print_classification(char * alert_ident,
                                 idmef_classification_t *class) 
{
        char values[MAX_QUERY_LENGTH];
        char * origin; char * name; char * url;

        static char * origin_names[] = { "unknown", "bugtraqid", "cve", 
                                         "vendor_specific" };

        /* escape SQL special chars */
        name = db_escape(class->name);
        url = db_escape(class->url);

        /* prepare values */
        snprintf(values, MAX_QUERY_LENGTH, "%s, %s, %s, %s",
                 alert_ident, origin_names[class->origin], name, url);

        /* insert into DB */
        db_insert("Prelude_Classification", "ident, origin, name, url", values);

        /* free memory allocated by db_escape() */
        free(origin);
        free(name);
        free(url);
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
        free(impact);
        free(action);

        print_analyzer(ident, &alert->analyzer);
        
        list_for_each(tmp, &alert->source_list) {
                source = list_entry(tmp, idmef_source_t, list);
                print_source(ident, source, "Source");
        }

        list_for_each(tmp, &alert->target_list) {
                source = list_entry(tmp, idmef_source_t, list);
                print_source(ident, source, "Target");
        }

        list_for_each(tmp, &alert->classification_list) {
                class = list_entry(tmp, idmef_classification_t, list);
                print_classification(ident, class);
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
        
        plugin_config_get((plugin_generic_t *)&plugin, opts, PRELUDE_MANAGER_CONF);
        
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
