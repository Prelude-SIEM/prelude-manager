/*****
*
* Copyright (C) 1998 - 2000 Vandoorselaere Yoann <yoann@mandrakesoft.com>
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

#include "config.h"
#include "report.h"


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
        struct list_head *tmp;
        idmef_source_t *source;
        idmef_classification_t *class;
        
        printf("Alert informations :\n");
        printf(" Ident: %s\n", alert->ident);
        printf(" Impact: %s\n", alert->impact);
        printf(" Action: %s\n", alert->action);

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
 *
 */
static void mysql_run(idmef_alert_t *alert)
{
        int i;
        print_alert(alert);
}



static void mysql_close(void) 
{
}



int plugin_init(unsigned int id)
{
        static plugin_report_t plugin;
        
        plugin_set_name(&plugin, "MySQL");
        plugin_set_desc(&plugin, "Will log all alert to a MySQL database.");
        plugin_set_running_func(&plugin, mysql_run);
        plugin_set_closing_func(&plugin, mysql_close);
        
	return plugin_register((plugin_generic_t *)&plugin);
}












