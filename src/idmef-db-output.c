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
#include <stdlib.h>
#include <inttypes.h>

#include <libprelude/common.h>
#include <libprelude/plugin-common.h>
#include <libprelude/idmef-tree.h>

#include "plugin-db.h"
#include "idmef-util.h"
#include "idmef-db-output.h"



static void insert_address(const uint64_t *alert_ident, const uint64_t *parent_ident,
                           char parent_type, const uint64_t *node_ident,
                           const idmef_address_t *addr) 
{
        char *vlan_name, *address, *netmask;

        address = db_plugin_escape(addr->address);
        netmask = db_plugin_escape(addr->netmask);
        vlan_name = db_plugin_escape(addr->vlan_name);
        
        db_plugin_insert("Prelude_Address", "alert_ident, parent_type, parent_ident, node_ident, ident, "
                          "category, vlan_name, vlan_num, address, netmask",
                          "%llu, '%c', %llu, %llu, %llu, '%s', '%s', '%d', '%s', '%s'",
                          *alert_ident, parent_type, *parent_ident, *node_ident, addr->ident,
                          idmef_address_category_to_string(addr->category), vlan_name, addr->vlan_num,
                          address, netmask);
        
        free(address);
        free(netmask);
        free(vlan_name);
}




static void insert_node(const uint64_t *alert_ident, const uint64_t *parent_ident,
                        char parent_type, const idmef_node_t *node) 
{
        idmef_address_t *addr;
        struct list_head *tmp;
        char *location, *name;

        if ( ! node )
                return;
        
        name = db_plugin_escape(node->name);
        location = db_plugin_escape(node->location);
        
        
        db_plugin_insert("Prelude_Node", "alert_ident, parent_type, parent_ident, ident, category, location, name",
                         "%llu, '%c', %llu, %llu, '%s', '%s', '%s'", *alert_ident, parent_type, *parent_ident,
                         node->ident, idmef_node_category_to_string(node->category), location, name);
        
        list_for_each(tmp, &node->address_list) {
                addr = list_entry(tmp, idmef_address_t, list);
                insert_address(alert_ident, parent_ident, parent_type, &node->ident, addr);
        }

        free(name);
        free(location);
}




static void insert_userid(const uint64_t *alert_ident, const uint64_t *parent_ident,
                          char parent_type, const uint64_t *user_ident, const idmef_userid_t *uid) 
{
        char *name;

        name = db_plugin_escape(uid->name);
               
        db_plugin_insert("Prelude_UserId", "alert_ident, parent_type, parent_ident, user_ident, ident, type, name, number",
                         "%llu, '%c', %llu, %llu, %llu, '%s', '%s', '%u'", *alert_ident, parent_type, *parent_ident,
                         *user_ident, uid->ident, idmef_userid_type_to_string(uid->type), name, uid->number);

        free(name);
}



static void insert_user(const uint64_t *alert_ident, const uint64_t *parent_ident,
                        char parent_type, const idmef_user_t *user) 
{
        idmef_userid_t *uid;
        struct list_head *tmp;

        if ( ! user )
                return;
        
        db_plugin_insert("Prelude_User", "alert_ident, parent_type, parent_ident, ident, category",
                         "%llu, '%c', %llu, %llu, '%s'", *alert_ident, parent_type, *parent_ident,
                         user->ident, idmef_user_category_to_string(user->category));
        
        list_for_each(tmp, &user->userid_list) {
                uid = list_entry(tmp, idmef_userid_t, list);
                insert_userid(alert_ident, parent_ident, parent_type, &user->ident, uid);
        }
}



static void insert_process(const uint64_t *alert_ident, const uint64_t *parent_ident,
                           char parent_type, const idmef_process_t *process) 
{
        char *name, *path;

        if ( ! process )
                return;
        
        name = db_plugin_escape(process->name);
        path = db_plugin_escape(process->path);
        
        db_plugin_insert("Prelude_Process", "alert_ident, parent_type, parent_ident, ident, name, pid, path",
                         "%llu, '%c', %llu, %llu, '%s', '%u', '%s'", *alert_ident, parent_type, *parent_ident,
                         process->ident, name, process->pid, path);
        
        free(name);
        free(path);
}



static void insert_snmp_service(const uint64_t *alert_ident, const uint64_t *service_ident,
                                const uint64_t *parent_ident, char parent_type, const idmef_snmpservice_t *snmp) 
{
        char *oid, *community, *command;

        oid = db_plugin_escape(snmp->oid);
        command = db_plugin_escape(snmp->command);
        community = db_plugin_escape(snmp->community);

        db_plugin_insert("Prelude_SnmpService", "alert_ident, parent_type, parent_ident, service_ident, oid, community, command",
                         "%llu, '%c', %llu, %llu, '%s', '%u', '%s'", *alert_ident, parent_type, *parent_ident, *service_ident,
                         oid, community, command);

        free(oid);
        free(command);
        free(community);
}



static void insert_web_service(const uint64_t *alert_ident, const uint64_t *service_ident,
                               const uint64_t *parent_ident, char parent_type, const idmef_webservice_t *web) 
{
        char *url, *cgi, *method;
        
        if ( ! web )
                return;

        url = db_plugin_escape(web->url);
        cgi = db_plugin_escape(web->cgi);
        method = db_plugin_escape(web->method);
        
        db_plugin_insert("Prelude_WebService", "alert_ident, parent_type, parent_ident, service_ident, url, cgi, method",
                         "%llu, '%c', %llu, %llu, '%s', '%u', '%s'", *alert_ident, parent_type, *parent_ident, *service_ident,
                         url, cgi, method);

        free(url);
        free(cgi);
        free(method);
}



static void insert_service(const uint64_t *alert_ident, const uint64_t *parent_ident,
                           char parent_type, const idmef_service_t *service) 
{
        char *name, *protocol;

        if ( ! service )
                return;
        
        name = db_plugin_escape(service->name);
        protocol = db_plugin_escape(service->protocol);
        
        db_plugin_insert("Prelude_Service", "alert_ident, parent_type, parent_ident, ident, name, port, protocol",
                         "%llu, '%c', %llu, %llu, '%s', '%u', '%s'", *alert_ident, parent_type,
                         *parent_ident, service->ident, name, service->port, protocol);

        free(name);
        free(protocol);

        switch (service->type) {
        case web_service:
                insert_web_service(alert_ident, &service->ident, parent_ident, parent_type, service->specific.web);
                break;

        case snmp_service:
                insert_snmp_service(alert_ident, &service->ident, parent_ident, parent_type, service->specific.snmp);
                break;

        default:
                break;
        }
}




static void insert_source(const uint64_t *alert_ident, const idmef_source_t *source)
{
        char *interface;

        if (! source )
                return;
        
        interface = db_plugin_escape(source->interface);
        
        db_plugin_insert("Prelude_Source", "alert_ident, ident, spoofed, interface",
                          "%llu, %llu, '%s', '%s'", *alert_ident, source->ident,
                          idmef_source_spoofed_to_string(source->spoofed), interface);
        
        insert_node(alert_ident, &source->ident, 'S', source->node);
        insert_user(alert_ident, &source->ident, 'S', source->user);
        insert_process(alert_ident, &source->ident, 'S', source->process);
        insert_service(alert_ident, &source->ident, 'S', source->service);

        free(interface);
}



static void insert_target(const uint64_t *alert_ident, const idmef_target_t *target)
{
        char *interface;

        if ( ! target )
                return;
        
        interface = db_plugin_escape(target->interface);
        
        db_plugin_insert("Prelude_Target", "alert_ident, ident, decoy, interface",
                          "%llu, %llu, '%s', '%s'", *alert_ident, target->ident,
                          idmef_target_decoy_to_string(target->decoy), interface);
        
        insert_node(alert_ident, &target->ident, 'T', target->node);
        insert_user(alert_ident, &target->ident, 'T', target->user);
        insert_process(alert_ident, &target->ident, 'T', target->process);
        insert_service(alert_ident, &target->ident, 'T', target->service);

        free(interface);
}



static void insert_analyzer(const uint64_t *parent_ident, char parent_type, const idmef_analyzer_t *analyzer) 
{
        char *manufacturer, *model, *version, *class;

        class = db_plugin_escape(analyzer->class);
        model = db_plugin_escape(analyzer->model);
        version = db_plugin_escape(analyzer->version);
        manufacturer = db_plugin_escape(analyzer->manufacturer);
        
        db_plugin_insert("Prelude_Analyzer", "parent_ident, parent_type, analyzerid, manufacturer, model, version, class",
                          "%llu, '%c', %llu, '%s', '%s', '%s', '%s'", *parent_ident, parent_type, analyzer->analyzerid,
                          manufacturer, model, version, class);
        
        insert_node(parent_ident, &analyzer->analyzerid, 'A', analyzer->node);
        insert_process(parent_ident, &analyzer->analyzerid, 'A', analyzer->process);

        free(class);
        free(model);
        free(version);
        free(manufacturer);
}




static void insert_classification(const uint64_t *alert_ident, const idmef_classification_t *class) 
{
        char *name, *url;

        url = db_plugin_escape(class->url);
        name = db_plugin_escape(class->name);
        
        db_plugin_insert("Prelude_Classification", "alert_ident, origin, name, url",
                          "%llu, '%s', '%s', '%s'", *alert_ident,
                          idmef_classification_origin_to_string(class->origin), name, url);

        free(url);
        free(name);
}



static void insert_data(const uint64_t *parent_ident, char parent_type, const idmef_additional_data_t *ad) 
{
        char *meaning, *data;

        data = db_plugin_escape(ad->data);
        meaning = db_plugin_escape(ad->meaning);
        
        db_plugin_insert("Prelude_AdditionalData", "parent_ident, parent_type, type, meaning, data",
                          "%llu, '%c', '%s', '%s', '%s'", *parent_ident, parent_type,
                          idmef_additional_data_type_to_string(ad->type), meaning, data);

        free(data);
        free(meaning);
}




static void insert_createtime(const uint64_t *parent_ident, char parent_type, const idmef_time_t *time) 
{
        char utc_time[MAX_UTC_DATETIME_SIZE], ntpstamp[MAX_NTP_TIMESTAMP_SIZE], *u, *n;

        idmef_get_timestamp(time, utc_time, sizeof(utc_time));
        idmef_get_ntp_timestamp(time, ntpstamp, sizeof(ntpstamp));
        
        u = db_plugin_escape(utc_time);
        n = db_plugin_escape(ntpstamp);
        
        db_plugin_insert("Prelude_CreateTime", "parent_ident, parent_type, time, ntpstamp", 
                         "%llu, '%c', '%s', '%s'", *parent_ident, parent_type, u, n);

        free(u);
        free(n);
}



static void insert_detecttime(const uint64_t *alert_ident, const idmef_time_t *time) 
{        
        char utc_time[MAX_UTC_DATETIME_SIZE], ntpstamp[MAX_NTP_TIMESTAMP_SIZE], *u, *n;

        if ( ! time )
                return;
        
        idmef_get_timestamp(time, utc_time, sizeof(utc_time));
        idmef_get_ntp_timestamp(time, ntpstamp, sizeof(ntpstamp));
        
        u = db_plugin_escape(utc_time);
        n = db_plugin_escape(ntpstamp);
        
        db_plugin_insert("Prelude_DetectTime", "alert_ident, time, ntpstamp",
                          "%llu, '%s', '%s'", *alert_ident, u, n);
        
        free(u);
        free(n);
}



static void insert_analyzertime(const uint64_t *parent_ident, char parent_type, const idmef_time_t *time) 
{
        char utc_time[MAX_UTC_DATETIME_SIZE], ntpstamp[MAX_NTP_TIMESTAMP_SIZE], *u, *n;

        if ( ! time )
                return;
        
        idmef_get_timestamp(time, utc_time, sizeof(utc_time));
        idmef_get_ntp_timestamp(time, ntpstamp, sizeof(ntpstamp));
        
        u = db_plugin_escape(utc_time);
        n = db_plugin_escape(ntpstamp);
                
        db_plugin_insert("Prelude_AnalyzerTime", "parent_ident, parent_type, time, ntpstamp",
                          "%llu, '%c', '%s', '%s'", *parent_ident, parent_type, u, n);
        
        free(u);
        free(n);
}





static void insert_alert(const idmef_alert_t *alert) 
{
        struct list_head *tmp;
        char *impact, *action;
        const idmef_source_t *source;
        const idmef_target_t *target;
        const idmef_classification_t *class;
        const idmef_additional_data_t *data;
        
        impact = db_plugin_escape(alert->impact);
        action = db_plugin_escape(alert->action);

        db_plugin_insert("Prelude_Alert", "ident, impact, action",
                         "%llu, '%s', '%s'", alert->ident, impact, action);

        free(impact);
        free(action);
        
        insert_analyzer(&alert->ident, 'A', &alert->analyzer);
        insert_createtime(&alert->ident, 'A', &alert->create_time);
        insert_detecttime(&alert->ident, alert->detect_time);
        insert_analyzertime(&alert->ident, 'A', alert->analyzer_time);

        list_for_each(tmp, &alert->source_list) {
                source = list_entry(tmp, idmef_source_t, list);
                insert_source(&alert->ident, source);
        }

        list_for_each(tmp, &alert->target_list) {
                target = list_entry(tmp, idmef_target_t, list);
                insert_target(&alert->ident, target);
        }

        list_for_each(tmp, &alert->classification_list) {
                class = list_entry(tmp, idmef_classification_t, list);
                insert_classification(&alert->ident, class);
        }

        list_for_each(tmp, &alert->additional_data_list) {
                data = list_entry(tmp, idmef_additional_data_t, list);
                insert_data(&alert->ident, 'A', data);
        }
}




static void insert_heartbeat(const idmef_heartbeat_t *heartbeat) 
{
        struct list_head *tmp;
        const idmef_additional_data_t *data;

        db_plugin_insert("Prelude_Heartbeat", "ident", "%llu", heartbeat->ident);
        
        insert_analyzer(&heartbeat->ident, 'H', &heartbeat->analyzer);
        insert_createtime(&heartbeat->ident, 'H', &heartbeat->create_time);
        insert_analyzertime(&heartbeat->ident, 'H', heartbeat->analyzer_time);

        list_for_each(tmp, &heartbeat->additional_data_list) {
                data = list_entry(tmp, idmef_additional_data_t, list);
                insert_data(&heartbeat->ident, 'H', data);
        }
}
        




void idmef_db_output(const idmef_message_t *msg) 
{
        switch (msg->type) {

        case idmef_alert_message:
                insert_alert(msg->message.alert);
                break;

        case idmef_heartbeat_message:
                insert_heartbeat(msg->message.heartbeat);
                break;

        default:
                log(LOG_ERR, "unknow message type: %d.\n", msg->type);
                break;
        }
}

