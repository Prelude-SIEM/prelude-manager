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
#include <stdlib.h>
#include <inttypes.h>

#include <libprelude/list.h>
#include <libprelude/prelude-log.h>
#include <libprelude/plugin-common.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/idmef-tree-func.h>

#include "plugin-db.h"
#include "idmef-util.h"
#include "idmef-db-output.h"

#ifdef DEBUG

/*
 * for an unknow reason, we don't see warning about
 * invalid fmt arguments when using db_plugin_insert().
 */
#define db_plugin_insert(tbl, field, fmt, args...) \
        printf(fmt, args); db_plugin_insert(tbl, field, fmt, args)

#endif

static int insert_file(uint64_t alert_ident, uint64_t parent_ident, char parent_type, idmef_file_t *file);


static int insert_address(uint64_t alert_ident, uint64_t parent_ident,
                          char parent_type, uint64_t node_ident, idmef_address_t *addr) 
{
        const char *category;
        char *vlan_name, *address, *netmask;

        category = idmef_address_category_to_string(addr->category);
        if ( ! category )
                return -1;
        
        address = db_plugin_escape(idmef_string(&addr->address));
        if ( ! address )
                return -1;
        
        netmask = db_plugin_escape(idmef_string(&addr->netmask));
        if ( ! netmask ) {
                free(address);
                return -1;
        }
        
        vlan_name = db_plugin_escape(idmef_string(&addr->vlan_name));
        if ( ! vlan_name ) {
                free(address);
                free(netmask);
                return -1;
        }
        
        db_plugin_insert("Prelude_Address", "alert_ident, parent_type, parent_ident, "
                          "category, vlan_name, vlan_num, address, netmask",
                          "%llu, '%c', %llu, '%s', '%s', '%d', '%s', '%s'",
                         alert_ident, parent_type, parent_ident, category, vlan_name, addr->vlan_num, address, netmask);
        
        free(address);
        free(netmask);
        free(vlan_name);

        return 0;
}




static int insert_node(uint64_t alert_ident, uint64_t parent_ident,
                       char parent_type, idmef_node_t *node) 
{
        int ret;
        const char *category;
        idmef_address_t *addr;
        struct list_head *tmp;
        char *location, *name;

        if ( ! node )
                return 0;

        category = idmef_node_category_to_string(node->category);
        if ( ! category )
                return -1;
        
        name = db_plugin_escape(idmef_string(&node->name));
        if ( ! name )
                return -1;
        
        location = db_plugin_escape(idmef_string(&node->location));
        if ( ! location ) {
                free(name);
                return -1;
        }
        
        db_plugin_insert("Prelude_Node", "alert_ident, parent_type, parent_ident, category, location, name",
                         "%llu, '%c', %llu, '%s', '%s', '%s'", alert_ident, parent_type, parent_ident,
                         category, location, name);
        
        free(name);
        free(location);

        list_for_each(tmp, &node->address_list) {
                addr = list_entry(tmp, idmef_address_t, list);

                ret = insert_address(alert_ident, parent_ident, parent_type, node->ident, addr);
                if ( ret < 0 )
                        return -1;
        }

        return 0;
}




static int insert_userid(uint64_t alert_ident, uint64_t parent_ident,
                         char parent_type, idmef_userid_t *uid) 
{
        char *name;
        const char *type;
        
        type = idmef_userid_type_to_string(uid->type);
        if ( ! type )
                return -1;
        
        name = db_plugin_escape(idmef_string(&uid->name));
        if ( ! name )
                return -1;
        
        db_plugin_insert("Prelude_UserId", "alert_ident, parent_type, parent_ident, ident, type, name, number",
                         "%llu, '%c', %llu, %llu, '%s', '%s', '%u'", alert_ident, parent_type, parent_ident,
                         uid->ident, type, name, uid->number);

        free(name);
        
        return 0;
}



static int insert_user(uint64_t alert_ident, uint64_t parent_ident,
                       char parent_type, idmef_user_t *user) 
{
        int ret;
        uint64_t tmpid = 0;
        idmef_userid_t *uid;
        const char *category;
        struct list_head *tmp;
        
        if ( ! user )
                return 0;

        category = idmef_user_category_to_string(user->category);
        if ( ! category )
                return -1;
        
        db_plugin_insert("Prelude_User", "alert_ident, parent_type, parent_ident, category",
                         "%llu, '%c', %llu, '%s'", alert_ident, parent_type, parent_ident,
                         category);
        
        list_for_each(tmp, &user->userid_list) {
                uid = list_entry(tmp, idmef_userid_t, list);

                if ( uid->ident == 0 )
                        uid->ident = tmpid++;
                
                ret = insert_userid(alert_ident, user->ident, parent_type, uid);
                if ( ret < 0 )
                        return -1;
        }

        return 0;
}



static int insert_process(uint64_t alert_ident, uint64_t parent_ident,
                          char parent_type, idmef_process_t *process) 
{
        char *name, *path;

        if ( ! process )
                return 0;
        
        name = db_plugin_escape(idmef_string(&process->name));
        if ( ! name )
                return -1;
        
        path = db_plugin_escape(idmef_string(&process->path));
        if ( ! path ) {
                free(name);
                return -1;
        }
        
        db_plugin_insert("Prelude_Process", "alert_ident, parent_type, parent_ident, name, pid, path",
                         "%llu, '%c', %llu, '%s', '%u', '%s'", alert_ident, parent_type, parent_ident,
                         name, process->pid, path);
        
        free(name);
        free(path);

        return 0;
}



static int insert_snmp_service(uint64_t alert_ident, uint64_t service_ident,
                               uint64_t parent_ident, char parent_type, idmef_snmpservice_t *snmp) 
{
        char *oid, *community, *command;

        oid = db_plugin_escape(idmef_string(&snmp->oid));
        if (! oid )
                return -1;
        
        command = db_plugin_escape(idmef_string(&snmp->command));
        if ( ! command ) {
                free(oid);
                return -1;
        }
        
        community = db_plugin_escape(idmef_string(&snmp->community));
        if ( ! community ) {
                free(oid);
                free(command);
                return -1;
        }
        
        db_plugin_insert("Prelude_SnmpService", "alert_ident, parent_type, parent_ident, service_ident, oid, community, command",
                         "%llu, '%c', %llu, %llu, '%s', '%s', '%s'", alert_ident, parent_type, parent_ident, service_ident,
                         oid, community, command);

        free(oid);
        free(command);
        free(community);

        return 0;
}



static int insert_web_service(uint64_t alert_ident, uint64_t service_ident,
                              uint64_t parent_ident, char parent_type, idmef_webservice_t *web) 
{
        char *url, *cgi, *method;
        
        if ( ! web )
                return 0;

        url = db_plugin_escape(idmef_string(&web->url));
        if ( ! url )
                return -1;
        
        cgi = db_plugin_escape(idmef_string(&web->cgi));
        if ( ! cgi ) {
                free(url);
                return -1;
        }
        
        method = db_plugin_escape(idmef_string(&web->http_method));
        if ( ! method ) {
                free(url);
                free(cgi);
                return -1;
        }
        
        db_plugin_insert("Prelude_WebService", "alert_ident, parent_type, parent_ident, service_ident, url, cgi, http_method",
                         "%llu, '%c', %llu, %llu, '%s', '%s', '%s'", alert_ident, parent_type, parent_ident, service_ident,
                         url, cgi, method);

        free(url);
        free(cgi);
        free(method);

        return 0;
}



static int insert_portlist(uint64_t alert_ident, uint64_t parent_ident,
                           char parent_type, idmef_string_t *portlist) 
{
        char *plist;
        
        plist = db_plugin_escape(idmef_string(portlist));
        if ( ! plist )
                return -1;
        
        db_plugin_insert("Prelude_ServicePortlist", "alert_ident, parent_type, parent_ident, portlist",
                         "%llu, '%c', %llu, '%s'", alert_ident, parent_type, parent_ident, plist);

        return 0;
}





static int insert_service(uint64_t alert_ident, uint64_t parent_ident,
                          char parent_type, idmef_service_t *service) 
{
        int ret;
        char *name, *protocol;

        if ( ! service )
                return 0;
        
        name = db_plugin_escape(idmef_string(&service->name));
        if ( ! name )
                return -1;
        
        protocol = db_plugin_escape(idmef_string(&service->protocol));
        if ( ! protocol ) {
                free(name);
                return -1;
        }
        
        db_plugin_insert("Prelude_Service", "alert_ident, parent_type, parent_ident, name, port, protocol",
                         "%llu, '%c', %llu, '%s', '%u', '%s'", alert_ident, parent_type, parent_ident,
                         name, service->port, protocol);

        if ( idmef_string(&service->portlist) )
        	insert_portlist(alert_ident, parent_ident, parent_type, &service->portlist);
        
        free(name);
        free(protocol);

        switch (service->type) {
        case web_service:
                ret = insert_web_service(alert_ident, service->ident, parent_ident, parent_type, service->specific.web);
                break;

        case snmp_service:
                ret = insert_snmp_service(alert_ident, service->ident, parent_ident, parent_type, service->specific.snmp);
                break;

        case no_specific_service:
                ret = 0;
                break;
                
        default:
                ret = -1;
                break;
        }

        return ret;
}



static int insert_linkage(uint64_t alert_ident, uint64_t target_ident,
                          uint64_t file_ident, idmef_linkage_t *linkage) 
{
        char *name, *path;
        const char *category;

        category = idmef_linkage_category_to_string(linkage->category);
        if ( ! category )
                return -1;
        
        name = db_plugin_escape(idmef_string(&linkage->name));
        if (! name )
                return -1;
        
        path = db_plugin_escape(idmef_string(&linkage->path));
        if ( ! path ) {
                free(name);
                return -1;
        }
                
        db_plugin_insert("Prelude_Linkage", "alert_ident, target_ident, file_ident, category, name, path",
                         "'%s', '%s', '%s'", category, name, path);
        
        free(name);
        free(path);
        
        return insert_file(alert_ident, target_ident, 'L', linkage->file);
}




static int insert_file_access(uint64_t alert_ident, uint64_t target_ident,
                              uint64_t file_ident, idmef_file_access_t *access)
{
        char *permission;

        permission = db_plugin_escape(idmef_string(&access->permission));
        if ( ! permission )
                return -1;
        
        db_plugin_insert("Prelude_FileAccess", "alert_ident, target_ident, file_ident, permission",
                         "%llu, %llu, %llu, '%s'", alert_ident, target_ident, file_ident, permission);
        free(permission);
        
        return insert_userid(alert_ident, target_ident, 'F', &access->userid);
}




static int insert_file(uint64_t alert_ident, uint64_t target_ident,
                       char parent_type, idmef_file_t *file) 
{
        int ret;
        char *name, *path;
        const char *category;
        struct list_head *tmp;
        idmef_linkage_t *linkage;
        idmef_file_access_t *access;
        char ctime[MAX_UTC_DATETIME_SIZE], mtime[MAX_UTC_DATETIME_SIZE], atime[MAX_UTC_DATETIME_SIZE];

        if ( ! file )
                return 0;

        /*
         * why no parent_ident ???
         */
        category = idmef_file_category_to_string(file->category);
        if ( ! category )
                return -1;
        
        name = db_plugin_escape(idmef_string(&file->name));
        if ( ! name )
                return -1;
        
        path = db_plugin_escape(idmef_string(&file->path));
        if ( ! path ) {
                free(name);
                return -1;
        }
        
        idmef_get_timestamp(file->create_time, ctime, sizeof(ctime));
        idmef_get_timestamp(file->modify_time, mtime, sizeof(mtime));
        idmef_get_timestamp(file->access_time, atime, sizeof(atime));
        
        db_plugin_insert("Prelude_File", "alert_ident, target_ident, ident, category, name, path, "
                         "create_time, modify_time, access_time, data_size, disk_size", "%llu, %llu, %llu, '%s', "
                         "'%s', '%s', '%s', '%s', '%s', '%d', %d", alert_ident, target_ident,
                         file->ident, category, name, path, ctime, mtime, atime, file->data_size, file->disk_size);

        free(name);
        free(path);

        list_for_each(tmp, &file->file_access_list) {
                access = list_entry(tmp, idmef_file_access_t, list);

                ret = insert_file_access(alert_ident, target_ident, file->ident, access);
                if ( ret < 0 )
                        return -1;
        }

        list_for_each(tmp, &file->file_linkage_list) {
                linkage = list_entry(tmp, idmef_linkage_t, list);
                
                ret = insert_linkage(alert_ident, target_ident, file->ident, linkage);
                if ( ret < 0 )
                        return -1;
        }

        return 0;
}






static int insert_source(uint64_t alert_ident, idmef_source_t *source)
{
        int ret;
        char *interface;
        const char *spoofed;

        if ( ! source )
                return 0;

        spoofed = idmef_source_spoofed_to_string(source->spoofed);
        if ( ! spoofed )
                return -1;

        interface = db_plugin_escape(idmef_string(&source->interface));
        if ( ! interface )
                return -1;
        
        db_plugin_insert("Prelude_Source", "alert_ident, ident, spoofed, interface",
                         "%llu, %llu, '%s', '%s'", alert_ident, source->ident, spoofed, interface);
        
        free(interface);
        
        ret = insert_node(alert_ident, source->ident, 'S', source->node);
        if ( ret < 0 )
                return -1;

        ret = insert_user(alert_ident, source->ident, 'S', source->user);
        if ( ret < 0 )
                return -1;
        
        ret = insert_process(alert_ident, source->ident, 'S', source->process);
        if ( ret < 0 )
                return -1;
        
        ret = insert_service(alert_ident, source->ident, 'S', source->service);
        if ( ret < 0 )
                return -1;
        
        return 0;
}



static int insert_file_list(uint64_t alert_ident, uint64_t target_ident, struct list_head *file_list) 
{
        int ret;
        idmef_file_t *file;
        struct list_head *tmp;

        if ( list_empty(file_list) )
                return 0;
        
        db_plugin_insert("Prelude_FileList", "alert_ident, target_ident",
                         "%llu, %llu", alert_ident, target_ident);
        
        list_for_each(tmp, file_list) {
                file = list_entry(tmp, idmef_file_t, list);

                ret = insert_file(alert_ident, target_ident, 'T', file);
                if ( ret < 0 )
                        return -1;
        }

        return 0;
}





static int insert_target(uint64_t alert_ident, idmef_target_t *target)
{
        int ret;
        char *interface;
        const char *decoy;
        
        if ( ! target )
                return 0;

        decoy = idmef_target_decoy_to_string(target->decoy);
        if ( ! decoy )
                return -1;
        
        interface = db_plugin_escape(idmef_string(&target->interface));
        if ( ! interface )
                return -1;
        
        db_plugin_insert("Prelude_Target", "alert_ident, ident, decoy, interface",
                         "%llu, %llu, '%s', '%s'", alert_ident, target->ident,
                         decoy, interface);
        
        ret = insert_node(alert_ident, target->ident, 'T', target->node);
        if ( ret < 0 )
                goto err;
        
        ret = insert_user(alert_ident, target->ident, 'T', target->user);
        if ( ret < 0 )
                goto err;
        
        ret = insert_process(alert_ident, target->ident, 'T', target->process);
        if ( ret < 0 )
                goto err;
        
        ret = insert_service(alert_ident, target->ident, 'T', target->service);
        if ( ret < 0 )
                goto err;

        ret = insert_file_list(alert_ident, target->ident, &target->file_list);

 err:
        free(interface);
        return ret;
}




static int insert_analyzer(uint64_t parent_ident, char parent_type, idmef_analyzer_t *analyzer) 
{
        int ret;
        char *manufacturer, *model, *version, *class, *ostype, *osversion;

        class = db_plugin_escape(idmef_string(&analyzer->class));
        if ( ! class )
                return -1;
        
        model = db_plugin_escape(idmef_string(&analyzer->model));
        if ( ! model ) {
                free(class);
                return -1;
        }
        
        version = db_plugin_escape(idmef_string(&analyzer->version));
        if ( ! version ) {
                free(class);
                free(model);
                return -1;
        }
        
        manufacturer = db_plugin_escape(idmef_string(&analyzer->manufacturer));
        if ( ! manufacturer ) {
                free(class);
                free(model);
                free(version);
                return -1;
        }

        ostype = db_plugin_escape(idmef_string(&analyzer->ostype));
        if ( ! ostype ) {
                free(class);
                free(model);
                free(version);
                free(manufacturer);
        }

        osversion = db_plugin_escape(idmef_string(&analyzer->osversion));
        if ( ! ostype ) {
                free(class);
                free(model);
                free(version);
                free(manufacturer);
                free(ostype);
        }

        
        db_plugin_insert("Prelude_Analyzer", "parent_ident, parent_type, analyzerid, manufacturer, model, version, class, "
                         "ostype, osversion", "%llu, '%c', %llu, '%s', '%s', '%s', '%s', '%s', '%s'", parent_ident,
                         parent_type, analyzer->analyzerid, manufacturer, model, version, class, ostype, osversion);
        
        free(class);
        free(model);
        free(version);
        free(manufacturer);
        free(ostype);
        free(osversion);
        
        ret = insert_node(parent_ident, analyzer->analyzerid, 'A', analyzer->node);
        if ( ret < 0 )
                return -1;
        
        ret = insert_process(parent_ident, analyzer->analyzerid, 'A', analyzer->process);
        if ( ret < 0 )
                return -1;

        return 0;
}




static int insert_classification(uint64_t alert_ident, idmef_classification_t *class) 
{
        char *name, *url;
        const char *origin;

        origin = idmef_classification_origin_to_string(class->origin);
        if ( ! origin )
                return -1;

        url = db_plugin_escape(idmef_string(&class->url));
        if ( ! url )
                return -1;
        
        name = db_plugin_escape(idmef_string(&class->name));
        if ( ! name ) {
                free(url);
                return -1;
        }
        
        db_plugin_insert("Prelude_Classification", "alert_ident, origin, name, url",
                         "%llu, '%s', '%s', '%s'", alert_ident, origin, name, url);

        free(url);
        free(name);

        return 0;
}



static int insert_data(uint64_t parent_ident, char parent_type, idmef_additional_data_t *ad) 
{
        int size;
        const char *type, *ptr;
        char buf[1024], *meaning, *data;

        type = idmef_additional_data_type_to_string(ad->type);
        if ( ! type )
                return -1;

        size = sizeof(buf);
        
        ptr = idmef_additional_data_to_string(ad, buf, &size);
        if ( ! ptr )
                return -1;

        meaning = db_plugin_escape(idmef_string(&ad->meaning));
        if ( ! meaning ) 
                return -1;
        
        data = db_plugin_escape(ptr);
        if ( ! data ) {
                free(meaning);
                return -1;
        }
        
        db_plugin_insert("Prelude_AdditionalData", "parent_ident, parent_type, type, meaning, data",
                         "%llu, '%c', '%s', '%s', '%s'", parent_ident, parent_type, type, meaning, data);

        free(data);
        free(meaning);

        return 0;
}




static int insert_createtime(uint64_t parent_ident, char parent_type, idmef_time_t *time) 
{
        char utc_time[MAX_UTC_DATETIME_SIZE], ntpstamp[MAX_NTP_TIMESTAMP_SIZE], *u, *n;

        idmef_get_timestamp(time, utc_time, sizeof(utc_time));
        idmef_get_ntp_timestamp(time, ntpstamp, sizeof(ntpstamp));
        
        u = db_plugin_escape(utc_time);
        if ( ! u )
                return -1;
        
        n = db_plugin_escape(ntpstamp);
        if ( ! n ) {
                free(u);
                return -1;
        }
        
        db_plugin_insert("Prelude_CreateTime", "parent_ident, parent_type, time, ntpstamp", 
                         "%llu, '%c', '%s', '%s'", parent_ident, parent_type, u, n);

        free(u);
        free(n);

        return 0;
}



static int insert_detecttime(uint64_t alert_ident, idmef_time_t *time) 
{        
        char utc_time[MAX_UTC_DATETIME_SIZE], ntpstamp[MAX_NTP_TIMESTAMP_SIZE], *u, *n;

        if ( ! time )
                return 0;
        
        idmef_get_timestamp(time, utc_time, sizeof(utc_time));
        idmef_get_ntp_timestamp(time, ntpstamp, sizeof(ntpstamp));
        
        u = db_plugin_escape(utc_time);
        if ( ! u )
                return -1;
        
        n = db_plugin_escape(ntpstamp);
        if ( ! n ) {
                free(u);
                return -1;
        }
        
        db_plugin_insert("Prelude_DetectTime", "alert_ident, time, ntpstamp",
                          "%llu, '%s', '%s'", alert_ident, u, n);
        
        free(u);
        free(n);

        return 0;
}



static int insert_analyzertime(uint64_t parent_ident, char parent_type, idmef_time_t *time) 
{
        char utc_time[MAX_UTC_DATETIME_SIZE], ntpstamp[MAX_NTP_TIMESTAMP_SIZE], *u, *n;

        if ( ! time )
                return 0;
        
        idmef_get_timestamp(time, utc_time, sizeof(utc_time));
        idmef_get_ntp_timestamp(time, ntpstamp, sizeof(ntpstamp));
        
        u = db_plugin_escape(utc_time);
        if ( ! u )
                return -1;
        
        n = db_plugin_escape(ntpstamp);
        if ( ! n ) {
                free(u);
                return -1;
        }
        
        db_plugin_insert("Prelude_AnalyzerTime", "parent_ident, parent_type, time, ntpstamp",
                          "%llu, '%c', '%s', '%s'", parent_ident, parent_type, u, n);
        
        free(u);
        free(n);

        return 0;
}




static int insert_impact(uint64_t alert_ident, idmef_impact_t *impact) 
{
        char *desc;
        const char *completion, *type, *severity;

        if ( ! impact )
                return 0;

        completion = idmef_impact_completion_to_string(impact->completion);
        if ( ! completion )
                return -1;

        type = idmef_impact_type_to_string(impact->type);
        if ( ! type )
                return -1;

        severity = idmef_impact_severity_to_string(impact->severity);
        if ( ! severity )
                return -1;
        
        desc = db_plugin_escape(idmef_string(&impact->description));
        if ( ! desc )
                return -1;
        
        db_plugin_insert("Prelude_Impact", "alert_ident, severity, completion, type, description",
                         "%llu, '%s', '%s', '%s', '%s'", alert_ident, severity, completion, type, desc);

        free(desc);
        
        return 0;
}




static int insert_action(uint64_t alert_ident, idmef_action_t *action)
{
        char *desc;
        const char *category;

        category = idmef_action_category_to_string(action->category);
        if ( ! category )
                return -1;
        
        desc = db_plugin_escape(idmef_string(&action->description));
        if ( ! desc )
                return -1;
        
        db_plugin_insert("Prelude_Action", "alert_ident, category, description",
                         "%llu, '%s', '%s'", alert_ident, category, desc);

        free(desc);

        return 0;
}




static int insert_confidence(uint64_t alert_ident, idmef_confidence_t *confidence) 
{
        if ( ! confidence )
                return 0;
        
        db_plugin_insert("Prelude_Confidence", "alert_ident, rating, confidence", "%llu, '%s', %f",
                         alert_ident, idmef_confidence_rating_to_string(confidence->rating),
                         confidence->confidence);

        return 0;
}




static int insert_assessment(uint64_t alert_ident, idmef_assessment_t *assessment) 
{
        int ret;
        struct list_head *tmp;
        idmef_action_t *action;

        if ( ! assessment )
                return 0;

        db_plugin_insert("Prelude_Assessment", "alert_ident", "%llu", alert_ident);
        
        ret = insert_impact(alert_ident, assessment->impact);
        if ( ret < 0 )
                return -1;
        
        ret = insert_confidence(alert_ident, assessment->confidence);
        if ( ret < 0 )
                return -1;
        
        list_for_each(tmp, &assessment->action_list) {
                action = list_entry(tmp, idmef_action_t, list);

                ret = insert_action(alert_ident, action);
                if ( ret < 0 )
                        return -1;
        }
        
        return 0;
}




static int insert_overflow_alert(uint64_t alert_ident, idmef_overflow_alert_t *overflow) 
{
        char *program, *buffer;

        program = db_plugin_escape(idmef_string(&overflow->program));
        if ( ! program )
                return -1;

        buffer = db_plugin_escape(overflow->buffer);
        if ( ! buffer ) {
                free(program);
                return -1;
        }
        
        db_plugin_insert("Prelude_OverflowAlert", "alert_ident, program, size, buffer",
                         "%llu, '%s', %d, '%s'", alert_ident, program, overflow->size, buffer);

        free(buffer);
        free(program);
        
        return 0;
}




static int insert_tool_alert(uint64_t alert_ident, idmef_tool_alert_t *tool) 
{
        char *name, *command;
        
        /*
         * FIXME use alert_ident ?
         */
        name = db_plugin_escape(idmef_string(&tool->name));
        if ( ! name )
                return -1;

        command = db_plugin_escape(idmef_string(&tool->command));
        if ( ! command ) {
                free(name);
                return -1;
        }

        db_plugin_insert("Prelude_ToolAlert", "alert_ident, name, command", "%llu, '%s', '%s'",
                         alert_ident, name, command);

        free(name);
        free(command);

        return 0;
}



static int insert_correlation_alert(uint64_t alert_ident, idmef_correlation_alert_t *correlation) 
{
        char *name;
        struct list_head *tmp;
        idmef_alertident_t *ai;
        
        /*
         * FIXME: use alert_ident ?
         */
        name = db_plugin_escape(idmef_string(&correlation->name));
        if ( ! name )
                return -1;

        db_plugin_insert("Prelude_CorrelationAlert", "ident, name", "%llu, '%s'",
                         alert_ident, name);
        free(name);

        list_for_each(tmp, &correlation->alertident_list){
                ai = list_entry(tmp, idmef_alertident_t, list);
                db_plugin_insert("Prelude_CorrelationAlert_Alerts", "ident, alert_ident", "%llu", alert_ident);
        }

        return 0;
}





static int insert_alert(idmef_alert_t *alert) 
{
        int ret;
        uint64_t tmpid;
        struct list_head *tmp;
        idmef_source_t *source;
        idmef_target_t *target;
        idmef_classification_t *class;
        idmef_additional_data_t *data;
        
        db_plugin_insert("Prelude_Alert", "ident", "%llu", alert->ident);

        ret = insert_assessment(alert->ident, alert->assessment);
        if ( ret < 0 )
                return -1;
        
        ret = insert_analyzer(alert->ident, 'A', &alert->analyzer);
        if ( ret < 0 )
                return -1;
        
        ret = insert_createtime(alert->ident, 'A', &alert->create_time);
        if ( ret < 0 )
                return -1;
        
        ret = insert_detecttime(alert->ident, alert->detect_time);
        if ( ret < 0 )
                return -1;
        
        ret = insert_analyzertime(alert->ident, 'A', alert->analyzer_time);
        if ( ret < 0 )
                return -1;

        switch (alert->type) {
        case idmef_default:
                ret = 0;
                break;

        case idmef_tool_alert:
                ret = insert_tool_alert(alert->ident, alert->detail.tool_alert);
                break;

        case idmef_overflow_alert:
                ret = insert_overflow_alert(alert->ident, alert->detail.overflow_alert);
                break;

        case idmef_correlation_alert:
                ret = insert_correlation_alert(alert->ident, alert->detail.correlation_alert);
                break;
        }

        if ( ret < 0 )
                return -1;

        tmpid = 0;
        list_for_each(tmp, &alert->source_list) {
                source = list_entry(tmp, idmef_source_t, list);

                if ( source->ident == 0 )
                        source->ident = tmpid++;
                
                ret = insert_source(alert->ident,source);
                if ( ret < 0 )
                        return -1;
        }

        tmpid = 0;
        list_for_each(tmp, &alert->target_list) {
                target = list_entry(tmp, idmef_target_t, list);

                if ( target->ident == 0 )
                        target->ident = tmpid++;
                
                ret = insert_target(alert->ident, target);
                if ( ret < 0 )
                        return -1;
        }
        
        list_for_each(tmp, &alert->classification_list) {
                class = list_entry(tmp, idmef_classification_t, list);
                ret = insert_classification(alert->ident, class);
                if ( ret < 0 )
                        return -1;
        }

        list_for_each(tmp, &alert->additional_data_list) {
                data = list_entry(tmp, idmef_additional_data_t, list);
                ret = insert_data(alert->ident, 'A', data);
                if ( ret < 0 )
                        return -1;
        }

        return 0;
}




static int insert_heartbeat(idmef_heartbeat_t *heartbeat) 
{
        int ret;
        struct list_head *tmp;
        idmef_additional_data_t *data;

        db_plugin_insert("Prelude_Heartbeat", "ident", "%llu", heartbeat->ident);
        
        ret = insert_analyzer(heartbeat->ident, 'H', &heartbeat->analyzer);
        if ( ret < 0 )
                return -1;
        
        ret = insert_createtime(heartbeat->ident, 'H', &heartbeat->create_time);
        if ( ret < 0 )
                return -1;
        
        ret = insert_analyzertime(heartbeat->ident, 'H', heartbeat->analyzer_time);
        if ( ret < 0 )
                return -1;
        
        list_for_each(tmp, &heartbeat->additional_data_list) {
                data = list_entry(tmp, idmef_additional_data_t, list);

                ret = insert_data(heartbeat->ident, 'H', data);
                if ( ret < 0 )
                        return -1;
        }

        return 0;
}
        




int idmef_db_output(idmef_message_t *msg) 
{
        int ret = -1;
        
        switch (msg->type) {

        case idmef_alert_message:
                ret = insert_alert(msg->message.alert);
                break;

        case idmef_heartbeat_message:
                ret = insert_heartbeat(msg->message.heartbeat);
                break;

        default:
                log(LOG_ERR, "unknow message type: %d.\n", msg->type);
                break;
        }

        if ( ret < 0 ) 
                log(LOG_ERR, "error processing IDMEF message.\n");

        return ret;
}

