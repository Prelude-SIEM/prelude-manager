#include <stdio.h>
#include <stdlib.h>

#include <libprelude/plugin-common.h>
#include <libprelude/idmef-tree.h>

#include "plugin-db.h"
#include "idmef-func.h"
#include "idmef-db-output.h"



static void insert_address(uint64_t alert_ident, const char *parent_ident,
                           const char parent_type, const char *node_ident,
                           const idmef_address_t *addr) 
{
        char *ident, *vlan_name, *address, *netmask;

        ident = db_plugin_escape(addr->ident);
        address = db_plugin_escape(addr->address);
        netmask = db_plugin_escape(addr->netmask);
        vlan_name = db_plugin_escape(addr->vlan_name);
        
        db_plugin_insert("Prelude_Address", "alert_ident, parent_type, parent_ident, node_ident, ident, "
                          "category, vlan_name, vlan_num, address, netmask",
                          "%llu, \"%c\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%d\", \"%s\", \"%s\"",
                          alert_ident, parent_type, parent_ident, node_ident, ident,
                          idmef_address_category_to_string(addr->category), vlan_name, addr->vlan_num,
                          address, netmask);

        free(ident);
        free(address);
        free(netmask);
        free(vlan_name);
}




static void insert_node(uint64_t alert_ident, const char *parent_ident,
                        const char parent_type, const idmef_node_t *node) 
{
        idmef_address_t *addr;
        struct list_head *tmp;
        char *ident, *location, *name;

        name = db_plugin_escape(node->name);
        ident = db_plugin_escape(node->ident);
        location = db_plugin_escape(node->location);
        
        
        db_plugin_insert("Prelude_Node", "alert_ident, parent_type, parent_ident, ident, category, location, name",
                         "%llu, \"%c\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"", alert_ident, parent_type, parent_ident,
                         ident, idmef_node_category_to_string(node->category), location, name);
        
        list_for_each(tmp, &node->address_list) {
                addr = list_entry(tmp, idmef_address_t, list);
                insert_address(alert_ident, parent_ident, parent_type, ident, addr);
        }

        free(name);
        free(ident);
        free(location);
}




static void insert_userid(uint64_t alert_ident, const char *parent_ident,
                          const char parent_type, const char *user_ident, const idmef_userid_t *uid) 
{
        char *ident, *name, *number;

        name = db_plugin_escape(uid->name);
        ident = db_plugin_escape(uid->ident);
        number = db_plugin_escape(uid->number);
        
        db_plugin_insert("Prelude_UserId", "alert_ident, parent_type, parent_ident, user_ident, ident, type, name, number",
                         "%llu, \"%c\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"", alert_ident, parent_type, parent_ident,
                         user_ident, ident, idmef_userid_type_to_string(uid->type), name, number);

        free(name);
        free(ident);
        free(number);
}



static void insert_user(uint64_t alert_ident, const char *parent_ident,
                        const char parent_type, const idmef_user_t *user) 
{
        char *ident;
        idmef_userid_t *uid;
        struct list_head *tmp;

        ident = db_plugin_escape(user->ident);
        
        db_plugin_insert("Prelude_User", "alert_ident, parent_type, parent_ident, ident, category",
                         "%llu, \"%c\", \"%s\", \"%s\", \"%s\"", alert_ident, parent_type, parent_ident,
                         ident, idmef_user_category_to_string(user->category));
        
        list_for_each(tmp, &user->userid_list) {
                uid = list_entry(tmp, idmef_userid_t, list);
                insert_userid(alert_ident, parent_ident, parent_type, ident, uid);
        }

        free(ident);
}



static void insert_process(uint64_t alert_ident, const char *parent_ident,
                           const char parent_type, const idmef_process_t *process) 
{
        char *ident, *name, *path;
        
        name = db_plugin_escape(process->name);
        path = db_plugin_escape(process->path);
        ident = db_plugin_escape(process->ident);       
        
        db_plugin_insert("Prelude_Process", "alert_ident, parent_type, parent_ident, ident, name, pid, path",
                         "%llu, \"%c\", \"%s\", \"%s\", \"%s\", \"%u\", \"%s\"", alert_ident, parent_type, parent_ident,
                         ident, name, process->pid, path);
        
        free(name);
        free(path);
        free(ident);
}



static void insert_service(uint64_t alert_ident, const char *parent_ident,
                           const char parent_type, const idmef_service_t *service) 
{
        char *ident, *name, *protocol;
 
        name = db_plugin_escape(service->name);
        ident = db_plugin_escape(service->ident);
        protocol = db_plugin_escape(service->protocol);
        
        db_plugin_insert("Prelude_Service", "alert_ident, parent_type, parent_ident, ident, name, port, protocol",
                         "%llu, \"%c\", \"%s\", \"%s\", \"%s\", \"%u\", \"%s\"", alert_ident, parent_type,
                         parent_ident, ident, name, service->port, protocol);

        free(name);
        free(ident);
        free(protocol);
}




static void insert_source(uint64_t alert_ident, const idmef_source_t *source)
{
        char *ident, *interface;

        ident = db_plugin_escape(source->ident);
        interface = db_plugin_escape(source->interface);
        
        db_plugin_insert("Prelude_Source", "alert_ident, ident, spoofed, interface",
                          "%llu, \"%s\", \"%s\", \"%s\"", alert_ident, ident,
                          idmef_source_spoofed_to_string(source->spoofed), interface);
        
        insert_node(alert_ident, ident, 'S', &source->node);
        insert_user(alert_ident, ident, 'S', &source->user);
        insert_process(alert_ident, ident, 'S', &source->process);
        insert_service(alert_ident, ident, 'S', &source->service);

        free(ident);
        free(interface);
}



static void insert_target(uint64_t alert_ident, const idmef_target_t *target)
{
        char *ident, *interface;

        ident = db_plugin_escape(target->ident);
        interface = db_plugin_escape(target->interface);
        
        db_plugin_insert("Prelude_Target", "alert_ident, ident, decoy, interface",
                          "%llu, \"%s\", \"%s\", \"%s\"", alert_ident, ident,
                          idmef_target_decoy_to_string(target->decoy), interface);
        
        insert_node(alert_ident, ident, 'T', &target->node);
        insert_user(alert_ident, ident, 'T', &target->user);
        insert_process(alert_ident, ident, 'T', &target->process);
        insert_service(alert_ident, ident, 'T', &target->service);

        free(ident);
        free(interface);
}



static void insert_analyzer(uint64_t parent_ident, const idmef_analyzer_t *analyzer) 
{
        char parent_type = 'A';
        char *analyzerid, *manufacturer, *model, *version, *class;

        class = db_plugin_escape(analyzer->class);
        model = db_plugin_escape(analyzer->model);
        version = db_plugin_escape(analyzer->version);
        analyzerid = db_plugin_escape(analyzer->analyzerid);
        manufacturer = db_plugin_escape(analyzer->manufacturer);
        
        db_plugin_insert("Prelude_Analyzer", "parent_ident, parent_type, analyzerid, manufacturer, model, version, class",
                          "%llu, \"%c\", \"%s\", \"%s\", \"%s\", \"%s\", \"%s\"", parent_ident, parent_type, analyzerid,
                          manufacturer, model, version, class);
        
        insert_node(parent_ident, analyzerid, 'A', &analyzer->node);
        insert_process(parent_ident, analyzerid, 'A', &analyzer->process);

        free(class);
        free(model);
        free(version);
        free(analyzerid);
        free(manufacturer);
}




static void insert_classification(uint64_t alert_ident, const idmef_classification_t *class) 
{
        char *name, *url;

        url = db_plugin_escape(class->url);
        name = db_plugin_escape(class->name);
        
        db_plugin_insert("Prelude_Classification", "alert_ident, origin, name, url",
                          "%llu, \"%s\", \"%s\", \"%s\"", alert_ident,
                          idmef_classification_origin_to_string(class->origin), name, url);

        free(url);
        free(name);
}



static void insert_data(uint64_t parent_ident, const idmef_additional_data_t *ad) 
{
        char parent_type = 'A'; /* should be A (alert) or H (heartbeat). */
        char *meaning, *data;

        data = db_plugin_escape(ad->data);
        meaning = db_plugin_escape(ad->meaning);
        
        db_plugin_insert("Prelude_AdditionalData", "parent_ident, parent_type, type, meaning, data",
                          "%llu, \"%c\", \"%s\", \"%s\", \"%s\"", parent_ident, parent_type,
                          idmef_additional_data_type_to_string(ad->type), meaning, data);

        free(data);
        free(meaning);
}




static void insert_createtime(uint64_t parent_ident, char parent_type, idmef_time_t *time) 
{
        char *t, *ntpstamp;

        t = db_plugin_escape(time->time);
        ntpstamp = db_plugin_escape(time->ntpstamp);
        
        db_plugin_insert("Prelude_CreateTime", "parent_ident, parent_type, time, ntpstamp", 
                          "%llu, \"%c\", \"%s\", \"%s\"", parent_ident, parent_type, t, ntpstamp);

        free(t);
        free(ntpstamp);
}



static void insert_detecttime(uint64_t alert_ident, idmef_time_t *time) 
{
        char *t, *ntpstamp;

        t = db_plugin_escape(time->time);
        ntpstamp = db_plugin_escape(time->ntpstamp);
        
        db_plugin_insert("Prelude_DetectTime", "alert_ident, time, ntpstamp",
                          "%llu, \"%s\", \"%s\"", alert_ident, t, ntpstamp);
        
        free(t);
        free(ntpstamp);
}



static void insert_analyzertime(uint64_t parent_ident, char parent_type, idmef_time_t *time) 
{
        char *t, *ntpstamp;

        t = db_plugin_escape(time->time);
        ntpstamp = db_plugin_escape(time->ntpstamp);
        
        db_plugin_insert("Prelude_AnalyzerTime", "parent_ident, parent_type, time, ntpstamp",
                          "%llu, \"%c\", \"%s\", \"%s\"", parent_ident, parent_type, t, ntpstamp);

        free(t);
        free(ntpstamp);
}





void idmef_db_output(idmef_alert_t *alert) 
{
        struct list_head *tmp;
        char *impact, *action;
        idmef_source_t *source;
        idmef_target_t *target;
        idmef_classification_t *class;
        idmef_additional_data_t *data;
        
        impact = db_plugin_escape(alert->impact);
        action = db_plugin_escape(alert->action);

        db_plugin_insert("Prelude_Alert", "ident, impact, action",
                         "%llu, \"%s\", \"%s\"", alert->ident, impact, action);

        free(impact);
        free(action);
        
        insert_analyzer(alert->ident, &alert->analyzer);
        insert_createtime(alert->ident, 'A', &alert->create_time);
        insert_detecttime(alert->ident, &alert->detect_time);
        insert_analyzertime(alert->ident, 'A', &alert->analyzer_time);
        
        list_for_each(tmp, &alert->source_list) {
                source = list_entry(tmp, idmef_source_t, list);
                insert_source(alert->ident, source);
        }

        list_for_each(tmp, &alert->target_list) {
                target = list_entry(tmp, idmef_target_t, list);
                insert_target(alert->ident, target);
        }

        list_for_each(tmp, &alert->classification_list) {
                class = list_entry(tmp, idmef_classification_t, list);
                insert_classification(alert->ident, class);
        }

        list_for_each(tmp, &alert->additional_data_list) {
                data = list_entry(tmp, idmef_additional_data_t, list);
                insert_data(alert->ident, data);
        }
}


