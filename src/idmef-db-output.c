#include <stdio.h>
#include <stdlib.h>

#include <libprelude/plugin-common.h>
#include <libprelude/idmef-tree.h>

#include "plugin-db.h"
#include "idmef-func.h"
#include "idmef-db-output.h"



static void insert_address(const char *alert_ident, const char *parent_ident,
                           const char *parent_type, const char *node_ident,
                           const idmef_address_t *addr) 
{        
        db_plugins_insert("Prelude_Address", "alert_ident, parent_type, parent_ident, node_ident, ident, "
                          "category, vlan_name, vlan_num, address, netmask", alert_ident, parent_type, parent_ident,
                          node_ident, addr->ident, idmef_address_category_to_string(addr->category),
                          addr->vlan_name, addr->vlan_num, addr->address, addr->netmask, DB_INSERT_END);
}




static void insert_node(const char *alert_ident, const char *parent_ident,
                        const char *parent_type, const idmef_node_t *node) 
{
        idmef_address_t *addr;
        struct list_head *tmp;
        
        db_plugins_insert("Prelude_Node", "alert_ident, parent_type, parent_ident, ident, category, location, name",
                          alert_ident, parent_type, parent_ident, node->ident, idmef_node_category_to_string(node->category),
                          node->location, node->name, DB_INSERT_END);
        
        list_for_each(tmp, &node->address_list) {
                addr = list_entry(tmp, idmef_address_t, list);
                insert_address(alert_ident, parent_ident, parent_type, node->ident, addr);
        }
}




static void insert_userid(const char *alert_ident, const char *parent_ident,
                          const char *parent_type, const char *user_ident, const idmef_userid_t *uid) 
{
        db_plugins_insert("Prelude_UserId", "alert_ident, parent_type, parent_ident, user_ident, ident, type, name, number",
                          alert_ident, parent_type, parent_ident, user_ident, uid->ident, idmef_userid_type_to_string(uid->type),
                          uid->name, uid->number, DB_INSERT_END);
}



static void insert_user(const char *alert_ident, const char *parent_ident,
                        const char *parent_type, const idmef_user_t *user) 
{
        idmef_userid_t *uid;
        struct list_head *tmp;
        
        db_plugins_insert("Prelude_User", "alert_ident, parent_type, parent_ident, ident, category",
                          alert_ident, parent_type, parent_ident, user->ident,
                          idmef_user_category_to_string(user->category), DB_INSERT_END);
        
        list_for_each(tmp, &user->userid_list) {
                uid = list_entry(tmp, idmef_userid_t, list);
                insert_userid(alert_ident, parent_ident, parent_type, user->ident, uid);
        }
}



static void insert_process(const char *alert_ident, const char *parent_ident,
                           const char *parent_type, const idmef_process_t *process) 
{
        char pid[100];

        snprintf(pid, sizeof(pid), "%u", process->pid);
        
        db_plugins_insert("Prelude_Process", "alert_ident, parent_type, parent_ident, ident, name, pid, path",
                          alert_ident, parent_type, parent_ident, process->ident, process->name, pid,
                          process->path, DB_INSERT_END);
}



static void insert_service(const char *alert_ident, const char *parent_ident,
                           const char *parent_type, const idmef_service_t *service) 
{
        char port[sizeof("65535")];
        
        snprintf(port, sizeof(port), "%d", service->port);
        
        db_plugins_insert("Prelude_Service", "alert_ident, parent_type, parent_ident, ident, name, port, protocol",
                          alert_ident, parent_type, parent_ident, service->ident, service->name, port,
                          service->protocol, DB_INSERT_END);
}




static void insert_source(const char *alert_ident, const idmef_source_t *source)
{
        db_plugins_insert("Prelude_Source", "alert_ident, ident, spoofed, interface",
                          alert_ident, source->ident, idmef_source_spoofed_to_string(source->spoofed),
                          source->interface, DB_INSERT_END);
        

        insert_node(alert_ident, source->ident, "S", &source->node);
        insert_user(alert_ident, source->ident, "S", &source->user);
        insert_process(alert_ident, source->ident, "S", &source->process);
        insert_service(alert_ident, source->ident, "S", &source->service);
}



static void insert_target(const char *alert_ident, const idmef_target_t *target)
{
        db_plugins_insert("Prelude_Target", "alert_ident, ident, decoy, interface",
                          alert_ident, target->ident, idmef_target_decoy_to_string(target->decoy),
                          target->interface, DB_INSERT_END);
        
        insert_node(alert_ident, target->ident, "T", &target->node);
        insert_user(alert_ident, target->ident, "T", &target->user);
        insert_process(alert_ident, target->ident, "T", &target->process);
        insert_service(alert_ident, target->ident, "T", &target->service);
}



static void insert_analyzer(const char *parent_ident, const idmef_analyzer_t *analyzer) 
{
        char *parent_type = "A";
        
        db_plugins_insert("Prelude_Analyzer", "parent_ident, parent_type, analyzerid, manufacturer, model, version, class",
                          parent_ident, parent_type, analyzer->analyzerid, analyzer->manufacturer, analyzer->model,
                          analyzer->version, analyzer->class, DB_INSERT_END);
        
        insert_node(parent_ident, analyzer->analyzerid, "A", &analyzer->node);
        insert_process(parent_ident, analyzer->analyzerid, "A", &analyzer->process);
}




static void insert_classification(const char *alert_ident, const idmef_classification_t *class) 
{
        db_plugins_insert("Prelude_Classification", "alert_ident, origin, name, url",
                          alert_ident, idmef_classification_origin_to_string(class->origin),
                          class->name, class->url, DB_INSERT_END);
}



static void insert_data(const char *parent_ident, const idmef_additional_data_t *ad) 
{
        char *parent_type = "A"; /* should be A (alert) or H (heartbeat). */
        
        db_plugins_insert("Prelude_AdditionalData", "parent_ident, parent_type, type, meaning, data",
                          parent_ident, parent_type, idmef_additional_data_type_to_string(ad->type),
                          ad->meaning, ad->data, DB_INSERT_END);
}




static void insert_createtime(const char *parent_ident, char *parent_type, idmef_time_t *time) 
{        
        db_plugins_insert("Prelude_CreateTime", "parent_ident, parent_type, time, ntpstamp", 
                          parent_ident, parent_type, time->time, time->ntpstamp, DB_INSERT_END);
}



static void insert_detecttime(const char *alert_ident, idmef_time_t *time) 
{
        db_plugins_insert("Prelude_DetectTime", "alert_ident, time, ntpstamp",
                          alert_ident, time->time, time->ntpstamp, DB_INSERT_END);
}



static void insert_analyzertime(const char *parent_ident, char *parent_type, idmef_time_t *time) 
{
        db_plugins_insert("Prelude_AnalyzerTime", "parent_ident, parent_type, time, ntpstamp",
                          parent_ident, parent_type, time->time, time->ntpstamp, DB_INSERT_END);
}





void idmef_db_output(idmef_alert_t *alert) 
{
        struct list_head *tmp;
        idmef_source_t *source;
        idmef_target_t *target;
        idmef_classification_t *class;
        idmef_additional_data_t *data;
        char ident[sizeof("18446744073709551616")];
        
        snprintf(ident, sizeof(ident), "%lu", alert->ident);        
        
        db_plugins_insert("Prelude_Alert", "ident, impact, action",
                          ident, alert->impact, alert->action, DB_INSERT_END);
        
        insert_analyzer(ident, &alert->analyzer);
        insert_createtime(ident, "A", &alert->create_time);
        insert_detecttime(ident, &alert->detect_time);
        insert_analyzertime(ident, "A", &alert->analyzer_time);
        
        list_for_each(tmp, &alert->source_list) {
                source = list_entry(tmp, idmef_source_t, list);
                insert_source(ident, source);
        }

        list_for_each(tmp, &alert->target_list) {
                target = list_entry(tmp, idmef_target_t, list);
                insert_target(ident, target);
        }

        list_for_each(tmp, &alert->classification_list) {
                class = list_entry(tmp, idmef_classification_t, list);
                insert_classification(ident, class);
        }

        list_for_each(tmp, &alert->additional_data_list) {
                data = list_entry(tmp, idmef_additional_data_t, list);
                insert_data(ident, data);
        }
}


