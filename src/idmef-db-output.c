#include <stdio.h>
#include <stdlib.h>

#include <libprelude/plugin-common.h>
#include <libprelude/idmef-tree.h>

#include "plugin-db.h"
#include "idmef-func.h"
#include "idmef-db-output.h"



static void insert_address(unsigned long alert_ident, const char *parent_ident,
                           const char *parent_type, const char *node_ident,
                           const idmef_address_t *addr) 
{
        db_plugins_insert_id("Prelude_Address", "alert_ident", &alert_ident);
        
        db_plugins_insert("Prelude_Address", "parent_type, parent_ident, node_ident, ident, "
                          "category, vlan_name, vlan_num, address, netmask", parent_type, parent_ident,
                          node_ident, addr->ident, idmef_address_category_to_string(addr->category),
                          addr->vlan_name, addr->vlan_num, addr->address, addr->netmask, DB_INSERT_END);
}




static void insert_node(unsigned long alert_ident, const char *parent_ident,
                       const char *parent_type, const idmef_node_t *node) 
{
        idmef_address_t *addr;
        struct list_head *tmp;
        
        db_plugins_insert_id("Prelude_Node", "alert_ident", &alert_ident);
        
        db_plugins_insert("Prelude_Node", "parent_type, parent_ident, ident, category, location, name",
                          parent_type, parent_ident, node->ident, idmef_node_category_to_string(node->category),
                          node->location, node->name, DB_INSERT_END);
        
        list_for_each(tmp, &node->address_list) {
                addr = list_entry(tmp, idmef_address_t, list);
                insert_address(alert_ident, parent_ident, parent_type, node->ident, addr);
        }
}




static void insert_userid(unsigned long alert_ident, const char *parent_ident,
                          const char *parent_type, const char *user_ident, const idmef_userid_t *uid) 
{
        db_plugins_insert_id("Prelude_UserId", "alert_ident", &alert_ident);

        db_plugins_insert("Prelude_UserId", "parent_type, parent_ident, user_ident, ident, type, name, number",
                          parent_type, parent_ident, user_ident, uid->ident, idmef_userid_type_to_string(uid->type),
                          uid->name, uid->number, DB_INSERT_END);
}



static void insert_user(unsigned long alert_ident, const char *parent_ident,
                        const char *parent_type, const idmef_user_t *user) 
{
        idmef_userid_t *uid;
        struct list_head *tmp;
        
        db_plugins_insert_id("Prelude_User", "alert_ident", &alert_ident);

        db_plugins_insert("Prelude_User", "parent_type, parent_ident, ident, category",
                          parent_type, parent_ident, user->ident,
                          idmef_user_category_to_string(user->category), DB_INSERT_END);
        
        list_for_each(tmp, &user->userid_list) {
                uid = list_entry(tmp, idmef_userid_t, list);
                insert_userid(alert_ident, parent_ident, parent_type, user->ident, uid);
        }
}



static void insert_process(unsigned long alert_ident, const char *parent_ident,
                           const char *parent_type, const idmef_process_t *process) 
{
        char pid[100];

        snprintf(pid, sizeof(pid), "%u", process->pid);
        
        db_plugins_insert_id("Prelude_Process", "alert_ident", &alert_ident);

        db_plugins_insert("Prelude_Process", "parent_type, parent_ident, ident, name, pid, path",
                          parent_type, parent_ident, process->ident, process->name, pid,
                          process->path, DB_INSERT_END);
}



static void insert_service(unsigned long alert_ident, const char *parent_ident,
                           const char *parent_type, const idmef_service_t *service) 
{
        char port[sizeof("65535")];
        
        snprintf(port, sizeof(port), "%d", service->port);
        
        db_plugins_insert_id("Prelude_Service", "alert_ident", &alert_ident);
        
        db_plugins_insert("Prelude_Service", "parent_type, parent_ident, ident, name, port, protocol",
                          parent_type, parent_ident, service->ident, service->name, port,
                          service->protocol, DB_INSERT_END);
}




static void insert_source(unsigned long alert_ident, const idmef_source_t *source)
{
        db_plugins_insert_id("Prelude_Source", "alert_ident", &alert_ident);

        db_plugins_insert("Prelude_Source", "ident, spoofed, interface",
                          source->ident, idmef_source_spoofed_to_string(source->spoofed),
                          source->interface, DB_INSERT_END);
        

        insert_node(alert_ident, source->ident, "S", &source->node);
        insert_user(alert_ident, source->ident, "S", &source->user);
        insert_process(alert_ident, source->ident, "S", &source->process);
        insert_service(alert_ident, source->ident, "S", &source->service);
}



static void insert_target(unsigned long alert_ident, const idmef_target_t *target)
{
        db_plugins_insert_id("Prelude_Target", "alert_ident", &alert_ident);

        db_plugins_insert("Prelude_Target", "ident, decoy, interface",
                          target->ident, idmef_target_decoy_to_string(target->decoy),
                          target->interface, DB_INSERT_END);
        
        insert_node(alert_ident, target->ident, "T", &target->node);
        insert_user(alert_ident, target->ident, "T", &target->user);
        insert_process(alert_ident, target->ident, "T", &target->process);
        insert_service(alert_ident, target->ident, "T", &target->service);
}



static void insert_analyzer(unsigned long parent_ident, const idmef_analyzer_t *analyzer) 
{
        char *parent_type = "A";

        db_plugins_insert_id("Prelude_Analyzer", "parent_ident", &parent_ident);
        db_plugins_insert("Prelude_Analyzer", "parent_type, analyzerid, manufacturer, model, version, class",
                          parent_type, analyzer->analyzerid, analyzer->manufacturer, analyzer->model,
                          analyzer->version, analyzer->class, DB_INSERT_END);
        
        insert_node(parent_ident, analyzer->analyzerid, "A", &analyzer->node);
        insert_process(parent_ident, analyzer->analyzerid, "A", &analyzer->process);
}




static void insert_classification(unsigned long alert_ident, const idmef_classification_t *class) 
{
        db_plugins_insert_id("Prelude_Classification", "alert_ident", &alert_ident);
        db_plugins_insert("Prelude_Classification", "origin, name, url",
                          idmef_classification_origin_to_string(class->origin),
                          class->name, class->url, DB_INSERT_END);
}



static void insert_data(unsigned long parent_ident, const idmef_additional_data_t *ad) 
{
        char *parent_type = "A"; /* should be A (alert) or H (heartbeat). */

        db_plugins_insert_id("Prelude_AdditionalData", "parent_ident", &parent_ident);

        db_plugins_insert("Prelude_AdditionalData", "parent_type, type, meaning, data",
                          parent_type, idmef_additional_data_type_to_string(ad->type),
                          ad->meaning, ad->data, DB_INSERT_END);
}




static void insert_createtime(unsigned long parent_ident, char *parent_type, idmef_time_t *time) 
{
        db_plugins_insert_id("Prelude_CreateTime", "parent_ident", &parent_ident);

        db_plugins_insert("Prelude_CreateTime", "parent_type, time, ntpstamp", 
                          parent_type, time->time, time->ntpstamp, DB_INSERT_END);
}



static void insert_detecttime(unsigned long alert_ident, idmef_time_t *time) 
{
        db_plugins_insert_id("Prelude_DetectTime", "alert_ident", &alert_ident);

        db_plugins_insert("Prelude_DetectTime", "time, ntpstamp",
                          time->time, time->ntpstamp, DB_INSERT_END);
}



static void insert_analyzertime(unsigned long parent_ident, char *parent_type, idmef_time_t *time) 
{
        db_plugins_insert_id("Prelude_AnalyzerTime", "parent_ident", &parent_ident);

        db_plugins_insert("Prelude_AnalyzerTime", "parent_type, time, ntpstamp",
                          parent_type, time->time, time->ntpstamp, DB_INSERT_END);
}





void idmef_db_output(idmef_alert_t *alert) 
{
        unsigned long ident;
        struct list_head *tmp;
        idmef_source_t *source;
        idmef_target_t *target;
        idmef_classification_t *class;
        idmef_additional_data_t *data;


        /* insert into DB */
        ident = DB_INSERT_AUTOINC_ID;
        db_plugins_insert("Prelude_Alert", "impact, action", alert->impact, alert->action,
                          DB_INSERT_END);


        /*
         * FIXME: this is not safe in case there is several database plugins enabled.
         */
        db_plugins_insert_id("Prelude_Alert", "ident", &ident);

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


