#include <stdio.h>
#include <stdlib.h>
#include <libprelude/common.h>

#include "idmef.h"


#define generic_free_list(type, head) do {           \
        type *decl;                                  \
        struct list_head *tmp;                       \
                                                     \
        for (tmp = (head)->next; tmp != (head); ) {  \
                decl = list_entry(tmp, type, list);  \
                tmp = tmp->next;                     \
                free(decl);                          \
        }                                            \
} while (0)



static idmef_message_t msg;



static void free_source_or_target(struct list_head *source_list) 
{
        struct list_head *tmp;
        idmef_source_t *source;

        for ( tmp = source_list->next; tmp != source_list; ) {
                source = list_entry(tmp, idmef_source_t, list);

                generic_free_list(idmef_userid_t, &source->user.userid_list);
                generic_free_list(idmef_address_t, &source->node.address_list);
                
                tmp = tmp->next;
                free(source);
        }
}



idmef_message_t *idmef_alert_new(void) 
{
        static idmef_alert_t alert;
        
        msg.version = IDMEF_VERSION;
        msg.type = idmef_alert_message;
        msg.message.alert = &alert;
        
        INIT_LIST_HEAD(&alert.source_list);
        INIT_LIST_HEAD(&alert.target_list);
        INIT_LIST_HEAD(&alert.classification_list);
        INIT_LIST_HEAD(&alert.additional_data_list);
        
        return &msg;
}




idmef_message_t *idmef_heartbeat_new(void) 
{
        static idmef_heartbeat_t heartbeat;

        msg.version = IDMEF_VERSION;
        msg.type = idmef_heartbeat_message;
        msg.message.heartbeat = &heartbeat;

        INIT_LIST_HEAD(&heartbeat.additional_data_list);

        return &msg;
}



void idmef_message_free(idmef_message_t *msg) 
{
        idmef_alert_t *alert = msg->message.alert;

        free_source_or_target(&alert->source_list);
        free_source_or_target(&alert->target_list);
        generic_free_list(idmef_classification_t, &alert->classification_list);
        generic_free_list(idmef_additional_data_t, &alert->additional_data_list);
}





idmef_additional_data_t *idmef_additional_data_new(idmef_alert_t *alert) 
{
        idmef_additional_data_t *ptr;

        ptr = calloc(1, sizeof(*ptr));
        if ( ! ptr ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }
        
        list_add_tail(&ptr->list, &alert->additional_data_list);

        return ptr;
}




idmef_source_t *idmef_source_new(idmef_alert_t *alert) 
{
        idmef_source_t *ptr;

        ptr = calloc(1, sizeof(*ptr));
        if ( ! ptr ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }
        
        INIT_LIST_HEAD(&ptr->user.userid_list);
        INIT_LIST_HEAD(&ptr->node.address_list);
        
        list_add_tail(&ptr->list, &alert->source_list);

        return ptr;
}




idmef_target_t *idmef_target_new(idmef_alert_t *alert) 
{
        idmef_target_t *ptr;

        ptr = calloc(1, sizeof(*ptr));
        if ( ! ptr ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }
        
        INIT_LIST_HEAD(&ptr->user.userid_list);
        INIT_LIST_HEAD(&ptr->node.address_list);
        
        list_add_tail(&ptr->list, &alert->target_list);

        return ptr;
}




idmef_classification_t *idmef_classification_new(idmef_alert_t *alert) 
{
        idmef_classification_t *ptr;

        ptr = calloc(1, sizeof(*ptr));
        if ( ! ptr ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        list_add_tail(&ptr->list, &alert->classification_list);

        return ptr;
}




idmef_address_t *idmef_address_new(idmef_node_t *node) 
{
        idmef_address_t *ptr;

        ptr = calloc(1, sizeof(*ptr));
        if ( ! ptr ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        list_add_tail(&ptr->list, &node->address_list);

        return ptr;
}




idmef_userid_t *idmef_userid_new(idmef_user_t *user)  
{
        idmef_userid_t *ptr;

        ptr = calloc(1, sizeof(*ptr));
        if ( ! ptr ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        list_add_tail(&ptr->list, &user->userid_list);
        
        return ptr;
}












