#ifndef IDMEF_H
#define IDMEF_H

#include <inttypes.h>
#include <libprelude/list.h>

#define IDMEF_VERSION "0.5"


/*
 * Additional Data class
 */
typedef enum {
        boolean,
        byte,
        character,
        date_time,
        integer,
        ntpstamps,
        portlist,
        real,
        string,
        xml,
} idmef_additional_data_type_t;



typedef struct {
        struct list_head list;
        idmef_additional_data_type_t type;
        const char *meaning;
        const char *data;
} idmef_additional_data_t;





/*
 * Classification class
 */
typedef enum {
        unknown,
        bugtraqid,
        cve,
        vendor_specific,
} idmef_origin_t;



typedef struct {
        struct list_head list;
        idmef_origin_t origin;
        const char *name;
        const char *url;
} idmef_classification_t;





/*
 * UserId class
 */
typedef enum {
        current_user,
        original_user,
        target_user,
        user_privs,
        current_group,
        group_privs,
} idmef_userid_type_t;


typedef struct {
        struct list_head list;
        
        const char *ident;
        idmef_userid_type_t type;
        const char *name;
        const char *number;
} idmef_userid_t;






/*
 * User class
 */
typedef enum {
        cat_unknow,
        application,
        os_device
} idmef_user_category_t;



typedef struct {
        const char *ident;
        idmef_user_category_t category;
        struct list_head userid_list;
} idmef_user_t;




/*
 * Address class
 */
typedef enum {
        addr_unknow,
        atm,
        e_mail,
        lotus_notes,
        mac,
        sna,
        vm,
        ipv4_addr,
        ipv4_addr_hex,
        ipv4_net,
        ipv4_net_mask,
        ipv6_addr,
        ipv6_addr_hex,
        ipv6_net,
        ipv6_net_mask
} idmef_address_category_t;




typedef struct {
        struct list_head list;
        
        const char *ident;
        idmef_address_category_t category;
        const char *vlan_name;
        int vlan_num;
        const char *address;
        const char *netmask;
} idmef_address_t;



/*
 * Process class
 */
typedef struct {
        const char *ident;
        const char *name;
        const char *pid;
        const char *path;
        const char **arg;
        const char **env;
} idmef_process_t;



/*
 * WebService class
 */
typedef struct {
        const char *url;
        const char *cgi;
        const char *method;
        const char *arg;
} idmef_webservice_t;




/*
 * SNMPService class
 */
typedef struct {
        const char *oid;
        const char *community;
        const char *command;
} idmef_snmpservice_t;

        


/*
 * Service class
 */
typedef struct {
        const char *ident;
        const char *name;
        uint16_t port;
        const char *portlist;
        const char *protocol;

        union {
                idmef_webservice_t *web;
                idmef_snmpservice_t *snmp;
        } specific;
        
} idmef_service_t;




/*
 * Node class
 */
typedef enum {
        node_unknow,
        ads,
        afs,
        coda,
        dfs,
        dns,
        kerberos,
        nds,
        nis,
        nisplus,
        nt,
        wfw
} idmef_node_category_t;


typedef struct {
        const char *ident;
        idmef_node_category_t category;
        const char *location;
        const char *name;
        struct list_head address_list;
} idmef_node_t;





/*
 * Source/Target class
 */
typedef enum {
        unknow,
        yes,
        no,
} idmef_spoofed_t;



typedef struct {
        struct list_head list;
        
        const char *ident;
        idmef_spoofed_t spoofed;
        const char *interface;

        idmef_node_t node;
        idmef_user_t user;
        idmef_process_t process;
        idmef_service_t service;
        
} idmef_source_t, idmef_target_t;





/*
 * Analyzer class
 */
typedef struct {
        const char *analyzerid;
        const char *manufacturer;
        const char *model;
        const char *version;
        const char *class;
} idmef_analyzer_t;





/*
 * Time class
 */
typedef struct {
        const char *ntpstamp;
        const char *time;
} idmef_time_t;




/*
 * Toolalert class
 */
typedef struct {
        const char *name;
        const char *command;
        const char **analyzerid;
} idmef_tool_alert_t;





/*
 * CorrelationAlert class
 */
typedef struct {
        const char *name;
        const char **alertident;
} idmef_correlation_alert_t;




/*
 * OverflowAlert class
 */
typedef struct {
        const char *program;
        uint32_t size;
        const unsigned char *buffer;
} idmef_overflow_alert_t;




/*
 * Alert class
 */
typedef enum {
        idmef_tool_alert,
        idmef_correlation_alert,
        idmef_overflow_alert,
} idmef_alert_type_t;



typedef struct {
        const char *ident;
        const char *impact;
        const char *action;
    
        idmef_analyzer_t analyzer;
    
        idmef_time_t create_time;
        idmef_time_t detect_time;
        idmef_time_t analyzer_time;

        struct list_head source_list;
        struct list_head target_list;
        struct list_head classification_list;
        struct list_head additional_data_list;

        idmef_alert_type_t type;
        union {
                idmef_tool_alert_t *tool_alert;
                idmef_correlation_alert_t *correlation_alert;
                idmef_overflow_alert_t *overflow_alert;
        } detail;
        
} idmef_alert_t;





/*
 * Heartbeat class
 */
typedef struct {
        const char *ident;

        idmef_analyzer_t analyzer;
        idmef_time_t analyzer_time;

        struct list_head additional_data_list;
} idmef_heartbeat_t;




/*
 * IDMEF Message class
 */
typedef enum {
        idmef_alert_message,
        idmef_heartbeat_message,
} idmef_message_type_t;


typedef struct {
        const char *version;

        idmef_message_type_t type;
        union {
                idmef_alert_t *alert;
                idmef_heartbeat_t *heartbeat;
        } message;
        
} idmef_message_t;




/*
 * Functions
 */
idmef_message_t *idmef_alert_new(void);
idmef_message_t *idmef_heartbeat_new(void);
void idmef_message_fee(idmef_message_t *msg);

idmef_additional_data_t *idmef_additional_data_new(idmef_alert_t *alert);

idmef_source_t *idmef_source_new(idmef_alert_t *alert);

idmef_target_t *idmef_target_new(idmef_alert_t *alert);

idmef_classification_t *idmef_classification_new(idmef_alert_t *alert);

idmef_address_t *idmef_address_new(idmef_node_t *node);

idmef_userid_t *idmef_userid_new(idmef_user_t *user);

#endif







