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

/*
 * Some of the code here was inspired from libidmef code.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>

#include <libprelude/common.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/prelude-ident.h>

#include "config.h"
#include "ntp.h"
#include "idmef-func.h"



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




static idmef_heartbeat_t heartbeat;
static prelude_ident_t *alert_ident;


static idmef_alert_t alert;
static idmef_tool_alert_t tool_alert;
static idmef_overflow_alert_t overflow_alert;
static idmef_correlation_alert_t correlation_alert;


static idmef_node_t analyzer_node;
static idmef_process_t analyzer_process;

static idmef_detect_time_t static_detect_time;
static idmef_analyzer_time_t static_analyzer_time;




static void free_service(idmef_service_t *service) 
{
        switch (service->type) {

        case web_service:
                free(service->specific.web);
                break;

        case snmp_service:
                free(service->specific.snmp);
                break;

        default:
                break;
        }

        free(service);
}



static void free_source_or_target(struct list_head *source_list) 
{
        struct list_head *tmp;
        idmef_source_t *source;

        for ( tmp = source_list->next; tmp != source_list; ) {
                source = list_entry(tmp, idmef_source_t, list);

                if ( source->user ) {
                        generic_free_list(idmef_userid_t, &source->user->userid_list);
                        free(source->user);
                }
                
                if ( source->node ) {
                        generic_free_list(idmef_address_t, &source->node->address_list);
                        free(source->node);
                }
                
                if ( source->process ) {
                        generic_free_list(idmef_process_env_t, &source->process->env_list);
                        generic_free_list(idmef_process_arg_t, &source->process->arg_list);
                        free(source->process);
                }

                if ( source->service )
                        free_service(source->service);
                                
                tmp = tmp->next;
                free(source);
        }
}



static void free_analyzer(idmef_analyzer_t *analyzer) 
{        
        if ( analyzer->node ) 
                generic_free_list(idmef_address_t, &analyzer->node->address_list);
        
        if ( analyzer->process ) {
                generic_free_list(idmef_process_env_t, &analyzer->process->env_list);
                generic_free_list(idmef_process_arg_t, &analyzer->process->arg_list);
        }
}



static void free_alert(idmef_alert_t *alert) 
{
        free_source_or_target(&alert->source_list);
        free_source_or_target(&alert->target_list);
        
        generic_free_list(idmef_classification_t, &alert->classification_list);
        generic_free_list(idmef_additional_data_t, &alert->additional_data_list);
        
        switch (alert->type) {
                
        case idmef_correlation_alert:
                generic_free_list(idmef_alertident_t, &alert->detail.correlation_alert->alertident_list);
                break;

        case idmef_tool_alert:
                generic_free_list(idmef_alertident_t, &alert->detail.correlation_alert->alertident_list);
                break;

        default:
                break;
        }

        free_analyzer(&alert->analyzer);
}



static void free_heartbeat(idmef_heartbeat_t *heartbeat) 
{
        free_analyzer(&heartbeat->analyzer);
        generic_free_list(idmef_additional_data_t, &heartbeat->additional_data_list);
}



int idmef_ident_init(void) 
{
        alert_ident = prelude_ident_new(PRELUDE_MANAGER_CONFDIR"/alert.ident");
        if ( ! alert_ident ) {
                log(LOG_ERR, "couldn't initialize unique alert ident.\n");
                return -1;
        }

        return 0;
}




void idmef_ident_exit(void) 
{
        prelude_ident_destroy(alert_ident);
}




void idmef_get_ntp_timestamp(struct timeval *tv, char *outptr, size_t size)
{
        l_fp ts;
        unsigned ts_mask = TS_MASK;             /* defaults to 20 bits (us) */
        unsigned ts_roundbit = TS_ROUNDBIT;     /* defaults to 20 bits (us) */

        sTVTOTS(tv, &ts);

        ts.l_ui += JAN_1970;                    /* make it time since 1900 */
        ts.l_uf += ts_roundbit;
        ts.l_uf &= ts_mask;

        snprintf(outptr, size, "0x%08lx.0x%08lx", (unsigned long) ts.l_ui, (unsigned long) ts.l_uf);
}




void idmef_get_timestamp(struct timeval *tv, char *outptr, size_t size) 
{
        struct tm *utc;

        /*
         * Convert from localtime to UTC.
         */
        utc = gmtime(&tv->tv_sec);

        /*
         * Format as the IDMEF draft tell us to.
         */
        /* strftime(outptr, size, "%Y-%m-%dT%H:%M:%S", utc); */
        strftime(outptr, size, "%Y-%m-%d%H:%M:%S", utc);
}



static void fill_alert_infos(idmef_alert_t *alert) 
{
        struct timeval tv;
        static char ctime[MAX_UTC_DATETIME_SIZE], ctime_ntp[MAX_NTP_TIMESTAMP_SIZE];

        gettimeofday(&tv, NULL);
        
        alert->create_time.time = ctime;
        alert->create_time.ntpstamp = ctime_ntp;
        alert->ident = prelude_ident_inc(alert_ident);
        
        idmef_get_timestamp(&tv, ctime, sizeof(ctime));
        idmef_get_ntp_timestamp(&tv, ctime_ntp, sizeof(ctime_ntp));
}




/*
 * Tool Alert stuff.
 */
idmef_alertident_t *idmef_tool_alert_alertident_new(idmef_tool_alert_t *tool_alert) 
{
        idmef_alertident_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        list_add(&new->list, &tool_alert->alertident_list);

        return new;
}




void idmef_tool_alert_new(idmef_alert_t *alert) 
{        
        alert->type = idmef_tool_alert;
        alert->detail.tool_alert = &tool_alert;
}




/*
 * Correlation Alert stuff
 */
idmef_alertident_t *idmef_correlation_alert_alertident_new(idmef_correlation_alert_t *correlation_alert) 
{
        idmef_alertident_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        list_add(&new->list, &correlation_alert->alertident_list);

        return new;
}


void idmef_correlation_alert_new(idmef_alert_t *alert) 
{        
        alert->type = idmef_correlation_alert;
        alert->detail.correlation_alert = &correlation_alert;
}



/*
 * Overflow alert stuff
 */
void idmef_overflow_alert_new(idmef_alert_t *alert) 
{
         
        alert->type = idmef_overflow_alert;
        alert->detail.overflow_alert = &overflow_alert;
}



idmef_message_t *idmef_message_new(void) 
{
        static idmef_message_t msg;
 
 
        /*
         * set static variable data to 0
         */
        memset(&msg, 0, sizeof(msg));
        memset(&alert, 0, sizeof(alert));
        memset(&static_detect_time, 0, sizeof(static_detect_time));
        memset(&static_analyzer_time, 0, sizeof(static_analyzer_time));
        memset(&analyzer_node, 0, sizeof(analyzer_node));
        memset(&analyzer_process, 0, sizeof(analyzer_process));

        /*
         * Re-initialize alert.
         */
        INIT_LIST_HEAD(&alert.source_list);
        INIT_LIST_HEAD(&alert.target_list);
        INIT_LIST_HEAD(&alert.classification_list);
        INIT_LIST_HEAD(&alert.additional_data_list);

        /*
         * tool alert.
         */
        memset(&tool_alert, 0, sizeof(tool_alert));        
        INIT_LIST_HEAD(&tool_alert.alertident_list);

        /*
         * overflow alert
         */
        memset(&overflow_alert, 0, sizeof(overflow_alert));

        /*
         * correlation alert
         */
        memset(&correlation_alert, 0, sizeof(correlation_alert));
        INIT_LIST_HEAD(&correlation_alert.alertident_list);

        /*
         * heartbeat.
         */
        memset(&heartbeat, 0, sizeof(heartbeat));
        INIT_LIST_HEAD(&heartbeat.additional_data_list);

        return &msg;
}



void idmef_message_free(idmef_message_t *msg) 
{
        switch ( msg->type ) {
        case idmef_alert_message:
                free_alert(msg->message.alert);
                break;

        case idmef_heartbeat_message:
                free_heartbeat(msg->message.heartbeat);
                break;
        }
}




/*
 * IDMEF Service.
 */
idmef_webservice_t *idmef_service_webservice_new(idmef_service_t *service)
{
        idmef_webservice_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        service->type = web_service;
        service->specific.web = new;

        return new;
}



idmef_snmpservice_t *idmef_service_snmpservice_new(idmef_service_t *service)
{
        idmef_snmpservice_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        service->type = snmp_service;
        service->specific.snmp = new;

        return new;
}



/*
 * IDMEF Node.
 */
idmef_address_t *idmef_node_address_new(idmef_node_t *node) 
{
        idmef_address_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->category = unknown;
        list_add(&new->list, &node->address_list);

        return new;
}




/*
 * IDMEF Process.
 */
idmef_process_arg_t *idmef_process_arg_new(idmef_process_t *process) 
{
        idmef_process_arg_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        list_add(&new->list, &process->arg_list);

        return new;
}




idmef_process_env_t *idmef_process_env_new(idmef_process_t *process) 
{
        idmef_process_env_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        list_add(&new->list, &process->env_list);

        return new;
}




/*
 * IDMEF User.
 */
idmef_userid_t *idmef_user_userid_new(idmef_user_t *user) 
{
        idmef_userid_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->type = original_user;
        list_add(&new->list, &user->userid_list);

        return new;
}




/*
 * IDMEF Source.
 * we don't use statically allocated data for data within the source
 * structure, cause there can be several source within an alert.
 */
idmef_service_t *idmef_source_service_new(idmef_source_t *source) 
{
        idmef_service_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->type = default_service;
        source->service = new;

        return new;
}



idmef_user_t *idmef_source_user_new(idmef_source_t *source) 
{
        idmef_user_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        source->user = new;
        new->category = unknown;
        INIT_LIST_HEAD(&new->userid_list);

        return new;
}


idmef_node_t *idmef_source_node_new(idmef_source_t *source) 
{
        idmef_node_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        source->node = new;
        
        new->category = unknown;
        INIT_LIST_HEAD(&new->address_list);

        return new;
}


idmef_process_t *idmef_source_process_new(idmef_source_t *source) 
{
        idmef_process_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }
        
        source->process = new;
        INIT_LIST_HEAD(&new->arg_list);
        INIT_LIST_HEAD(&new->env_list);
        
        return new;
}




/*
 * IDMEF Analyzer.
 */
void idmef_analyzer_node_new(idmef_analyzer_t *analyzer) 
{
        analyzer->node = &analyzer_node;
        analyzer_node.category = unknown;
}



void idmef_analyzer_process_new(idmef_analyzer_t *analyzer) 
{
        analyzer->process = &analyzer_process;
        INIT_LIST_HEAD(&analyzer_process.arg_list);
        INIT_LIST_HEAD(&analyzer_process.env_list);
}




/*
 * IDMEF Alert
 */
void idmef_alert_detect_time_new(idmef_alert_t *alert) 
{
        alert->detect_time = &static_detect_time;
}



void idmef_alert_analyzer_time_new(idmef_alert_t *alert) 
{
        alert->analyzer_time = &static_analyzer_time;
}



idmef_target_t *idmef_alert_target_new(idmef_alert_t *alert) 
{
        idmef_target_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->decoy = unknown;
        list_add(&new->list, &alert->target_list);

        return new;
}




idmef_source_t *idmef_alert_source_new(idmef_alert_t *alert) 
{
        idmef_source_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->spoofed = unknown;
        list_add(&new->list, &alert->source_list);

        return new;
}



idmef_classification_t *idmef_alert_classification_new(idmef_alert_t *alert) 
{
        idmef_classification_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->origin = unknown;
        list_add(&new->list, &alert->classification_list);

        return new;
}




idmef_additional_data_t *idmef_alert_additional_data_new(idmef_alert_t *alert)  
{
        idmef_additional_data_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->type = string;
        list_add(&new->list, &alert->additional_data_list);

        return new;
}




void idmef_alert_new(idmef_message_t *message) 
{
        message->message.alert = &alert;
        message->type = idmef_alert_message;
        
        fill_alert_infos(&alert);
}




/*
 * IDMEF Heartbeat
 */
idmef_additional_data_t *idmef_heartbeat_additional_data_new(idmef_heartbeat_t *hb)  
{
        idmef_additional_data_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        new->type = string;
        list_add(&new->list, &hb->additional_data_list);

        return new;
}



void idmef_heartbeat_analyzer_time_new(idmef_heartbeat_t *heartbeat) 
{
        heartbeat->analyzer_time = &static_analyzer_time;
}



void idmef_heartbeat_new(idmef_message_t *message) 
{        
        message->message.heartbeat = &heartbeat;
        message->type = idmef_heartbeat_message;
}




/*
 *
 */


const char *idmef_additional_data_type_to_string(idmef_additional_data_type_t type)  
{
        static const char *tbl[] = {
                "boolean",
                "byte",
                "character",
                "date-time",
                "integer",
                "ntpstamps",
                "portlist",
                "real",
                "string",
                "xml",
        };

        /*
         * Assert on read overflow.
         */
        assert( type < (sizeof(tbl) / sizeof(void *)) );

        return tbl[type];        
}




const char *idmef_classification_origin_to_string(idmef_classification_origin_t origin)  
{
        static const char *tbl[] = {
                "unknown",
                "bugtraqid",
                "cve",
                "vendor-specific",
        };
        
        /*
         * Assert on read overflow.
         */
        assert( origin < (sizeof(tbl) / sizeof(void *)) );

        return tbl[origin];  
}




const char *idmef_address_category_to_string(idmef_address_category_t category) 
{
        static const char *tbl[] = {
                "unknown",
                "atm",
                "e-mail",
                "lotus-notes",
                "mac",
                "sna",
                "vm",
                "ipv4-addr",
                "ipv4-addr-hex",
                "ipv4-net",
                "ipv4-net-mask",
                "ipv6-addr",
                "ipv6-addr-hex",
                "ipv6-net",
                "ipv6-net-mask",
        };
        

        assert( category < (sizeof(tbl) / sizeof(void *)) );
        
        return tbl[category];
}





const char *idmef_node_category_to_string(idmef_node_category_t category) 
{
        static const char *tbl[] = {
                "unknown",
                "ads",
                "afs",
                "coda",
                "dfs",
                "dns",
                "kerberos",
                "nds",
                "nis",
                "nisplus",
                "nt",
                "wfw",
        };

        assert( category < (sizeof(tbl) / sizeof(void *)) );

        return tbl[category];
}



const char *idmef_user_category_to_string(idmef_user_category_t category) 
{
        static const char *tbl[] = {
                "unknown",
                "application",
                "os-device",
        };

        assert( category < (sizeof(tbl) / sizeof(void *)) );

        return tbl[category];
}




const char *idmef_userid_type_to_string(idmef_userid_type_t type) 
{
        static const char *tbl[] = {
                "current-user",
                "original-user",
                "target-user",
                "user-privs",
                "current-group",
                "group-privs",
        };
        
        assert( type < (sizeof(tbl) / sizeof(void *)) );

        return tbl[type];
}



const char *idmef_source_spoofed_to_string(idmef_spoofed_t spoofed) 
{
        static const char *tbl[] = {
                "unknown",
                "yes",
                "no",
        };

        assert( spoofed < (sizeof(tbl) / sizeof(void *)) );

        return tbl[spoofed];
}



const char *idmef_target_decoy_to_string(idmef_spoofed_t decoy) 
{
        static const char *tbl[] = {
                "unknown",
                "yes",
                "no",
        };

        assert( decoy < (sizeof(tbl) / sizeof(void *)) );

        return tbl[decoy];
}
