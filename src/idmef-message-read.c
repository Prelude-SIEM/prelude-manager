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
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libprelude/list.h>
#include <libprelude/prelude-log.h>
#include <libprelude/extract.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/idmef-message-id.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/idmef-tree-func.h>
#include <libprelude/plugin-common.h>

#include "plugin-decode.h"
#include "idmef-message-read.h"
#include "idmef-util.h"
#include "config.h"


#define extract_idmef_string(buf, blen, dst) do {                         \
        int ret;                                                          \
        ret = extract_string_safe(&dst.string, buf, blen);                \
        if ( ret < 0 )                                                    \
               return -1;                                                 \
        dst.len = blen;							  \
} while(0)



#define extract_int(type, buf, blen, dst) do {        \
                                                      \
        if ( sizeof(type ## _t) != blen ) {           \
                log(LOG_ERR, "Datatype error, buffer is not %s: couldn't convert.\n", "type ## _t"); \
                return -1;                            \
        }                                             \
                                                      \
        dst = extract_ ## type ((unsigned char *) buf);   \
} while (0)



static int additional_data_get(prelude_msg_t *msg, idmef_additional_data_t *data) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;

        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_ADDITIONALDATA_TYPE:
                extract_int(uint32, buf, len, data->type);
                break;

        case MSG_ADDITIONALDATA_MEANING:
                extract_idmef_string(buf, len, data->meaning);
                break;

        case MSG_ADDITIONALDATA_DATA:
                data->data = buf;
                data->dlen = len;
                break;

        case MSG_END_OF_TAG:
                return 0;
                
        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;
        }

        return additional_data_get(msg, data);
}




static int classification_get(prelude_msg_t *msg, idmef_classification_t *class) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;

        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_CLASSIFICATION_ORIGIN:
                extract_int(uint32, buf, len, class->origin);
                break;

        case MSG_CLASSIFICATION_NAME:
                extract_idmef_string(buf, len, class->name);
                break;

        case MSG_CLASSIFICATION_URL:
                extract_idmef_string(buf, len, class->url);
                break;

        case MSG_END_OF_TAG:
                return 0;
                
        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;
        }

        return classification_get(msg, class);
}




static int userid_get(prelude_msg_t *msg, idmef_userid_t *uid) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;

        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_USERID_TYPE:
                extract_int(uint32, buf, len, uid->type);
                break;

        case MSG_USERID_NAME:
                extract_idmef_string(buf, len, uid->name);
                break;

        case MSG_USERID_NUMBER:
                extract_int(uint32, buf, len, uid->number);
                break;

        case MSG_END_OF_TAG:
                return 0;
                
        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;
        }

        return userid_get(msg, uid);
}



static int user_get(prelude_msg_t *msg, idmef_user_t *user) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        idmef_userid_t *uid;
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_USER_CATEGORY:
                extract_int(uint32, buf, len, user->category);
                break;

        case MSG_USERID_TAG:
                uid = idmef_user_userid_new(user);
                if ( ! uid )
                        return -1;
                
                ret = userid_get(msg, uid);
                if ( ret < 0 )
                        return ret;
                break;

        case MSG_END_OF_TAG:
                return 0;
                
        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;
        }

        return user_get(msg, user);
}




static int process_get(prelude_msg_t *msg, idmef_process_t *process) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        idmef_process_env_t *env;
        idmef_process_arg_t *arg;

        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_PROCESS_NAME:
                extract_idmef_string(buf, len, process->name);
                break;

        case MSG_PROCESS_PID:
                extract_int(uint32, buf, len, process->pid);
                break;

        case MSG_PROCESS_PATH:
                extract_idmef_string(buf, len, process->path);
                break;

        case MSG_PROCESS_ARG:
                arg = idmef_process_arg_new(process);
                if ( ! arg )
                        return -1;
                
                extract_idmef_string(buf, len, arg->string);
                break;

        case MSG_PROCESS_ENV:
                env = idmef_process_env_new(process);
                if ( ! env )
                        return -1;
                
                extract_idmef_string(buf, len, env->string);
                break;

        case MSG_END_OF_TAG:
                return 0;

        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;                
        }

        return process_get(msg, process);
}



static int address_get(prelude_msg_t *msg, idmef_address_t *addr) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;

        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_ADDRESS_CATEGORY:
                extract_int(uint32, buf, len, addr->category);
                break;

        case MSG_ADDRESS_VLAN_NAME:
                extract_idmef_string(buf, len, addr->vlan_name);
                break;

        case MSG_ADDRESS_VLAN_NUM:
                extract_int(uint32, buf, len, addr->vlan_num);
                break;

        case MSG_ADDRESS_ADDRESS:
                extract_idmef_string(buf, len, addr->address);
                break;

        case MSG_ADDRESS_NETMASK:
                extract_idmef_string(buf, len, addr->netmask);
                break;

        case MSG_END_OF_TAG:
                return 0;

        default:
               log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;                
        }

        return address_get(msg, addr);
}



static int snmp_service_get(prelude_msg_t *msg, idmef_snmpservice_t *snmp) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {
                
        case MSG_SNMPSERVICE_OID:
                extract_idmef_string(buf, len, snmp->oid);
                break;

        case MSG_SNMPSERVICE_COMMUNITY:
                extract_idmef_string(buf, len, snmp->community);
                break;

        case MSG_SNMPSERVICE_COMMAND:
                extract_idmef_string(buf, len, snmp->command);
                break;

        case MSG_END_OF_TAG:
                return 0;

        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;         
        }

        return snmp_service_get(msg, snmp);
}



static int web_service_get(prelude_msg_t *msg, idmef_webservice_t *web) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        idmef_webservice_arg_t *arg;
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_WEBSERVICE_URL:
                extract_idmef_string(buf, len, web->url);
                break;

        case MSG_WEBSERVICE_CGI:
                extract_idmef_string(buf, len, web->cgi);
                break;

        case MSG_WEBSERVICE_HTTP_METHOD:
                extract_idmef_string(buf, len, web->http_method);
                break;

        case MSG_WEBSERVICE_ARG:
                arg = idmef_webservice_arg_new(web);
                if ( ! arg )
                        return -1;
                
                extract_idmef_string(buf, len, arg->arg);
                break;

        case MSG_END_OF_TAG:
                return 0;

        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;         
        }

        return web_service_get(msg, web);
}





static int service_get(prelude_msg_t *msg, idmef_service_t *service) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        idmef_webservice_t *web;
        idmef_snmpservice_t *snmp;
        
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_SERVICE_NAME:
                extract_idmef_string(buf, len, service->name);
                break;

        case MSG_SERVICE_PORT:
                extract_int(uint16, buf, len, service->port);
                break;

        case MSG_SERVICE_PORTLIST:
                extract_idmef_string(buf, len, service->portlist);
                break;

        case MSG_SERVICE_PROTOCOL:
                extract_idmef_string(buf, len, service->protocol);
                break;

        case MSG_WEBSERVICE_TAG:
                web = idmef_service_webservice_new(service);
                if ( ! web )
                        return -1;
                
                ret = web_service_get(msg, web);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_SNMPSERVICE_TAG:
                snmp = idmef_service_snmpservice_new(service);
                if ( ! snmp )
                        return -1;

                ret = snmp_service_get(msg, snmp);
                if ( ret < 0 )
                        return -1;
                break;
                
        case MSG_END_OF_TAG:
                return 0;
                
        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;
        }

        return service_get(msg, service);
}



static int node_get(prelude_msg_t *msg, idmef_node_t *node) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        idmef_address_t *addr;

        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_NODE_CATEGORY:
                extract_int(uint32, buf, len, node->category);
                break;

        case MSG_NODE_LOCATION:
                extract_idmef_string(buf, len, node->location);
                break;

        case MSG_NODE_NAME:
                extract_idmef_string(buf, len, node->name);
                break;

        case MSG_ADDRESS_TAG:
                addr = idmef_node_address_new(node);
                if (! addr )
                        return -1;
                
                ret = address_get(msg, addr);
                if ( ret < 0 )
                        return -1;
                break;
                
        case MSG_END_OF_TAG:
                return 0;

        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;                 
        }

        return node_get(msg, node);
}





static int analyzer_get(prelude_msg_t *msg, idmef_analyzer_t *analyzer) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_ANALYZER_ID:
                extract_int(uint64, buf, len, analyzer->analyzerid);
                break;
                
        case MSG_ANALYZER_MANUFACTURER:
                extract_idmef_string(buf, len, analyzer->manufacturer);
                break;

        case MSG_ANALYZER_MODEL:
                extract_idmef_string(buf, len, analyzer->model);
                break;

        case MSG_ANALYZER_VERSION:
                extract_idmef_string(buf, len, analyzer->version);
                break;

        case MSG_ANALYZER_CLASS:
                extract_idmef_string(buf, len, analyzer->class);
                break;

        case MSG_ANALYZER_OSTYPE:
                extract_idmef_string(buf, len, analyzer->ostype);
                break;

        case MSG_ANALYZER_OSVERSION:
                extract_idmef_string(buf, len, analyzer->osversion);
                break;
                
        case MSG_NODE_TAG:                
                idmef_analyzer_node_new(analyzer);
                ret = node_get(msg, analyzer->node);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_PROCESS_TAG:
                idmef_analyzer_process_new(analyzer);
                
                ret = process_get(msg, analyzer->process);
                if ( ret < 0 )
                        return -1;
                break;
                
        case MSG_END_OF_TAG:
                return 0;

        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;
        }

        return analyzer_get(msg, analyzer);
}




static int source_get(prelude_msg_t *msg, idmef_source_t *src) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;

        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_SOURCE_IDENT:
                extract_int(uint64, buf, len, src->ident);
                break;
                
        case MSG_SOURCE_SPOOFED:
                extract_int(uint32, buf, len, src->spoofed);
                break;

        case MSG_SOURCE_INTERFACE:
                extract_idmef_string(buf, len, src->interface);
                break;

        case MSG_NODE_TAG:
                idmef_source_node_new(src);
                
                ret = node_get(msg, src->node);
                if ( ret < 0 )
                        return ret;
                break;

        case MSG_USER_TAG:
                idmef_source_user_new(src);
                
                ret = user_get(msg, src->user);
                if ( ret < 0 )
                        return ret;
                break;

        case MSG_PROCESS_TAG:
                idmef_source_process_new(src);
                                
                ret = process_get(msg, src->process);
                if ( ret < 0 )
                        return ret;
                break;

        case MSG_SERVICE_TAG:
                idmef_source_service_new(src);
                                
                ret = service_get(msg, src->service);
                if ( ret < 0 )
                        return ret;
                break;

        case MSG_END_OF_TAG:
                return 0;

        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;
        }

        return source_get(msg, src);
}




static int target_get(prelude_msg_t *msg, idmef_target_t *dst) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;

        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_TARGET_IDENT:
                extract_int(uint64, buf, len, dst->ident);
                break;
                
        case MSG_TARGET_DECOY:
                extract_int(uint32, buf, len, dst->decoy);
                break;

        case MSG_TARGET_INTERFACE:
                extract_idmef_string(buf, len, dst->interface);
                break;

        case MSG_NODE_TAG:
                idmef_target_node_new(dst);
                
                ret = node_get(msg, dst->node);
                if ( ret < 0 )
                        return ret;
                break;

        case MSG_USER_TAG:
                idmef_target_user_new(dst);

                ret = user_get(msg, dst->user);
                if ( ret < 0 )
                        return ret;
                break;

        case MSG_PROCESS_TAG:
                idmef_target_process_new(dst);
                                
                ret = process_get(msg, dst->process);
                if ( ret < 0 )
                        return ret;
                break;

        case MSG_SERVICE_TAG:
                idmef_target_service_new(dst);
                
                ret = service_get(msg, dst->service);
                if ( ret < 0 )
                        return ret;
                break;

        case MSG_END_OF_TAG:
                return 0;
                
        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;
        }

        return target_get(msg, dst);
}





static int time_get(prelude_msg_t *msg, idmef_time_t *time,
                    char *ctime, size_t csize, char *ntptime, size_t nsize)
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_TIME_SEC:
                extract_int(uint32, buf, len, time->sec);
                break;

        case MSG_TIME_USEC:
                extract_int(uint32, buf, len, time->usec);
                break;

        case MSG_END_OF_TAG:
                return 0;
                
        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;
        }
        
        return time_get(msg, time, ctime, csize, ntptime, nsize);
}



static int create_time_get(prelude_msg_t *msg, idmef_time_t *time)
{
        static char ctime[MAX_UTC_DATETIME_SIZE], ntptime[MAX_NTP_TIMESTAMP_SIZE];
        return time_get(msg, time, ctime, sizeof(ctime), ntptime, sizeof(ntptime));
}



static int analyzer_time_get(prelude_msg_t *msg, idmef_time_t *time) 
{
        static char ctime[MAX_UTC_DATETIME_SIZE], ntptime[MAX_NTP_TIMESTAMP_SIZE];
        return time_get(msg, time, ctime, sizeof(ctime), ntptime, sizeof(ntptime));
}


static int detect_time_get(prelude_msg_t *msg, idmef_time_t *time) 
{
        static char ctime[MAX_UTC_DATETIME_SIZE], ntptime[MAX_NTP_TIMESTAMP_SIZE];
        return time_get(msg, time, ctime, sizeof(ctime), ntptime, sizeof(ntptime));
}



static int alertident_get(prelude_msg_t *msg, idmef_alertident_t *alertident) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_ALERTIDENT_IDENT:
                extract_int(uint64, buf, len, alertident->alertident);
                break;

        case MSG_ALERTIDENT_ANALYZER_IDENT:
                extract_int(uint64, buf, len, alertident->analyzerid);
                break;

        case MSG_END_OF_TAG:
                return 0;
                
        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;
        }
        
        return alertident_get(msg, alertident);
}
                          



static int tool_alert_get(prelude_msg_t *msg, idmef_tool_alert_t *tool) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        idmef_alertident_t *alertident;
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_TOOL_ALERT_NAME:
                extract_idmef_string(buf, len, tool->name);
                break;

        case MSG_TOOL_ALERT_COMMAND:
                extract_idmef_string(buf, len, tool->command);
                break;

        case MSG_ALERTIDENT_TAG:
                alertident = idmef_tool_alert_alertident_new(tool);
                if ( ! alertident )
                        return -1;

                ret = alertident_get(msg, alertident);
                if ( ret < 0 )
                        return -1;
                
        case MSG_END_OF_TAG:
                return 0;
                
        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;      
        }

        return tool_alert_get(msg, tool);
}



static int correlation_alert_get(prelude_msg_t *msg, idmef_correlation_alert_t *correlation) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        idmef_alertident_t *alertident;
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_CORRELATION_ALERT_NAME:
                extract_idmef_string(buf, len, correlation->name);
                break;

        case MSG_ALERTIDENT_TAG:
                alertident = idmef_correlation_alert_alertident_new(correlation);
                if ( ! alertident )
                        return -1;

                ret = alertident_get(msg, alertident);
                if ( ret < 0 )
                        return -1;
                break;
                
        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;      
        }

        return correlation_alert_get(msg, correlation);
}




static int overflow_alert_get(prelude_msg_t *msg, idmef_overflow_alert_t *overflow) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_OVERFLOW_ALERT_PROGRAM:
                extract_idmef_string(buf, len, overflow->program);
                break;

        case MSG_OVERFLOW_ALERT_SIZE:
                /*
                 * ignore this one,
                 * prefer the use of len in MSG_OVERFLOW_BUFFER
                 */
                break;

        case MSG_OVERFLOW_ALERT_BUFFER:
                overflow->size = len;
                overflow->buffer = (const unsigned char *) buf;
                break;
                
        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;      
        }

        return overflow_alert_get(msg, overflow);
}





static int impact_get(prelude_msg_t *msg, idmef_impact_t *impact) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_IMPACT_SEVERITY:
                extract_int(uint32, buf, len, impact->severity);
                break;

        case MSG_IMPACT_COMPLETION:
                extract_int(uint32, buf, len, impact->completion);
                break;

        case MSG_IMPACT_TYPE:
                extract_int(uint32, buf, len, impact->type);
                break;

        case MSG_IMPACT_DESCRIPTION:
                extract_idmef_string(buf, len, impact->description);
                break;

        case MSG_END_OF_TAG:
                return 0;
                
        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;      
        }

        return impact_get(msg, impact);
}




static int confidence_get(prelude_msg_t *msg, idmef_confidence_t *confidence) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        
        switch (tag) {

        case MSG_CONFIDENCE_RATING:
                extract_int(uint32, buf, len, confidence->rating);
                break;

        case MSG_CONFIDENCE_CONFIDENCE:
                extract_int(uint32, buf, len, confidence->confidence);
                break;
                
        case MSG_END_OF_TAG:
                return 0;

        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;      
        }

        return confidence_get(msg, confidence);
}



static int action_get(prelude_msg_t *msg, idmef_action_t *action) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_ACTION_CATEGORY:
                extract_int(uint32, buf, len, action->category);
                break;

        case MSG_ACTION_DESCRIPTION:
                extract_idmef_string(buf, len, action->description);
                break;
                
        case MSG_END_OF_TAG:
                return 0;

        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;      
        }

        return action_get(msg, action);
}




static int assessment_get(prelude_msg_t *msg, idmef_assessment_t *assessment) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        idmef_action_t *action;
        
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_IMPACT_TAG:
                idmef_assessment_impact_new(assessment);
                ret = impact_get(msg, assessment->impact);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_ACTION_TAG:
                action = idmef_assessment_action_new(assessment);
                if ( ! action )
                        return -1;
                
                ret = action_get(msg, action);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_CONFIDENCE_TAG:
                idmef_assessment_confidence_new(assessment);
                ret = confidence_get(msg, assessment->confidence);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_END_OF_TAG:
                return 0;
                
        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;      
        }

        return assessment_get(msg, assessment);
}




static int alert_get(prelude_msg_t *msg, idmef_alert_t *alert) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        idmef_source_t *src;
        idmef_target_t *dst;
        idmef_classification_t *class;
        idmef_additional_data_t *data;        
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);        
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_ALERT_IDENT:
                extract_int(uint64, buf, len, alert->ident);
                break;

        case MSG_ASSESSMENT_TAG:
                idmef_alert_assessment_new(alert);
                
                ret = assessment_get(msg, alert->assessment);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_ANALYZER_TAG:
                ret = analyzer_get(msg, &alert->analyzer);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_CREATE_TIME_TAG:
                ret = create_time_get(msg, &alert->create_time);
                if ( ret < 0 )
                        return -1;
                break;
                
        case MSG_DETECT_TIME_TAG:
                idmef_alert_detect_time_new(alert);

                ret = detect_time_get(msg, alert->detect_time);
                if ( ret < 0 )
                        return -1;
                break;
                
        case MSG_ANALYZER_TIME_TAG:
                idmef_alert_analyzer_time_new(alert);
                
                ret = analyzer_time_get(msg, alert->analyzer_time);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_SOURCE_TAG:
                src = idmef_alert_source_new(alert);
                if ( ! src )
                        return -1;

                ret = source_get(msg, src);
                if ( ret < 0 ) 
                        return -1;
                break;

        case MSG_TARGET_TAG:
                dst = idmef_alert_target_new(alert);
                if ( ! dst )
                        return -1;

                ret = target_get(msg, dst);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_CLASSIFICATION_TAG:
                class = idmef_alert_classification_new(alert);
                if ( ! class )
                        return -1;

                ret = classification_get(msg, class);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_ADDITIONALDATA_TAG:
                data = idmef_alert_additional_data_new(alert);
                if ( ! data )
                        return -1;

                ret = additional_data_get(msg, data);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_TOOL_ALERT_TAG:
                idmef_tool_alert_new(alert);
                
                ret = tool_alert_get(msg, alert->detail.tool_alert);
                if ( ret < 0 )
                        return -1;
                break;
                
        case MSG_CORRELATION_ALERT_TAG:
                idmef_correlation_alert_new(alert);
                
                ret = correlation_alert_get(msg, alert->detail.correlation_alert);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_OVERFLOW_ALERT_TAG:
                idmef_overflow_alert_new(alert);

                ret = overflow_alert_get(msg, alert->detail.overflow_alert);
                if ( ret < 0 )
                        return -1;
                
        case MSG_END_OF_TAG:
                return 0;
                
        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;
        }

        return alert_get(msg, alert);
}




static int heartbeat_get(prelude_msg_t *msg, idmef_heartbeat_t *heartbeat) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        idmef_additional_data_t *data;
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);        
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_ANALYZER_TAG:
                ret = analyzer_get(msg, &heartbeat->analyzer);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_CREATE_TIME_TAG:
                ret = create_time_get(msg, &heartbeat->create_time);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_ANALYZER_TIME_TAG:
                idmef_heartbeat_analyzer_time_new(heartbeat);
                
                ret = analyzer_time_get(msg, heartbeat->analyzer_time);
                if ( ret < 0 )
                        return -1;
                break;
                
        case MSG_ADDITIONALDATA_TAG:
                data = idmef_heartbeat_additional_data_new(heartbeat);
                if ( ! data )
                        return -1;
                
                ret = additional_data_get(msg, data);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_END_OF_TAG:
                return 0;

        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;     
        }

        return heartbeat_get(msg, heartbeat);
}



/**
 * idmef_message_read:
 * @idmef: A new IDMEF message.
 * @msg: The message to translate to IDMEF.
 *
 * idmef_message_read() extract an IDMEF message from @msg and
 * store it into @idmef.
 *
 * Returns: 0 on success, -1 on error.
 */
int idmef_message_read(idmef_message_t *idmef, prelude_msg_t *msg)
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;


        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 ) 
                return ret; /* Message should always terminate by END OF TAG */
        
        switch (tag) {

        case MSG_ALERT_TAG:
                idmef_alert_new(idmef);

                ret = alert_get(msg, idmef->message.alert);
                if ( ret < 0 )
                        return -1;
                
                idmef_alert_get_ident(idmef->message.alert);

                break;

        case MSG_HEARTBEAT_TAG:
                                
                idmef_heartbeat_new(idmef);

                ret = heartbeat_get(msg, idmef->message.heartbeat);
                if ( ret < 0 )
                        return -1;

                idmef_heartbeat_get_ident(idmef->message.heartbeat);
                
                break;
                
        case MSG_OWN_FORMAT:
                                
                ret = extract_uint8_safe(&tag, buf, len);
                if ( ret < 0 )
                        return -1;
                
                ret = decode_plugins_run(tag, msg, idmef);                
                if ( ret < 0 ) 
                        return ret;
                
                break;
                
        case MSG_END_OF_TAG:
                return 0;

        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;
        }
        
        return idmef_message_read(idmef, msg);
}


