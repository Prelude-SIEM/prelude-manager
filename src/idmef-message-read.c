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
#include <unistd.h>
#include <inttypes.h>
#include <netinet/in.h>

#include <libprelude/common.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/idmef-message-id.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/plugin-common.h>

#include "plugin-decode.h"
#include "idmef-func.h"
#include "idmef-message-read.h"





static int extract_uint64(uint64_t *dst, void *buf, uint32_t blen) 
{
        if ( blen != sizeof(uint64_t) ) {
                log(LOG_ERR, "Datatype error, buffer is not uint64: couldn't convert.\n");
                return -1;
        }

        *dst = *(uint64_t *) buf;

        return 0;
}




static int extract_uint32(uint32_t *dst, void *buf, uint32_t blen) 
{
        if ( blen != sizeof(uint32_t) ) {
                log(LOG_ERR, "Datatype error, buffer is not uint32: couldn't convert.\n");
                return -1;
        }

        *dst = ntohl(*(uint32_t *) buf);

        return 0;
}



static int extract_uint16(uint16_t *dst, void *buf, uint32_t blen) 
{
        if ( blen != sizeof(uint16_t) ) {
                log(LOG_ERR, "Datatype error, buffer is not uint16: couldn't convert.\n");
                return -1;
        }

        *dst = ntohs(*(uint16_t *) buf);

        return 0;
}





static int extract_uint8(uint8_t *dst, void *buf, uint32_t blen) 
{
        if ( blen != sizeof(uint8_t) ) {
                log(LOG_ERR, "Datatype error, buffer is not uint8: couldn't convert.\n");
                return -1;
        }

        *dst = *(uint8_t *) buf;

        return 0;
}




static const char *extract_str(void *buf, uint32_t blen) 
{
        const char *str = buf;
        
        if ( str[blen - 1] != '\0' ) 
                return NULL;

        return buf;
}



#define extract_int(type, buf, blen, dst) do {        \
        int ret;                                      \
        ret = extract_ ## type (&dst, buf, blen);     \
        if ( ret < 0 )                                \
                return -1;                            \
} while (0)
           

#define extract_string(buf, blen, dst)      \
        dst = extract_str(buf, blen);       \
        if ( ! dst ) {                      \
               log(LOG_ERR, "Datatype error, buffer is not a string.\n"); \
               return -1;                                                 \
        }                                                                 
               




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
                data->type = ntohl( *(uint32_t *) buf);
                extract_int(uint32, buf, len, data->type);
                break;

        case MSG_ADDITIONALDATA_MEANING:
                extract_string(buf, len, data->meaning);
                break;

        case MSG_ADDITIONALDATA_DATA:
                extract_string(buf, len, data->data);
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
                extract_string(buf, len, class->name);
                break;

        case MSG_CLASSIFICATION_URL:
                extract_string(buf, len, class->url);
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
                extract_string(buf, len, uid->name);
                break;

        case MSG_USERID_NUMBER:
                extract_string(buf, len, uid->number);
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
                extract_string(buf, len, process->name);
                break;

        case MSG_PROCESS_PID:
                extract_int(uint32, buf, len, process->pid);
                break;

        case MSG_PROCESS_PATH:
                extract_string(buf, len, process->path);
                break;

        case MSG_PROCESS_ARG:
                arg = idmef_process_arg_new(process);
                if ( ! arg )
                        return -1;
                
                extract_string(buf, len, arg->string);
                break;

        case MSG_PROCESS_ENV:
                env = idmef_process_env_new(process);
                if ( ! env )
                        return -1;
                
                extract_string(buf, len, env->string);
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
                extract_string(buf, len, addr->vlan_name);
                break;

        case MSG_ADDRESS_VLAN_NUM:
                extract_int(uint32, buf, len, addr->vlan_num);
                break;

        case MSG_ADDRESS_ADDRESS:
                extract_string(buf, len, addr->address);
                break;

        case MSG_ADDRESS_NETMASK:
                extract_string(buf, len, addr->netmask);
                break;

        case MSG_END_OF_TAG:
                return 0;

        default:
               log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;                
        }

        return address_get(msg, addr);
}



static int service_get(prelude_msg_t *msg, idmef_service_t *service) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;

        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_SERVICE_NAME:
                extract_string(buf, len, service->name);
                break;

        case MSG_SERVICE_PORT:
                extract_int(uint16, buf, len, service->port);
                break;

        case MSG_SERVICE_PORTLIST:
                extract_string(buf, len, service->portlist);
                break;

        case MSG_SERVICE_PROTOCOL:
                extract_string(buf, len, service->protocol);
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
                extract_string(buf, len, node->location);
                break;

        case MSG_NODE_NAME:
                extract_string(buf, len, node->name);
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

        case MSG_ANALYZER_MANUFACTURER:
                extract_string(buf, len, analyzer->manufacturer);
                break;

        case MSG_ANALYZER_MODEL:
                extract_string(buf, len, analyzer->model);
                break;

        case MSG_ANALYZER_VERSION:
                extract_string(buf, len, analyzer->version);
                break;

        case MSG_ANALYZER_CLASS:
                extract_string(buf, len, analyzer->class);
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
                extract_string(buf, len, src->interface);
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
                extract_string(buf, len, dst->interface);
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




static int time_get(prelude_msg_t *msg, idmef_time_t *time)
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        struct timeval tv;
        static char ctime[MAX_UTC_DATETIME_SIZE], ntptime[MAX_NTP_TIMESTAMP_SIZE];
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_TIME_SEC:
                ret = extract_uint32((uint32_t *) &tv.tv_sec, buf, len);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_TIME_USEC:
                ret = extract_uint32((uint32_t *)&tv.tv_usec, buf, len);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_END_OF_TAG:
                idmef_get_timestamp(&tv, ctime, sizeof(ctime));
                idmef_get_ntp_timestamp(&tv, ntptime, sizeof(ntptime));
                return 0;
                
        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;
        }
        
        return time_get(msg, time);
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
                extract_string(buf, len, tool->name);
                break;

        case MSG_TOOL_ALERT_COMMAND:
                extract_string(buf, len, tool->command);
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
                extract_string(buf, len, correlation->name);
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
                extract_string(buf, len, overflow->program);
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

        case MSG_ALERT_IMPACT:
                extract_string(buf, len, alert->impact);
                break;

        case MSG_ALERT_ACTION:
                extract_string(buf, len, alert->action);
                break;

        case MSG_ANALYZER_TAG:
                ret = analyzer_get(msg, &alert->analyzer);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_CREATE_TIME_TAG:
                ret = time_get(msg, &alert->create_time);
                if ( ret < 0 )
                        return -1;
                break;
                
        case MSG_DETECT_TIME_TAG:
                idmef_alert_detect_time_new(alert);

                ret = time_get(msg, alert->detect_time);
                if ( ret < 0 )
                        return -1;
                break;
                
        case MSG_ANALYZER_TIME_TAG:
                idmef_alert_analyzer_time_new(alert);
                
                ret = time_get(msg, alert->analyzer_time);
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
                ret = time_get(msg, &heartbeat->create_time);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_ANALYZER_TIME_TAG:
                idmef_heartbeat_analyzer_time_new(heartbeat);
                
                ret = time_get(msg, heartbeat->analyzer_time);
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
                break;

        case MSG_HEARTBEAT_TAG:
                idmef_heartbeat_new(idmef);
                ret = heartbeat_get(msg, idmef->message.heartbeat);
                if ( ret < 0 )
                        return -1;

        case MSG_OWN_FORMAT:
                extract_int(uint8, buf, len, tag);
                
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


