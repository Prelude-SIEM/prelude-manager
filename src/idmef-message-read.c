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
                data->type = ntohl( *((uint32_t *) buf));
                break;

        case MSG_ADDITIONALDATA_MEANING:
                data->meaning = buf;
                break;

        case MSG_ADDITIONALDATA_DATA:
                data->data = buf;
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
        printf("class %d\n", ret);
        
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_CLASSIFICATION_ORIGIN:
                class->origin = ntohl( *((uint32_t *) buf));                
                break;

        case MSG_CLASSIFICATION_NAME:
                class->name = buf;
                break;

        case MSG_CLASSIFICATION_URL:
                class->url = buf;
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
                uid->type = ntohl( *((uint32_t *) buf));
                break;

        case MSG_USERID_NAME:
                uid->name = buf;
                break;

        case MSG_USERID_NUMBER:
                uid->number = buf;
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

        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_USER_CATEGORY:
                user->category = ntohl( *((uint32_t *) buf));
                break;

        case MSG_USERID_TAG:
                ret = userid_get(msg, NULL);
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

        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_PROCESS_NAME:
                process->name = buf;
                break;

        case MSG_PROCESS_PID:
                process->pid = buf;
                break;

        case MSG_PROCESS_PATH:
                process->path = buf;
                break;

        case MSG_PROCESS_ARG:
                process->arg = buf;
                break;

        case MSG_PROCESS_ENV:
                process->env = buf;
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
                addr->category = ntohl( *((uint32_t *) buf)); 
                break;

        case MSG_ADDRESS_VLAN_NAME:
                addr->vlan_name = buf;
                break;

        case MSG_ADDRESS_VLAN_NUM:
                addr->vlan_num = ntohl( *((uint32_t *) buf));
                break;

        case MSG_ADDRESS_ADDRESS:
                addr->address = buf;
                break;

        case MSG_ADDRESS_NETMASK:
                addr->netmask = buf;
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
                service->name = buf;
                break;

        case MSG_SERVICE_PORT:
                service->port = ntohl( *((uint16_t *) buf) );
                break;

        case MSG_SERVICE_PORTLIST:
                service->portlist = buf;
                break;

        case MSG_SERVICE_PROTOCOL:
                service->protocol = buf;
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

        printf("HERE\n");

        ret = prelude_msg_get(msg, &tag, &len, &buf);
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_NODE_CATEGORY:
                node->category = ntohl( *((uint32_t *) buf));
                break;

        case MSG_NODE_LOCATION:
                node->location = buf;
                break;

        case MSG_NODE_NAME:
                node->name = buf;
                break;

        case MSG_ADDRESS_TAG:
                addr = idmef_address_new(node);
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
                analyzer->manufacturer = buf;
                break;

        case MSG_ANALYZER_MODEL:
                analyzer->model = buf;
                break;

        case MSG_ANALYZER_VERSION:
                analyzer->version = buf;
                break;

        case MSG_ANALYZER_CLASS:
                analyzer->class = buf;
                break;

        case MSG_NODE_TAG:
                ret = node_get(msg, &analyzer->node);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_PROCESS_TAG:
                ret = process_get(msg, &analyzer->process);
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

        case MSG_SOURCE_SPOOFED:
                src->spoofed = ntohl( *((uint32_t *) buf));
                break;

        case MSG_SOURCE_INTERFACE:
                src->interface = buf;
                break;

        case MSG_NODE_TAG:
                ret = node_get(msg, &src->node);
                if ( ret < 0 )
                        return ret;
                break;

        case MSG_USER_TAG:
                ret = user_get(msg, &src->user);
                if ( ret < 0 )
                        return ret;
                break;

        case MSG_PROCESS_TAG:
                ret = process_get(msg, &src->process);
                if ( ret < 0 )
                        return ret;
                break;

        case MSG_SERVICE_TAG:
                ret = service_get(msg, &src->service);
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

        case MSG_TARGET_DECOY:
                dst->decoy = ntohl( *((uint32_t *) buf));
                break;

        case MSG_TARGET_INTERFACE:
                dst->interface = buf;
                break;

        case MSG_NODE_TAG:
                ret = node_get(msg, &dst->node);
                if ( ret < 0 )
                        return ret;
                break;

        case MSG_USER_TAG:
                ret = user_get(msg, &dst->user);
                if ( ret < 0 )
                        return ret;
                break;

        case MSG_PROCESS_TAG:
                ret = process_get(msg, &dst->process);
                if ( ret < 0 )
                        return ret;
                break;

        case MSG_SERVICE_TAG:
                ret = service_get(msg, &dst->service);
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
        return 0;
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

        printf("alert get ret = %d, tag=%d\n", ret, tag);
        
        if ( ret <= 0 )
                return -1; /* Message should always terminate by END OF TAG */

        switch (tag) {

        case MSG_ALERT_IMPACT:
                alert->impact = buf;
                break;

        case MSG_ALERT_ACTION:
                alert->action = buf;
                break;

        case MSG_ANALYZER_TAG:
                ret = analyzer_get(msg, &alert->analyzer);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_ALERT_CREATE_TIME:
                ret = time_get(msg, &alert->create_time);
                if ( ret < 0 )
                        return -1;
                break;
                
        case MSG_ALERT_DETECT_TIME:
                ret = time_get(msg, &alert->detect_time);
                if ( ret < 0 )
                        return -1;
                break;
                
        case MSG_ALERT_ANALYZER_TIME:
                ret = time_get(msg, &alert->analyzer_time);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_SOURCE_TAG:
                src = idmef_source_new(alert);
                if ( ! src )
                        return -1;

                ret = source_get(msg, src);
                if ( ret < 0 ) 
                        return -1;
                break;

        case MSG_TARGET_TAG:
                dst = idmef_target_new(alert);
                if ( ! dst )
                        return -1;

                ret = target_get(msg, dst);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_CLASSIFICATION_TAG:
                class = idmef_classification_new(alert);
                if ( ! class )
                        return -1;

                ret = classification_get(msg, class);
                if ( ret < 0 )
                        return -1;
                break;

        case MSG_ADDITIONALDATA_TAG:
                data = idmef_additional_data_new(alert);
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

        return alert_get(msg, alert);
}




int idmef_message_read(idmef_message_t *idmef, prelude_msg_t *msg)
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        
        ret = prelude_msg_get(msg, &tag, &len, &buf);
        printf("msg get returned %d\n", ret);
        
        if ( ret <= 0 ) 
                return ret; /* Message should always terminate by END OF TAG */
        
        printf("tag = %d\n", tag);
        
        switch (tag) {

        case MSG_ALERT_TAG:
                ret = alert_get(msg, idmef->message.alert);
                if ( ret < 0 )
                        return -1;
                break;

                
        case MSG_OWN_FORMAT:
                ret = decode_plugins_run(msg, idmef->message.alert);
                if ( ret < 0 ) {
                        printf("ret = %d\n", ret);
                        return ret;
                }
                break;
                
        case MSG_END_OF_TAG:
                return 0;

        default:
                log(LOG_ERR, "couldn't handle tag %d.\n", tag);
                return -1;
        }
        
        return idmef_message_read(idmef, msg);
}



