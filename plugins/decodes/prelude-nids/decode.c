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
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <netdb.h>
#include <assert.h>

#include <libprelude/list.h>
#include <libprelude/common.h>
#include <libprelude/plugin-common.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/idmef-message-id.h>
#include <libprelude/idmef-tree.h>

#include "idmef-func.h"
#include "nids-alert-id.h"
#include "plugin-decode.h"
#include "packet.h"




static int gather_ip_infos(idmef_alert_t *alert, iphdr_t *ip) 
{
        idmef_source_t *source;
        idmef_target_t *target;
        idmef_address_t *saddr, *daddr;

        source = idmef_source_new(alert);
        if ( ! source )
                return -1;
        
        target = idmef_target_new(alert);
        if ( ! target )
                return -1;

        saddr = idmef_address_new(&source->node);
        if ( ! saddr )
                return -1;

        daddr = idmef_address_new(&target->node);
        if ( ! daddr )
                return -1;
        
        source->spoofed = unknown;
        source->node.category = unknown;

        saddr->category = ipv4_addr;
        saddr->address = strdup(inet_ntoa(ip->ip_src));
        
        target->decoy = unknown;
        target->node.category = unknown;

        daddr->category = ipv4_addr;
        daddr->address = strdup(inet_ntoa(ip->ip_dst));

        return 0;
}




static void gather_protocol_infos(idmef_alert_t *alert, uint16_t sport, uint16_t dport, const char *proto) 
{
        const char *name;
        struct servent *ptr;
        idmef_source_t *source;
        idmef_target_t *target;

        source = list_entry(alert->source_list.prev, idmef_source_t, list);
        target = list_entry(alert->target_list.prev, idmef_target_t, list);

        ptr = getservbyport(sport, proto);
        name = (ptr) ? ptr->s_name : NULL;
        
        source->service.name = name;
        source->service.port = ntohs(sport);
        source->service.protocol = proto;

        ptr = getservbyport(dport, proto);
        name = (ptr) ? ptr->s_name : NULL;
        
        target->service.name = name;
        target->service.port = ntohs(dport);
        target->service.protocol = proto;
}




static void gather_payload_infos(idmef_alert_t *alert, unsigned char *data, size_t len) 
{
        idmef_additional_data_t *pdata;

        pdata = idmef_additional_data_new(alert);
        if ( ! pdata )
                return;
        
        pdata->type = string;
        pdata->meaning = "Packet Payload";
        
        pdata->data = prelude_string_to_hex(data, len);
        if ( ! pdata->data )
                idmef_additional_data_free(alert);
}




static void packet_to_idmef(idmef_alert_t *alert, packet_t *p) 
{
        int i;
        
        for ( i = 0; p[i].proto != p_end; i++ ) {
                
                if ( p[i].proto == p_ip )           
                        gather_ip_infos(alert, p[i].p.ip);

                else if ( p[i].proto == p_tcp )
                        gather_protocol_infos(alert, p[i].p.tcp->th_sport, p[i].p.tcp->th_dport, "tcp");

                else if ( p[i].proto == p_udp )
                        gather_protocol_infos(alert, p[i].p.udp_hdr->uh_sport, p[i].p.udp_hdr->uh_dport, "udp");
                
                else if ( p[i].proto == p_data ) 
                        gather_payload_infos(alert, p[i].p.data, p[i].len);
        }        
}



static int msg_to_packet(prelude_msg_t *pmsg, idmef_alert_t *alert) 
{
        void *buf;
        uint8_t tag;
        uint32_t len;
        int i = 0, ret;
        packet_t packet[MAX_PKTDEPTH + 1];
        
                        
        do {    
                ret = prelude_msg_get(pmsg, &tag, &len, &buf);
                if ( ret < 0 ) {
                        log(LOG_ERR, "error decoding message.\n");
                        return -1;
                }
                
                if ( ret == 0 ) 
                        break;
                
                packet[i].len = len;
                packet[i].proto = tag;
                packet[i].p.ip = buf;
                
        } while ( packet[i++].proto != p_end );
        
        packet_to_idmef(alert, packet);

        return 0;
}




static int nids_decode_run(prelude_msg_t *pmsg, idmef_alert_t *alert) 
{
        void *buf;
        int ret;
        uint8_t tag;
        uint32_t len;
        struct timeval tv;
        
        ret = prelude_msg_get(pmsg, &tag, &len, &buf);
        if ( ret < 0 ) {
                log(LOG_ERR, "error decoding message.\n");
                return -1;
        }
        
        /*
         * End of message.
         */
        if ( ret == 0 ) 
                return -1; /* message should always terminate by END OF TAG */
        
        switch (tag) {
                
        case ID_PRELUDE_NIDS_TS_SEC:
                tv.tv_sec = ntohl( (*(long *)buf));
                break;
                
        case ID_PRELUDE_NIDS_TS_USEC:
                tv.tv_usec = ntohl( (*(long *)buf)) ;
                break;
                
        case ID_PRELUDE_NIDS_PACKET:
                ret = msg_to_packet(pmsg, alert);
                if ( ret < 0 )
                        return -1;
                break;
                
        case MSG_END_OF_TAG:
                return 0;
                
        default:
                log(LOG_ERR, "unknown tag : %d.\n", tag);
                break;
        }
        
        return nids_decode_run(pmsg, alert);
}




int plugin_init(unsigned int id)
{
        static plugin_decode_t plugin;
        
        plugin_set_name(&plugin, "Prelude NIDS data decoder");
        plugin_set_author(&plugin, "Yoann Vandoorselaere");
        plugin_set_contact(&plugin, "yoann@mandrakesoft.com");
        plugin_set_desc(&plugin, "Decode Prelude NIDS message, and translate them to IDMEF.");
        plugin_set_running_func(&plugin, nids_decode_run);

        plugin.decode_id = MSG_FORMAT_PRELUDE_NIDS;
        
	return plugin_register((plugin_generic_t *)&plugin);
}






