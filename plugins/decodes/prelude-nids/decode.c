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

#include "decode.h"
#include "packet.h"
#include "nids-alert-id.h"




static char *hex_data = NULL;
static char *sport_data = NULL;
static char *dport_data = NULL;
static char *shost_data = NULL;
static char *dhost_data = NULL;





static int gather_ip_infos(idmef_alert_t *alert, iphdr_t *ip) 
{
        idmef_source_t *source;
        idmef_target_t *target;
        idmef_address_t *saddr, *daddr;
        
        source = idmef_alert_source_new(alert);
        if ( ! source )
                return -1;
        
        target = idmef_alert_target_new(alert);
        if ( ! target )
                return -1;
        
        idmef_source_node_new(source);
        saddr = idmef_node_address_new(source->node);
        if ( ! saddr )
                return -1;

        idmef_target_node_new(target);
        daddr = idmef_node_address_new(target->node);
        if ( ! daddr )
                return -1;
        
        saddr->category = ipv4_addr;
        saddr->address = shost_data = strdup(inet_ntoa(ip->ip_src));
        
        daddr->category = ipv4_addr;
        daddr->address = dhost_data = strdup(inet_ntoa(ip->ip_dst));

        return 0;
}




static int gather_protocol_infos(idmef_alert_t *alert, uint16_t sport, uint16_t dport, const char *proto) 
{
        struct servent *ptr;
        idmef_source_t *source;
        idmef_target_t *target;

        if ( ! list_empty(&alert->source_list) ) {
                               
                source = list_entry(alert->source_list.prev, idmef_source_t, list);
                ptr = getservbyport(sport, proto);
                sport_data = (ptr) ? strdup(ptr->s_name) : NULL;

                idmef_source_service_new(source);
                source->service->name = sport_data;
                source->service->port = ntohs(sport);
                source->service->protocol = proto;
        }

        if ( ! list_empty(&alert->target_list) ) {
                
                target = list_entry(alert->target_list.prev, idmef_target_t, list);
                ptr = getservbyport(dport, proto);
                dport_data = (ptr) ? strdup(ptr->s_name) : NULL;

                idmef_target_service_new(target);
                target->service->name = dport_data;
                target->service->port = ntohs(dport);
                target->service->protocol = proto;
        }

        return 0;
}




static int gather_payload_infos(idmef_alert_t *alert, unsigned char *data, size_t len) 
{
        idmef_additional_data_t *pdata;
        
        pdata = idmef_alert_additional_data_new(alert);
        if ( ! pdata ) 
                return -1;
        
        pdata->type = string;
        pdata->meaning = "Packet Payload";
        
        pdata->data = hex_data = prelude_string_to_hex(data, len);
        if ( ! pdata->data )
                return -1;

        return 0;
}




static int packet_to_idmef(idmef_alert_t *alert, packet_t *p) 
{
        int i;
        int ret;
        
        for ( i = 0; p[i].proto != p_end; i++ ) {

                if ( p[i].proto == p_ip ) {
                        ret = gather_ip_infos(alert, p[i].p.ip);
                        if ( ret < 0 )
                                return -1;
                }
                
                else if ( p[i].proto == p_tcp ) {
                        ret = gather_protocol_infos(alert, p[i].p.tcp->th_sport, p[i].p.tcp->th_dport, "tcp");
                        if ( ret < 0 )
                                return -1;
                }
                else if ( p[i].proto == p_udp ) {
                        ret = gather_protocol_infos(alert, p[i].p.udp_hdr->uh_sport, p[i].p.udp_hdr->uh_dport, "udp");
                        if ( ret < 0 )
                                return -1;
                }
                
                else if ( p[i].proto == p_data ) {
                        ret = gather_payload_infos(alert, p[i].p.data, p[i].len);
                        if ( ret < 0 )
                                return -1;
                }
        }

        return 0;
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




static int decode_message(prelude_msg_t *pmsg, idmef_alert_t *alert) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
                
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
        
        return decode_message(pmsg, alert);
}



static int nids_decode_run(prelude_msg_t *pmsg, idmef_message_t *idmef) 
{
        idmef_alert_new(idmef);
        return decode_message(pmsg, idmef->message.alert);
}



static void nids_decode_free(void) 
{
        if ( hex_data ) {
                free(hex_data);
                hex_data = NULL;
        }

        if ( shost_data ) {
                free(shost_data);
                shost_data = NULL;
        }

        if ( dhost_data ) {
                free(dhost_data);
                dhost_data = NULL;
        }

        if ( sport_data ) {
                free(sport_data);
                sport_data = NULL;
        }

        if ( dport_data ) {
                free(dport_data);
                dport_data = NULL;
        }
}




int plugin_init(unsigned int id)
{
        static plugin_decode_t plugin;
        
        plugin_set_name(&plugin, "Prelude NIDS data decoder");
        plugin_set_author(&plugin, "Yoann Vandoorselaere");
        plugin_set_contact(&plugin, "yoann@mandrakesoft.com");
        plugin_set_desc(&plugin, "Decode Prelude NIDS message, and translate them to IDMEF.");
        
        plugin_set_running_func(&plugin, nids_decode_run);
        plugin_set_freeing_func(&plugin, nids_decode_free);
        
        plugin.decode_id = MSG_FORMAT_PRELUDE_NIDS;
        
	return plugin_register((plugin_generic_t *)&plugin);
}






