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
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>

#include <libprelude/extract.h>

#include "packet.h"
#include "decode.h"
#include "packet-decode.h"
#include "nids-alert-id.h"




static char *sport_data = NULL;
static char *dport_data = NULL;
static char *shost_data = NULL;
static char *dhost_data = NULL;
static packet_t packet[MAX_PKTDEPTH + 1];



static const char *get_address(struct in_addr *addr) 
{
        struct in_addr tmp;

        extract_ipv4_addr(&tmp, addr);
        return inet_ntoa(tmp);        
}




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
        shost_data = strdup(get_address(&ip->ip_src));
        idmef_string_set(&saddr->address, shost_data);
        
        daddr->category = ipv4_addr;
        dhost_data = strdup(get_address(&ip->ip_dst));
        idmef_string_set(&daddr->address, dhost_data);

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
                idmef_string(&source->service->name) = sport_data;
                idmef_string(&source->service->protocol) = proto;

                source->service->port = sport;
        }

        if ( ! list_empty(&alert->target_list) ) {
                
                target = list_entry(alert->target_list.prev, idmef_target_t, list);
                ptr = getservbyport(dport, proto);
                
                idmef_target_service_new(target);
                target->service->port = dport;
                idmef_string(&target->service->protocol) = proto;
                idmef_string(&target->service->name) = dport_data = (ptr) ? strdup(ptr->s_name) : NULL;
        }

        return 0;
}




static int packet_to_idmef(idmef_alert_t *alert, packet_t *p) 
{
        int i;
        int ret;
        uint16_t sport, dport;
        
        for ( i = 0; p[i].proto != p_end; i++ ) {

                if ( p[i].proto == p_ip ) {
                        ret = gather_ip_infos(alert, p[i].p.ip);
                        if ( ret < 0 )
                                return -1;
                }
                
                else if ( p[i].proto == p_tcp ) {
                        extract_int(uint16, &p[i].p.tcp->th_sport, sizeof(uint16_t), sport);
                        extract_int(uint16, &p[i].p.tcp->th_dport, sizeof(uint16_t), dport);
                        
                        ret = gather_protocol_infos(alert, sport, dport, "tcp");
                        if ( ret < 0 )
                                return -1;
                }
                else if ( p[i].proto == p_udp ) {
                        extract_int(uint16, &p[i].p.udp_hdr->uh_sport, sizeof(uint16_t), sport);
                        extract_int(uint16, &p[i].p.udp_hdr->uh_dport, sizeof(uint16_t), dport);
                        
                        ret = gather_protocol_infos(alert, sport, dport, "udp");
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
                        
        do {    
                ret = prelude_msg_get(pmsg, &tag, &len, &buf);
                if ( ret < 0 ) {
                        log(LOG_ERR, "error decoding message.\n");
                        return -1;
                }
                
                if ( ret == 0 ) 
                        break;
                
                packet[i].data = NULL;
                packet[i].len = len;
                packet[i].proto = tag;
                packet[i].p.ip = buf;
                
        } while ( packet[i++].proto != p_end && i < MAX_PKTDEPTH );

        /*
         * put a delimiter, for safety
         */
        packet[i].proto = p_end;
        
        packet_to_idmef(alert, packet);
        nids_packet_dump(alert, packet);

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
        nids_packet_free(packet);

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




plugin_generic_t *plugin_init(int argc, char **argv)
{
        static plugin_decode_t plugin;
        
        plugin_set_name(&plugin, "Prelude NIDS data decoder");
        plugin_set_author(&plugin, "Yoann Vandoorselaere");
        plugin_set_contact(&plugin, "yoann@mandrakesoft.com");
        plugin_set_desc(&plugin, "Decode Prelude NIDS message, and translate them to IDMEF.");
        
        plugin_set_running_func(&plugin, nids_decode_run);
        plugin_set_freeing_func(&plugin, nids_decode_free);
        plugin.decode_id = MSG_FORMAT_PRELUDE_NIDS;

        plugin_subscribe((plugin_generic_t *) &plugin);
        
	return (plugin_generic_t *) &plugin;
}






