/*****
*
* Copyright (C) 2001, 2002, 2003 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

#include <libprelude/idmef.h>
#include <libprelude/idmef-tree-wrap.h>
#include <libprelude/prelude-log.h>
#include <libprelude/extract.h>

#include "packet.h"
#include "decode.h"
#include "packet-decode.h"
#include "nids-alert-id.h"
#include "passive-os-fingerprint.h"


pof_host_data_t pof_host_data;



static const char *get_address(struct in_addr *addr) 
{
        return inet_ntoa(extract_ipv4_addr(addr));        
}



static idmef_node_t *create_node(const char *addr_string)
{
        idmef_node_t *node;
        idmef_string_t *tmp;
        idmef_address_t *addr;

        tmp = idmef_string_new_dup(addr_string);
        if ( ! tmp )
                return NULL;
        
        addr = idmef_address_new();
        if ( ! addr ) {
                idmef_string_destroy(tmp);
                return NULL;
        }

        idmef_address_set_address(addr, tmp);
        idmef_address_set_category(addr, ipv4_addr);
        
        node = idmef_node_new();
        if ( ! node ) {
                idmef_address_destroy(addr);
                return NULL;
        }
                        
        idmef_node_set_address(node, addr);
        
        return node;
}



static int gather_ip_infos(idmef_alert_t *alert, iphdr_t *ip) 
{
        idmef_source_t *source;
        idmef_target_t *target;
        idmef_node_t *snode, *dnode;

        /*
         * set source ip
         */
        snode = create_node(get_address(&ip->ip_src));
        if ( ! snode )
                return -1;
        
        source = idmef_source_new();
        if ( ! source ) {
                idmef_node_destroy(snode);
                return -2;
        }

        idmef_source_set_node(source, snode);

        /* set target ip */
        dnode = create_node(get_address(&ip->ip_dst));
        if ( ! dnode ) {
                idmef_source_destroy(source);
                return -3;
        }

        target = idmef_target_new();
        if ( ! target ) {
                idmef_node_destroy(dnode);
                idmef_source_destroy(source);
                return -1;
        }

        idmef_target_set_node(target, dnode);
        idmef_alert_set_source(alert, source);
        idmef_alert_set_target(alert, target);
        
        return 0;
}



static int set_idmef_service(idmef_service_t *service, uint16_t port, const char *proto)
{
        struct servent *ptr;
        idmef_string_t *port_str, *proto_str;
                
        proto_str = idmef_string_new_ref(proto);
        if ( ! proto_str ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }
        
        idmef_service_set_port(service, port);
        idmef_service_set_protocol(service, proto_str);

        ptr = getservbyport(htons(port), proto);
        if ( ! ptr )
                return 0;
        
        port_str = idmef_string_new_dup(ptr->s_name);
        if ( ! port_str ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }
        
        idmef_service_set_name(service, port_str);

        return 0;
}




static int gather_protocol_infos(idmef_alert_t *alert, uint16_t sport, uint16_t dport, const char *proto) 
{
        idmef_source_t *source;
        idmef_target_t *target;
        idmef_service_t *service;

        if ( (source = idmef_alert_get_next_source(alert, NULL)) ) {

                service = idmef_service_new();
                if ( ! service ) {
                        log(LOG_ERR, "memory exhausted.\n");
                        return -1;
                }
                
                set_idmef_service(service, sport, proto);
                idmef_source_set_service(source, service);
        }
        
        if ( (target = idmef_alert_get_next_target(alert, NULL)) ) {
                
                service = idmef_service_new();
                if ( ! service ) {
                        log(LOG_ERR, "memory exhausted.\n");
                        return -1;
                }

                set_idmef_service(service, dport, proto);
                idmef_target_set_service(target, service);
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
                        if ( p[i].len != sizeof(iphdr_t) )
                                return -1;
                        
                        ret = gather_ip_infos(alert, p[i].p.ip);
                        if ( ret < 0 )
                                return -1;
                }
                
                else if ( p[i].proto == p_tcp ) {
                        /*
                         * we want to bound check the buffer sent by the sensor.
                         */
                        if ( p[i].len != sizeof(tcphdr_t) )
                                return -1;

                        sport = extract_uint16(&p[i].p.tcp->th_sport);
                        dport = extract_uint16(&p[i].p.tcp->th_dport);
                                          
                        ret = gather_protocol_infos(alert, sport, dport, "tcp");
                        if ( ret < 0 )
                                return -1;
                }
                
                else if ( p[i].proto == p_udp ) {

                        if ( p[i].len != sizeof(udphdr_t) )
                                return -1;
                        
                        sport = extract_uint16(&p[i].p.udp_hdr->uh_sport);
                        dport = extract_uint16(&p[i].p.udp_hdr->uh_dport);
                        
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
        packet_t packet[MAX_PKTDEPTH + 1];

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
        
        passive_os_fingerprint_zero(&pof_host_data);
        
        packet_to_idmef(alert, packet);
        nids_packet_dump(alert, packet);
        passive_os_fingerprint_dump(alert, &pof_host_data);
        
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



static int nids_decode_run(prelude_msg_t *pmsg, idmef_message_t *message) 
{        
        idmef_alert_t *alert;

        alert = idmef_message_new_alert(message);
        if ( ! alert )
                return -1;

        if ( decode_message(pmsg, alert) < 0 )
                return -2;

        return decode_message(pmsg, alert);
}



plugin_generic_t *plugin_init(int argc, char **argv)
{
        static plugin_decode_t plugin;

        plugin_set_name(&plugin, "Prelude NIDS data decoder");
        plugin_set_author(&plugin, "Yoann Vandoorselaere");
        plugin_set_contact(&plugin, "yoann@prelude-ids.org");
        plugin_set_desc(&plugin, "Decode Prelude NIDS message, and translate them to IDMEF.");
        
        plugin_set_running_func(&plugin, nids_decode_run);
        plugin.decode_id = MSG_FORMAT_PRELUDE_NIDS;

        plugin_subscribe((plugin_generic_t *) &plugin);
        
	return (plugin_generic_t *) &plugin;
}






