/*****
*
* Copyright (C) 2001-2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
        idmef_address_t *addr;
        
        node = idmef_node_new();
        if ( ! node ) 
                return NULL;
        
        addr = idmef_node_new_address(node);
        if ( ! addr ) {
                idmef_node_destroy(node);
                return NULL;
        }

        idmef_address_set_category(addr, IDMEF_ADDRESS_CATEGORY_IPV4_ADDR);
        idmef_string_set_dup(idmef_address_new_address(addr), addr_string);
                
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
        
        source = idmef_alert_get_next_source(alert, NULL);        
        if ( ! source && !(source = idmef_alert_new_source(alert)) ) {
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
        
        target = idmef_alert_get_next_target(alert, NULL);
        if ( ! target && !(target = idmef_alert_new_target(alert)) ) {
                idmef_node_destroy(dnode);
                idmef_source_destroy(source);
                return -1;
        }

        idmef_target_set_node(target, dnode);
        
        return 0;
}



static int set_idmef_service(idmef_service_t *service, uint16_t port, const char *proto)
{
        struct servent *ptr;
        
        idmef_service_set_port(service, port);
        idmef_string_set_ref(idmef_service_new_protocol(service), proto);

        ptr = getservbyport(htons(port), proto);
        if ( ! ptr )
                return 0;

        idmef_string_set_dup(idmef_service_new_name(service), ptr->s_name);
        
        return 0;
}




static int gather_protocol_infos(idmef_alert_t *alert, uint16_t sport, uint16_t dport, const char *proto) 
{
        idmef_source_t *source;
        idmef_target_t *target;
        idmef_service_t *service;
        
        if ( (source = idmef_alert_get_next_source(alert, NULL)) ) {

                service = idmef_source_new_service(source);
                if ( ! service ) {
                        log(LOG_ERR, "memory exhausted.\n");
                        return -1;
                }
                
                set_idmef_service(service, sport, proto);
        }
        
        if ( (target = idmef_alert_get_next_target(alert, NULL)) ) {
                
                service = idmef_target_new_service(target);
                if ( ! service ) {
                        log(LOG_ERR, "memory exhausted.\n");
                        return -1;
                }

                set_idmef_service(service, dport, proto);
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
        if ( ret == 0 ) {
                log(LOG_ERR, "message should always terminate by END OF TAG.\n");
                return -1;
        }
        
        switch (tag) {
                                
        case ID_PRELUDE_NIDS_PACKET:
                ret = msg_to_packet(pmsg, alert);
                if ( ret < 0 ) {
                        log(LOG_ERR, "message to packet convertion failed.\n");
                        return -1;
                }
                
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

        alert = idmef_message_get_alert(message);
        if ( ! alert ) {
                log(LOG_ERR, "idmef message contain no alert: %p.\n", alert);
                return -1;
        }
        
        return decode_message(pmsg, alert);
}



prelude_plugin_generic_t *prelude_plugin_init(void)
{
        static plugin_decode_t plugin;

        prelude_plugin_set_name(&plugin, "Prelude NIDS data decoder");
        prelude_plugin_set_author(&plugin, "Yoann Vandoorselaere");
        prelude_plugin_set_contact(&plugin, "yoann@prelude-ids.org");
        prelude_plugin_set_desc(&plugin, "Decode Prelude NIDS message, and translate them to IDMEF.");
        
        decode_plugin_set_running_func(&plugin, nids_decode_run);
        plugin.decode_id = MSG_FORMAT_PRELUDE_NIDS;
        
        prelude_plugin_subscribe((void *) &plugin, NULL, NULL);
        
	return (void *) &plugin;
}






