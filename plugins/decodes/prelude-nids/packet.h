#ifndef PACKET_H
#define PACKET_H

/*****
*
* Copyright (C) 1998 - 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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

#include "nethdr.h"


typedef enum {
	p_raw,
        p_ether,
        p_ip,
        p_ipopts,
        p_ipencap,
        p_ipicmp,
        p_arp,
        p_rarp,
        p_udp,
        p_tcp,
        p_tcpopts,
        p_icmp,
        p_igmp,
        p_data,
        p_all,
        p_external,
        p_end
} proto_enum_t;



/*
 * Max number of packet that can be kept in memory by Prelude.
 */
#define MAX_PKTINUSE 1000 


/*
 *
 */
#define MAX_PKTDEPTH 20


/*
 * Packet stuff
 */


union proto_u {
        etherhdr_t *ether_hdr;
        iphdr_t *ip;
        tcphdr_t *tcp;
        udphdr_t *udp_hdr;
        icmphdr_t *icmp_hdr;
        igmphdr_t *igmp_hdr;
        etherarphdr_t *arp_hdr;
        unsigned char *data, *opts;
};



typedef struct {
        char *data; /* we store pointer to string here */
        uint16_t len;
        uint8_t proto;
        union proto_u p;
} packet_t;



typedef struct {
	/*
	 * Current depth of the packet (used in order to index the headers array).
	 */
        int8_t depth;
        
        /*
	 * Used by the stream reassembly module and the signature engine
	 * to directly address the packet array without having to search through it.
	 */
        int8_t network_layer_depth;     /* Ip, Icmp, Igmp */
        int8_t transport_layer_depth;   /* Tcp, udp */
        int8_t application_layer_depth; /* application data */
        
	/*
	 * How many place are currently referencing this packet.
	 */
        int refcount;
        
	/*
	 * Pointer on the raw data packet buffer.
	 */
	unsigned char *captured_data;

	/*
	 * If data allocation was needed in order to store this packet after the capture,
	 * (for exemple for IP defragmentation) it is referenced here.
	 */
        unsigned char *allocated_data;

	/*
	 * Protocol plugin related data, not part of the headers array, 
	 * because only the plugin know about theses data (private, but still packet related).
	 */
	int8_t protocol_plugin_id;
	void *protocol_plugin_data;
        
	/*
	 * Array containing the headers.
	 */ 
	packet_t packet[MAX_PKTDEPTH];
} packet_container_t;



#define packet_2_container(packet) packet - offsetof(packet_container_t, packet)



#define packet_add_header(pc, type, data, dlen, protocol, member) do {     \
        (pc)->depth++;                                                     \
                                                                           \
        if ( ((pc)->depth + 1) < MAX_PKTDEPTH ) {                          \
                (pc)->packet[(pc)->depth].len = (dlen);                    \
                (pc)->packet[(pc)->depth].proto = (protocol);              \
                (pc)->packet[(pc)->depth].p.member = (type *) (data);      \
                (pc)->packet[(pc)->depth + 1].proto = p_end;               \
        }                                                                  \
        else {                                                             \
                (pc)->packet[(pc)->depth].proto = p_end;                   \
                (pc)->packet[(pc)->depth].len = 0;                         \
                nids_emmit_alert(NULL, (pc),                               \
                          "Packet depth is too high",                      \
                          "%s : Maximum packet depth (%d) reached.\n",     \
                          __FUNCTION__, MAX_PKTDEPTH);                     \
                return;                                                    \
        }                                                                  \
} while(0)


#endif





