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
#include <stdarg.h>

#include "packet.h"

#include <libprelude/list.h>
#include <libprelude/prelude-log.h>
#include <libprelude/extract.h>
#include <libprelude/prelude-strbuf.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/idmef.h>
#include <libprelude/idmef-tree-wrap.h>

#include "config.h"
#include "plugin-util.h"
#include "optparse.h"
#include "ethertype.h"
#include "packet-decode.h"
#include "passive-os-fingerprint.h"


/* ARP protocol opcodes. */
#define ARPOP_REQUEST   1               /* ARP request.  */
#define ARPOP_REPLY     2               /* ARP reply.  */
#define ARPOP_RREQUEST  3               /* RARP request.  */
#define ARPOP_RREPLY    4               /* RARP reply.  */
#define ARPOP_InREQUEST 8               /* InARP request.  */
#define ARPOP_InREPLY   9               /* InARP reply.  */
#define ARPOP_NAK       10              /* (ATM)ARP NAK.  */


/* ARP protocol HARDWARE identifiers. */
#define ARPHRD_NETROM   0               /* From KA9Q: NET/ROM pseudo. */
#define ARPHRD_ETHER    1               /* Ethernet 10/100Mbps.  */
#define ARPHRD_EETHER   2               /* Experimental Ethernet.  */
#define ARPHRD_CHAOS    5               /* Chaosnet.  */
#define ARPHRD_IEEE802  6               /* IEEE 802.2 Ethernet/TR/TB.  */
#define ARPHRD_ARCNET   7               /* ARCnet.  */
#define ARPHRD_APPLETLK 8               /* APPLEtalk.  */
#define ARPHRD_DLCI     15              /* Frame Relay DLCI.  */
#define ARPHRD_ATM      19              /* ATM.  */
#define ARPHRD_AX25     3               /* AX.25 Level 2.  */

#define REVARP_REQUEST           3
#define REVARP_REPLY             4


extern pof_host_data_t pof_host_data;



static const char *get_address(struct in_addr *addr) 
{
        return inet_ntoa(extract_ipv4_addr(addr));
}




/*
 * snipped from tcpdump code 
 */
static const char *etheraddr_string(const unsigned char *ep) 
{
        char *ptr;
        unsigned int i, j;
        const char *hex = "0123456789abcdef";
        static char buf[sizeof("00:00:00:00:00:00")];
        
        ptr = buf;
        if ( (j = *ep >> 4) != 0 )
                *ptr++ = hex[j];
        
        *ptr++ = hex[*ep++ & 0xf];
        
        for (i = 5; (int)--i >= 0;) {
                *ptr++ = ':';

                if ( (j = *ep >> 4) != 0)
                        *ptr++ = hex[j];

                *ptr++ = hex[*ep++ & 0xf];
        }
        *ptr = '\0';

        return buf;
}





static const char *switch_ethertype(uint16_t type) 
{
        switch (type) {

        case ETHERTYPE_IP:
                return "ip";

        case ETHERTYPE_NS:
                return "ns";
             
        case ETHERTYPE_SPRITE:
                return "sprite";
             
        case ETHERTYPE_TRAIL:
                return "trail";

        case ETHERTYPE_MOPDL:
                return "mopdl";

        case ETHERTYPE_MOPRC:
                return "moprc";

        case ETHERTYPE_DN:
                return "dn";

        case ETHERTYPE_LAT:
                return "lat";

        case ETHERTYPE_SCA:
                return "sca";

        case ETHERTYPE_ARP:
                return "arp";
                
        case ETHERTYPE_REVARP:
                return "revarp";

        case ETHERTYPE_LANBRIDGE:
                return "lanbridge";

        case ETHERTYPE_DECDNS:
                return "decdns";

        case ETHERTYPE_DECDTS:
                return "decdts";

        case ETHERTYPE_VEXP:
                return "vexp";

        case ETHERTYPE_VPROD:
                return "vprod";

        case ETHERTYPE_ATALK:
                return "atalk";

        case ETHERTYPE_AARP:
                return "aarp";

        case ETHERTYPE_8021Q:
                return "8021q";

        case ETHERTYPE_IPX:
                return "ipx";

        case ETHERTYPE_IPV6:
                return "ipv6";

        case ETHERTYPE_PPPOED:
                return "pppoed";

        case ETHERTYPE_PPPOES:
                return "pppoes";

        case ETHERTYPE_LOOPBACK:
                return "loopback";

        default:
                return "unknow";
        }

        return NULL;
}



static int ether_dump(idmef_alert_t *alert, idmef_additional_data_t *ad, packet_t *packet) 
{
        uint16_t t;
        const char *type;
        idmef_data_t *data;
        prelude_strbuf_t *buf;
        etherhdr_t *hdr = packet->p.ether_hdr;

        buf = prelude_strbuf_new();
        if ( ! buf )
                return -1;
        
        prelude_strbuf_sprintf(buf, "%s -> ", etheraddr_string(hdr->ether_shost));
        
        t = extract_uint16(&hdr->ether_type);
        type = switch_ethertype(t);
        prelude_strbuf_sprintf(buf, "%s [ether_type=%s (%d)]", etheraddr_string(hdr->ether_dhost), type, t);

        data = idmef_data_new_nodup(prelude_strbuf_get_string(buf), prelude_strbuf_get_len(buf) + 1);
        if ( ! data ) {
                prelude_strbuf_destroy(buf);
                return -1;
        }
        
        idmef_additional_data_set_data(ad, data);
        idmef_additional_data_set_type(ad, string);

        prelude_strbuf_dont_own(buf);
        prelude_strbuf_destroy(buf);
        
        return 0;
}




static int arp_dump(idmef_alert_t *alert, idmef_additional_data_t *ad, packet_t *packet) 
{
        int i;
        const char *ptr;
        uint16_t op, hrd;
        idmef_data_t *data;
        prelude_strbuf_t *buf;
        etherarphdr_t *arp = packet->p.arp_hdr;
        struct {
                int type;
                const char *name;
        } type_tbl[] = {
                { ARPOP_REQUEST, "request" },
                { ARPOP_REPLY, "reply" },
                { ARPOP_RREQUEST, "request(RArp)" },
                { ARPOP_RREPLY, "reply(RArp)" },
                { ARPOP_InREQUEST, "request(InArp)" },
                { ARPOP_InREPLY, "reply(InArp)" },
                { ARPOP_NAK, "reply(atm Arp NAK)" },
                { 0, NULL },
        };

        struct {
                int type;
                const char *name;
        } f_tbl[] = {
                { ARPHRD_NETROM, "netrom" },
                { ARPHRD_ETHER, "ether" },
                { ARPHRD_EETHER, "eether" },
                { ARPHRD_AX25, "ax25" },
                { ARPHRD_CHAOS, "chaos" },
                { ARPHRD_IEEE802, "ieee802" },
                { ARPHRD_ARCNET, "arcnet" },
                { ARPHRD_APPLETLK, "appletalk" },
                { ARPHRD_DLCI, "dlci" },
                { ARPHRD_ATM, "atm" },
                { 0, NULL },
        };

        buf = prelude_strbuf_new();
        if ( ! buf )
                return -1;
        
        op = extract_uint16(&arp->arp_op);
        hrd = extract_uint16(&arp->arp_hrd);

        ptr = NULL;
        for ( i = 0; type_tbl[i].name != NULL; i++ ) {
                if ( op == type_tbl[i].type ) {
                        ptr = type_tbl[i].name;
                        break;
                }
        }

        prelude_strbuf_sprintf(buf, "type=%d(%s) ", op, (ptr) ? ptr : "unknown" );     
        
        ptr = NULL;
        for ( i = 0; f_tbl[i].name != NULL; i++ ) {
                if ( hrd == f_tbl[i].type ) {
                        ptr = f_tbl[i].name;
                        break;
                }
        }
        
        prelude_strbuf_sprintf(buf, "f=%d(%s) ", hrd, (ptr) ? ptr : "unknown");

        prelude_strbuf_sprintf(buf, "tpa=%s,tha=%s,",
                               get_address((struct in_addr *)arp->arp_tpa), etheraddr_string(arp->arp_tha));

        prelude_strbuf_sprintf(buf, "spa=%s,sha=%s",
                               get_address((struct in_addr *)arp->arp_spa), etheraddr_string(arp->arp_sha));

        data = idmef_data_new_nodup(prelude_strbuf_get_string(buf), prelude_strbuf_get_len(buf) + 1);
        if ( ! data ) {
                prelude_strbuf_destroy(buf);
                return -1;
        }
        
        idmef_additional_data_set_data(ad, data);
        idmef_additional_data_set_type(ad, string);
        
        prelude_strbuf_dont_own(buf);
        prelude_strbuf_destroy(buf);
        
        return 0;
}



static int ipopts_dump(idmef_alert_t *alert, idmef_additional_data_t *ad, packet_t *packet) 
{
        int ret;
        idmef_data_t *data;
        prelude_strbuf_t *buf;

        buf = prelude_strbuf_new();
        if ( ! buf )
                return -1;
        
        ret = ip_optdump(buf, packet->p.opts, packet->len);
        if ( ret < 0 ) {
                prelude_strbuf_destroy(buf);
                return -1;
        }

        data = idmef_data_new_nodup(prelude_strbuf_get_string(buf), prelude_strbuf_get_len(buf) + 1);
        if ( ! data ) {
                prelude_strbuf_destroy(buf);
                return -1;
        }
        
        idmef_additional_data_set_data(ad, data);
        idmef_additional_data_set_type(ad, string);

        prelude_strbuf_dont_own(buf);
        prelude_strbuf_destroy(buf);
        
        return 0;
}




static int tcpopts_dump(idmef_alert_t *alert, idmef_additional_data_t *ad, packet_t *packet) 
{
        int ret;
        idmef_data_t *data;
        prelude_strbuf_t *buf;

        buf = prelude_strbuf_new();
        if ( ! buf )
                return -1;
        
        ret = tcp_optdump(buf, packet->p.opts, packet->len);
        if ( ret < 0 ) {
                prelude_strbuf_destroy(buf);
                return -1;
        }

        data = idmef_data_new_nodup(prelude_strbuf_get_string(buf), prelude_strbuf_get_len(buf) + 1);
        if ( ! data ) {
                prelude_strbuf_destroy(buf);
                return -1;
        }
        
        idmef_additional_data_set_data(ad, data);
        idmef_additional_data_set_type(ad, string);

        prelude_strbuf_dont_own(buf);
        prelude_strbuf_destroy(buf);
        
        return 0;
}



static int dump_ip_offset(uint16_t off, prelude_strbuf_t *buf) 
{
        int ret;
        
        ret = prelude_strbuf_sprintf(buf, ",frag=[");
        if ( ret < 0 )
                return -1;
        
        if ( off & IP_OFFMASK ) {
                ret = prelude_strbuf_sprintf(buf, "offset=%d ", (off & 0x1fff) * 8);
                if ( ret < 0 )
                        return -1;
        }
        
        if ( off & IP_MF ) {
                ret = prelude_strbuf_sprintf(buf, "MF ");
                if ( ret < 0 )
                        return -1;
        }
        
        if ( off & IP_DF ) {
                pof_host_data.df = 1;
                
                ret = prelude_strbuf_sprintf(buf, "DF ");
                if ( ret < 0 ) 
                        return -1;
        }
                                
        return prelude_strbuf_sprintf(buf, "]");
}



static int ip_dump(idmef_alert_t *alert, idmef_additional_data_t *ad, packet_t *packet) 
{
        int ret;
        idmef_data_t *data;
        uint16_t off, len, id;
        prelude_strbuf_t *buf;
        iphdr_t *ip = packet->p.ip;

        buf = prelude_strbuf_new();
        if ( ! buf )
                return -1;
        
        id = extract_uint16(&ip->ip_id);
        off = extract_uint16(&ip->ip_off);
        len = extract_uint16(&ip->ip_len);
        pof_host_data.len = IP_HL(ip) * 4;

        prelude_strbuf_sprintf(buf, "%s -> ", get_address(&ip->ip_src));
        prelude_strbuf_sprintf(buf,
                               "%s [hl=%d,version=%d,tos=%d,len=%d,id=%d,ttl=%d,prot=%d",
                               get_address(&ip->ip_dst), IP_HL(ip) * 4, IP_V(ip), ip->ip_tos,
                               len, id, ip->ip_ttl, ip->ip_p);
                
        if ( ip->ip_ttl > 128 )
                pof_host_data.ttl = 255;

        else if ( ip->ip_ttl > 64 )
                pof_host_data.ttl = 128;

        else if ( ip->ip_ttl > 32 )
                pof_host_data.ttl = 64;

        else
                pof_host_data.ttl = 32;
        
        if ( off ) {
                ret = dump_ip_offset(off, buf);
                if ( ret < 0 )
                        return -1;
        }

        prelude_strbuf_sprintf(buf, "]");

        data = idmef_data_new_nodup(prelude_strbuf_get_string(buf), prelude_strbuf_get_len(buf) + 1);
        if ( ! data ) {
                prelude_strbuf_destroy(buf);
                return -1;
        }
        
        idmef_additional_data_set_data(ad, data);
        idmef_additional_data_set_type(ad, string);
        
        prelude_strbuf_dont_own(buf);
        prelude_strbuf_destroy(buf);
        
        return 0;
}




static int dump_tcp_flags(uint8_t flags, prelude_strbuf_t *buf)
{        
        if ( ! (flags & (TH_SYN|TH_FIN|TH_RST|TH_PSH|TH_ACK|TH_URG)) )
                return prelude_strbuf_sprintf(buf, ".");
             
        if (flags & TH_SYN)
                prelude_strbuf_sprintf(buf, "SYN ");
        
        if (flags & TH_FIN) 
                prelude_strbuf_sprintf(buf, "FIN ");
        
        if (flags & TH_RST)
                prelude_strbuf_sprintf(buf, "RST ");
        
        if (flags & TH_PSH)
                prelude_strbuf_sprintf(buf, "PUSH ");
        
        if (flags & TH_ACK)
                prelude_strbuf_sprintf(buf, "ACK ");
        
        if (flags & TH_URG) 
                prelude_strbuf_sprintf(buf, "URG ");
        
        if (flags & TH_ECNECHO) 
                prelude_strbuf_sprintf(buf, "ECNECHO ");

        if (flags & TH_CWR)
                prelude_strbuf_sprintf(buf, "CWR ");
        
        return 0;
}



static int tcp_dump(idmef_alert_t *alert, idmef_additional_data_t *ad, packet_t *packet) 
{
        uint32_t seq, ack;
        idmef_data_t *data;
        unsigned char flags;
        prelude_strbuf_t *buf;
        tcphdr_t *tcp = packet->p.tcp;
        uint16_t urp, win, sport, dport;

        buf = prelude_strbuf_new();
        if ( ! buf )
                return -1;
        
        pof_host_data.len += TH_OFF(tcp) * 4;
        
        pof_host_data.win = win = extract_uint16(&tcp->th_win);
        urp = extract_uint16(&tcp->th_urp);
        sport = extract_uint16(&tcp->th_sport);
        dport = extract_uint16(&tcp->th_dport);
        seq = extract_uint32(&tcp->th_seq);
        ack = extract_uint32(&tcp->th_ack);
        
        prelude_strbuf_sprintf(buf, "%d -> %d [flags=", sport, dport);
        flags = tcp->th_flags & ~(TH_ECNECHO|TH_CWR);

        if ( flags == TH_SYN )
                pof_host_data.flags = 'S';

        else if ( flags == (TH_SYN|TH_ACK) )
                pof_host_data.flags = 'A';

        dump_tcp_flags(tcp->th_flags, buf);
                
        prelude_strbuf_sprintf(buf, ",seq=%u", seq);
        
        if ( flags & TH_ACK ) 
                prelude_strbuf_sprintf(buf, ",ack=%u", ack);
        
        if ( flags & TH_URG )
                prelude_strbuf_sprintf(buf, ",urg=%d", urp);

        prelude_strbuf_sprintf(buf, ",win=%d]", win);


        data = idmef_data_new_nodup(prelude_strbuf_get_string(buf), prelude_strbuf_get_len(buf) + 1);
        if ( ! data ) {
                prelude_strbuf_destroy(buf);
                return -1;
        }
        
        idmef_additional_data_set_data(ad, data);
        idmef_additional_data_set_type(ad, string);
        
        prelude_strbuf_dont_own(buf);
        prelude_strbuf_destroy(buf);
        
        return 0;
}




static int udp_dump(idmef_alert_t *alert, idmef_additional_data_t *ad, packet_t *packet) 
{
        idmef_data_t *data;
        prelude_strbuf_t *buf;
        uint16_t sport, dport, len;
        udphdr_t *udp = packet->p.udp_hdr;

        buf = prelude_strbuf_new();
        if (! buf )
                return -1;
        
        len = extract_uint16(&udp->uh_ulen);
        sport = extract_uint16(&udp->uh_sport);
        dport = extract_uint16(&udp->uh_dport);
        
        prelude_strbuf_sprintf(buf, "%d -> %d [len=%d]", sport, dport, len);

        data = idmef_data_new_nodup(prelude_strbuf_get_string(buf), prelude_strbuf_get_len(buf) + 1);
        if ( ! data ) {
                prelude_strbuf_destroy(buf);
                return -1;
        }

        idmef_additional_data_set_data(ad, data);
        idmef_additional_data_set_type(ad, string);
        
        prelude_strbuf_dont_own(buf);
        prelude_strbuf_destroy(buf);
        
        return 0;
}




static int data_dump(idmef_alert_t *alert, idmef_additional_data_t *ad, packet_t *pkt) 
{
        idmef_data_t *data;

        if ( ! pkt->len )
                return -1;

        data = idmef_data_new_ref(pkt->p.data, pkt->len);
        if ( ! data ) 
                return -1;
        
        idmef_additional_data_set_data(ad, data);
        idmef_additional_data_set_type(ad, byte);
        
        return 0;
}




static int igmp_dump(idmef_alert_t *alert, idmef_additional_data_t *ad, packet_t *packet) 
{
        const char *type;
        idmef_data_t *data;
        prelude_strbuf_t *buf;
        igmphdr_t *igmp = packet->p.igmp_hdr;
        
        switch (igmp->igmp_type) {

        case IGMP_MEMBERSHIP_QUERY:
                type = "Igmp Membership Query";
                break;
        case IGMP_V1_MEMBERSHIP_REPORT:
                type = "Igmp V1 Membership Report";
                break;
        case IGMP_V2_MEMBERSHIP_REPORT:
                type = "Igmp V2 Membership Report";
                break;
        case IGMP_V2_LEAVE_GROUP:
                type = "Igmp V2 Leave Group";
                break;
        default:
                type = "Unknow Igmp type";
                break;
        }        

        buf = prelude_strbuf_new();
        if ( ! buf )
                return -1;
        
        prelude_strbuf_sprintf(buf, "type=%s code=%d group=%s",
                               type, igmp->igmp_code, get_address(&igmp->igmp_group));

        data = idmef_data_new_nodup(prelude_strbuf_get_string(buf), prelude_strbuf_get_len(buf) + 1);
        if ( ! data ) {
                prelude_strbuf_destroy(buf);
                return -1;
        }
        
        idmef_additional_data_set_data(ad, data);
        idmef_additional_data_set_type(ad, string);
        
        prelude_strbuf_dont_own(buf);
        prelude_strbuf_destroy(buf);
        
        return 0;
}




static int icmp_dump(idmef_alert_t *alert, idmef_additional_data_t *ad, packet_t *packet) 
{
        icmphdr_t *icmp;
        idmef_data_t *data;
        prelude_strbuf_t *buf;
        
        if ( packet->len < ICMP_MINLEN ) {
                log(LOG_ERR, "ICMP message should be at least %d bytes.\n", ICMP_MINLEN);
                return -1;
        }

        buf = prelude_strbuf_new();
        if ( ! buf )
                return -1;
        
        icmp = packet->p.icmp_hdr;
        prelude_strbuf_sprintf(buf, "type=%d code=%d", icmp->icmp_type, icmp->icmp_code);

        data = idmef_data_new_nodup(prelude_strbuf_get_string(buf), prelude_strbuf_get_len(buf) + 1);
        if ( ! data ) {
                prelude_strbuf_destroy(buf);
                return -1;
        }
        
        idmef_additional_data_set_data(ad, data);
        idmef_additional_data_set_type(ad, string);
        
        prelude_strbuf_dont_own(buf);
        prelude_strbuf_destroy(buf);

        return 0;
}





int nids_packet_dump(idmef_alert_t *alert, packet_t *p)
{
        int ret, i, j;
        idmef_string_t *meaning;
        idmef_additional_data_t *data;
        struct {
                char *name;
                proto_enum_t proto;
                int (*func)(idmef_alert_t *alert, idmef_additional_data_t *data, packet_t *p);
                int size;
        } tbl[] = {
                { "Ethernet header", p_ether, ether_dump, sizeof(etherhdr_t)    },
                { "Arp header", p_arp, arp_dump, sizeof(etherarphdr_t)          },
                { "Rarp header", p_rarp, arp_dump, sizeof(etherarphdr_t)        },
                { "Ip header", p_ip, ip_dump, sizeof(iphdr_t)                   },
                { "Ip encapsulated header", p_ipencap, ip_dump, sizeof(iphdr_t) },
                { "Icmp header", p_icmp, icmp_dump, -1                          },
                { "Igmp header", p_igmp, igmp_dump, sizeof(igmphdr_t)           },
                { "Tcp header", p_tcp, tcp_dump, sizeof(tcphdr_t)               },
                { "Udp header", p_udp, udp_dump, sizeof(udphdr_t)               },
                { "Tcp options", p_tcpopts, tcpopts_dump, -1                    },
                { "Ip options", p_ipopts, ipopts_dump, -1                       },
                { "Packet Payload", p_data, data_dump, -1                       },
                { NULL, },
        };

        
        for ( i = 0; p[i].proto != p_end; i++ ) {
                
                for ( j = 0; tbl[j].name != NULL; j++ ) {
                        
                        if ( p[i].proto != tbl[j].proto )
                                continue;

                        if ( tbl[j].size > 0 && tbl[j].size != p[i].len ) {
                                log(LOG_ERR, "[%s] received len (%d) isn't equal to specified len (%d)!\n",
                                    tbl[j].name, p[i].len, tbl[j].size);
                                return -1;
                        }
                        
                        data = idmef_additional_data_new();
                        if ( ! data ) 
                                return -1;

                        meaning = idmef_string_new_ref(tbl[j].name);
                        if ( ! meaning ) {
                                idmef_additional_data_destroy(data);
                                return -1;
                        }

                        idmef_additional_data_set_type(data, string);
                        idmef_additional_data_set_meaning(data, meaning);
                        
                        ret = tbl[j].func(alert, data, &p[i]);
                        if ( ret < 0 ) {
                                idmef_additional_data_destroy(data);
                                continue;
                        }
                        
                        idmef_alert_set_additional_data(alert, data);
                        break;
                }
        }

        return 0;
}

