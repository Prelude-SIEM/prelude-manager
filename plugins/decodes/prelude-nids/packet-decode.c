/*****
*
* Copyright (C) 2001, 2002, 2003 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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

#include "packet.h"

#include <libprelude/list.h>
#include <libprelude/prelude-log.h>
#include <libprelude/extract.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/idmef-tree-func.h>

#include "config.h"
#include "plugin-util.h"
#include "optparse.h"
#include "ethertype.h"
#include "packet-decode.h"


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



static idmef_alert_t *global_alert;
static char buf[1024], *payload = NULL;



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



static int ether_dump(idmef_additional_data_t *data, packet_t *packet) 
{
        int i;
        uint16_t t;
        const char *type;
        etherhdr_t *hdr = packet->p.ether_hdr;

        t = extract_uint16(&hdr->ether_type);
        
        i = snprintf(buf, sizeof(buf), "%s -> ",
                     etheraddr_string(hdr->ether_shost));
        
        type = switch_ethertype(t);
        
        i += snprintf(buf + i, sizeof(buf) - i, "%s [ether_type=%s (%d)]",
                      etheraddr_string(hdr->ether_dhost), type, t);

        packet->data = strdup(buf);
        idmef_additional_data_set_data(data, string, packet->data, i + 1);
        
        return 0;
}




static int arp_dump(idmef_additional_data_t *data, packet_t *packet) 
{
        int i, len = 0;
        uint16_t op, hrd;
        const char *ptr = NULL;
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
        
        op = extract_uint16(&arp->arp_op);
        hrd = extract_uint16(&arp->arp_hrd);
        
        for ( i = 0; type_tbl[i].name != NULL; i++ ) {
                if ( op == type_tbl[i].type ) {
                        ptr = type_tbl[i].name;
                        break;
                }
        }

        len = snprintf(buf, sizeof(buf), "type=%d(%s) ", op, (ptr) ? ptr : "unknown" );     

        for ( i = 0; f_tbl[i].name != NULL; i++ ) {
                if ( hrd == f_tbl[i].type ) {
                        ptr = f_tbl[i].name;
                        break;
                }
        }
        
        len += snprintf(buf + len, sizeof(buf) - len, "f=%d(%s) ", hrd, (ptr) ? ptr : "unknown");
        
        len += snprintf(buf + len, sizeof(buf) - len, "tpa=%s,tha=%s,",
                        get_address((struct in_addr *)arp->arp_tpa), etheraddr_string(arp->arp_tha));
        
        len += snprintf(buf + len, sizeof(buf) - len, "spa=%s,sha=%s",
                        get_address((struct in_addr *)arp->arp_spa), etheraddr_string(arp->arp_sha));

        packet->data = strdup(buf);
        idmef_additional_data_set_data(data, string, packet->data, len + 1);
                
        return 0;
}



static int ipopts_dump(idmef_additional_data_t *data, packet_t *packet) 
{
        const char *ipopt;
        
        ipopt = ip_optdump(packet->p.opts, packet->len);
        if ( ! ipopt )
                return -1;

        packet->data = strdup(ipopt);
        if ( ! packet->data ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        idmef_additional_data_set_data(data, string, packet->data, strlen(ipopt) + 1);
        
        return 0;
}




static int tcpopts_dump(idmef_additional_data_t *data, packet_t *packet) 
{
        const char *tcpopt;
        
        tcpopt = tcp_optdump(packet->p.opts, packet->len);
        if ( ! tcpopt )
                return -1;

        packet->data = strdup(tcpopt);
        if ( ! packet->data ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        idmef_additional_data_set_data(data, string, packet->data, strlen(tcpopt) + 1);

        return 0;
}




static int ip_dump(idmef_additional_data_t *data, packet_t *packet) 
{
        int r;
        char *src, *dst;
        uint16_t off, len, id;
        iphdr_t *ip = packet->p.ip;        
        
        id = extract_uint16(&ip->ip_id);
        off = extract_uint16(&ip->ip_off);
        len = extract_uint16(&ip->ip_len);
        
        src = strdup(get_address(&ip->ip_src));
        dst = strdup(get_address(&ip->ip_dst));
        
        r = snprintf(buf, sizeof(buf),
                     "%s -> %s [hl=%d,version=%d,tos=%d,len=%d,id=%d,ttl=%d,prot=%d",
                     src, dst, IP_HL(ip) * 4, IP_V(ip), ip->ip_tos, len, id, ip->ip_ttl, ip->ip_p);

        if ( off & 0x3fff ) {
                r += snprintf(buf + r, sizeof(buf) - r, ",frag=[offset=%d",  (off & 0x1fff) * 8);

                if ( off & IP_MF )
                        r += snprintf(buf + r, sizeof(buf) - r, ",MF");

                if ( off & IP_DF )
                        r += snprintf(buf + r, sizeof(buf) - r, ",DF");
                
                r += snprintf(buf + r, sizeof(buf) - r, "]");
        }
        
        r += snprintf(buf + r, sizeof(buf) - r, "]");

        free(src);
        free(dst);

        packet->data = strdup(buf);
        idmef_additional_data_set_data(data, string, packet->data, r + 1);
        
        return 0;
}




static int tcp_dump(idmef_additional_data_t *data, packet_t *packet) 
{
        int r, blen;
        char buf[1024];
        unsigned char flags;
        uint32_t seq, ack;
        tcphdr_t *tcp = packet->p.tcp;
        uint16_t urp, win, sport, dport;
        
        win = extract_uint16(&tcp->th_win);
        urp = extract_uint16(&tcp->th_urp);
        sport = extract_uint16(&tcp->th_sport);
        dport = extract_uint16(&tcp->th_dport);
        seq = extract_uint32(&tcp->th_seq);
        ack = extract_uint32(&tcp->th_ack);
        
        blen = sizeof(buf);

        r = snprintf(buf, blen, "%d -> %d [flags=", sport, dport);
              
        flags = tcp->th_flags;

        if ( flags & (TH_SYN|TH_FIN|TH_RST|TH_PSH|TH_ACK|TH_URG) ) {
                if (flags & TH_SYN)
                        r += snprintf(&buf[r], blen - r, "SYN ");
                if (flags & TH_FIN)
                        r += snprintf(&buf[r], blen - r, "FIN ");
                if (flags & TH_RST)
                        r += snprintf(&buf[r], blen - r, "RST ");
                if (flags & TH_PSH)
                        r += snprintf(&buf[r], blen - r, "PUSH ");
                if (flags & TH_ACK)
                        r += snprintf(&buf[r], blen - r, "ACK ");
                if (flags & TH_URG)
                        r += snprintf(&buf[r], blen - r, "URG ");
        } else
                r += snprintf(&buf[r], blen - r, ".");
        
        r += snprintf(&buf[r], blen - r, ",seq=%u", seq);
        
        if ( flags & TH_ACK )
                r += snprintf(&buf[r], blen - r, ",ack=%u", ack);

        if ( flags & TH_URG )
                r += snprintf(&buf[r], blen - r, ",urg=%d", urp);
        
        r += snprintf(&buf[r], blen - r, ",win=%d]", win);

        packet->data = strdup(buf);
        idmef_additional_data_set_data(data, string, packet->data, r + 1);
        
        return 0;
}




static int udp_dump(idmef_additional_data_t *data, packet_t *packet) 
{
        int ret;
        uint16_t sport, dport, len;
        udphdr_t *udp = packet->p.udp_hdr;
        
        len = extract_uint16(&udp->uh_ulen);
        sport = extract_uint16(&udp->uh_sport);
        dport = extract_uint16(&udp->uh_dport);
        
        ret = snprintf(buf, sizeof(buf), "%d -> %d [len=%d]", sport, dport, len);

        
        packet->data = strdup(buf);
        idmef_additional_data_set_data(data, string, packet->data, ret + 1);
        
        return 0;
}




static int data_dump(idmef_additional_data_t *data, packet_t *pkt) 
{
        int ret;

        if ( pkt->len ) {
                idmef_additional_data_t *pdata;
                
                payload = prelude_string_to_hex(pkt->p.data, pkt->len);
                if ( ! payload ) 
                        return -1;

                pdata = idmef_alert_additional_data_new(global_alert);
                if ( ! pdata ) {
                        free(payload);
                        return -1;
                }
                
                idmef_string_set_constant(&pdata->meaning, "Payload Hexadecimal Dump");
                idmef_additional_data_set_data(pdata, string, payload, strlen(payload) + 1);
        }
        
        ret = snprintf(buf, sizeof(buf), "size=%d bytes", pkt->len);

        pkt->data = strdup(buf);
        idmef_additional_data_set_data(data, string, pkt->data, ret + 1);
                
        return 0;
}




static int igmp_dump(idmef_additional_data_t *data, packet_t *packet) 
{
        int ret;
        const char *type;
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
        
        ret = snprintf(buf, sizeof(buf), "type=%s code=%d group=%s",
                       type, igmp->igmp_code, get_address(&igmp->igmp_group));

        packet->data = strdup(buf);
        idmef_additional_data_set_data(data, string, packet->data, ret + 1);
        
        return 0;
}




static int icmp_dump(idmef_additional_data_t *data, packet_t *packet) 
{
        int ret;
        icmphdr_t *icmp;

        if ( packet->len < ICMP_MINLEN ) {
                log(LOG_ERR, "ICMP message should be at least %d bytes.\n", ICMP_MINLEN);
                return -1;
        }

        icmp = packet->p.icmp_hdr;
        ret = snprintf(buf, sizeof(buf), "type=%d code=%d", icmp->icmp_type, icmp->icmp_code);

        packet->data = strdup(buf);
        idmef_additional_data_set_data(data, string, packet->data, ret + 1);

        return 0;
}




typedef int (dump_func_t)(idmef_additional_data_t *data, packet_t *p);

int nids_packet_dump(idmef_alert_t *alert, packet_t *p)
{
        int ret;
        int i, j;
        idmef_additional_data_t *data;
        struct {
                char *name;
                proto_enum_t proto;
                dump_func_t *func;
                int size;
        } tbl[] = {
                { "Ethernet header", p_ether, (dump_func_t *) ether_dump, sizeof(etherhdr_t) },
                { "Arp header", p_arp, (dump_func_t *) arp_dump, sizeof(etherarphdr_t)  },
                { "Rarp header", p_rarp, (dump_func_t *) arp_dump, sizeof(etherarphdr_t) },
                { "Ip header", p_ip, (dump_func_t *) ip_dump, sizeof(iphdr_t) },
                { "Ip encapsulated header", p_ipencap, (dump_func_t *) ip_dump, sizeof(iphdr_t) },
                { "Icmp header", p_icmp, (dump_func_t *) icmp_dump, -1 },
                { "Igmp header", p_igmp, (dump_func_t *) igmp_dump, sizeof(igmphdr_t) },
                { "Tcp header", p_tcp, (dump_func_t *) tcp_dump, sizeof(tcphdr_t) },
                { "Udp header", p_udp, (dump_func_t *) udp_dump, sizeof(udphdr_t) },
                { "Tcp options", p_tcpopts, (dump_func_t *) tcpopts_dump, -1 },
                { "Ip options", p_ipopts, (dump_func_t *) ipopts_dump, -1 },
                { "Payload header", p_data, (dump_func_t *) data_dump, -1 },
                { NULL, },
        };


        global_alert = alert;
        for ( i = 0; p[i].proto != p_end; i++ ) {
                
                for ( j = 0; tbl[j].name != NULL; j++ ) {
                        
                        if ( p[i].proto == tbl[j].proto ) {

                                if ( tbl[j].size > 0 && tbl[j].size != p[i].len ) {
                                        log(LOG_ERR, "[%s] received len (%d) isn't equal to specified len (%d)!\n",
                                            tbl[j].name, p[i].len, tbl[j].size);
                                        return -1;
                                }
                                
                                data = idmef_alert_additional_data_new(alert);
                                if ( ! data ) 
                                        return -1;

                                data->type = string;
                                
                                ret = tbl[j].func(data, &p[i]);
                                if ( ret < 0 ) 
                                        return -1;
                                
                                idmef_string_set(&data->meaning, tbl[j].name);
                                break;
                        }
                }
        }

        return 0;
}




void nids_packet_free(packet_t *packet) 
{
        int i;
        
        if ( payload ) {
                free(payload);
                payload = NULL;
        }
        
        for ( i = 0; packet[i].proto != p_end; i++ )
                if ( packet[i].data )
                        free(packet[i].data);
}

