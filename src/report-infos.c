
/*****
*
* Copyright (C) 1999 Vandoorselaere Yoann
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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "list.h"

#include <libprelude/plugin-common.h>
#include <libprelude/alert.h>

#include "packet.h"
#include "optparse.h"
#include "extract.h"
#include "ethertype.h"
#include "tcpdump-func.h"
#include "report-infos.h"


#define PRINT_CHAR 16
#define HEX_CHAR PRINT_CHAR * 2
#define SPACE_CHAR 24
#define LINE_SIZE PRINT_CHAR + HEX_CHAR + SPACE_CHAR
#define PRINT_START HEX_CHAR + SPACE_CHAR


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


/*
 * Append a line to an array of line.
 * Take the address of the array and the line to append as arguments.
 *
 * list must be NULL the first time this function is called,
 * in order to initialize indexing variable.
 */
static int append_line(char ***list, char *line)
{
        static int i;
        char **l = *list;
        
        if ( ! l )
                i = 2;

        l = (char **) realloc(l, i * sizeof(char **));
        if ( ! l )
                return -1;        
        
        l[i - 2] = line;
        l[i - 1] = NULL;
        i++;

        *list = l;
        
        return 0;
}



/*
 * Test a character to see if it is printable,
 * if it is, return the character, else return '.'
 * which mean hidden.
 */
static int convert_char(int c) 
{
        return (c >= 0x20 && c < 0x7f) ? c : '.';
}



/*
 *
 */
static char **hexdump(const unsigned char *data, size_t size)
{
        int i, j, k;
        unsigned char c;
        char **ret = NULL;
        char line[LINE_SIZE + 1];
        static unsigned char binhex[16] = {
                '0', '1', '2', '3', '4', '5', '6', '7',
                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
        };
                
        memset(line, ' ', sizeof(line));
                
        for ( i = 0, k = 0, j = 0; i < size; i++ ) {
                c = *data++;
                line[j++] = binhex[c >> 4];
                line[j++] = binhex[c & 0xf];
                line[j++] = ' ';

                line[PRINT_START + k++] = convert_char(c);
                
                if ( i ) {
                        if ( (i + 1) % 4 == 0 ) {
                                line[j++] = ' ';
                                line[j++] = ' ';
                        }

                        if ( (i + 1) % 16 == 0 ) {
                                line[PRINT_START + k++] = '\0';
                                append_line(&ret, strdup(line));
                                memset(line, ' ', sizeof(line));
                                k = j = 0;
                        }
                }
        }
        
        if ( line[0] != ' ' ) {
                line[PRINT_START + k++] = '\0';
                append_line(&ret, strdup(line));
        }
        
        return ret;
}                        
        

static const char *switch_ethertype(unsigned short type) 
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

static char *ether_dump(etherhdr_t *hdr) 
{
        int i;
        char buf[1024];
        const char *type;
        
        i = snprintf(buf, sizeof(buf), "Ether hdr : %s -> ",
                     etheraddr_string(hdr->ether_shost));
        
        type = switch_ethertype(ntohs(hdr->ether_type));
        
        snprintf(buf + i, sizeof(buf) - i, "%s [ether_type=%s (%d)]",
                 etheraddr_string(hdr->ether_dhost),
                 type, ntohs(hdr->ether_type));
        
        
        return strdup(buf);
}


static char *arp_dump(etherarphdr_t *arp) 
{
        int i;
        char buf[1024];              

        i = snprintf(buf, sizeof(buf), "Arp hdr :");

        switch (EXTRACT_16BITS(&arp->arp_op)) {

        case ARPOP_REQUEST:
                i += snprintf(buf + i, sizeof(buf) - i, "type=request ");
                break;
        
        case ARPOP_REPLY:
                i += snprintf(buf + i, sizeof(buf) - i, "type=reply ");
                break;

        case ARPOP_RREQUEST:
                i += snprintf(buf + i, sizeof(buf) - i, "type=request(RArp) ");
                break;
                
        case ARPOP_RREPLY:
                i += snprintf(buf + i, sizeof(buf) - i, "type=reply(RArp) ");
                break;

        case ARPOP_InREQUEST:
                i += snprintf(buf + i, sizeof(buf) - i, "type=request(InArp) ");
                break;
                
        case ARPOP_InREPLY:
                i += snprintf(buf + i, sizeof(buf) - i, "type=reply(InArp) ");
                break;

        case ARPOP_NAK:
                i += snprintf(buf + i, sizeof(buf) - i, "type=reply(atm Arp NAK) ");
                break;
                
        default:
                i += snprintf(buf + i, sizeof(buf) - i, "type=Unknow(%d) ",
                              EXTRACT_16BITS(&arp->arp_op));
                break;
        }

        switch(EXTRACT_16BITS(&arp->arp_hrd)) {
        case ARPHRD_NETROM:
                i += snprintf(buf + i, sizeof(buf) - i, "f=netrom ");
                break;

        case ARPHRD_ETHER:
                i += snprintf(buf + i, sizeof(buf) - i, "f=ether ");
                break;

        case ARPHRD_EETHER:
                i += snprintf(buf + i, sizeof(buf) - i, "f=eether ");
                break;

        case ARPHRD_AX25:
                i += snprintf(buf + i, sizeof(buf) - i, "f=ax25 ");
                break;

        case ARPHRD_CHAOS:
                i += snprintf(buf + i, sizeof(buf) - i, "f=chaos ");
                break;

        case ARPHRD_IEEE802:
                i += snprintf(buf + i, sizeof(buf) - i, "f=ieee802,");
                break;

        case ARPHRD_ARCNET:
                i += snprintf(buf + i, sizeof(buf) - i, "f=arcnet,");
                break;
                
        case ARPHRD_APPLETLK:
                i += snprintf(buf + i, sizeof(buf) - i, "f=appletlk,");
                break;
                
        case ARPHRD_DLCI:
                i += snprintf(buf + i, sizeof(buf) - i, "f=dlci,");
                break;

        case ARPHRD_ATM:
                i += snprintf(buf + i, sizeof(buf) - i, "f=atm,");
                break;
                
        }
        

        i += snprintf(buf + i, sizeof(buf) - i, "tpa=%s,tha=%s,",
                      inet_ntoa(*((struct in_addr *)arp->arp_tpa)), etheraddr_string(arp->arp_tha));
        
        i += snprintf(buf + i, sizeof(buf) - i, "spa=%s,sha=%s",
                      inet_ntoa(*((struct in_addr *)arp->arp_spa)), etheraddr_string(arp->arp_sha));
        
        
        return strdup(buf);       
}


static char *ip_dump(iphdr_t *ip) 
{
        char *src, *dst, frag[1024];
        unsigned int off;
        char buf[1024];
        int r;
        
        src = strdup(inet_ntoa(ip->ip_src));
        dst = strdup(inet_ntoa(ip->ip_dst));

        off = ntohs(ip->ip_off);
        
        if ( off & 0x3fff ) {
                r = snprintf(frag, sizeof(frag),
                             ",frag=[offset=%d%s]", (off & 0x1fff) * 8, (off & IP_MF) ? ",MF" : "");
        
                if ( off & IP_DF )
                        snprintf(&frag[r], sizeof(frag) - r, "DF");
        } else frag[0] = '\0';
        
        snprintf(buf, sizeof(buf),
                 "Ip hdr    : %s -> %s [hl=%d,version=%d,tos=%d,len=%d,id=%d,ttl=%d%s]",
                 src, dst, ip->ip_hl * 4, ip->ip_v, ip->ip_tos,
                 ntohs(ip->ip_len), ntohs(ip->ip_id), ip->ip_ttl, frag);

        free(src);
        free(dst);
        
        return strdup(buf);
}

static char *tcp_dump(tcphdr_t *tcp) 
{
        unsigned char flags;
        char buf[1024];
        int r, blen;

        blen = sizeof(buf);

        r = snprintf(buf, blen, "Tcp hdr   : %d -> %d [flags=",
                     ntohs(tcp->th_sport), ntohs(tcp->th_dport));
              
        flags = tcp->th_flags;

        if ( flags & (TH_SYN|TH_FIN|TH_RST|TH_PUSH|TH_ACK|TH_URG) ) {
                if (flags & TH_SYN)
                        r += snprintf(&buf[r], blen - r, "SYN ");
                if (flags & TH_FIN)
                        r += snprintf(&buf[r], blen - r, "FIN ");
                if (flags & TH_RST)
                        r += snprintf(&buf[r], blen - r, "RST ");
                if (flags & TH_PUSH)
                        r += snprintf(&buf[r], blen - r, "PUSH ");
                if (flags & TH_ACK)
                        r += snprintf(&buf[r], blen - r, "ACK ");
                if (flags & TH_URG)
                        r += snprintf(&buf[r], blen - r, "URG ");
        } else r += snprintf(&buf[r], blen - r, ".");
        
        r += snprintf(&buf[r], blen - r, ",seq=%u", (uint32_t) ntohl(tcp->th_seq));
        
        if ( flags & TH_ACK )
                r += snprintf(&buf[r], blen - r, ",ack=%u", (uint32_t) ntohl(tcp->th_ack));
        if ( flags & TH_URG )
                r += snprintf(&buf[r], blen - r, ",urg=%d", ntohs(tcp->th_urp));
        
        r += snprintf(&buf[r], blen - r, ",win=%d]", ntohs(tcp->th_win));

        return strdup(buf);
}

static char *tcpopt_dump(packet_t *p) 
{
        char buf[1024], *ptr;
        size_t len = sizeof(buf);
        
        ptr = buf + snprintf(buf, sizeof(buf), "Tcp opts  : ");
        tcp_optdump(p->p.opts, p->len, &ptr, &len);
                
        return strdup(buf);
}

static char *ipopt_dump(packet_t *p) 
{
        char buf[1024], *ptr;
        size_t len = sizeof(buf);
        
        ptr = buf + snprintf(buf, sizeof(buf), "Ip opts   : ");
        ip_optdump(p->p.opts, p->len, &ptr, &len);
        
        return strdup(buf);
}

static char *udp_dump(udphdr_t *udp) 
{
        char buf[1024];

        snprintf(buf, sizeof(buf), "Udp hdr   : %d -> %d [len=%d]",
                 ntohs(udp->uh_sport), ntohs(udp->uh_dport), ntohs(udp->uh_ulen));
        
        return strdup(buf);
}


static char *data_dump(packet_t *pkt) 
{
        char buf[1024];

        snprintf(buf, sizeof(buf), "Data hdr  : size=%d bytes", pkt->len);
        return strdup(buf);
}


static char *igmp_dump(igmphdr_t *igmp) 
{
        char buf[1024];
        const char *type;
        
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

        snprintf(buf, sizeof(buf), "Igmp hdr  : type=%s code=%d group=%s",
                 type, igmp->igmp_code, inet_ntoa(igmp->igmp_group));

        return strdup(buf);
}


static char *icmp_dump(icmphdr_t *icmp) 
{
        char buf[1024];

        snprintf(buf, sizeof(buf), "Icmp hdr  : type=%d code=%d",
                 icmp->icmp_type, icmp->icmp_code);

        return strdup(buf);
}



static void create_pktdump(packet_t *p, report_infos_t *rinfos)
{
        int i, j = 0;
        static char *pktdump[MAX_PKTDEPTH + 2];
        int addr_depth = -1, port_depth = -1;
        
        rinfos->hexdump = NULL;
        rinfos->pktdump = pktdump;
        
        for (i = 0; p[i].proto != p_end ; i++) {

                switch (p[i].proto) {
                case p_ether:
                        addr_depth = i;
                        pktdump[j++] = ether_dump(p[i].p.ether_hdr);
                        break;

                case p_rarp:
                case p_arp:
                        pktdump[j++] = arp_dump(p[i].p.arp_hdr);
                        break;
                        
		case p_ip:
                        addr_depth = i;
                        
                case p_ipencap:
                        pktdump[j++] = ip_dump(p[i].p.ip);
                        break;

                case p_ipopts:
                        pktdump[j++] = ipopt_dump(&p[i]);
                        break;
                        
                case p_icmp:
                        pktdump[j++] = icmp_dump(p[i].p.icmp_hdr);
                        break;
                        
                case p_igmp:
                        pktdump[j++] = igmp_dump(p[i].p.igmp_hdr);
                        break;
                        
		case p_tcp:
                        port_depth = i;
                        pktdump[j++] = tcp_dump(p[i].p.tcp);
                        break;

                case p_tcpopts:
                        pktdump[j++] = tcpopt_dump(&p[i]);
                        break;
                        
                case p_udp:
                        port_depth = i;
                        pktdump[j++] = udp_dump(p[i].p.udp_hdr);
			break;

                case p_data:
                        pktdump[j++] = data_dump(&p[i]);
                        rinfos->hexdump = hexdump(p[i].p.data, p[i].len);
                default:
			break;
		}
	}
        
        pktdump[j++] = NULL;

        if ( addr_depth != -1 ) {
                if ( p[addr_depth].proto == p_ip ) {
                        rinfos->sh = strdup(inet_ntoa(p[addr_depth].p.ip->ip_src));
                        rinfos->dh = strdup(inet_ntoa(p[addr_depth].p.ip->ip_dst));
                } else if ( p[addr_depth].proto == p_ether ) {
                        rinfos->sh = strdup(etheraddr_string(p[addr_depth].p.ether_hdr->ether_shost));
                        rinfos->dh = strdup(etheraddr_string(p[addr_depth].p.ether_hdr->ether_dhost));
                }
        }

        if ( port_depth != -1 ) {
                if ( p[port_depth].proto == p_tcp ) {
                        rinfos->sp = ntohs(p[port_depth].p.tcp->th_sport);
                        rinfos->dp = ntohs(p[port_depth].p.tcp->th_dport);
                } else if ( p[port_depth].proto == p_udp ) {
                        rinfos->sp = ntohs(p[port_depth].p.udp_hdr->uh_sport);
                        rinfos->dp = ntohs(p[port_depth].p.udp_hdr->uh_dport);
                }
        }
}




static const char *get_cleartext_alert_kind(rkind_t kind) 
{
        switch(kind) {

        case maybe_faked:
                return "Could be faked";

        case maybe_not_reliable:
                return "May not be reliable";

        case normal:
                return "Should be ok";

        case guess:
                abort();
        }

        return "";
}



void report_infos_get(alert_t *alert, report_infos_t *rinfo) 
{
        rinfo->kind = get_cleartext_alert_kind(alert_kind(alert));
        
        rinfo->date_start = strdup(ctime(&alert_time_start(alert)));
        *(rinfo->date_start + strlen(rinfo->date_start) - 1) = 0;
        
        if ( alert_time_end(alert) ) {
                rinfo->date_end = strdup(ctime(&alert_time_end(alert)));
                *(rinfo->date_end + strlen(rinfo->date_end) - 1) = 0;
        } else
                rinfo->date_end = NULL;

        rinfo->sh = rinfo->dh = NULL;
        rinfo->sp = rinfo->dp = 0;
        rinfo->pktdump = NULL;
        rinfo->hexdump = NULL;
            //create_pktdump(alert_data(alert)->packet, rinfo);
}



void report_infos_free(report_infos_t *rinfo) 
{
        int i;

        free(rinfo->date_start);
        if ( rinfo->date_end )
                free(rinfo->date_end);

        if ( rinfo->sh ) 
                free(rinfo->sh);
                
        if ( rinfo->dh )
                free(rinfo->dh);
                
        if ( rinfo->pktdump ) 
                for (i = 0; rinfo->pktdump[i] != NULL; i++)
                        free(rinfo->pktdump[i]);
        
        if ( rinfo->hexdump ) {
                for (i = 0; rinfo->hexdump[i] != NULL; i++)
                        free(rinfo->hexdump[i]);
                
                free(rinfo->hexdump);
        }
}

















