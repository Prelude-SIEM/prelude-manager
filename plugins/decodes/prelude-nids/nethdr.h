/*
 *  Copyright (C) 2000, 2002 Yoann Vandoorselaere <yoann@prelude-ids.org>.
 *
 *  This program is free software; you can redistribute it and/or modify 
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  Authors: Yoann Vandoorselaere <yoann@prelude-ids.org>
 *
 */

/*
 * Include this header for portability.
 */

#define __USE_BSD 1
#define __FAVOR_BSD 1

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/in_systm.h>
#include <net/if.h>


#include "config.h"

#define ETH_ALEN 6

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
#define ARPHRD_AX25     3               /* AX.25 Level 2.  */
#define ARPHRD_PRONET   4               /* PROnet token ring.  */
#define ARPHRD_CHAOS    5               /* Chaosnet.  */
#define ARPHRD_IEEE802  6               /* IEEE 802.2 Ethernet/TR/TB.  */
#define ARPHRD_ARCNET   7               /* ARCnet.  */
#define ARPHRD_APPLETLK 8               /* APPLEtalk.  */
#define ARPHRD_DLCI     15              /* Frame Relay DLCI.  */
#define ARPHRD_ATM      19              /* ATM.  */
#define ARPHRD_METRICOM 23              /* Metricom STRIP (new IANA id).  */

/* Dummy types for non ARP hardware */
#define ARPHRD_SLIP     256
#define ARPHRD_CSLIP    257
#define ARPHRD_SLIP6    258
#define ARPHRD_CSLIP6   259
#define ARPHRD_RSRVD    260             /* Notional KISS type.  */
#define ARPHRD_ADAPT    264
#define ARPHRD_ROSE     270
#define ARPHRD_X25      271             /* CCITT X.25.  */
#define ARPHDR_HWX25    272             /* Boards with X.25 in firmware.  */
#define ARPHRD_PPP      512
#define ARPHRD_CISCO    513             /* Cisco HDLC.  */
#define ARPHRD_HDLC     ARPHRD_CISCO
#define ARPHRD_LAPB     516             /* LAPB.  */
#define ARPHRD_DDCMP    517             /* Digital's DDCMP.  */
#define ARPHRD_RAWHDLC  518             /* Raw HDLC.  */

#define ARPHRD_TUNNEL   768             /* IPIP tunnel.  */
#define ARPHRD_TUNNEL6  769             /* IPIP6 tunnel.  */
#define ARPHRD_FRAD     770             /* Frame Relay Access Device.  */
#define ARPHRD_SKIP     771             /* SKIP vif.  */
#define ARPHRD_LOOPBACK 772             /* Loopback device.  */
#define ARPHRD_LOCALTLK 773             /* Localtalk device.  */
#define ARPHRD_FDDI     774             /* Fiber Distributed Data Interface. */
#define ARPHRD_BIF      775             /* AP1000 BIF.  */
#define ARPHRD_SIT      776             /* sit0 device - IPv6-in-IPv4.  */
#define ARPHRD_IPDDP    777             /* IP-in-DDP tunnel.  */
#define ARPHRD_IPGRE    778             /* GRE over IP.  */
#define ARPHRD_PIMREG   779             /* PIMSM register interface.  */
#define ARPHRD_HIPPI    780             /* High Performance Parallel I'face. */
#define ARPHRD_ASH      781             /* (Nexus Electronics) Ash.  */
#define ARPHRD_ECONET   782             /* Acorn Econet.  */
#define ARPHRD_IRDA     783             /* Linux-IrDA.  */
#define ARPHRD_FCPP     784             /* Point to point fibrechanel.  */
#define ARPHRD_FCAL     785             /* Fibrechanel arbitrated loop.  */
#define ARPHRD_FCPL     786             /* Fibrechanel public loop.  */
#define ARPHRD_FCPFABRIC 787            /* Fibrechanel fabric.  */
#define ARPHRD_IEEE802_TR 800           /* Magic type ident for TR.  */
#define ARPHRD_IEEE80211 801            /* IEEE 802.11.  */



typedef struct {
        uint16_t ar_hrd;     /* format of hardware address */
        uint16_t ar_pro;     /* format of protocol address */
        uint8_t ar_hln;     /* length of hardware address */
        uint8_t ar_pln;     /* length of protocol address */
        uint16_t ar_op;      /* one of: */
} arphdr_t;



typedef struct {
        arphdr_t ea_hdr;
        uint8_t arp_sha[ETH_ALEN]; /* sender hardware address */
        uint8_t arp_spa[4];        /* sender protocol address */
        uint8_t arp_tha[ETH_ALEN]; /* target hardware address */
        uint8_t arp_tpa[4];        /* target protocol address */
} etherarphdr_t;



#define arp_hrd ea_hdr.ar_hrd
#define arp_pro ea_hdr.ar_pro
#define arp_hln ea_hdr.ar_hln
#define arp_pln ea_hdr.ar_pln
#define arp_op  ea_hdr.ar_op



/*
 * Structure of a DEC/Intel/Xerox or 802.3 Ethernet header.
 */

#define ETHERTYPE_IP      0x0800
#define ETHERTYPE_ARP     0x0806 /* Address resolution */
#define ETHERTYPE_REVARP  0x8035 /* Reverse ARP */


typedef struct {
        uint8_t ether_dhost[ETH_ALEN];
        uint8_t  ether_shost[ETH_ALEN];
        uint16_t ether_type;
} etherhdr_t;




/*
 * FDDI header
 */
typedef struct {
        uint8_t fddi_fc;          /* Frame Control (FC) value */
        uint8_t fddi_dhost[6];    /* Destination host */
        uint8_t fddi_shost[6];    /* Source host */
} fddihdr_t;


#define FDDI_HDRLEN 13





/*
 * IP header
 */
#define IP_RF 0x8000                    /* reserved fragment flag */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
#define IP_MAXPACKET    65535           /* maximum packet size */
#define IP_MSS          576             /* default maximum segment size */

typedef struct {
        uint8_t ip_vhl;         /* header length, version */

#define IP_V(ip)  (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip) ((ip)->ip_vhl & 0x0f)

        uint8_t ip_tos;
        uint16_t ip_len;
        uint16_t ip_id;
        uint16_t ip_off;
        uint8_t ip_ttl;
        uint8_t ip_p;
        uint16_t ip_sum;
        struct in_addr ip_src;
        struct in_addr ip_dst;
} iphdr_t;




/*
 * TCP header
 */
#define TH_FIN     0x01
#define TH_SYN     0x02
#define TH_RST     0x04
#define TH_PSH     0x08
#define TH_ACK     0x10
#define TH_URG     0x20
#define TH_ECNECHO 0x40    /* ECN Echo */
#define TH_CWR     0x80    /* ECN Cwnd Reduced */



typedef struct {
        uint16_t th_sport;
        uint16_t th_dport;
        uint32_t th_seq;
        uint32_t th_ack;

        uint8_t th_offx2; /* th_off and th_x2 */

#define TH_X2(tcp)  ((tcp)->th_offx2 & 0x0f)
#define TH_OFF(tcp) (((tcp)->th_offx2 & 0xf0) >> 4)
    
        uint8_t th_flags;
        uint16_t th_win;
        uint16_t th_sum;
        uint16_t th_urp;
} tcphdr_t;




/*
 * UDP header
 */
typedef struct {
        uint16_t uh_sport;           /* source port */
        uint16_t uh_dport;           /* destination port */
        uint16_t uh_ulen;            /* udp length */
        uint16_t uh_sum;             /* udp checksum */
} udphdr_t;



/*
 * Internal of an ICMP Router Advertisement
 */

#define ICMP_MINLEN 8
#define ICMP_DEST_UNREACH 3



struct icmp_ra_addr {
        uint32_t ira_addr;
        uint32_t ira_preference;
};



typedef struct {
        uint8_t  icmp_type;  /* type of message, see below */
        uint8_t  icmp_code;  /* type sub code */
        uint16_t icmp_cksum; /* ones complement checksum of struct */

        union {
                unsigned char ih_pptr;       /* ICMP_PARAMPROB */
                struct in_addr ih_gwaddr;   /* gateway address */

                struct ih_idseq {           /* echo datagram */
                        uint16_t icd_id;
                        uint16_t icd_seq;
                } ih_idseq;

                uint32_t ih_void;

                /* ICMP_UNREACH_NEEDFRAG -- Path MTU Discovery (RFC1191) */
                struct ih_pmtu {
                        uint16_t ipm_void;
                        uint16_t ipm_nextmtu;
                } ih_pmtu;
                 
                struct ih_rtradv {
                        uint8_t irt_num_addrs;
                        uint8_t irt_wpa;
                        uint16_t irt_lifetime;
                } ih_rtradv;
        } icmp_hun;
        
#define icmp_pptr       icmp_hun.ih_pptr
#define icmp_gwaddr     icmp_hun.ih_gwaddr
#define icmp_id         icmp_hun.ih_idseq.icd_id
#define icmp_seq        icmp_hun.ih_idseq.icd_seq
#define icmp_void       icmp_hun.ih_void
#define icmp_pmvoid     icmp_hun.ih_pmtu.ipm_void
#define icmp_nextmtu    icmp_hun.ih_pmtu.ipm_nextmtu
#define icmp_num_addrs  icmp_hun.ih_rtradv.irt_num_addrs
#define icmp_wpa        icmp_hun.ih_rtradv.irt_wpa
#define icmp_lifetime   icmp_hun.ih_rtradv.irt_lifetime
        union {
                struct {
                        uint32_t its_otime;
                        uint32_t its_rtime;
                        uint32_t its_ttime;
                } id_ts;
                
                struct {
                        iphdr_t idi_ip;  
                        unsigned char data[8];
                } id_ip;

                struct icmp_ra_addr id_radv;
                uint32_t   id_mask;
                uint8_t    id_data[1];
        } icmp_dun;

#define icmp_otime      icmp_dun.id_ts.its_otime
#define icmp_rtime      icmp_dun.id_ts.its_rtime
#define icmp_ttime      icmp_dun.id_ts.its_ttime
#define icmp_ip         icmp_dun.id_ip.idi_ip
#define icmp_radv       icmp_dun.id_radv
#define icmp_mask       icmp_dun.id_mask
#define icmp_data       icmp_dun.id_data
        
} icmphdr_t;







/*
 * IGMP header
 */

/*
 * Message types, including version number.
 */
#define IGMP_MEMBERSHIP_QUERY           0x11    /* membership query         */
#define IGMP_V1_MEMBERSHIP_REPORT       0x12    /* Ver. 1 membership report */
#define IGMP_V2_MEMBERSHIP_REPORT       0x16    /* Ver. 2 membership report */
#define IGMP_V2_LEAVE_GROUP             0x17    /* Leave-group message      */

typedef struct {
        uint8_t igmp_type;             /* IGMP type */
        uint8_t igmp_code;             /* routing code */
        uint16_t igmp_cksum;           /* checksum */
        struct in_addr igmp_group;      /* group address */
} igmphdr_t;











/*
 * TCP / IP options 
 */
/*
 * ip_hl is 4 bits long and is the number of 32 bits words
 * in the header including options :
 * so max ip_hl value is ((4 ^ 2) -1) = 15
 * 15 * 4 = 60. ( 4 is the number of bytes in one 32 bits word ).
 * 60 - 20 = 40 ( 20 == size of tcp / ip headers without options ).
 */
#define MAX_OPTS_LEN 40

/*
 * Value from rfc 1072, 1323, 1644, 1693.
 */
#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_MAXSEG 2
#define TCPOPT_WSCALE 3
#define TCPOPT_SACK_PERMITTED 4
#define TCPOPT_SACK 5
#define TCPOPT_ECHO 6
#define TCPOPT_ECHOREPLY 7
#define TCPOPT_TIMESTAMP 8
#define TCPOPT_POC_PERMITTED 9
#define TCPOPT_POC 10
#define TCPOPT_CC 11
#define TCPOPT_CCNEW 12
#define TCPOPT_CCECHO 13

#define TCPOLEN_EOL 1
#define TCPOLEN_NOP 1
#define TCPOLEN_MAXSEG 4
#define TCPOLEN_WSCALE 3
#define TCPOLEN_SACK_PERMITTED 2
#define TCPOLEN_ECHO 6
#define TCPOLEN_ECHOREPLY 6
#define TCPOLEN_TIMESTAMP 10
#define TCPOLEN_CC 6
#define TCPOLEN_CCNEW 6
#define TCPOLEN_CCECHO 6
#define TCPOLEN_POC_PERMITTED 2
#define TCPOLEN_POC 3

#define IPOPT_EOL               0
#define IPOPT_NOP               1
#define IPOPT_RR                7
#define IPOPT_TIMESTAMP         68
#define IPOPT_SECURITY          130
#define IPOPT_LSRR              131
#define IPOPT_LSRRE             132
#define IPOPT_SATID             136
#define IPOPT_SSRR              137
#define IPOPT_RA                148
