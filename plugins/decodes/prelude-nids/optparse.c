/*****
*
* Copyright (C) 1999,2000, 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <assert.h>
#include <stdarg.h>
#include <inttypes.h>

#include <libprelude/prelude-log.h>

#include "nethdr.h"
#include "optparse.h"

#define MAX_OPTS_LEN 40

#ifndef IPOPT_SECURITY
 #define IPOPT_SECURITY 130
#endif

#ifndef IPOPT_RA
 #define IPOPT_RA 148
#endif

#ifdef NEED_ALIGNED_ACCESS
#define EXTRACT_16BITS(p) \
        ((u_int16_t)*((const u_int8_t *)(p) + 0) << 8 | \
        (u_int16_t)*((const u_int8_t *)(p) + 1))
#define EXTRACT_32BITS(p) \
        ((u_int32_t)*((const u_int8_t *)(p) + 0) << 24 | \
        (u_int32_t)*((const u_int8_t *)(p) + 1) << 16 | \
        (u_int32_t)*((const u_int8_t *)(p) + 2) << 8 | \
        (u_int32_t)*((const u_int8_t *)(p) + 3))
#else

#define EXTRACT_16BITS(p) \
        ((u_int16_t)ntohs(*(const u_int16_t *)(p)))
#define EXTRACT_32BITS(p) \
        ((u_int32_t)ntohl(*(const u_int32_t *)(p)))
#endif


/*
 * From rfc793 :
 * Options may occupy space at the end of the TCP header and are a
 * multiple of 8 bits in length.  All options are included in the
 * checksum.  An option may begin on any octet boundary.  There are two
 * cases for the format of an option:
 *
 *  Case 1:  A single octet of option-kind.
 *
 *  Case 2:  An octet of option-kind, an octet of option-length, and
 *           the actual option-data octets.
 *
 * The option-length counts the two octets of option-kind and
 * option-length as well as the option-data octets.
 *
 * Note that the list of options may be shorter than the data offset
 * field might imply.  The content of the header beyond the
 * End-of-Option option must be header padding (i.e., zero).
 *
 * A TCP must implement all options.
 */


static char *buf;
static size_t bsize;


static void printopt(const char *comment, ...) 
{
        int ret;
        va_list va;

        va_start(va, comment);
        ret = vsnprintf(buf, bsize, comment, va);
        va_end(va);
        
        buf += ret;
        bsize -= ret;
}



/*
 * Dump tcp options and their value.
 */
static int tcp_optval(unsigned char *optbuf, int opt, int datalen) 
{
        int i;
        
        switch (opt) {
                
        case TCPOPT_MAXSEG:
                printopt("mss %u", EXTRACT_16BITS(optbuf));
                break;
                
        case TCPOPT_WSCALE:
                printopt("wscale %u", *optbuf);
                break;

        case TCPOPT_SACK_PERMITTED:
                printopt("sackOK");
                break;
                
        case TCPOPT_SACK:
                if ( datalen % 8 != 0 )
                        printopt("malformed sack");
                else {
                        uint32_t s, e;

                        printopt("sack %d", datalen / 8 );
                        for ( i = 0; i < datalen; i += 8 ) {
                                s = EXTRACT_32BITS(optbuf + i);
                                e = EXTRACT_32BITS(optbuf + i + 4);
                        }
                        
                }
                break;
                                
        case TCPOPT_ECHO:
                printopt("echo %u", EXTRACT_32BITS(optbuf));
                break;
                              
        case TCPOPT_ECHOREPLY:
                printopt("echoreply %u", EXTRACT_32BITS(optbuf));
                break;

        case TCPOPT_TIMESTAMP:
                printopt("timestamp %u %u",
                         EXTRACT_32BITS(optbuf), EXTRACT_32BITS(optbuf + 4));
                break;
                
        case TCPOPT_CC:
                printopt("cc %u", EXTRACT_32BITS(optbuf));
                break;

        case TCPOPT_CCNEW:
                printopt("ccnew %u", EXTRACT_32BITS(optbuf));
                break;
                
        case TCPOPT_CCECHO:
                printopt("ccecho %u", EXTRACT_32BITS(optbuf));
                break;

        default:
                printopt("opt-%d:", opt);
                break;

        }

        return -1;
}



/*
 * Dump Ip options and their value.
 */
static int ip_optval(unsigned char *optbuf, int opt, int datalen)
{
        int optlen = datalen + 2;

#warning "support for dumping the following options should be added : ts, rr, srr, lsrr"

        switch (opt) {
                                
        case IPOPT_TIMESTAMP:
                printopt("ts");
                break;
                
        case IPOPT_SECURITY:
                printopt("security{%d}", optlen);
                break;
                
        case IPOPT_RR:
                printopt("rr");
                break;
                
        case IPOPT_SSRR:
                printopt("ssrr");
                break;
                
        case IPOPT_LSRR:
                printopt("lsrr");
                break;

        case IPOPT_RA:
                if (datalen != 2)
                        printopt("ra{%d}", optlen);
                else if (optbuf[0] || optbuf[1])
                        printopt("ra{%d.%d}", optbuf[0], optbuf[1]);
                break;
                
        default:
                printopt("ipopt-%d{%d}", opt, optlen);
                break;
        }
        
        return -1;
}



/*
 * Verify if the option 'opt' is one of
 * the 1 byte only option (nop || eol).
 */
static int is_1byte_option(int opt) 
{
        if ( opt == TCPOPT_NOP ) {
                printopt("nop");
                return 0;
        }

        else if (opt == TCPOPT_EOL) {
                printopt("eol");
                return 0;
        }

        return -1;
}



/*
 * Verify that an option is valid :
 * - verify that this option len is > 2 bytes.
 * - verify that this option len is < than our total option len.
 * - do some bound check on our option buffer, to avoid going out of bound.
 */
static int is_option_valid(unsigned char *optbuf, int optlen, int totlen) 
{        
        if ( optlen < 2 ) {
                printopt("options is not \"nop\" or \"eol\" so option len (%d) "
                         "should be >= 2.", optlen);
                return -1;
        }
                
        if ( optlen > totlen ) {
                printopt("option len (%d) is > remaining total options len (%d).",
                         optlen, totlen);
                return -1;
        }

        /*
         * This check should never be reached because
         * of the optlen > totlen test.
         */
        if ( (optbuf + (optlen - 2)) > (optbuf + (totlen - 2) ) ) {
                printopt("options buffer seem to be truncated (%p > %p).",
                         (optbuf + (optlen - 2)),  (optbuf + (totlen - 2)));
                return -1;
        }

        return 0;
}



/*
 * Verify that our total options len is big enough
 * to contain a len byte, which mean totlen must be
 * >= 2 (1 byte for optkind, and 1 for optlen).
 */
static int is_len_byte_ok(int totlen) 
{
        if ( totlen < 2 ) {
                printopt("not \"nop\" or \"eol\", "
                         "but no space remaining for option len byte"
                         "in option buffer.");
                return -1;
        }
        
        return 0;
}



/*
 * Walk options in 'optbuf' of total len 'totlen',
 * the callback function optval should point on a function
 * printing tcp or ip options, depending on the kind of header
 * theses options are from.
 */
static int walk_options(unsigned char *optbuf, int totlen,
                        int (*optval)(unsigned char *optbuf, int opt, int optlen)) 
{
        int opt, optlen, ret;
        
        do {
                opt = *optbuf++;

                if ( is_1byte_option(opt) == 0 )
                        totlen -= 1;
                else {
                        if ( is_len_byte_ok(totlen) < 0 )
                                return -1;

                        optlen = *optbuf++;
                        
                        ret = is_option_valid(optbuf, optlen, totlen);
                        if ( ret < 0 )
                                return -1;
                        
                        optval(optbuf, opt, optlen - 2);
                        totlen -= optlen;
                        optbuf += optlen - 2;

                }
                
                assert(totlen >= 0);
                
                if ( totlen > 0 )
                        printopt(",");
                
        } while ( totlen != 0 );

        return 0;
}



/*
 *
 */
const char *tcp_optdump(unsigned char *optbuf, size_t optlen)
{
        static char buffer[1024];
        
        buf = buffer;
        bsize = sizeof(buffer);
        
        if ( optlen > MAX_OPTS_LEN ) {
                printopt("total option len (%d) > maximum option len (%d).",
                         optlen, MAX_OPTS_LEN);
                return buffer;
        }
        
        walk_options(optbuf, optlen, tcp_optval);

        return buffer;
}



/*
 *
 */
const char *ip_optdump(unsigned char *optbuf, size_t optlen)
{
        static char buffer[1024];
        
        buf = buffer;
        bsize = sizeof(buffer);

        if ( optlen > MAX_OPTS_LEN ) {
                printopt("total option len (%d) > maximum option len (%d).",
                         optlen, MAX_OPTS_LEN);
                return buffer;
        }

        walk_options(optbuf, optlen, ip_optval);
        
        return buffer;
}














