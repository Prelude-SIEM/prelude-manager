/*****
*
* Copyright (C) 1999,2000, 2002, 2003 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <sys/types.h>
#include <netinet/in.h>

#include <libprelude/prelude-inttypes.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-strbuf.h>
#include <libprelude/extract.h>

#include "nethdr.h"
#include "optparse.h"

#define MAX_OPTS_LEN 40

#ifndef IPOPT_SECURITY
 #define IPOPT_SECURITY 130
#endif

#ifndef IPOPT_RA
 #define IPOPT_RA 148
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


/*
 * Dump tcp options and their value.
 */
static int tcp_optval(prelude_strbuf_t *obuf, unsigned char *optbuf, int opt, size_t datalen) 
{
        int i;
        
        switch (opt) {
                
        case TCPOPT_MAXSEG:
                prelude_strbuf_sprintf(obuf, "mss %u", extract_uint16(optbuf));
                break;
                
        case TCPOPT_WSCALE:
                prelude_strbuf_sprintf(obuf, "wscale %u", *optbuf);
                break;

        case TCPOPT_SACK_PERMITTED:
                prelude_strbuf_sprintf(obuf, "sackOK");
                break;
                
        case TCPOPT_SACK:
                if ( datalen % 8 != 0 )
                        prelude_strbuf_sprintf(obuf, "malformed sack");
                else {
                        uint32_t s, e;

                        prelude_strbuf_sprintf(obuf, "sack %d", datalen / 8);
                        for ( i = 0; i < datalen; i += 8 ) {
                                s = extract_uint32(optbuf + i);
                                e = extract_uint32(optbuf + i + 4);
                        }
                }
                break;
                                
        case TCPOPT_ECHO:
                prelude_strbuf_sprintf(obuf, "echo %u", extract_uint32(optbuf));
                break;
                              
        case TCPOPT_ECHOREPLY:
                prelude_strbuf_sprintf(obuf, "echoreply %u", extract_uint32(optbuf));
                break;

        case TCPOPT_TIMESTAMP:
                prelude_strbuf_sprintf(obuf, "timestamp %u %u",
                                       extract_uint32(optbuf), extract_uint32(optbuf + 4));
                break;
                
        case TCPOPT_CC:
                prelude_strbuf_sprintf(obuf, "cc %u", extract_uint32(optbuf));
                break;

        case TCPOPT_CCNEW:
                prelude_strbuf_sprintf(obuf, "ccnew %u", extract_uint32(optbuf));
                break;
                
        case TCPOPT_CCECHO:
                prelude_strbuf_sprintf(obuf, "ccecho %u", extract_uint32(optbuf));
                break;

        default:
                prelude_strbuf_sprintf(obuf, "opt-%d:", opt);
                break;

        }

        return -1;
}



/*
 * Dump Ip options and their value.
 */
static int ip_optval(prelude_strbuf_t *obuf, unsigned char *optbuf, int opt, size_t datalen)
{
        int optlen = datalen + 2;

        switch (opt) {
                
        case IPOPT_RR:
                prelude_strbuf_sprintf(obuf, "rr");
                break;

        case IPOPT_EOL:
                prelude_strbuf_sprintf(obuf, "eol");
                break;

        case IPOPT_NOP:
                prelude_strbuf_sprintf(obuf, "nop");
                break;
                
        case IPOPT_TIMESTAMP:
                prelude_strbuf_sprintf(obuf, "ts");
                break;
                
        case IPOPT_SECURITY:
                prelude_strbuf_sprintf(obuf, "security{%d}", optlen);
                break;
                
        case IPOPT_LSRR:
                prelude_strbuf_sprintf(obuf, "lsrr");
                break;

        case IPOPT_LSRRE:
                prelude_strbuf_sprintf(obuf, "lsrre");
                break;
                
        case IPOPT_SSRR:
                prelude_strbuf_sprintf(obuf, "ssrr");
                break;

        case IPOPT_SATID:
                prelude_strbuf_sprintf(obuf, "satid");
                break;

        case IPOPT_RA:
                if (datalen != 2)
                        prelude_strbuf_sprintf(obuf, "ra{%d}", optlen);
                else if (optbuf[0] || optbuf[1])
                        prelude_strbuf_sprintf(obuf, "ra{%d.%d}", optbuf[0], optbuf[1]);
                break;
                
        default:
                prelude_strbuf_sprintf(obuf, "ipopt-%d{%d}", opt, optlen);
                break;
        }
        
        return -1;
}



/*
 * Verify if the option 'opt' is one of
 * the 1 byte only option (nop || eol).
 */
static int is_1byte_option(prelude_strbuf_t *obuf, int opt) 
{
        if ( opt == TCPOPT_NOP ) {
                prelude_strbuf_sprintf(obuf, "nop");
                return 0;
        }

        else if (opt == TCPOPT_EOL) {
                prelude_strbuf_sprintf(obuf, "eol");
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
static int is_option_valid(prelude_strbuf_t *obuf, unsigned char *optbuf, size_t optlen, size_t totlen) 
{        
        if ( optlen < 2 ) {
                prelude_strbuf_sprintf(obuf, "options is not \"nop\" or \"eol\" so option len (%d) "
                                       "should be >= 2.", optlen);
                return -1;
        }
                
        if ( optlen > totlen ) {
                prelude_strbuf_sprintf(obuf, "option len (%d) is > remaining total options len (%d).",
                                       optlen, totlen);
                return -1;
        }

        /*
         * This check should never be reached because
         * of the optlen > totlen test... use an assert.
         */
        assert( (optbuf + (optlen - 2)) <= (optbuf + (totlen - 2)) );

        return 0;
}



/*
 * Verify that our total options len is big enough
 * to contain a len byte, which mean totlen must be
 * >= 2 (1 byte for optkind, and 1 for optlen).
 */
static int is_len_byte_ok(prelude_strbuf_t *obuf, size_t totlen) 
{
        if ( totlen < 2 ) {
                prelude_strbuf_sprintf(obuf, "not \"nop\" or \"eol\", "
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
static int walk_options(prelude_strbuf_t *obuf, unsigned char *optbuf, size_t totlen,
                        int (*optval)(prelude_strbuf_t *obuf, unsigned char *optbuf, int opt, size_t optlen)) 
{
        int opt, ret;
        size_t optlen, origlen = totlen;
        
        do {
                opt = *optbuf++;

                if ( is_1byte_option(obuf, opt) == 0 )
                        totlen -= 1;
                else {
                        if ( is_len_byte_ok(obuf, totlen) < 0 )
                                return origlen - totlen;

                        optlen = *optbuf++;
                        
                        ret = is_option_valid(obuf, optbuf, optlen, totlen);
                        if ( ret < 0 )
                                return origlen - (totlen - 2);
                        
                        optval(obuf, optbuf, opt, optlen - 2);

                        totlen -= optlen;
                        optbuf += optlen - 2;

                }
                
                assert(totlen >= 0);
                
                if ( totlen > 0 )
                        prelude_strbuf_sprintf(obuf, ",");
                
        } while ( totlen != 0 );

        return origlen - totlen;
}



/*
 *
 */
int tcp_optdump(prelude_strbuf_t *obuf, unsigned char *optbuf, size_t optlen)
{
        if ( optlen > MAX_OPTS_LEN ) {
                prelude_strbuf_sprintf(obuf, "total option len (%d) > maximum option len (%d).",
                                       optlen, MAX_OPTS_LEN);
                return -1;
        }
        
        return walk_options(obuf, optbuf, optlen, tcp_optval);
}



/*
 *
 */
int ip_optdump(prelude_strbuf_t *obuf, unsigned char *optbuf, size_t optlen)
{
        if ( optlen > MAX_OPTS_LEN ) {
                prelude_strbuf_sprintf(obuf, "total option len (%d) > maximum option len (%d).",
                                       optlen, MAX_OPTS_LEN);
                return -1;
        }

        return walk_options(obuf, optbuf, optlen, ip_optval);
}














