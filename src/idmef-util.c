/*****
*
* Copyright (C) 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>
#include <netinet/in.h> /* for extract.h */

#include <libprelude/list.h>
#include <libprelude/prelude-log.h>
#include <libprelude/extract.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/prelude-ident.h>
#include <libprelude/idmef-tree-func.h>

#include "config.h"
#include "ntp.h"
#include "idmef-util.h"


static prelude_ident_t *alert_ident;
static prelude_ident_t *heartbeat_ident;


int idmef_ident_init(void) 
{
        alert_ident = prelude_ident_new(PRELUDE_MANAGER_CONFDIR"/alert.ident");
        if ( ! alert_ident ) {
                log(LOG_ERR, "couldn't initialize unique alert ident.\n");
                return -1;
        }

        heartbeat_ident = prelude_ident_new(PRELUDE_MANAGER_CONFDIR"/heartbeat.ident");
        if ( ! heartbeat_ident ) {
                log(LOG_ERR, "couldn't initialize unique heartbeat ident.\n");
                return -1;
        }
        
        return 0;
}


void idmef_ident_exit(void) 
{
        prelude_ident_destroy(alert_ident);
        prelude_ident_destroy(heartbeat_ident);        
}


void idmef_alert_get_ident(idmef_alert_t *alert) 
{
        alert->ident = prelude_ident_inc(alert_ident);
}



void idmef_heartbeat_get_ident(idmef_heartbeat_t *hb) 
{
        hb->ident = prelude_ident_inc(heartbeat_ident);
}



/*
 * Some of the code here was inspired from libidmef code.
 */

void idmef_get_ntp_timestamp(const idmef_time_t *time, char *outptr, size_t size)
{
        l_fp ts;
        struct timeval tv;
        unsigned ts_mask = TS_MASK;             /* defaults to 20 bits (us) */
        unsigned ts_roundbit = TS_ROUNDBIT;     /* defaults to 20 bits (us) */

        tv.tv_sec = time->sec;
        tv.tv_usec = time->usec;
        
        sTVTOTS(&tv, &ts);

        ts.l_ui += JAN_1970;                    /* make it time since 1900 */
        ts.l_uf += ts_roundbit;
        ts.l_uf &= ts_mask;

        snprintf(outptr, size, "0x%08lx.0x%08lx", (unsigned long) ts.l_ui, (unsigned long) ts.l_uf);
}



void idmef_get_timestamp(const idmef_time_t *time, char *outptr, size_t size) 
{
        struct tm *utc;
        
        /*
         * Convert from localtime to UTC.
         */
        utc = gmtime((const time_t *) &time->sec);

        /*
         * Format as the IDMEF draft tell us to.
         */
        /* strftime(outptr, size, "%Y-%m-%dT%H:%M:%S", utc); */
        strftime(outptr, size, "%Y-%m-%d%H:%M:%S", utc);
}




/**
 * idmef_additional_data_to_string:
 * @ad: An additional data object.
 * @out: A buffer where the output should be stored.
 * @size: Pointer to the size of the destination buffer.
 *
 * This function take care of converting the IDMEF AdditionalData data
 * member to a string suitable to be outputed in the IDMEF database.
 *
 * The provided buffer might not be used.
 * Uppon return, size will reflect the amount of size used in the buffer.
 *
 * Returns: NULL on error, a pointer to @buf if conversion succeed,
 * or a pointer to the actual data if no conversion is needed.
 */
const char *idmef_additional_data_to_string(const idmef_additional_data_t *ad, char *buf, size_t *size) 
{
        uint32_t out32;
        uint64_t out64;
        int ret = *size;
        
        switch (ad->type) {
                
        case byte:
                /*
                 * FIXME:
                 *
                 * from section 4.3.2.2 of the IDMEF specs:
                 *
                 * Any character defined by the ISO/IEC 10646 and Unicode standards may
                 * be included in an XML document by the use of a character reference.
                 *
                 * A character reference is started with the characters '&' and '#', and
                 * ended with the character ';'.  Between these characters, the
                 * character code for the character inserted.
                 *
                 * If the character code is preceded by an 'x' it is interpreted in
                 * hexadecimal (base 16), otherwise, it is interpreted in decimal (base
                 * 10).  For instance, the ampersand (&) is encoded as &#38; or &#x0026;
                 * and the less-than sign (<) is encoded as &#60; or &#x003C;.
                 *
                 * Any one-, two-, or four-byte character specified in the ISO/IEC 10646
                 * and Unicode standards can be included in a document using this
                 * technique.
                 */
                break;

        case character:
                ret = snprintf(buf, *size, "%c", *(const char *) ad->data);
                break;

        case integer:
                ret = extract_uint32_safe(&out32, ad->data, ad->dlen);
                if ( ret < 0 )
                        return NULL;
                
                ret = snprintf(buf, *size, "%d", out32);
                break;
                
        case ntpstamp:
                ret = extract_uint64_safe(&out64, ad->data, ad->dlen);
                if ( ret < 0 )
                        return NULL;
                
                ret = snprintf(buf, *size, "0x%08ux.0x%08ux",
                         ((const uint32_t *) &out64)[0],((const uint32_t *) &out64)[1]);
                break;

        case real:
                ret = extract_uint32_safe(&out32, ad->data, ad->dlen);
                if ( ret < 0 )
                        return NULL;
                
                ret = snprintf(buf, *size, "%f", (float) out32);
                break;

        case boolean:
        case date_time:
        case portlist:
        case string:
        case xml:
                ret = extract_string_safe((const char **) &buf, ad->data, ad->dlen);
                if ( ret < 0 )
                        return NULL;

                *size = ad->dlen;
                
                return buf;

        default:
                log(LOG_ERR, "Unknown data type: %d.\n", ad->type);
                return NULL;
        }

        /*
         * Since glibc 2.1 snprintf follow the C99 standard and return
         * the number of characters (excluding the trailibng '\0') which
         * would have been written to the final string if enought space
         * had been available.
         */
        if ( ret < *size )
                *size = ret;

        return buf;
}



/*
 * IDMEF enum -> string converter
 */
const char *idmef_additional_data_type_to_string(idmef_additional_data_type_t type)  
{
        static const char *tbl[] = {
                "string",
                "boolean", 
                "byte",
                "character",
                "date-time",
                "integer",
                "ntpstamps",
                "portlist",
                "real",
                "xml",
        };
        
        if ( type >= (sizeof(tbl) / sizeof(char *)) ) {
                log(LOG_ERR, "invalid additional data type requested.\n");
                return NULL;
        }

        return tbl[type];        
}





const char *idmef_classification_origin_to_string(idmef_classification_origin_t origin)  
{
        static const char *tbl[] = {
                "unknown",
                "bugtraqid",
                "cve",
                "vendor-specific",
        };

        if ( origin >= (sizeof(tbl) / sizeof(char *)) ) {
                log(LOG_ERR, "invalid classification origin requested.\n");
                return NULL;
        }

        return tbl[origin];  
}




const char *idmef_address_category_to_string(idmef_address_category_t category) 
{
        static const char *tbl[] = {
                "unknown",
                "atm",
                "e-mail",
                "lotus-notes",
                "mac",
                "sna",
                "vm",
                "ipv4-addr",
                "ipv4-addr-hex",
                "ipv4-net",
                "ipv4-net-mask",
                "ipv6-addr",
                "ipv6-addr-hex",
                "ipv6-net",
                "ipv6-net-mask",
        };

        if ( category >= (sizeof(tbl) / sizeof(char *)) ) {
                log(LOG_ERR, "invalid address category requested.\n");
                return NULL;
        }
        
        return tbl[category];
}





const char *idmef_node_category_to_string(idmef_node_category_t category) 
{
        static const char *tbl[] = {
                "unknown",
                "ads",
                "afs",
                "coda",
                "dfs",
                "dns",
                "hosts",
                "kerberos",
                "nds",
                "nis",
                "nisplus",
                "nt",
                "wfw",
        };

        if ( category >= (sizeof(tbl) / sizeof(char *)) ) {
                log(LOG_ERR, "invalid node category requested.\n");
                return NULL;
        }

        return tbl[category];
}



const char *idmef_user_category_to_string(idmef_user_category_t category) 
{
        static const char *tbl[] = {
                "unknown",
                "application",
                "os-device",
        };

        if ( category >= (sizeof(tbl) / sizeof(char *)) ) {
                log(LOG_ERR, "invalid user category requested.\n");
                return NULL;
        }
        
        return tbl[category];
}




const char *idmef_userid_type_to_string(idmef_userid_type_t type) 
{
        static const char *tbl[] = {
                "original-user",
                "current-user",
                "target-user",
                "user-privs",
                "current-group",
                "group-privs",
                "others-privs",
        };

        if ( type >= (sizeof(tbl) / sizeof(char *)) ) {
                log(LOG_ERR, "invalid userid type requested.\n");
                return NULL;
        }

        return tbl[type];
}



const char *idmef_source_spoofed_to_string(idmef_spoofed_t spoofed) 
{
        static const char *tbl[] = {
                "unknown",
                "yes",
                "no",
        };

        if ( spoofed >= (sizeof(tbl) / sizeof(char *)) ) {
                log(LOG_ERR, "invalid source spoofed requested.\n");
                return NULL;
        }

        return tbl[spoofed];
}



const char *idmef_target_decoy_to_string(idmef_spoofed_t decoy) 
{
        static const char *tbl[] = {
                "unknown",
                "yes",
                "no",
        };

        if ( decoy >= (sizeof(tbl) / sizeof(char *)) ) {
                log(LOG_ERR, "invalid target decoy requested.\n");
                return NULL;
        }

        return tbl[decoy];
}



const char *idmef_impact_severity_to_string(idmef_impact_severity_t severity) 
{
        static const char *tbl[] = {
                "NULL",
                "low",
                "medium",
                "high",
        };
        
        if ( severity >= (sizeof(tbl) / sizeof(char *)) ) {
                log(LOG_ERR, "invalid impact severity requested.\n");
                return NULL;
        }
        
        return tbl[severity];
}



const char *idmef_impact_completion_to_string(idmef_impact_completion_t completion) 
{
        static const char *tbl[] = {
                "NULL",
                "failed",
                "succeeded",
        };

        if ( completion >= (sizeof(tbl) / sizeof(char *)) ) {
                log(LOG_ERR, "invalid impact completion requested.\n");
                return NULL;
        }
        
        return tbl[completion];
}



const char *idmef_impact_type_to_string(idmef_impact_type_t type)
{
        static const char *tbl[] = {
                "other",
                "admin",
                "dos",
                "file",
                "recon",
                "user",
        };

        if ( type >= (sizeof(tbl) / sizeof(char *)) ) {
                log(LOG_ERR, "invalid impact type requested.\n");
                return NULL;
        }
        
        return tbl[type];
}



const char *idmef_linkage_category_to_string(idmef_linkage_category_t category) 
{
        static const char *tbl[] = {
                "NULL",
                "hard-link",
                "mount-point",
                "reparse-point",
                "shortcut",
                "stream",
                "symbolic-link",
        };

        if ( category >= (sizeof(tbl) / sizeof(char *)) ) {
                log(LOG_ERR, "invalid linkage category requested.\n");
                return NULL;
        }

        return tbl[category];
}



const char *idmef_file_category_to_string(idmef_file_category_t category) 
{
        static const char *tbl[] = {
                "NULL",
                "current",
                "original",
        };

        if ( category >= (sizeof(tbl) / sizeof(char *)) ) {
                log(LOG_ERR, "invalid file category requested.\n");
                return NULL;
        }
        
        return tbl[category];
}



const char *idmef_confidence_rating_to_string(idmef_confidence_rating_t rating) 
{
        static const char *tbl[] = {
                "numeric",
                "low",
                "medium",
                "high",
        };

        if ( rating >= (sizeof(tbl) / sizeof(char *)) ) {
                log(LOG_ERR, "invalid confidence rating requested.\n");
                return NULL;
        }
        
        return tbl[rating];
}


const char *idmef_action_category_to_string(idmef_action_category_t category)
{
        static const char *tbl[] = {
                "other",
                "block-installed",
                "notification-sent",
                "taken-offline",
        };

        if ( category >= (sizeof(tbl) / sizeof(char *)) ) {
                log(LOG_ERR, "invalid action category requested.\n");
                return NULL;
        }
        
        return tbl[category];
}
