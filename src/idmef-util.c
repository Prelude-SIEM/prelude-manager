#include <stdio.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>

#include <libprelude/list.h>
#include <libprelude/prelude-log.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/prelude-ident.h>

#include "config.h"
#include "ntp.h"
#include "idmef-util.h"


static prelude_ident_t *alert_ident;


int idmef_ident_init(void) 
{
        alert_ident = prelude_ident_new(PRELUDE_MANAGER_CONFDIR"/alert.ident");
        if ( ! alert_ident ) {
                log(LOG_ERR, "couldn't initialize unique alert ident.\n");
                return -1;
        }

        return 0;
}


void idmef_ident_exit(void) 
{
        prelude_ident_destroy(alert_ident);
}


void idmef_alert_get_ident(idmef_alert_t *alert) 
{
        alert->ident = prelude_ident_inc(alert_ident);
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




/*
 * IDMEF enum -> string converter
 */
const char *idmef_additional_data_type_to_string(idmef_additional_data_type_t type)  
{
        static const char *tbl[] = {
                "string",
                "byte",
                "character",
                "date-time",
                "integer",
                "ntpstamps",
                "portlist",
                "real",
                "boolean",
                "xml",
        };

        /*
         * Assert on read overflow.
         */
        assert( type < (sizeof(tbl) / sizeof(void *)) );

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
        
        /*
         * Assert on read overflow.
         */
        assert( origin < (sizeof(tbl) / sizeof(void *)) );

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
        

        assert( category < (sizeof(tbl) / sizeof(void *)) );
        
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
                "kerberos",
                "nds",
                "nis",
                "nisplus",
                "nt",
                "wfw",
        };

        assert( category < (sizeof(tbl) / sizeof(void *)) );

        return tbl[category];
}



const char *idmef_user_category_to_string(idmef_user_category_t category) 
{
        static const char *tbl[] = {
                "unknown",
                "application",
                "os-device",
        };

        assert( category < (sizeof(tbl) / sizeof(void *)) );

        return tbl[category];
}




const char *idmef_userid_type_to_string(idmef_userid_type_t type) 
{
        static const char *tbl[] = {
                "current-user",
                "original-user",
                "target-user",
                "user-privs",
                "current-group",
                "group-privs",
        };
        
        assert( type < (sizeof(tbl) / sizeof(void *)) );

        return tbl[type];
}



const char *idmef_source_spoofed_to_string(idmef_spoofed_t spoofed) 
{
        static const char *tbl[] = {
                "unknown",
                "yes",
                "no",
        };

        assert( spoofed < (sizeof(tbl) / sizeof(void *)) );

        return tbl[spoofed];
}



const char *idmef_target_decoy_to_string(idmef_spoofed_t decoy) 
{
        static const char *tbl[] = {
                "unknown",
                "yes",
                "no",
        };

        assert( decoy < (sizeof(tbl) / sizeof(void *)) );

        return tbl[decoy];
}
