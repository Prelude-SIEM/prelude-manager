/*****
*
* Copyright (C) 2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>

#include <libprelude/idmef.h>
#include <libprelude/prelude-log.h>
#include <libprelude/idmef-message-id.h>
#include <libprelude/idmef-message-read.h>
#include <libprelude/prelude-ident.h>
#include <libprelude/prelude-client.h>
#include <libprelude/prelude-error.h>
#include <libprelude/prelude-extract.h>

#include "decode-plugins.h"
#include "pmsg-to-idmef.h"
#include "config.h"


#define MANAGER_MODEL "Prelude Manager"
#define MANAGER_CLASS "Manager"
#define MANAGER_MANUFACTURER "The Prelude Team http://www.prelude-ids.org"



extern prelude_client_t *manager_client;




static int fill_local_analyzer_infos(idmef_analyzer_t *analyzer)
{
        idmef_analyzer_t *next, *local;
        
        if ( ! analyzer )
                return -1;
        
        do {
                next = idmef_analyzer_get_analyzer(analyzer);
                if ( ! next ) {
                        local = idmef_analyzer_ref(prelude_client_get_analyzer(manager_client));
                        idmef_analyzer_set_analyzer(analyzer, local);
                }
                
                analyzer = next;

        } while ( next );

        return 0;
}




static int get_msg_time(prelude_msg_t *msg, idmef_time_t *create_time, idmef_time_t **ret)
{
        int retval;
        struct timeval tv;

        if ( ! create_time )
                return -1;
        
        prelude_msg_get_time(msg, &tv);
        
        retval = idmef_time_new(ret);
        if ( retval < 0 )
                return retval;

        idmef_time_set_sec(*ret, tv.tv_sec);
        idmef_time_set_usec(*ret, tv.tv_usec);
	idmef_time_set_gmt_offset(*ret, idmef_time_get_gmt_offset(create_time));
        
        return retval;
}




static int handle_heartbeat_msg(prelude_msg_t *msg, idmef_message_t *idmef)
{
        int ret;
        idmef_time_t *analyzer_time;
        idmef_heartbeat_t *heartbeat;
        
        ret = idmef_message_new_heartbeat(idmef, &heartbeat);
        if ( ret < 0 )
                return ret;

        ret = idmef_heartbeat_read(heartbeat, msg);
        if ( ret < 0 ) 
                return ret;
        
        if ( ! idmef_heartbeat_get_analyzer_time(heartbeat) ) {
                ret = get_msg_time(msg, idmef_heartbeat_get_create_time(heartbeat), &analyzer_time);
                if ( ret < 0 )
                        return ret;
                
                idmef_heartbeat_set_analyzer_time(heartbeat, analyzer_time);
        }

        return fill_local_analyzer_infos(idmef_heartbeat_get_analyzer(heartbeat));
}




static int handle_alert_msg(prelude_msg_t *msg, idmef_message_t *idmef)
{
        int ret;
        idmef_alert_t *alert;
        idmef_time_t *analyzer_time;
        
        ret = idmef_message_new_alert(idmef, &alert);
        if ( ret < 0 )
                return ret;

        ret = idmef_alert_read(alert, msg);
        if ( ret < 0 )
                return ret;
        
        if ( ! idmef_alert_get_analyzer_time(alert) ) {
                ret = get_msg_time(msg, idmef_alert_get_create_time(alert), &analyzer_time);
                if ( ret < 0 )
                        return ret;
                
                idmef_alert_set_analyzer_time(alert, analyzer_time);
        }       
        
        return fill_local_analyzer_infos(idmef_alert_get_analyzer(alert));
}




static int handle_proprietary_msg(prelude_msg_t *msg, idmef_message_t *idmef, void *buf, uint32_t len)
{
        int ret;
        uint8_t tag;
        
        ret = prelude_extract_uint8_safe(&tag, buf, len);
        if ( ret < 0 )
                return -1;
                        
        ret = decode_plugins_run(tag, msg, idmef);
        if ( ret < 0 )
                return -1;

        return 0;
}




int pmsg_to_idmef(idmef_message_t **idmef, prelude_msg_t *msg) 
{
	int ret;
	void *buf;
	uint8_t tag;
	uint32_t len;
        
	ret = idmef_message_new(idmef);
	if ( ret < 0 ) {
                prelude_perror(ret, "error creating idmef-message");
                return ret;
        }

        while ( (ret = prelude_msg_get(msg, &tag, &len, &buf)) == 0 ) {
                
                if ( tag == MSG_ALERT_TAG ) 
			ret = handle_alert_msg(msg, *idmef);

                else if ( tag == MSG_HEARTBEAT_TAG ) 
                        ret = handle_heartbeat_msg(msg, *idmef);

                else if ( tag == MSG_OWN_FORMAT )
                        ret = handle_proprietary_msg(msg, *idmef, buf, len);

                else if ( tag == MSG_END_OF_TAG )
                        continue;
                
                else prelude_log(PRELUDE_LOG_ERR, "unknown IDMEF tag: %d.\n", tag);
                        
                if ( ret < 0 )
                        break;
        }
        
        if ( prelude_error_get_code(ret) == PRELUDE_ERROR_EOF )
                return 0;

        prelude_log(PRELUDE_LOG_INFO, "%s: error reading IDMEF message: %s.\n", prelude_strsource(ret), prelude_strerror(ret));
        idmef_message_destroy(*idmef);
                
        return ret;
}
