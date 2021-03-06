/*****
*
* Copyright (C) 2004-2020 CS GROUP - France. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
*
* This file is part of the Prelude-Manager program.
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
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
*****/

#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

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


extern prelude_client_t *manager_client;



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

        idmef_heartbeat_set_analyzer(heartbeat, idmef_analyzer_ref(prelude_client_get_analyzer(manager_client)), IDMEF_LIST_PREPEND);

        return 0;
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

        idmef_alert_set_analyzer(alert, idmef_analyzer_ref(prelude_client_get_analyzer(manager_client)), IDMEF_LIST_PREPEND);

        return 0;
}




static int handle_proprietary_msg(prelude_msg_t *msg, idmef_message_t *idmef, void *buf, uint32_t len)
{
        int ret;
        uint8_t tag = 0;

        ret = prelude_extract_uint8_safe(&tag, buf, len);
        if ( ret < 0 )
                return ret;

        ret = decode_plugins_run(tag, msg, idmef);
        if ( ret < 0 )
                return ret;

        return 0;
}




int pmsg_to_idmef(idmef_message_t **idmef, prelude_msg_t *msg)
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        prelude_string_t *tmp;

        ret = idmef_message_new(idmef);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating idmef-message");
                return ret;
        }

        while ( (ret = prelude_msg_get(msg, &tag, &len, &buf)) == 0 ) {

                if ( tag == IDMEF_MSG_ALERT_TAG )
                        ret = handle_alert_msg(msg, *idmef);

                else if ( tag == IDMEF_MSG_HEARTBEAT_TAG )
                        ret = handle_heartbeat_msg(msg, *idmef);

                else if ( tag == IDMEF_MSG_OWN_FORMAT )
                        ret = handle_proprietary_msg(msg, *idmef, buf, len);

                else if ( tag == IDMEF_MSG_MESSAGE_VERSION ) {
                        /*
                         * we use len - 1 since len is supposed to include \0 to avoid making a dup.
                         */
                        ret = prelude_string_new_ref_fast(&tmp, buf, len - 1);
                        if ( ret < 0 ) {
                                prelude_perror(ret, "could not extract version string: %s", prelude_strerror(ret));
                                break;
                        }

                        idmef_message_set_version(*idmef, tmp);
                }

                else if ( tag == IDMEF_MSG_END_OF_TAG )
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
