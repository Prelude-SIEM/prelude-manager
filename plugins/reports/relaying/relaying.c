/*****
*
* Copyright (C) 2004 Yoann Vandoorselaere <yoann@mandrakesoft.com>
*
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

#include <libprelude/idmef.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-plugin.h>
#include <libprelude/prelude-client.h>
#include <libprelude/idmef-message-write.h>
#include <libprelude/prelude-error.h>

#include "plugin-report.h"


int relaying_LTX_manager_plugin_init(prelude_plugin_generic_t **plugin, void *data);


typedef struct {
        prelude_connection_mgr_t *parent_manager;
} relaying_plugin_t;



static prelude_msgbuf_t *msgbuf = NULL;
extern prelude_client_t *manager_client;



static int send_msgbuf(prelude_msgbuf_t *msgbuf, prelude_msg_t *msg)
{
        prelude_connection_mgr_t *mgr = prelude_msgbuf_get_data(msgbuf);
        
        prelude_connection_mgr_broadcast(mgr, msg);
                
        return 0;
}



static int relaying_process(prelude_plugin_instance_t *pi, idmef_message_t *idmef)
{
        int ret;
        relaying_plugin_t *plugin = prelude_plugin_instance_get_data(pi);

        if ( ! plugin->parent_manager )
                return 0;
        
        if ( ! msgbuf ) {
                ret = prelude_msgbuf_new(&msgbuf);
                if ( ret < 0 )
                        return ret;

                prelude_msgbuf_set_callback(msgbuf, send_msgbuf);
                prelude_msgbuf_set_data(msgbuf, plugin->parent_manager);
        }
        
        idmef_message_write(idmef, msgbuf);
        prelude_msgbuf_mark_end(msgbuf);
        
        return 0;
}



static int relaying_activate(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        relaying_plugin_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) 
                return prelude_error_from_errno(errno);
                
        prelude_plugin_instance_set_data(context, new);
        
        return 0;
}



static int relaying_set_manager(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        int ret;
        prelude_client_profile_t *cp;
        relaying_plugin_t *plugin = prelude_plugin_instance_get_data(context);

        if ( ! plugin->parent_manager ) {
                cp = prelude_client_get_profile(manager_client);
                
                ret = prelude_connection_mgr_new(&plugin->parent_manager, cp, PRELUDE_CONNECTION_CAPABILITY_CONNECT);
                if ( ! plugin->parent_manager )
                        return ret;

                prelude_connection_mgr_set_flags(plugin->parent_manager, PRELUDE_CONNECTION_MGR_FLAGS_RECONNECT);
        }
                
        ret = prelude_connection_mgr_set_connection_string(plugin->parent_manager, optarg);
        if ( ret < 0 )
                return ret;

        ret = prelude_connection_mgr_init(plugin->parent_manager);
        if ( ret < 0 )
                return ret;

        return 0;
}




static int relaying_get_manager(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        relaying_plugin_t *plugin = prelude_plugin_instance_get_data(context);

        if ( ! plugin->parent_manager )
                return 0;

        prelude_string_sprintf(out, "%s", prelude_connection_mgr_get_connection_string(plugin->parent_manager));

        return 0;
}



int relaying_LTX_manager_plugin_init(prelude_plugin_generic_t **plugin, void *rootopt)
{
        int ret;
        prelude_option_t *opt;
        static plugin_report_t relaying_plugin;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;
        
        ret = prelude_option_add(rootopt, &opt, hook, 0, "relaying",
                                 "Relaying plugin option", PRELUDE_OPTION_ARGUMENT_OPTIONAL,
                                 relaying_activate, NULL);
        if ( ret < 0 )
                return ret;
        
        prelude_plugin_set_activation_option((void *) &relaying_plugin, opt, NULL);

        ret = prelude_option_add(opt, NULL, hook, 'p', "parent-managers",
                                 "List of managers address:port pair where messages should be sent to",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, relaying_set_manager, relaying_get_manager);
        if ( ret < 0 )
                return ret;
        
        prelude_plugin_set_name(&relaying_plugin, "Relaying");
        prelude_plugin_set_author(&relaying_plugin, "Yoann Vandoorselaere");
        prelude_plugin_set_contact(&relaying_plugin, "yoann@prelude-ids.org");
        prelude_plugin_set_desc(&relaying_plugin, "Plugin that relay event to a parent manager");

        report_plugin_set_running_func(&relaying_plugin, relaying_process);

        *plugin = (void *) &relaying_plugin;
        
	return 0;
}
