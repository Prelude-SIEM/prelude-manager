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

#include "plugin-report.h"


prelude_plugin_generic_t *relaying_LTX_prelude_plugin_init(void);


typedef struct {
        prelude_connection_mgr_t *parent_manager;
} relaying_plugin_t;



static prelude_msgbuf_t *msgbuf = NULL;
extern prelude_client_t *manager_client;
extern prelude_option_t *manager_root_optlist;


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



static int relaying_activate(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err)
{
        relaying_plugin_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) 
                return prelude_error_from_errno(errno);
                
        prelude_plugin_instance_set_data(context, new);
        
        return 0;
}



static int relaying_set_manager(void *context, prelude_option_t *opt, const char *optarg, prelude_string_t *err)
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




static int relaying_get_manager(void *context, prelude_option_t *opt, prelude_string_t *out)
{
        relaying_plugin_t *plugin = prelude_plugin_instance_get_data(context);

        if ( ! plugin->parent_manager )
                return 0;

        prelude_string_sprintf(out, "%s", prelude_connection_mgr_get_connection_string(plugin->parent_manager));

        return 0;
}



prelude_plugin_generic_t *relaying_LTX_prelude_plugin_init(void)
{
        prelude_option_t *opt;
        static plugin_report_t plugin;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;
        
        opt = prelude_option_add(manager_root_optlist, hook, 0, "relaying",
                                 "Relaying plugin option", PRELUDE_OPTION_ARGUMENT_OPTIONAL,
                                 relaying_activate, NULL);

        prelude_plugin_set_activation_option((void *) &plugin, opt, NULL);

        prelude_option_add(opt, hook, 'p', "parent-managers",
                           "List of managers address:port pair where messages should be sent to",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, relaying_set_manager, relaying_get_manager);
        
        prelude_plugin_set_name(&plugin, "Relaying");
        prelude_plugin_set_author(&plugin, "Yoann Vandoorselaere");
        prelude_plugin_set_contact(&plugin, "yoann@prelude-ids.org");
        prelude_plugin_set_desc(&plugin, "Plugin that relay event to a parent manager");

        report_plugin_set_running_func(&plugin, relaying_process);

	return (void *) &plugin;
}
