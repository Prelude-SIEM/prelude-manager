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
#include <libprelude/prelude-client-mgr.h>
#include <libprelude/prelude-message-buffered.h>
#include <libprelude/idmef-message-write.h>

#include "plugin-report.h"


typedef struct {
        prelude_client_mgr_t *parent_manager;
} relaying_plugin_t;



static prelude_msgbuf_t *msgbuf = NULL;



static prelude_msg_t *send_msgbuf(prelude_msgbuf_t *msgbuf)
{
        prelude_msg_t *msg = prelude_msgbuf_get_msg(msgbuf);
        prelude_client_mgr_t *mgr = prelude_msgbuf_get_data(msgbuf);
        
        prelude_client_mgr_broadcast(mgr, msg);
        prelude_msg_recycle(msg);
        
        return msg;
}



static int relaying_process(prelude_plugin_instance_t *pi, idmef_message_t *idmef)
{
        relaying_plugin_t *plugin = prelude_plugin_instance_get_data(pi);
        
        if ( ! msgbuf ) {
                msgbuf = prelude_msgbuf_new(0);
                if ( ! msgbuf )
                        return -1;

                prelude_msgbuf_set_callback(msgbuf, send_msgbuf);
                prelude_msgbuf_set_data(msgbuf, plugin->parent_manager);
        }
        
        idmef_write_message(msgbuf, idmef);
        prelude_msgbuf_mark_end(msgbuf);
        
        return 0;
}



static int relaying_activate(prelude_plugin_instance_t *pi, prelude_option_t *opt, const char *optarg)
{
        relaying_plugin_t *new;

        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        prelude_plugin_instance_set_data(pi, new);

        return 0;
}



static int relaying_set_manager(prelude_plugin_instance_t *pi, prelude_option_t *opt, const char *optarg)
{
        relaying_plugin_t *plugin = prelude_plugin_instance_get_data(pi);

        plugin->parent_manager = prelude_client_mgr_new(PRELUDE_CLIENT_TYPE_MANAGER_CHILDREN, optarg);
        if ( ! plugin->parent_manager )
                return -1;

        return 0;
}




prelude_plugin_generic_t *prelude_plugin_init(void)
{
        prelude_option_t *opt;
        static plugin_report_t plugin;
        
        opt = prelude_plugin_option_add(NULL, CLI_HOOK|CFG_HOOK, '0', "relaying",
                                        "Relaying plugin option", optionnal_argument,
                                        relaying_activate, NULL);

        prelude_plugin_set_activation_option((void *) &plugin, opt, NULL);

        prelude_plugin_option_add(opt, CLI_HOOK|CFG_HOOK, 'p', "parent-managers",
                                  "List of managers address:port pair where messages should be sent to",
                                  required_argument, relaying_set_manager, NULL);
        
        prelude_plugin_set_name(&plugin, "Relaying");
        prelude_plugin_set_author(&plugin, "Yoann Vandoorselaere");
        prelude_plugin_set_contact(&plugin, "yoann@prelude-ids.org");
        prelude_plugin_set_desc(&plugin, "Plugin that relay event to a parent manager");

        report_plugin_set_running_func(&plugin, relaying_process);

	return (void *) &plugin;
}
