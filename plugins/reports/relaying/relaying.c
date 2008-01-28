/*****
*
* Copyright (C) 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

#include "config.h"
#include "libmissing.h"

#include <stdio.h>
#include <stdlib.h>

#include "prelude-manager.h"


int relaying_LTX_prelude_plugin_version(void);
int relaying_LTX_manager_plugin_init(prelude_plugin_entry_t *plugin, void *data);


typedef struct {
        prelude_connection_pool_t *conn_pool;
} relaying_plugin_t;



static prelude_msgbuf_t *msgbuf = NULL;
extern prelude_client_t *manager_client;



static int send_msgbuf(prelude_msgbuf_t *msgbuf, prelude_msg_t *msg)
{
        prelude_connection_pool_t *pool = prelude_msgbuf_get_data(msgbuf);

        prelude_connection_pool_broadcast(pool, msg);

        return 0;
}



static int relaying_process(prelude_plugin_instance_t *pi, idmef_message_t *idmef)
{
        int ret;
        relaying_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        if ( ! plugin->conn_pool )
                return 0;

        if ( ! msgbuf ) {
                ret = prelude_msgbuf_new(&msgbuf);
                if ( ret < 0 )
                        return ret;

                prelude_msgbuf_set_callback(msgbuf, send_msgbuf);
        }

        prelude_msgbuf_set_data(msgbuf, plugin->conn_pool);

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

        prelude_plugin_instance_set_plugin_data(context, new);

        return 0;
}



static int relaying_set_manager(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        int ret;
        prelude_client_profile_t *cp;
        relaying_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);

        if ( ! plugin->conn_pool ) {
                cp = prelude_client_get_profile(manager_client);

                ret = prelude_connection_pool_new(&plugin->conn_pool, cp, PRELUDE_CONNECTION_PERMISSION_IDMEF_WRITE);
                if ( ! plugin->conn_pool )
                        return ret;

                prelude_connection_pool_set_flags(plugin->conn_pool, prelude_connection_pool_get_flags(plugin->conn_pool)
                                                  | PRELUDE_CONNECTION_POOL_FLAGS_RECONNECT);
                prelude_client_set_flags(manager_client, prelude_client_get_flags(manager_client) | PRELUDE_CLIENT_FLAGS_ASYNC_SEND);
        }

        ret = prelude_connection_pool_set_connection_string(plugin->conn_pool, optarg);
        if ( ret < 0 )
                return ret;

        ret = prelude_connection_pool_init(plugin->conn_pool);
        if ( ret < 0 )
                return ret;

        return 0;
}




static int relaying_get_manager(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        relaying_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);

        if ( ! plugin->conn_pool )
                return 0;

        prelude_string_sprintf(out, "%s", prelude_connection_pool_get_connection_string(plugin->conn_pool));

        return 0;
}



static void relaying_destroy(prelude_plugin_instance_t *pi, prelude_string_t *out)
{
        relaying_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        if ( plugin->conn_pool )
                prelude_connection_pool_destroy(plugin->conn_pool);

        free(plugin);
}



int relaying_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *rootopt)
{
        int ret;
        prelude_option_t *opt;
        static manager_report_plugin_t relaying_plugin;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;

        ret = prelude_option_add(rootopt, &opt, hook, 0, "relaying",
                                 "Relaying plugin option", PRELUDE_OPTION_ARGUMENT_OPTIONAL,
                                 relaying_activate, NULL);
        if ( ret < 0 )
                return ret;

        prelude_plugin_set_activation_option(pe, opt, NULL);

        ret = prelude_option_add(opt, NULL, hook, 'p', "parent-managers",
                                 "List of managers address:port pair where messages should be sent to",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, relaying_set_manager, relaying_get_manager);
        if ( ret < 0 )
                return ret;

        prelude_plugin_set_name(&relaying_plugin, "Relaying");
        prelude_plugin_set_destroy_func(&relaying_plugin, relaying_destroy);

        manager_report_plugin_set_running_func(&relaying_plugin, relaying_process);

        prelude_plugin_entry_set_plugin(pe, (void *) &relaying_plugin);

        return 0;
}



int relaying_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}
