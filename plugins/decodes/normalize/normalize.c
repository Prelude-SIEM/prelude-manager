/*****
*
* Copyright (C) 2006-2012 CS-SI. All Rights Reserved.
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

#include <stdio.h>
#include <string.h>

#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
# include <netdb.h>
#endif

#include <libprelude/prelude.h>
#include "prelude-manager.h"


int normalize_LTX_prelude_plugin_version(void);
int normalize_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *root_opt);



static prelude_bool_t no_ipv6_prefix = TRUE;
static prelude_bool_t normalize_to_ipv6 = FALSE;



static int sanitize_service_protocol(idmef_service_t *service)
{
        int ret;
        uint8_t *ipn;
        struct protoent *proto;
        prelude_string_t *str;

        if ( ! service )
                return 0;

        ipn = idmef_service_get_iana_protocol_number(service);
        if ( ipn ) {
                proto = getprotobynumber(*ipn);
                if ( proto ) {
                        ret = idmef_service_new_iana_protocol_name(service, &str);
                        if ( ret < 0 )
                                return ret;

                        ret = prelude_string_set_dup(str, proto->p_name);
                        if ( ret < 0 )
                                return ret;
                }
        }

        else if ( (str = idmef_service_get_iana_protocol_name(service)) && ! prelude_string_is_empty(str) ) {
                proto = getprotobyname(prelude_string_get_string(str));
                if ( proto )
                        idmef_service_set_iana_protocol_number(service, proto->p_proto);
        }

        if ( ! idmef_service_get_port(service) && ! idmef_service_get_name(service) ) {
                ret = idmef_service_new_name(service, &str);
                if ( ret < 0 )
                        return ret;

                ret = prelude_string_set_constant(str, "unknown");
                if ( ret < 0 )
                        return ret;
        }

        return 0;
}




static void sanitize_address_string(idmef_address_t *addr, const char *str, prelude_bool_t have_v6_prefix)
{
        int ret;
        prelude_string_t *pstr;

        if ( have_v6_prefix && no_ipv6_prefix && ! normalize_to_ipv6 ) {
                ret = prelude_string_new_dup(&pstr, str + 7);
                if ( ret < 0 )
                        return;

                idmef_address_set_address(addr, pstr);
        }

        else if ( ! have_v6_prefix && normalize_to_ipv6 ) {
                ret = prelude_string_new_dup(&pstr, "::ffff:");
                if ( ret < 0 )
                        return;

                ret = prelude_string_cat(pstr, str);
                if ( ret < 0 ) {
                        prelude_string_destroy(pstr);
                        return;
                }

                idmef_address_set_address(addr, pstr);
                idmef_address_set_category(addr, IDMEF_ADDRESS_CATEGORY_IPV6_ADDR);
        }

        return;
}


static void sanitize_address(idmef_address_t *addr)
{
        int ret;
        const char *str;
        int a, b, c, d;
        char buf1[256], buf2[256];
        prelude_bool_t ipv6_prefix = FALSE;

        if ( idmef_address_get_category(addr) != IDMEF_ADDRESS_CATEGORY_UNKNOWN ||
             ! idmef_address_get_address(addr) )
                return;


        str = prelude_string_get_string(idmef_address_get_address(addr));

        if ( strncmp(str, "::ffff:", 7) == 0 )
                ipv6_prefix = TRUE;

        ret = sscanf(str + ((ipv6_prefix) ? 7 : 0), "%d.%d.%d.%d", &a, &b, &c, &d);
        if ( ret == 4 ) {
                idmef_address_set_category(addr, IDMEF_ADDRESS_CATEGORY_IPV4_ADDR);
                return sanitize_address_string(addr, str, ipv6_prefix);
        }

        ret = sscanf(str, "%255[^@]@%255s", buf1, buf2);
        if ( ret == 2 ) {
                idmef_address_set_category(addr, IDMEF_ADDRESS_CATEGORY_E_MAIL);
                return;
        }

        if ( (str = strchr(str, ':')) && strchr(str + 1, ':') ) {
                idmef_address_set_category(addr, IDMEF_ADDRESS_CATEGORY_IPV6_ADDR);
                return;
        }
}



static int sanitize_node(idmef_node_t *node)
{
        const char *str;
        prelude_string_t *pstr;
        idmef_address_t *address = NULL;

        while ( (address = idmef_node_get_next_address(node, address)) ) {

                pstr = idmef_address_get_address(address);
                if ( ! pstr ) {
                        idmef_address_destroy(address); address = NULL;
                        continue;
                }

                str = prelude_string_get_string(pstr);
                if ( ! str || ! *str ) {
                        idmef_address_destroy(address); address = NULL;
                        continue;
                }

                sanitize_address(address);
        }

        if ( ! idmef_node_get_next_address(node, NULL) && ! idmef_node_get_name(node) )
                return -1;

        return 0;
}



static void sanitize_alert(idmef_alert_t *alert)
{
        int ret;
        idmef_node_t *node;
        idmef_source_t *src = NULL;
        idmef_target_t *dst = NULL;
        idmef_analyzer_t *analyzer = NULL;

        if ( ! alert )
                return;

        while ( (analyzer = idmef_alert_get_next_analyzer(alert, analyzer)) ) {
                node = idmef_analyzer_get_node(analyzer);
                if ( node ) {
                        ret = sanitize_node(node);
                        if ( ret < 0 )
                                idmef_analyzer_set_node(analyzer, NULL);
                }
        }

        while ( (src = idmef_alert_get_next_source(alert, src)) ) {

                sanitize_service_protocol(idmef_source_get_service(src));

                node = idmef_source_get_node(src);
                if ( node ) {
                        ret = sanitize_node(node);
                        if ( ret < 0 )
                                idmef_source_set_node(src, NULL);
                }
        }


        while ( (dst = idmef_alert_get_next_target(alert, dst)) ) {

                sanitize_service_protocol(idmef_target_get_service(dst));

                node = idmef_target_get_node(dst);
                if ( node ) {
                        ret = sanitize_node(node);
                        if ( ret < 0 )
                                idmef_target_set_node(dst, NULL);
                }
        }
}



static void sanitize_heartbeat(idmef_heartbeat_t *heartbeat)
{
        int ret;
        idmef_node_t *node;
        idmef_analyzer_t *analyzer = NULL;

        if ( ! heartbeat )
                return;

        while ( (analyzer = idmef_heartbeat_get_next_analyzer(heartbeat, analyzer)) ) {
                node = idmef_analyzer_get_node(analyzer);
                if ( node ) {
                        ret = sanitize_node(node);
                        if ( ret < 0 )
                                idmef_analyzer_set_node(analyzer, NULL);
                }
        }
}




static int normalize_run(prelude_msg_t *msg, idmef_message_t *idmef)
{
        if ( idmef_message_get_type(idmef) == IDMEF_MESSAGE_TYPE_ALERT )
                sanitize_alert(idmef_message_get_alert(idmef));
        else
                sanitize_heartbeat(idmef_message_get_heartbeat(idmef));

        return 0;
}



static int normalize_to_ipv6_cb(prelude_option_t *option, const char *arg, prelude_string_t *err, void *context)
{
        normalize_to_ipv6 = TRUE;
        return 0;
}


static int normalize_keep_ipv6(prelude_option_t *option, const char *arg, prelude_string_t *err, void *context)
{
        no_ipv6_prefix = FALSE;
        return 0;
}


int normalize_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *root_opt)
{
        prelude_option_t *opt;
        prelude_plugin_instance_t *pi;
        static manager_decode_plugin_t normalize;

#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        setprotoent(1);
#endif

        memset(&normalize, 0, sizeof(normalize));

        prelude_plugin_set_name(&normalize, "Normalize");
        manager_decode_plugin_set_running_func(&normalize, normalize_run);
        prelude_plugin_entry_set_plugin(pe, (void *) &normalize);

        prelude_option_add(root_opt, &opt, PRELUDE_OPTION_TYPE_CFG,
                           0, "normalize", "Option for the normalize plugin", PRELUDE_OPTION_ARGUMENT_NONE, NULL, NULL);

        prelude_option_add(opt, NULL, PRELUDE_OPTION_TYPE_CFG,
                           '6', "ipv6-only", "Map IPv4 addresses to IPv6",
                           PRELUDE_OPTION_ARGUMENT_NONE, normalize_to_ipv6_cb, NULL);

        prelude_option_add(opt, NULL, PRELUDE_OPTION_TYPE_CFG,
                           '4', "keep-ipv4-mapped-ipv6",
                           "Do not normalize IPv4 mapped IPv6 address to IPv4",
                           PRELUDE_OPTION_ARGUMENT_NONE, normalize_keep_ipv6, NULL);

        return prelude_plugin_new_instance(&pi, (void *) &normalize, NULL, NULL);
}



int normalize_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}
