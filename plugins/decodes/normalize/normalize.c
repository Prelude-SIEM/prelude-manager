#include <stdio.h>
#include <string.h>
#include <netdb.h>

#include <libprelude/prelude.h>
#include "prelude-manager.h"


int normalize_LTX_prelude_plugin_version(void);
int normalize_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *root_opt);



static int sanitize_service_protocol(idmef_service_t *service)
{
        int ret;
        uint8_t *ipn;
        struct protoent *proto;
        prelude_string_t *pname;

        if ( ! service )
                return 0;
        
        setprotoent(1);
        
        ipn = idmef_service_get_iana_protocol_number(service);
        if ( ipn) {
                proto = getprotobynumber(*ipn);
                if ( proto ) {
                        ret = idmef_service_new_iana_protocol_name(service, &pname);
                        if ( ret < 0 )
                                return ret;
                        
                        return prelude_string_set_dup(pname, proto->p_name);
                }
        }

        pname = idmef_service_get_iana_protocol_name(service);
        if ( pname && ! prelude_string_is_empty(pname) ) {
                proto = getprotobyname(prelude_string_get_string(pname));
                if ( proto )
                        idmef_service_set_iana_protocol_number(service, proto->p_proto);
        }

        return 0;
}



static void sanitize_address(idmef_address_t *addr)
{
        int ret;
        const char *str;
        int a, b, c, d;
        char buf1[256], buf2[256];
        
        if ( idmef_address_get_category(addr) != IDMEF_ADDRESS_CATEGORY_UNKNOWN )
                return;
        
        str = prelude_string_get_string(idmef_address_get_address(addr));

        ret = sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d);
        if ( ret == 4 ) {
                idmef_address_set_category(addr, IDMEF_ADDRESS_CATEGORY_IPV4_ADDR);                        
                return;
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
        idmef_address_t *address = NULL;
        
        while ( (address = idmef_node_get_next_address(node, address)) ) {

                str = prelude_string_get_string(idmef_address_get_address(address));
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





static int normalize_run(prelude_msg_t *msg, idmef_message_t *idmef)
{
        idmef_alert_t *alert;

        alert = idmef_message_get_alert(idmef);
        if ( ! alert )
                return 0;

        sanitize_alert(alert);
        
        return 0;
}



int normalize_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *root_opt)
{
        prelude_plugin_instance_t *pi;
        static manager_decode_plugin_t normalize;

        memset(&normalize, 0, sizeof(normalize));
        
        prelude_plugin_set_name(&normalize, "Normalize");
        manager_decode_plugin_set_running_func(&normalize, normalize_run);
        prelude_plugin_entry_set_plugin(pe, (void *) &normalize);

        return prelude_plugin_new_instance(&pi, (void *) &normalize, NULL, NULL);
}



int normalize_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}
