#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <assert.h>

#include <libprelude/common.h>
#include <libprelude/plugin-common.h>
#include <libprelude/alert-read.h>
#include <libprelude/alert-id.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include <libidmef/idmefxml.h>

#include "nids-alert-id.h"
#include "plugin-decode.h"
#include "packet.h"
#include "optparse.h"
#include "ethertype.h"




static char *hex(unsigned char *data, size_t len) 
{
        int i;
        char *buf, *r;

        r = buf = malloc(len * 2 + 1);
        if ( ! buf ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        for ( i = 0; i < len; i++ ) {
                snprintf(buf, 3, "%02x", data[i]);
                buf += 2;
        }

        r[len * 2] = '\0';
        
        return r;
}




static char *databuf;
static xmlDocPtr xmldoc;
static xmlNodePtr target = NULL, source = NULL, data = NULL;



static xmlNodePtr build_ipv4_saddr(struct in_addr addr) 
{
        xmlNodePtr saddr, node;

        source = newSource(NULL);
        node = newNode(NULL);
        
        saddr = newAddress(newSimpleElement("category", "ipv4-addr"),
                           newSimpleElement("address", inet_ntoa(addr)),
                           NULL);

        addElement(node, saddr);
        addElement(source, node);

        return source;
}



static xmlNodePtr build_ipv4_daddr(struct in_addr addr) 
{
        xmlNodePtr daddr, node;

        target = newTarget(NULL);
        node = newNode(NULL);
        
        daddr = newAddress(newSimpleElement("category", "ipv4-addr"),
                           newSimpleElement("address", inet_ntoa(addr)),
                           NULL);

        addElement(node, daddr);
        addElement(target, node);

        return target;
}



static void build_port(xmlNodePtr addr, uint16_t port) 
{
        char buf[sizeof("65535")];
        xmlNodePtr service;

        snprintf(buf, sizeof(buf), "%u", port);
        service = newService(newSimpleElement("port", buf), NULL);
        addElement(addr, service);
}



static void packet_to_idmef(packet_t *p) 
{
        int i;
        
        for ( i = 0; p[i].proto != p_end; i++ ) {
                
                if ( p[i].proto == p_ip ) {                        
                        source = build_ipv4_saddr(p[i].p.ip->ip_src);
                        target = build_ipv4_daddr(p[i].p.ip->ip_dst);
                }

                if ( p[i].proto == p_tcp ) {                        
                        build_port(source, ntohs(p[i].p.tcp->th_sport));
                        build_port(target, ntohs(p[i].p.tcp->th_dport));
                }

                if ( p[i].proto == p_udp ) {
                        build_port(source, ntohs(p[i].p.udp_hdr->uh_sport));
                        build_port(target, ntohs(p[i].p.udp_hdr->uh_dport));
                }

                if ( p[i].proto == p_data ) {
                        databuf = hex(p[i].p.data, p[i].len);
                        data = newAdditionalData(
                                newAttribute("meaning", "Packet Payload"),
                                newAttribute("type", "string"),
                                newSimpleElement("value", databuf),
                                NULL);
                }
        }        
}



static xmlNodePtr build_analyzer(void) 
{
        xmlNodePtr analyzer, node;

        analyzer = newAnalyzer(newSimpleElement("analyzerid", "no id"), NULL);

        node = newNode(NULL);
        addElement(node, newSimpleElement("name", getenv("HOSTNAME")));

        addElement(analyzer, node);

        return analyzer;
}




static char *build_alert_id(void) 
{
        static unsigned long id = 0;

        if ( ! id ) {
                id = 1;
                
                id = getStoredAlertID("/var/log/prelude/alertid");
                if ( id == 0 ) 
                        log(LOG_ERR, "couldn't retrieve the stored alert id.\n");
                
                else if ( id == 1 )
                        log(LOG_INFO, "no stored alert id, continuing with id == 1.\n");
        }
        
        return ulongToString(id++);
}




static xmlNodePtr nids_decode_run(alert_container_t *ac) 
{
        int ret;
        int i = 0;
        uint8_t tag;
        uint32_t len;
        packet_t packet[MAX_PKTDEPTH + 1];
        void *buf;
        struct timeval tv;
        char *alertid;
        xmlNodePtr origin = NULL, msg = NULL, analyzer = NULL;
        xmlNodePtr alert, class = NULL, classname = NULL, refurl = NULL;

        databuf = NULL;
        data = source = target = NULL;
        
        ret = createCurrentDoc("1.0");
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't create an XML document.\n");
                return NULL;
        }

        
        while ( 1 ) {

                ret = prelude_alert_read_msg(ac, &tag, &len, &buf);
                if ( ret < 0 ) {
                        log(LOG_ERR, "error decoding message.\n");
                        return NULL;
                }

                /*
                 * End of message.
                 */
                if ( ret == 0 ) 
                        break;

                switch (tag) {
                        
                case ID_PRELUDE_NIDS_PLUGIN_NAME:
                case ID_PRELUDE_NIDS_PLUGIN_AUTHOR:
                case ID_PRELUDE_NIDS_PLUGIN_CONTACT:
                case ID_PRELUDE_NIDS_PLUGIN_DESC:
                        break;
                        
                case ID_PRELUDE_NIDS_MESSAGE:
                        msg = newAdditionalData(
                                newAttribute("meaning", "Attack information"),
                                newAttribute("type", "string"),
                                newSimpleElement("value", buf),
                                NULL);
                        break;

                case ID_PRELUDE_NIDS_REFERENCE_ORIGIN:
                        origin = newAttribute("origin", buf);
                        break;

                case ID_PRELUDE_NIDS_REFERENCE_URL:
                        refurl = newSimpleElement("url", buf);
                        break;

                case ID_PRELUDE_NIDS_TS_SEC:
                        tv.tv_sec = ntohl( (*(long *)buf));
                        break;

                case ID_PRELUDE_NIDS_TS_USEC:
                        tv.tv_usec = ntohl( (*(long *)buf)) ;
                        break;
                        
                case ID_PRELUDE_NIDS_CLASSIFICATION_NAME:
                        classname = newSimpleElement("name", buf);
                        break;

                case ID_PRELUDE_NIDS_PACKET:
                        i = 0;
                        
                        do {    
                                ret = prelude_alert_read_msg(ac, &tag, &len, &buf);
                                if ( ret < 0 ) {
                                        log(LOG_ERR, "error decoding message.\n");
                                        return NULL;
                                }

                                if ( ret == 0 ) 
                                        break;

                                packet[i].len = len;
                                packet[i].proto = tag;
                                packet[i].p.ip = buf;
                                
                        } while ( packet[i++].proto != p_end );
                        
                        packet_to_idmef(packet);
                        
                        break;

                default:
                        log(LOG_ERR, "unknow tag : %d.\n", tag);
                        break;
                }
        }


        alertid = build_alert_id();
        
        alert = newAlert(newSimpleElement("ident", alertid),
                         newSimpleElement("impact", "unknown"),
                         build_analyzer(),
                         newCreateTime(NULL), newDetectTime(&tv), source, target, NULL);
        free(alertid);
        
        assert(classname);
        
        if ( ! origin )
                origin = newAttribute("origin", "unknow");

        if ( ! refurl )
                refurl = newSimpleElement("url", "No URL available");

        class = newClassification(origin, classname, refurl, NULL);
        addElement(alert, class);
        
        if ( data ) 
                addElement(alert, data);

        if ( msg )
                addElement(alert, msg);
        
        msg = newIDMEF_Message(newAttribute("version", IDMEF_MESSAGE_VERSION), alert, NULL);

        validateCurrentDoc();
        xmlKeepBlanksDefault(0);
        printCurrentMessage(stderr);
        
        clearCurrentDoc();

        if ( databuf )
                free(databuf);
        
        return msg;
}




int plugin_init(unsigned int id)
{
        int ret;
        static plugin_decode_t plugin;
        
        globalsInit("/home/yoann/idmef-message.dtd");        

        plugin_set_name(&plugin, "Prelude NIDS data decoder");
        plugin_set_author(&plugin, "Yoann Vandoorselaere");
        plugin_set_contact(&plugin, "yoann@mandrakesoft.com");
        plugin_set_desc(&plugin, "Decode Prelude NIDS message, and translate them to IDMEF.");
        plugin_set_running_func(&plugin, nids_decode_run);

        plugin.decode_id = ID_PRELUDE_NIDS_ALERT;
        
	return plugin_register((plugin_generic_t *)&plugin);
}






