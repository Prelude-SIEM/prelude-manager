/*****
*
* Copyright (C) 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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
#include <stdarg.h>
#include <libxml/parser.h>

#include "libmissing.h"
#include "prelude-manager.h"


int xmlmod_LTX_prelude_plugin_version(void);
int xmlmod_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *data);


static void process_file(xmlNodePtr parent, idmef_file_t *file);


typedef struct {
        int format;
        int no_buffering;
        char *logfile;
        xmlDtdPtr idmef_dtd;
        FILE *fd;
} xmlmod_plugin_t;



PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(xmlmod, xmlmod_plugin_t, logfile)




#define idmef_attr_generic_optional(node, attr, fmt, ptr)                       \
do {                                                                            \
        char buf[512];                                                          \
        if ( ptr ) {                                                            \
               snprintf(buf, sizeof(buf), fmt, *ptr);                           \
               xmlSetProp(node, (const xmlChar *) attr, (const xmlChar *) buf); \
        }                                                                       \
} while (0)


#define idmef_attr_generic(node, attr, fmt, value)                              \
do {                                                                            \
        char buf[512];                                                          \
        if ( value ) {                                                          \
               snprintf(buf, sizeof(buf), fmt, value);                          \
               xmlSetProp(node, (const xmlChar *) attr, (const xmlChar *) buf); \
        }                                                                       \
} while (0) 


#define idmef_content_generic_optional(node, tag, fmt, ptr)                               \
do {                                                                                      \
        char buf[512];                                                                    \
        if ( ptr ) {                                                                      \
               snprintf(buf, sizeof(buf), fmt, *ptr);                                     \
               xmlNewTextChild(node, NULL, (const xmlChar *) tag, (const xmlChar *) buf); \
        }                                                                                 \
} while (0)



static void idmef_content_string(xmlNodePtr node, const char *tag, prelude_string_t *string) 
{
	const char *content;

        if ( ! string )
                return;

	content = prelude_string_get_string(string);

        xmlNewTextChild(node, NULL, (const xmlChar *) tag, (const xmlChar *) (content ? content : ""));
}



static void idmef_attr_string(xmlNodePtr node, const char *attr, prelude_string_t *string) 
{
	const char *content;

        if ( ! string )
                return;

	content = prelude_string_get_string(string);

        xmlSetProp(node, (const xmlChar *) attr, (const xmlChar *) (content ? content : ""));
}



static void _idmef_attr_enum(xmlNodePtr node, const char *attr, int value, const char *(*convert)(int))
{
        const char *content = convert(value);
	xmlSetProp(node, (const xmlChar *) attr, (const xmlChar *) (content ? content : ""));
}

#define idmef_attr_enum(node, attr, value, convert) \
	_idmef_attr_enum(node, attr, value, (const char *(*)(int)) convert)



static void _idmef_attr_enum_optional(xmlNodePtr node, const char *attr, int *value, const char *(*convert)(int))
{
	if ( ! value )
		return;

	idmef_attr_enum(node, attr, *value, convert);
}

#define idmef_attr_enum_optional(node, attr, value, convert) \
	_idmef_attr_enum_optional(node, attr, value, (const char *(*)(int)) convert)



static void process_time(xmlNodePtr parent, const char *type, idmef_time_t *time, prelude_bool_t enable_ntpstamp) 
{
        int ret;
        xmlNodePtr new;
        prelude_string_t *out;
        
        if ( ! time )
                return;

        ret = prelude_string_new(&out);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating object");
                return;
        }
        
        ret = idmef_time_to_string(time, out);
        if ( ret < 0 ) {
                prelude_string_destroy(out);
                return;
        }
        
        new = xmlNewTextChild(parent, NULL, (const xmlChar *) type, (const xmlChar *) prelude_string_get_string(out));
        if ( ! new ) {
                prelude_string_destroy(out);
                return;
        }

        if ( enable_ntpstamp ) {
                prelude_string_clear(out);
                
                ret = idmef_time_to_ntpstamp(time, out);
                if ( ret < 0 ) {
                        prelude_string_destroy(out);
                        return;
                }
        
                xmlSetProp(new, (const xmlChar *) "ntpstamp", (const xmlChar *) prelude_string_get_string(out));
        }
        
        prelude_string_destroy(out);
}



static void process_address(xmlNodePtr parent, idmef_address_t *address) 
{
        xmlNodePtr new;

        if ( ! address )
                return;
        
        new = xmlNewTextChild(parent, NULL, (const xmlChar *) "Address", NULL);
        if ( ! new )
                return;

        idmef_attr_string(new, "ident", idmef_address_get_ident(address));
        idmef_attr_enum(new, "category", idmef_address_get_category(address), idmef_address_category_to_string);
        idmef_attr_string(new, "vlan-name", idmef_address_get_vlan_name(address));
        
        idmef_attr_generic_optional(new, "vlan-num", "%d", idmef_address_get_vlan_num(address));
        
        idmef_content_string(new, "address", idmef_address_get_address(address));
        idmef_content_string(new, "netmask", idmef_address_get_netmask(address));
}




static void process_node(xmlNodePtr parent, idmef_node_t *node) 
{
        xmlNodePtr new;
        idmef_address_t *address;
        
        if ( ! node )
                return;

        new = xmlNewChild(parent, NULL, (const xmlChar *) "Node", NULL);
        if ( ! new )
                return;
        
        idmef_attr_string(new, "ident", idmef_node_get_ident(node));
        idmef_attr_enum(new, "category", idmef_node_get_category(node), idmef_node_category_to_string);
        idmef_content_string(new, "location", idmef_node_get_location(node));
        idmef_content_string(new, "name", idmef_node_get_name(node));

	address = NULL;
	while ( (address = idmef_node_get_next_address(node, address)) )
		process_address(new, address);
}



static void process_user_id(xmlNodePtr parent, idmef_user_id_t *user_id) 
{
        xmlNodePtr new;

        if ( ! user_id )
                return;
        
        new = xmlNewChild(parent, NULL, (const xmlChar *) "UserId", NULL);
        if ( ! new )
                return;

        idmef_attr_string(new, "ident", idmef_user_id_get_ident(user_id));
        idmef_attr_enum(new, "type", idmef_user_id_get_type(user_id), idmef_user_id_type_to_string);
        idmef_content_string(new, "name", idmef_user_id_get_name(user_id));
        idmef_content_generic_optional(new, "number", "%" PRELUDE_PRIu32, idmef_user_id_get_number(user_id));
}



static void process_user(xmlNodePtr parent, idmef_user_t *user) 
{
        xmlNodePtr new;
        idmef_user_id_t *user_id;

        if ( ! user )
                return;

        new = xmlNewChild(parent, NULL, (const xmlChar *) "User", NULL);
        if ( ! new )
                return;

        idmef_attr_string(new, "ident", idmef_user_get_ident(user));
        idmef_attr_enum(new, "category", idmef_user_get_category(user), idmef_user_category_to_string);

	user_id = NULL;
	while ( (user_id = idmef_user_get_next_user_id(user, user_id)) )
		process_user_id(new, user_id);
}




static void process_process(xmlNodePtr parent, idmef_process_t *process)
{
        xmlNodePtr new;
	prelude_string_t *string;

        if ( ! process )
                return;

        new = xmlNewChild(parent, NULL, (const xmlChar *) "Process", NULL);
        if ( ! new )
                return;

        idmef_attr_string(new, "ident", idmef_process_get_ident(process));
        idmef_content_string(new, "name", idmef_process_get_name(process));
        idmef_content_generic_optional(new, "pid", "%" PRELUDE_PRIu32, idmef_process_get_pid(process));
        idmef_content_string(new, "path", idmef_process_get_path(process));

	string = NULL;
	while ( (string = idmef_process_get_next_arg(process, string)) )
		xmlNewTextChild(new, NULL, (const xmlChar *) "arg", (const xmlChar *) prelude_string_get_string(string));

	string = NULL;
	while ( (string = idmef_process_get_next_env(process, string)) )
		xmlNewTextChild(new, NULL, (const xmlChar *) "env", (const xmlChar *) prelude_string_get_string(string));
}




static void process_snmp_service(xmlNodePtr parent, idmef_snmp_service_t *snmp) 
{
        xmlNodePtr new;

        if ( ! snmp )
                return;

        new = xmlNewChild(parent, NULL, (const xmlChar *) "SNMPService", NULL);
        if ( ! new )
                return;

        idmef_content_string(new, "oid", idmef_snmp_service_get_oid(snmp));
        idmef_content_generic_optional(new, "messageProcessingModel", "%" PRELUDE_PRIu32, idmef_snmp_service_get_message_processing_model(snmp));
        idmef_content_generic_optional(new, "securityModel", "%" PRELUDE_PRIu32, idmef_snmp_service_get_security_model(snmp));
        idmef_content_string(new, "securityName", idmef_snmp_service_get_security_name(snmp));
        idmef_content_generic_optional(new, "securityLevel", "%" PRELUDE_PRIu32, idmef_snmp_service_get_security_level(snmp));
        idmef_content_string(new, "contextName", idmef_snmp_service_get_context_name(snmp));
        idmef_content_string(new, "contextEngineId", idmef_snmp_service_get_context_engine_id(snmp));
        idmef_content_string(new, "command", idmef_snmp_service_get_command(snmp));
}




static void process_web_service(xmlNodePtr parent, idmef_web_service_t *web) 
{
        xmlNodePtr new;
	prelude_string_t *arg;

        if ( ! web )
                return;

        new = xmlNewChild(parent, NULL, (const xmlChar *) "WebService", NULL);

        idmef_content_string(new, "url", idmef_web_service_get_url(web));
        idmef_content_string(new, "cgi", idmef_web_service_get_cgi(web));
        idmef_content_string(new, "http-method", idmef_web_service_get_http_method(web));

	arg = NULL;
	while ( (arg = idmef_web_service_get_next_arg(web, arg)) )
		xmlNewTextChild(new, NULL, (const xmlChar *) "arg", (const xmlChar *) prelude_string_get_string(arg));
}



static void process_service(xmlNodePtr parent, idmef_service_t *service) 
{
        xmlNodePtr new;

        if ( ! service )
                return;

        new = xmlNewChild(parent, NULL, (const xmlChar *) "Service", NULL);
        if ( ! new )
                return;

        idmef_attr_string(new, "ident", idmef_service_get_ident(service));
	idmef_attr_generic_optional(new, "ip_version", "%" PRELUDE_PRIu8, idmef_service_get_ip_version(service));
        idmef_content_string(new, "name", idmef_service_get_name(service));
        idmef_content_generic_optional(new, "port", "%" PRELUDE_PRIu16, idmef_service_get_port(service));
	idmef_attr_generic_optional(new, "iana_protocol_number", "%" PRELUDE_PRIu8, idmef_service_get_iana_protocol_number(service));
	idmef_attr_string(new, "iana_protocol_name", idmef_service_get_iana_protocol_name(service));
        idmef_content_string(new, "portlist", idmef_service_get_portlist(service));
        idmef_content_string(new, "protocol", idmef_service_get_protocol(service));

        switch ( idmef_service_get_type(service) ) {

        case IDMEF_SERVICE_TYPE_SNMP:
                process_snmp_service(new, idmef_service_get_snmp_service(service));
                break;

        case IDMEF_SERVICE_TYPE_WEB:
                process_web_service(new, idmef_service_get_web_service(service));
                break;

        default:
                break;
        }
}



static void process_source(xmlNodePtr parent, idmef_source_t *source)
{
        xmlNodePtr new;

        if ( ! source )
                return;
        
        new = xmlNewChild(parent, NULL, (const xmlChar *) "Source", NULL);
        if ( ! new )
                return;
        
        idmef_attr_string(new, "ident", idmef_source_get_ident(source));
        idmef_attr_enum(new, "spoofed", idmef_source_get_spoofed(source), idmef_source_spoofed_to_string);
        idmef_attr_string(new, "interface", idmef_source_get_interface(source));
        
        process_node(new, idmef_source_get_node(source));
        process_user(new, idmef_source_get_user(source));
        process_process(new, idmef_source_get_process(source));
        process_service(new, idmef_source_get_service(source));
}



static void process_file_access(xmlNodePtr parent, idmef_file_access_t *file_access)
{
        xmlNodePtr new;
	prelude_string_t *permission;

        if ( ! file_access )
                return;
        
	new = xmlNewChild(parent, NULL, (const xmlChar *) "FileAccess", NULL);
	if ( ! new )
		return;

	process_user_id(new, idmef_file_access_get_user_id(file_access));

	permission = NULL;
	while ( (permission = idmef_file_access_get_next_permission(file_access, permission)) )
		xmlNewTextChild(new, NULL, (const xmlChar *) "Permission", (const xmlChar *) prelude_string_get_string(permission));
}



static void process_file_linkage(xmlNodePtr parent, idmef_linkage_t *linkage) 
{
        xmlNodePtr new;

        if ( ! linkage )
                return;
        
	new = xmlNewChild(parent, NULL, (const xmlChar *) "Linkage", NULL);
	if ( ! new )
		return;

	idmef_attr_enum(new, "category", idmef_linkage_get_category(linkage), idmef_linkage_category_to_string);
	idmef_content_string(new, "name", idmef_linkage_get_name(linkage));
	idmef_content_string(new, "path", idmef_linkage_get_path(linkage));

	process_file(new, idmef_linkage_get_file(linkage));
}




static void process_inode(xmlNodePtr parent, idmef_inode_t *inode) 
{
        xmlNodePtr new;

        if ( ! inode )
                return;

        new = xmlNewChild(parent, NULL, (const xmlChar *) "Inode", NULL);
        if ( ! new )
                return;

        process_time(new, "change-time", idmef_inode_get_change_time(inode), FALSE);

        idmef_content_generic_optional(new, "number", "%" PRELUDE_PRIu32, idmef_inode_get_number(inode));
        idmef_content_generic_optional(new, "major-device", "%" PRELUDE_PRIu32,  idmef_inode_get_major_device(inode));
        idmef_content_generic_optional(new, "minor-device", "%" PRELUDE_PRIu32, idmef_inode_get_minor_device(inode));
        idmef_content_generic_optional(new, "c-major-device", "%" PRELUDE_PRIu32, idmef_inode_get_c_major_device(inode));
        idmef_content_generic_optional(new, "c-minor-devide", "%" PRELUDE_PRIu32, idmef_inode_get_c_minor_device(inode));
}


static void process_file_checksum(xmlNodePtr parent, idmef_checksum_t *csum) 
{
        xmlNodePtr new;

        if ( ! csum )
                return;

        new = xmlNewChild(parent, NULL, (const xmlChar *) "Checksum", NULL);
        if ( ! new )
                return;

        idmef_attr_enum(new, "algorithm", idmef_checksum_get_algorithm(csum), idmef_checksum_algorithm_to_string);
        idmef_content_string(new, "value", idmef_checksum_get_value(csum));
        idmef_content_string(new, "key", idmef_checksum_get_key(csum));
}



static void process_file(xmlNodePtr parent, idmef_file_t *file) 
{
        xmlNodePtr new;
	idmef_linkage_t *file_linkage;       
        idmef_checksum_t *file_checksum;
	idmef_file_access_t *file_access;

        if ( ! file )
                return;
        
        new = xmlNewChild(parent, NULL, (const xmlChar *) "File", NULL);
        if ( ! new )
                return;

        idmef_attr_string(new, "ident", idmef_file_get_ident(file));
        idmef_attr_enum(new, "category", idmef_file_get_category(file), idmef_file_category_to_string);
	idmef_attr_enum_optional(new, "fstype", idmef_file_get_fstype(file), idmef_file_fstype_to_string);
        idmef_content_string(new, "name", idmef_file_get_name(file));
        idmef_content_string(new, "path", idmef_file_get_path(file));
        process_time(new, "create-time", idmef_file_get_create_time(file), FALSE);
        process_time(new, "modify-time", idmef_file_get_modify_time(file), FALSE);
        process_time(new, "access-time", idmef_file_get_access_time(file), FALSE);
        idmef_content_generic_optional(new, "data-size", "%" PRELUDE_PRIu64, idmef_file_get_data_size(file));
        idmef_content_generic_optional(new, "disk-size", "%" PRELUDE_PRIu64, idmef_file_get_disk_size(file));

	file_access = NULL;
	while ( (file_access = idmef_file_get_next_file_access(file, file_access)) )
		process_file_access(new, file_access);

	file_linkage = NULL;
	while ( (file_linkage = idmef_file_get_next_linkage(file, file_linkage)) )
		process_file_linkage(new, file_linkage);

        file_checksum = NULL;
        while ( (file_checksum = idmef_file_get_next_checksum(file, file_checksum)) )
                process_file_checksum(new, file_checksum);
        
        process_inode(new, idmef_file_get_inode(file));
}




static void process_target(xmlNodePtr parent, idmef_target_t *target)
{
        xmlNodePtr new;
        idmef_file_t *file;

        if ( ! target )
                return;
        
        new = xmlNewChild(parent, NULL, (const xmlChar *) "Target", NULL);
        if ( ! new )
                return;

        idmef_attr_string(new, "ident", idmef_target_get_ident(target));
        idmef_attr_enum(new, "decoy", idmef_target_get_decoy(target), idmef_target_decoy_to_string);
        idmef_attr_string(new, "interface", idmef_target_get_interface(target));

        process_node(new, idmef_target_get_node(target));
        process_user(new, idmef_target_get_user(target));
        process_process(new, idmef_target_get_process(target));
        process_service(new, idmef_target_get_service(target));

	file = NULL;
	while ( (file = idmef_target_get_next_file(target, file)) )
                process_file(new, file);
}



static xmlNodePtr process_analyzer(xmlNodePtr parent, idmef_analyzer_t *analyzer) 
{
        xmlNodePtr new;

        new = xmlNewChild(parent, NULL, (const xmlChar *) "Analyzer", NULL);
        if ( ! new )
                return NULL;
        
        idmef_attr_string(new, "analyzerid", idmef_analyzer_get_analyzerid(analyzer));
        idmef_attr_string(new, "name", idmef_analyzer_get_name(analyzer));
        idmef_attr_string(new, "manufacturer", idmef_analyzer_get_manufacturer(analyzer));
        idmef_attr_string(new, "model", idmef_analyzer_get_model(analyzer));
        idmef_attr_string(new, "version", idmef_analyzer_get_version(analyzer));
        idmef_attr_string(new, "class", idmef_analyzer_get_class(analyzer));
        idmef_attr_string(new, "ostype", idmef_analyzer_get_ostype(analyzer));
        idmef_attr_string(new, "osversion", idmef_analyzer_get_osversion(analyzer));

        process_node(new, idmef_analyzer_get_node(analyzer));
        process_process(new, idmef_analyzer_get_process(analyzer));

        return new;
}



static void process_reference(xmlNodePtr parent, idmef_reference_t *reference)
{
        xmlNodePtr new;
        
        new = xmlNewChild(parent, NULL, (const xmlChar *) "Reference", NULL);
        if ( ! new )
                return;

        idmef_attr_enum(new, "origin", idmef_reference_get_origin(reference), idmef_reference_origin_to_string);
        
        idmef_content_string(new, "name", idmef_reference_get_name(reference));

        idmef_content_string(new, "url", idmef_reference_get_url(reference));
}



static void process_classification(xmlNodePtr parent, idmef_classification_t *classification) 
{
        xmlNodePtr new;
        idmef_reference_t *reference;
        
        if ( ! classification )
                return;
        
        new = xmlNewChild(parent, NULL, (const xmlChar *) "Classification", NULL);
        if ( ! new )
                return;

        idmef_attr_string(new, "ident", idmef_classification_get_ident(classification));
        
        idmef_attr_string(new, "text", idmef_classification_get_text(classification));

        reference = NULL;
        while ( (reference = idmef_classification_get_next_reference(classification, reference)) )
                process_reference(new, reference);
}



static void process_additional_data(xmlNodePtr parent, idmef_additional_data_t *ad) 
{
        int ret;
        xmlNodePtr new;
        prelude_string_t *out;

        if ( ! ad )
                return;
        
        ret = prelude_string_new(&out);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating object");
                return;
        }
        
	ret = idmef_additional_data_data_to_string(ad, out);
	if ( ret < 0 ) {
                prelude_string_destroy(out);
		return;
        }
        
        new = xmlNewChild(parent, NULL, (const xmlChar *) "AdditionalData", NULL);
        if ( ! new ) {
                prelude_string_destroy(out);
                return;
        }

        idmef_attr_enum(new, "type", idmef_additional_data_get_type(ad), idmef_additional_data_type_to_string);
        idmef_attr_string(new, "meaning", idmef_additional_data_get_meaning(ad));

        xmlNewTextChild(new, NULL, (const xmlChar *) idmef_additional_data_type_to_string(
                                idmef_additional_data_get_type(ad)),
                        (const xmlChar *) prelude_string_get_string(out));

        prelude_string_destroy(out);
}




static void process_impact(xmlNodePtr parent, idmef_impact_t *impact) 
{
        xmlNodePtr new;
        
        if ( ! impact )
                return;

        new = xmlNewTextChild(parent, NULL, (const xmlChar *) "Impact",
			  (const xmlChar *) prelude_string_get_string(idmef_impact_get_description(impact)));
        if ( ! new )
                return;

	idmef_attr_enum_optional(new, "severity", idmef_impact_get_severity(impact), idmef_impact_severity_to_string);
	idmef_attr_enum_optional(new, "completion", idmef_impact_get_completion(impact), idmef_impact_completion_to_string);
        
        idmef_attr_enum(new, "type", idmef_impact_get_type(impact), idmef_impact_type_to_string);
}



static void process_confidence(xmlNodePtr parent, idmef_confidence_t *confidence) 
{
        char buf[64];
        xmlNodePtr new;

        if ( ! confidence )
                return;

        if ( idmef_confidence_get_rating(confidence) == IDMEF_CONFIDENCE_RATING_NUMERIC ) {
                snprintf(buf, sizeof(buf), "%f", idmef_confidence_get_confidence(confidence));
                new = xmlNewChild(parent, NULL, (const xmlChar *) "Confidence", (const xmlChar *) buf);
        } else
                new = xmlNewChild(parent, NULL, (const xmlChar *) "Confidence", NULL);

        if ( ! new )
                return;

        idmef_attr_enum(new, "rating", idmef_confidence_get_rating(confidence), idmef_confidence_rating_to_string);
}




static void process_action(xmlNodePtr parent, idmef_action_t *action) 
{
        xmlNodePtr new;
        prelude_string_t *str;
        
        if ( ! action )
                return;

        str = idmef_action_get_description(action);
	if ( str )
		new = xmlNewTextChild(parent, NULL, (const xmlChar *) "Action",
                                      (const xmlChar *) prelude_string_get_string(str));
	else
		new = xmlNewChild(parent, NULL, (const xmlChar *) "Action", NULL);
	
        if ( ! new )
                return;

        idmef_attr_enum(new, "category", idmef_action_get_category(action), idmef_action_category_to_string);
}




static void process_assessment(xmlNodePtr parent, idmef_assessment_t *assessment) 
{
        xmlNodePtr new;
        idmef_action_t *action;

        if ( ! assessment )
                return;

        new = xmlNewChild(parent, NULL, (const xmlChar *) "Assessment", NULL);
        if ( ! new )
                return;

        process_impact(new, idmef_assessment_get_impact(assessment));

	action = NULL;
	while ( (action = idmef_assessment_get_next_action(assessment, action)) )
                process_action(new, action);

        process_confidence(new, idmef_assessment_get_confidence(assessment));
}



static void process_correlation_alert(xmlNodePtr parent, idmef_correlation_alert_t *ca)
{
        xmlNodePtr new, anew;
        prelude_string_t *str;
        idmef_alertident_t *alertident = NULL;
        
        if ( ! ca )
                return;

        new = xmlNewChild(parent, NULL, (const xmlChar *) "CorrelationAlert", NULL);
        if ( ! new )
                return;

        str = idmef_correlation_alert_get_name(ca);
	if ( str )
		xmlNewTextChild(new, NULL, (const xmlChar *) "name", (const xmlChar *) prelude_string_get_string(str));

        while ( (alertident = idmef_correlation_alert_get_next_alertident(ca, alertident)) ) {
                anew = xmlNewTextChild(new, NULL, (const xmlChar *) "alertident",
                                       (const xmlChar *) prelude_string_get_string(idmef_alertident_get_alertident(alertident)));
                if ( ! anew )
                        break;

                if ( idmef_alertident_get_analyzerid(alertident) )
                        idmef_attr_string(anew, "analyzerid", idmef_alertident_get_analyzerid(alertident));
        }
}



static void process_alert(xmlNodePtr root, idmef_alert_t *alert) 
{
        xmlNodePtr new, anode;
        idmef_source_t *source;
        idmef_target_t *target;
        idmef_analyzer_t *analyzer = NULL;
        idmef_additional_data_t *additional_data;

        if ( ! alert )
                return;
        
        new = xmlNewChild(root, NULL, (const xmlChar *) "Alert", NULL);
        if ( ! new )
                return;
        
        idmef_attr_string(new, "messageid", idmef_alert_get_messageid(alert));

        anode = new;
        while ( (analyzer = idmef_alert_get_next_analyzer(alert, analyzer)) )      
                anode = process_analyzer(anode, analyzer);
        
        process_time(new, "CreateTime", idmef_alert_get_create_time(alert), TRUE);
        process_time(new, "DetectTime", idmef_alert_get_detect_time(alert), TRUE);
        process_time(new, "AnalyzerTime", idmef_alert_get_analyzer_time(alert), TRUE);
        
	source = NULL;
	while ( (source = idmef_alert_get_next_source(alert, source)) )
                process_source(new, source);

	target = NULL;
	while ( (target = idmef_alert_get_next_target(alert, target)) )
                process_target(new, target);

        process_classification(new, idmef_alert_get_classification(alert));
        process_assessment(new, idmef_alert_get_assessment(alert));
        process_correlation_alert(new, idmef_alert_get_correlation_alert(alert));
        
	additional_data = NULL;
	while ( (additional_data = idmef_alert_get_next_additional_data(alert, additional_data)) )
                process_additional_data(new, additional_data);
}





static void process_heartbeat(xmlNodePtr idmefmsg, idmef_heartbeat_t *heartbeat) 
{
        xmlNodePtr hb, anode;
        idmef_analyzer_t *analyzer = NULL;
        idmef_additional_data_t *additional_data;

        if ( ! heartbeat )
                return;
        
        hb = xmlNewChild(idmefmsg, NULL, (const xmlChar *) "Heartbeat", NULL);
        if ( ! hb )
                return;

	idmef_attr_string(hb, "messageid", idmef_heartbeat_get_messageid(heartbeat));

        anode = hb;
        while ( (analyzer = idmef_heartbeat_get_next_analyzer(heartbeat, analyzer)) )      
                anode = process_analyzer(anode, analyzer);
        
        process_time(hb, "CreateTime", idmef_heartbeat_get_create_time(heartbeat), TRUE);
        process_time(hb, "AnalyzerTime", idmef_heartbeat_get_analyzer_time(heartbeat), TRUE);

	additional_data = NULL;
	while ( (additional_data = idmef_heartbeat_get_next_additional_data(heartbeat, additional_data)) )
                process_additional_data(hb, additional_data);
}



static void validate_dtd(xmlmod_plugin_t *plugin, xmlDoc *doc) 
{
        xmlValidCtxt validation_context;

        memset(&validation_context, 0, sizeof(validation_context));
        
        validation_context.doc = doc;
        validation_context.userData = (void *) plugin->fd;
        validation_context.error = (xmlValidityErrorFunc) fprintf;
        validation_context.warning = (xmlValidityWarningFunc) fprintf;
        
        xmlValidateDtd(&validation_context, doc, plugin->idmef_dtd);
}


static void dump_document(xmlmod_plugin_t *plugin, xmlDoc *doc) 
{
        int ret;
        
        ret = xmlDocFormatDump(plugin->fd, doc, plugin->format);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "could not write IDMEF-XML data: '%s'.\n", strerror(errno));
                return -1;
        }
       
        if ( plugin->idmef_dtd )
                validate_dtd(plugin, doc);

        if ( ! plugin->no_buffering )
                fflush(plugin->fd);
}



static int xmlmod_run(prelude_plugin_instance_t *pi, idmef_message_t *message) 
{
        xmlNodePtr root;
        xmlDoc *document;
        xmlmod_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);
        
        document = xmlNewDoc((const xmlChar *) "1.0");
        if ( ! document ) {
                prelude_log(PRELUDE_LOG_ERR, "error creating XML document.\n");
                return -1;
        }
        
        root = xmlNewDocNode(document, NULL, (const xmlChar *) "IDMEF-Message", NULL);
        if ( ! root ) {
                xmlFreeDoc(document);
                return -1;
        }
        
        xmlDocSetRootElement(document, root);
                 
        switch ( idmef_message_get_type(message) ) {

        case IDMEF_MESSAGE_TYPE_ALERT:
                process_alert(root, idmef_message_get_alert(message));
                break;

        case IDMEF_MESSAGE_TYPE_HEARTBEAT:
                process_heartbeat(root, idmef_message_get_heartbeat(message));
                break;

        default:
                prelude_log(PRELUDE_LOG_ERR, "unknow message type: %d.\n", idmef_message_get_type(message));
                xmlFreeDoc(document);
                return -1;
        }

        dump_document(plugin, document);
        xmlFreeDoc(document);

        return 0;
}



static int xmlmod_init(prelude_plugin_instance_t *pi, prelude_string_t *out)
{
        int ret;
        xmlmod_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);
        
        if ( ! plugin->logfile ) {
                plugin->logfile = strdup("-");
                if ( ! plugin->logfile )
                        return prelude_error_from_errno(errno);
                
                plugin->fd = stdout;
        }
        
        else if ( strcmp(plugin->logfile, "-") == 0 )
                plugin->fd = stdout;
        
        else if ( ! (plugin->fd = fopen(plugin->logfile, "a+")) ) {
                prelude_string_sprintf(out, "error opening %s for writing", plugin->logfile);
                return -1;
        }
        
        return 0;
}



static void xmlmod_destroy(prelude_plugin_instance_t *pi, prelude_string_t *out)
{
        xmlmod_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);
        
        if ( plugin->fd && plugin->fd != stdout )
                fclose(plugin->fd);
        
        if ( plugin->logfile )
                free(plugin->logfile);

        free(plugin);
}




static int xmlmod_activate(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        xmlmod_plugin_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);
        
        prelude_plugin_instance_set_plugin_data(context, new);
        
        return 0;
}



static int set_dtd_check(prelude_option_t *option, const char *arg, prelude_string_t *err, void *context)
{
        xmlmod_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);

        if ( plugin->idmef_dtd && arg && strcasecmp(arg, "false") == 0 ) {
                xmlFreeDtd(plugin->idmef_dtd);
                plugin->idmef_dtd = NULL;
                return 0;
        }
                
        plugin->idmef_dtd = xmlParseDTD(NULL, (const xmlChar *) IDMEF_DTD);
        if ( ! plugin->idmef_dtd ) {
                prelude_string_sprintf(err, "error loading IDMEF DTD '%s'", IDMEF_DTD);
                return -1;
        }

        return 0;
}



static int enable_formatting(prelude_option_t *option, const char *arg, prelude_string_t *err, void *context)
{
        xmlmod_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        
        if ( ! arg )
                plugin->format = ! plugin->format;

        else {
                if ( strcasecmp(arg, "true") == 0 )
                        plugin->format = TRUE;

                else if ( strcasecmp(arg, "false") == 0 )
                        plugin->format = FALSE;
        }
        
        return 0;
}



static int get_formatting(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        xmlmod_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        
        prelude_string_sprintf(out, "%s", plugin->format ? "true" : "false");

        return 0;
}



static int disable_buffering(prelude_option_t *option, const char *arg, prelude_string_t *err, void *context)
{
        xmlmod_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);

        if ( ! arg )
                plugin->no_buffering = ! plugin->no_buffering;        
        else {
                if ( strcasecmp(arg, "true") == 0 )
                        plugin->no_buffering = TRUE;
                else
                        plugin->no_buffering = FALSE;
        }
        
        return 0;
}



int xmlmod_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *rootopt) 
{
        int ret;
	prelude_option_t *opt, *cur;
        static manager_report_plugin_t xmlmod_plugin;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;
        
        xmlInitParser();
        
        ret = prelude_option_add(rootopt, &opt, hook, 0, "xmlmod", "Option for the xmlmod plugin",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, xmlmod_activate, NULL);
        if ( ret < 0 )
                return ret;
        
        prelude_plugin_set_activation_option(pe, opt, xmlmod_init);
        
        ret = prelude_option_add(opt, NULL, hook, 'l', "logfile", "Specify output file to use",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, xmlmod_set_logfile, xmlmod_get_logfile);
        if ( ret < 0 )
                return ret;
        
        ret = prelude_option_add(opt, &cur, hook, 'v', "validate", "Validate IDMEF XML output against DTD",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, set_dtd_check, NULL);
        if ( ret < 0 )
                return ret;
        prelude_option_set_input_type(cur, PRELUDE_OPTION_INPUT_TYPE_BOOLEAN);
        
        ret = prelude_option_add(opt, &cur, hook, 'f', "format", "Format XML output so that it is readable",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, enable_formatting, get_formatting);
        if ( ret < 0 )
                return ret;
        prelude_option_set_input_type(cur, PRELUDE_OPTION_INPUT_TYPE_BOOLEAN);
        
        ret = prelude_option_add(opt, NULL, hook, 'd', "disable-buffering",
                                 "Disable output file buffering to prevent truncated tags",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, disable_buffering, NULL);
        if ( ret < 0 )
                return ret;
        
        prelude_plugin_set_name(&xmlmod_plugin, "XmlMod");
        prelude_plugin_set_destroy_func(&xmlmod_plugin, xmlmod_destroy);
        manager_report_plugin_set_running_func(&xmlmod_plugin, xmlmod_run);
        
        prelude_plugin_entry_set_plugin(pe, (void *) &xmlmod_plugin);
        
        return 0;
}



int xmlmod_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}
