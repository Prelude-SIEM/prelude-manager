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
#include "libmissing.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include "prelude-manager.h"


int textmod_LTX_prelude_plugin_version(void);
int textmod_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *rootopt);


typedef struct {
        FILE *fd;
        char *logfile;
} textmod_plugin_t;



PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(textmod, textmod_plugin_t, logfile)
static void process_file(textmod_plugin_t *plugin, int depth, idmef_file_t *file);



static void do_print(FILE *fd, int depth, const char *fmt, va_list ap) 
{
        int i;
        
        for ( i = 0; i < depth; i++ )
                fprintf(fd, " ");
        
        vfprintf(fd, fmt, ap);
}




static void print(textmod_plugin_t *plugin, int depth, const char *fmt, ...) 
{
        va_list ap;

        /*
         * we have to call va_start() / va_end() once by
         * do_print(plugin, ) call. It'll SIGSEGV on some architecture otherwise.
         */
        va_start(ap, fmt);
        do_print(plugin->fd, depth, fmt, ap);
        va_end(ap);
}



static void print_string(textmod_plugin_t *plugin, int depth, const char *format, prelude_string_t *string)
{
	const char *content;

	if ( ! string )
		return;

	content = prelude_string_get_string(string);
	print(plugin, depth, format, content ? content : "");
}




static void process_time(textmod_plugin_t *plugin, const char *type, idmef_time_t *time) 
{
        int ret;
	time_t t;
	struct tm tm;
        size_t len = 0;
        char time_human[64];
        prelude_string_t *ntpstamp;
        
        if ( ! time )
                return;
        
	t = idmef_time_get_sec(time);

	if ( ! localtime_r(&t, &tm) ) {
                prelude_log(PRELUDE_LOG_ERR, "error converting timestamp to local time.\n");
                return;
        }

        len = strftime(time_human, sizeof(time_human), "%Y-%m-%d %H:%M:%S", &tm);
        if ( len == 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error converting UTC time to string.\n");
                return;
        }
        
        len += ret = snprintf(time_human + len, sizeof(time_human) - len, ".%u%+.2d:%.2d",
                              idmef_time_get_usec(time), idmef_time_get_gmt_offset(time) / 3600,
                              idmef_time_get_gmt_offset(time) % 3600 / 60);
        if ( ret < 0 || len >= sizeof(time_human) ) {
                prelude_log(PRELUDE_LOG_ERR, "error converting UTC time to string.\n");
                return;
        }
        
        ret = prelude_string_new(&ntpstamp);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating object");
                return;
        }
        
        idmef_time_to_ntpstamp(time, ntpstamp);

        print(plugin, 0, "%s: %s (%s)\n", type, prelude_string_get_string(ntpstamp), time_human);
        prelude_string_destroy(ntpstamp);
}



static void process_address(textmod_plugin_t *plugin, int depth, idmef_address_t *address) 
{
        if ( ! address )
                return;
        
        print(plugin, 0, "* Addr[%s]:", idmef_address_category_to_string(idmef_address_get_category(address)));
        
	print_string(plugin, 0, " %s", idmef_address_get_address(address));
	print_string(plugin, 0, "/%s", idmef_address_get_netmask(address));
	print_string(plugin, 0, " vlan=%s", idmef_address_get_vlan_name(address));

        if ( idmef_address_get_vlan_num(address) )
                print(plugin, 0, " vnum=%u", * idmef_address_get_vlan_num(address));

        print(plugin, 0, "\n");
}




static void process_node(textmod_plugin_t *plugin, int depth, idmef_node_t *node) 
{
        idmef_address_t *address;

        if ( ! node )
                return;

        print(plugin, 0, "* Node[%s]:", idmef_node_category_to_string(idmef_node_get_category(node)));

	print_string(plugin, depth, " name:%s", idmef_node_get_name(node));
	print_string(plugin, depth, " location:%s", idmef_node_get_location(node));

        print(plugin, 0, "\n");

	address = NULL;
	while ( (address = idmef_node_get_next_address(node, address)) ) {
		process_address(plugin, depth + 1, address);
	}
}




static void process_user_id(textmod_plugin_t *plugin, int depth, idmef_user_id_t *user_id) 
{
        uint32_t *number;
        
        if ( ! user_id )
                return;
        
        print(plugin, 0, "*");
        print(plugin, depth, "");
        
	print_string(plugin, 0, " name=%s", idmef_user_id_get_name(user_id));

        number = idmef_user_id_get_number(user_id);
        if ( number ) 
                print(plugin, 0, " number=%u", *number);

	print(plugin, 0, " type=%s\n", idmef_user_id_type_to_string(idmef_user_id_get_type(user_id)));
}



static void process_user(textmod_plugin_t *plugin, int depth, idmef_user_t *user) 
{
        idmef_user_id_t *user_id;

        if ( ! user )
                return;

	print(plugin, 0, "* %s user: \n", idmef_user_category_to_string(idmef_user_get_category(user)));

	user_id = NULL;
	while ( (user_id = idmef_user_get_next_user_id(user, user_id)) ) 
		process_user_id(plugin, depth + 1, user_id);
}




static void process_process(textmod_plugin_t *plugin, int depth, idmef_process_t *process)
{
        int header;
        uint32_t *pid;
	prelude_string_t *string;

        if ( ! process )
                return;

        pid = idmef_process_get_pid(process);
        if ( pid )
                print(plugin, depth, "* Process: pid=%u", *pid);
        
	print_string(plugin, 0, " name=%s", idmef_process_get_name(process));
        
	print_string(plugin, 0, " path=%s", idmef_process_get_path(process));

	header = 0;
	string = NULL;
	while ( (string = idmef_process_get_next_arg(process, string)) ) {
		if ( ! header ) {
			print(plugin, depth, " arg: ");
			header = 1;
		}

		print(plugin, depth, "%s ", prelude_string_get_string(string));
	}

	header = 0;
	string = NULL;
	while ( (string = idmef_process_get_next_env(process, string)) ) {
		if ( ! header ) {
			print(plugin, depth, " env: ");
			header = 1;
		}

		print(plugin, depth, "%s ", prelude_string_get_string(string));
	}

        print(plugin, 0, "\n");
}




static void process_snmp_service(textmod_plugin_t *plugin, idmef_snmp_service_t *snmp) 
{
        if ( ! snmp )
                return;
        
	print_string(plugin, 0, " oid=%s", idmef_snmp_service_get_oid(snmp));

	print_string(plugin, 0, " community=%s", idmef_snmp_service_get_community(snmp));

	print_string(plugin, 0, " security_name=%s", idmef_snmp_service_get_security_name(snmp));

	print_string(plugin, 0, " context_name=%s", idmef_snmp_service_get_context_name(snmp));

	print_string(plugin, 0, " context_engine_id=%s", idmef_snmp_service_get_context_engine_id(snmp));

	print_string(plugin, 0, " command=%s", idmef_snmp_service_get_command(snmp));

}




static void process_web_service(textmod_plugin_t *plugin, idmef_web_service_t *web) 
{
	int header;
	prelude_string_t *string;

        if ( ! web )
                return;

	print_string(plugin, 0, " url=%s", idmef_web_service_get_url(web));

	print_string(plugin, 0, " cgi=%s", idmef_web_service_get_cgi(web));

	print_string(plugin, 0, " http method=%s", idmef_web_service_get_http_method(web));

	header = 0;
	string = NULL;
	while ( (string = idmef_web_service_get_next_arg(web, string)) ) {
		if ( ! header ) {
			print(plugin, 0, " arg: ");
			header = 1;
		}

		print(plugin, 0, "%s ", prelude_string_get_string(string));
	}

}



static void process_service(textmod_plugin_t *plugin, int depth, idmef_service_t *service) 
{
        uint16_t *port;
        uint8_t *ip_v, *iana_protocol_number;
        
        if ( ! service )
                return;

        print(plugin, depth, "* Service:");

        ip_v = idmef_service_get_ip_version(service);
        if ( ip_v )
                print(plugin, 0, " ip_version=%u", (unsigned int) *ip_v);

        iana_protocol_number = idmef_service_get_iana_protocol_number(service);
        if ( iana_protocol_number )
                print(plugin, 0, " iana_protocol_number=%u", (unsigned int) *iana_protocol_number);

	print_string(plugin, 0, " iana_protocol_name=%s", idmef_service_get_iana_protocol_name(service));
        
        port = idmef_service_get_port(service);
        if ( port )
                print(plugin, 0, " port=%hu", *port);
        
	print_string(plugin, 0, " (%s)", idmef_service_get_name(service));
        
	print_string(plugin, 0, " protocol=%s", idmef_service_get_protocol(service));
        
        switch ( idmef_service_get_type(service) ) {

        case IDMEF_SERVICE_TYPE_WEB:
                process_web_service(plugin, idmef_service_get_web_service(service));
                break;

        case IDMEF_SERVICE_TYPE_SNMP:
                process_snmp_service(plugin, idmef_service_get_snmp_service(service));
                break;

        default:
                /* nop */;
        }

        print(plugin, 0, "\n");
}



static void process_source(textmod_plugin_t *plugin, int depth, idmef_source_t *source)
{
        if ( ! source )
                return;
        
	print(plugin, depth, "* Source spoofed: %s\n", idmef_source_spoofed_to_string(idmef_source_get_spoofed(source)));

	print_string(plugin, depth, "* Source interface=%s\n", idmef_source_get_interface(source));
        
        process_node(plugin, depth, idmef_source_get_node(source));
        process_service(plugin, depth, idmef_source_get_service(source));
        process_process(plugin, depth, idmef_source_get_process(source));
        process_user(plugin, depth, idmef_source_get_user(source));
}



static void process_file_access(textmod_plugin_t *plugin, int depth, idmef_file_access_t *file_access) 
{
	int header;
	prelude_string_t *permission;

        if ( ! file_access )
                return;
        
	print(plugin, depth, "Access: ");

	header = 0;
	permission = NULL;
        
	while ( (permission = idmef_file_access_get_next_permission(file_access, permission)) ) {
		if ( ! header ) {
			print(plugin, depth, " permission: ");
			header = 1;
		}

		print(plugin, depth, "%s ", prelude_string_get_string(permission));
	}

	process_user_id(plugin, depth + 1, idmef_file_access_get_user_id(file_access));
}



static void process_file_linkage(textmod_plugin_t *plugin, int depth, idmef_linkage_t *linkage) 
{
        if ( ! linkage )
                return;
        
	print(plugin, depth, "Linkage: %s",
	      idmef_linkage_category_to_string(idmef_linkage_get_category(linkage)));

	print_string(plugin, 0, " name=%s", idmef_linkage_get_name(linkage));

	print_string(plugin, 0, " path=%s", idmef_linkage_get_path(linkage));

	if ( idmef_linkage_get_file(linkage) )
		process_file(plugin, depth, idmef_linkage_get_file(linkage));
}




static void process_inode(textmod_plugin_t *plugin, int depth, idmef_inode_t *inode) 
{
        if ( ! inode )
                return;
        
        print(plugin, depth, "* Inode:");

        if ( idmef_inode_get_number(inode) )
                print(plugin, 0, " number=%u", * idmef_inode_get_number(inode));

        if ( idmef_inode_get_major_device(inode) )
                print(plugin, 0, " major=%u", * idmef_inode_get_major_device(inode));

        if ( idmef_inode_get_minor_device(inode) )
                print(plugin, 0, " minor=%u", * idmef_inode_get_minor_device(inode));

        if ( idmef_inode_get_c_major_device(inode) )
                print(plugin, 0, " c_major=%u", * idmef_inode_get_c_major_device(inode));

        if ( idmef_inode_get_c_minor_device(inode) )
                print(plugin, 0, " c_minor=%u", * idmef_inode_get_c_minor_device(inode));

        print(plugin, 0, "\n");
        
        process_time(plugin, " ctime=", idmef_inode_get_change_time(inode));
}




static void process_file(textmod_plugin_t *plugin, int depth, idmef_file_t *file) 
{
        idmef_file_fstype_t *fstype;
	idmef_linkage_t *file_linkage;
	idmef_file_access_t *file_access;
        
        if ( ! file )
                return;
        
        print(plugin, 0, "* ");
        
        print(plugin, depth, "File %s: ",
	      idmef_file_category_to_string(idmef_file_get_category(file)));

        fstype = idmef_file_get_fstype(file);
        if ( fstype )
                print(plugin, 0, " fstype=%s", idmef_file_fstype_to_string(*fstype));

	print_string(plugin, 0, " name=%s", idmef_file_get_name(file));

	print_string(plugin, 0, " path=%s", idmef_file_get_path(file));
        
        if ( idmef_file_get_data_size(file) )
                print(plugin, 0, " dsize=%u", * idmef_file_get_data_size(file));

        if ( idmef_file_get_disk_size(file) )
                print(plugin, 0, " disk-size=%u", * idmef_file_get_disk_size(file));

        print(plugin, 0, "\n");
        
        process_time(plugin, "* ctime=", idmef_file_get_create_time(file));
        process_time(plugin, "* mtime=", idmef_file_get_modify_time(file));
        process_time(plugin, "* atime=", idmef_file_get_access_time(file));
        
	file_access = NULL;
	while ( (file_access = idmef_file_get_next_file_access(file, file_access)) )
		process_file_access(plugin, depth, file_access);

	file_linkage = NULL;
	while ( (file_linkage = idmef_file_get_next_linkage(file, file_linkage)) )
		process_file_linkage(plugin, depth, file_linkage);

        process_inode(plugin, depth, idmef_file_get_inode(file));
}




static void process_target(textmod_plugin_t *plugin, int depth, idmef_target_t *target)
{
        idmef_file_t *file;

        if ( ! target )
                return;
        
        print(plugin, 0, "* Target decoy: %s\n", 
	      idmef_target_decoy_to_string(idmef_target_get_decoy(target)));
        
	print_string(plugin, 0, "* Target Interface: %s\n", idmef_target_get_interface(target));
        
        process_node(plugin, 0, idmef_target_get_node(target));
        process_service(plugin, 0, idmef_target_get_service(target));
        process_process(plugin, 0, idmef_target_get_process(target));
        process_user(plugin, 0, idmef_target_get_user(target));

	file = NULL;
	while ( (file = idmef_target_get_next_file(target, file)) )
		process_file(plugin, depth, file);
}



static void process_analyzer(textmod_plugin_t *plugin, idmef_analyzer_t *analyzer) 
{
        if ( ! analyzer )
                return;
        
	print_string(plugin, 0, "* Analyzer ID: %s\n", idmef_analyzer_get_analyzerid(analyzer));
        print_string(plugin, 0, "* Analyzer name: %s\n", idmef_analyzer_get_name(analyzer));
	print_string(plugin, 0, "* Analyzer model: %s\n", idmef_analyzer_get_model(analyzer));
	print_string(plugin, 0, "* Analyzer version: %s\n", idmef_analyzer_get_version(analyzer));
	print_string(plugin, 0, "* Analyzer class: %s\n", idmef_analyzer_get_class(analyzer));
	print_string(plugin, 0, "* Analyzer manufacturer: %s\n", idmef_analyzer_get_manufacturer(analyzer));
	print_string(plugin, 0, "* Analyzer OS type: %s\n", idmef_analyzer_get_ostype(analyzer));
	print_string(plugin, 0, "* Analyzer OS version: %s\n", idmef_analyzer_get_osversion(analyzer));

        if ( idmef_analyzer_get_node(analyzer) )
                process_node(plugin, 0, idmef_analyzer_get_node(analyzer));

        if ( idmef_analyzer_get_process(analyzer) )
                process_process(plugin, 0, idmef_analyzer_get_process(analyzer));
}


static void process_reference(textmod_plugin_t *plugin, idmef_reference_t *reference) 
{        
        print(plugin, 0, "* Reference origin: %s\n",
              idmef_reference_origin_to_string(idmef_reference_get_origin(reference)));

        print_string(plugin, 0, "* Reference name: %s\n", idmef_reference_get_name(reference));

        print_string(plugin, 0, "* Reference url: %s\n", idmef_reference_get_url(reference));
}




static void process_classification(textmod_plugin_t *plugin, idmef_classification_t *classification) 
{
        idmef_reference_t *reference;
        
        if ( ! classification )
                return;
        
        print_string(plugin, 0, "* Classification ident: %s\n", idmef_classification_get_ident(classification));

        print_string(plugin, 0, "* Classification text: %s\n", idmef_classification_get_text(classification));

        reference = NULL;
	while ( (reference = idmef_classification_get_next_reference(classification, reference)) )
		process_reference(plugin, reference);
        
        print(plugin, 0, "*\n");
}



static void process_data(textmod_plugin_t *plugin, idmef_additional_data_t *ad) 
{
        int ret;
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

	print_string(plugin, 0, "* %s:", idmef_additional_data_get_meaning(ad));
        
	if ( prelude_string_get_len(out) <= 80 )
                print(plugin, 0, " %s\n", prelude_string_get_string(out));
        else
                print(plugin, 0, "\n%s\n", prelude_string_get_string(out));

        prelude_string_destroy(out);
}




static void process_impact(textmod_plugin_t *plugin, idmef_impact_t *impact) 
{
        idmef_impact_severity_t *severity;
        idmef_impact_completion_t *completion;
        
        if ( ! impact )
                return;

        severity = idmef_impact_get_severity(impact);
        if ( severity )
                print(plugin, 0, "* Impact severity: %s\n",
                      idmef_impact_severity_to_string(*severity));

        completion = idmef_impact_get_completion(impact);
        if ( completion )
                print(plugin, 0, "* Impact completion: %s\n",
                      idmef_impact_completion_to_string(*completion));

        print(plugin, 0, "* Impact type: %s\n", 
	      idmef_impact_type_to_string(idmef_impact_get_type(impact)));

        print_string(plugin, 0, "* Impact description: %s\n",  idmef_impact_get_description(impact));
}



static void process_confidence(textmod_plugin_t *plugin, idmef_confidence_t *confidence) 
{
        if ( ! confidence )
                return;
        
        print(plugin, 0, "* Confidence rating: %s\n",
	      idmef_confidence_rating_to_string(idmef_confidence_get_rating(confidence)));

        if ( idmef_confidence_get_rating(confidence) == IDMEF_CONFIDENCE_RATING_NUMERIC )
                print(plugin, 0, "* Confidence value: %f\n", idmef_confidence_get_confidence(confidence));
}




static void process_action(textmod_plugin_t *plugin, idmef_action_t *action) 
{
        if ( ! action )
                return;
        
        print(plugin, 0, "* Action category: %s\n",
	      idmef_action_category_to_string(idmef_action_get_category(action)));

        print_string(plugin, 0, "* Action description: %s\n", idmef_action_get_description(action));
}




static void process_assessment(textmod_plugin_t *plugin, idmef_assessment_t *assessment) 
{
        idmef_action_t *action;

        if ( ! assessment )
                return;
        
        process_impact(plugin, idmef_assessment_get_impact(assessment));

        print(plugin, 0, "*\n");

        process_confidence(plugin, idmef_assessment_get_confidence(assessment));

	action = NULL;
	while ( (action = idmef_assessment_get_next_action(assessment, action)) ) {
		print(plugin, 0, "*\n");
		process_action(plugin, action);
	}

        print(plugin, 0, "*\n");
}





static void process_alert(textmod_plugin_t *plugin, idmef_alert_t *alert) 
{
        int header;
        idmef_source_t *source;
        idmef_target_t *target;
        idmef_analyzer_t *analyzer;
        idmef_additional_data_t *data;

        if ( ! alert )
                return;
        
        print(plugin, 0, "********************************************************************************\n");
        print_string(plugin, 0, "* Alert: ident=%s\n", idmef_alert_get_messageid(alert));
        
        process_classification(plugin, idmef_alert_get_classification(alert));
        
        process_time(plugin, "* Creation time", idmef_alert_get_create_time(alert));
        process_time(plugin, "* Detection time", idmef_alert_get_detect_time(alert));
        process_time(plugin, "* Analyzer time", idmef_alert_get_analyzer_time(alert));

        analyzer = NULL;
        while ( (analyzer = idmef_alert_get_next_analyzer(alert, analyzer)) )
                process_analyzer(plugin, analyzer);

        print(plugin, 0, "*\n");

        process_assessment(plugin, idmef_alert_get_assessment(alert));

	header = 0;
	source = NULL;
	while ( (source = idmef_alert_get_next_source(alert, source)) ) {
		if ( ! header ) {
			print(plugin, 0, "*** Source information ********************************************************\n");
			header = 1;
		}

		process_source(plugin, 0, source);
	}

	header = 0;
	target = NULL;
	while ( (target = idmef_alert_get_next_target(alert, target)) ) {
		if ( ! header ) {
			print(plugin, 0, "*\n*** Target information ********************************************************\n");
			header = 1;
		}

		process_target(plugin, 0, target);
	}

	header = 0;
	data = NULL;
	while ( (data = idmef_alert_get_next_additional_data(alert, data)) ) {
		if ( ! header ) {
			print(plugin, 0, "*\n*** Additional data within the alert  ******************************************\n");
			header = 1;
		}

		process_data(plugin, data);
	}

        print(plugin, 0, "*\n********************************************************************************\n\n");
}





static void process_heartbeat(textmod_plugin_t *plugin, idmef_heartbeat_t *heartbeat) 
{
        idmef_analyzer_t *analyzer;
	idmef_additional_data_t *data;

        if ( ! heartbeat )
                return;
        
        print(plugin, 0, "********************************************************************************\n");
        print_string(plugin, 0, "* Heartbeat: ident=%s\n", idmef_heartbeat_get_messageid(heartbeat));

        analyzer = NULL;
        while ( (analyzer = idmef_heartbeat_get_next_analyzer(heartbeat, analyzer)) ) 
                process_analyzer(plugin, analyzer);
        
        process_time(plugin, "* Creation time", idmef_heartbeat_get_create_time(heartbeat));
        process_time(plugin, "* Analyzer time", idmef_heartbeat_get_analyzer_time(heartbeat));

	data = NULL;
	while ( (data = idmef_heartbeat_get_next_additional_data(heartbeat, data)) )
                process_data(plugin, data);

        print(plugin, 0, "*\n********************************************************************************\n\n");
}




static int textmod_run(prelude_plugin_instance_t *pi, idmef_message_t *message) 
{
        textmod_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);
        
        switch ( idmef_message_get_type(message) ) {

        case IDMEF_MESSAGE_TYPE_ALERT:
                process_alert(plugin, idmef_message_get_alert(message));
                break;

        case IDMEF_MESSAGE_TYPE_HEARTBEAT:
                process_heartbeat(plugin, idmef_message_get_heartbeat(message));
                break;

        default:
                prelude_log(PRELUDE_LOG_WARN, "unknow message type: %d.\n", idmef_message_get_type(message));
                break;
        }
        
        fflush(plugin->fd);
        
        return 0;
}




static int textmod_init(prelude_plugin_instance_t *pi, prelude_string_t *out)
{
        FILE *fd;
        textmod_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);
        
        if ( ! plugin->logfile ) {
                prelude_string_sprintf(out, "no logfile specified");
                return -1;
        }
        
        if ( strcmp(plugin->logfile, "stdout") == 0 )
                fd = stdout;

        else if ( strcmp(plugin->logfile, "stderr") == 0 )
                fd = stderr;
        
        else {
                fd = fopen(plugin->logfile, "a+");
                if ( ! fd ) {
                        prelude_string_sprintf(out, "error opening %s in append mode", plugin->logfile);
                        return -1;
                }
        }
        
        plugin->fd = fd;
        
        return 0;
}




static int textmod_activate(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context) 
{
        textmod_plugin_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);

        prelude_plugin_instance_set_plugin_data(context, new);
        
        return 0;
}




static void textmod_destroy(prelude_plugin_instance_t *pi, prelude_string_t *err)
{
        textmod_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        if ( plugin->fd && plugin->fd != stderr )
                fclose(plugin->fd);

        if ( plugin->logfile )
                free(plugin->logfile);
        
        free(plugin);
}



int textmod_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *rootopt)
{
        int ret;
	prelude_option_t *opt;
        static manager_report_plugin_t textmod_plugin;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;
        
        ret = prelude_option_add(rootopt, &opt, hook, 0, "textmod", "Option for the textmod plugin",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, textmod_activate, NULL);
        if ( ret < 0 )
                return ret;

        prelude_plugin_set_activation_option(pe, opt, textmod_init);
        
        ret = prelude_option_add(opt, NULL, hook, 'l', "logfile", "Specify logfile to use",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED,
                                 textmod_set_logfile, textmod_get_logfile);
        if ( ret < 0 )
                return ret;
        
        prelude_plugin_set_name(&textmod_plugin, "TextMod");
        prelude_plugin_set_destroy_func(&textmod_plugin, textmod_destroy);
        manager_report_plugin_set_running_func(&textmod_plugin, textmod_run);

        prelude_plugin_entry_set_plugin(pe, (void *) &textmod_plugin);
        
        return 0;
}



int textmod_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}
