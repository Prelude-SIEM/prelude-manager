/*****
*
* Copyright (C) 2002, 2003, 2004 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <string.h>
#include <stdarg.h>
#include <libprelude/list.h>
#include <libprelude/idmef.h>
#include <libprelude/idmef-util.h>

#include "report.h"
#include "idmef-util.h"

static void process_file(int depth, idmef_file_t *file);


static FILE *out_fd = NULL;
static plugin_report_t plugin;
static const char *logfile = NULL;
static int enabled = 0, out_stderr = 0;


static void do_print(FILE *fd, int depth, const char *fmt, va_list ap) 
{
        int i;
        
        for ( i = 0; i < depth; i++ )
                fprintf(fd, " ");
        
        vfprintf(fd, fmt, ap);
}




static void print(int depth, const char *fmt, ...) 
{
        va_list ap;

        /*
         * we have to call va_start() / va_end() once by
         * do_print() call. It'll SIGSEGV on some architecture otherwise.
         */
        if ( out_fd ) {
                va_start(ap, fmt);
                do_print(out_fd, depth, fmt, ap);
                va_end(ap);
        }
        
        if ( out_stderr ) {
                va_start(ap, fmt);
                do_print(stderr, depth, fmt, ap);
                va_end(ap);
        }
}



static void process_time(const char *type, idmef_time_t *time) 
{
        char utc_time[MAX_UTC_DATETIME_SIZE], ntpstamp[MAX_NTP_TIMESTAMP_SIZE];

        if ( ! time )
                return;
        
        idmef_time_get_timestamp(time, utc_time, sizeof(utc_time));
        idmef_time_get_ntp_timestamp(time, ntpstamp, sizeof(ntpstamp));

        print(0, "%s: %s (%s)\n", type, ntpstamp, utc_time);
}



static void process_address(int depth, idmef_address_t *address) 
{
        print(0, "* Addr[%s]:", idmef_address_category_to_string(idmef_address_get_category(address)));
        
        if ( idmef_string(idmef_address_get_address(address)) )
                print(0, " %s", idmef_string(idmef_address_get_address(address)));

        if ( idmef_string(idmef_address_get_netmask(address)) )
                print(0, "/%s", idmef_string(idmef_address_get_netmask(address)));

        if ( idmef_string(idmef_address_get_vlan_name(address)) )
                print(0, " vlan=%s", idmef_string(idmef_address_get_vlan_name(address)));

        if ( idmef_address_get_vlan_num(address) )
                print(0, " vnum=%u", idmef_address_get_vlan_num(address));

        print(0, "\n");
}




static void process_node(int depth, idmef_node_t *node) 
{
        idmef_address_t *address;

        if ( ! node )
                return;

        print(0, "* Node[%s]:", idmef_node_category_to_string(idmef_node_get_category(node)));

        if ( idmef_string(idmef_node_get_name(node)) )
                print(depth, " name:%s", idmef_string(idmef_node_get_name(node)));

        if ( idmef_string(idmef_node_get_location(node)) )
                print(depth, " location:%s", idmef_string(idmef_node_get_location(node)));

        print(0, "\n");

	address = NULL;
	while ( (address = idmef_node_get_next_address(node, address)) ) {
		process_address(depth + 1, address);
	}
}




static void process_userid(int depth, idmef_userid_t *userid) 
{
        const char *type;
        
        print(0, "*");
        print(depth, "");
        
        if ( idmef_string(idmef_userid_get_name(userid)) )
                print(0, " name=%s", idmef_string(idmef_userid_get_name(userid)));

        print(0, " number=%u", idmef_userid_get_number(userid));

        type = idmef_userid_type_to_string(idmef_userid_get_type(userid));
        if ( type )
                print(0, " type=%s\n", type);
}



static void process_user(int depth, idmef_user_t *user) 
{
        idmef_userid_t *userid;
        const char *category;

        if ( ! user )
                return;

        category = idmef_user_category_to_string(idmef_user_get_category(user));
        if ( category )
                print(0, "* %s user: \n", category);

	userid = NULL;
	while ( (userid = idmef_user_get_next_userid(user, userid)) ) {
		process_userid(depth + 1, userid);
	}
}




static void process_process(int depth, idmef_process_t *process)
{
	idmef_string_t *string;
	int header;

        if ( ! process )
                return;

        print(depth, "* Process: pid=%u", idmef_process_get_pid(process));
        
        if ( idmef_string(idmef_process_get_name(process)) )
                print(0, " name=%s", idmef_string(idmef_process_get_name(process)));
        
        if ( idmef_string(idmef_process_get_path(process)) )
                print(0, " path=%s", idmef_string(idmef_process_get_path(process)));

	header = 0;
	string = NULL;
	while ( (string = idmef_process_get_next_arg(process, string)) ) {
		if ( ! header ) {
			print(depth, " arg: ");
			header = 1;
		}

		print(depth, "%s ", idmef_string(string));
	}

	header = 0;
	string = NULL;
	while ( (string = idmef_process_get_next_env(process, string)) ) {
		if ( ! header ) {
			print(depth, " env: ");
			header = 1;
		}

		print(depth, "%s ", idmef_string(string));
	}

        print(0, "\n");
}




static void process_snmp_service(idmef_snmpservice_t *snmp) 
{
        if ( idmef_string(idmef_snmpservice_get_oid(snmp)) )
                print(0, " oid=%s", idmef_string(idmef_snmpservice_get_oid(snmp)));

        if ( idmef_string(idmef_snmpservice_get_command(snmp)) )
                print(0, " command=%s", idmef_string(idmef_snmpservice_get_command(snmp)));

        if ( idmef_string(idmef_snmpservice_get_community(snmp)) )
                print(0, " community=%s", idmef_string(idmef_snmpservice_get_community(snmp)));
}




static void process_web_service(idmef_webservice_t *web) 
{        
        if ( ! web )
                return;

        if ( idmef_string(idmef_webservice_get_url(web)) )
                print(0, " url=%s", idmef_string(idmef_webservice_get_url(web)));

        if ( idmef_string(idmef_webservice_get_cgi(web)) )
                print(0, " cgi=%s", idmef_string(idmef_webservice_get_cgi(web)));

        if ( idmef_string(idmef_webservice_get_http_method(web)) )
                print(0, " http method=%s", idmef_string(idmef_webservice_get_http_method(web)));
}



static void process_service(int depth, idmef_service_t *service) 
{
        if ( ! service )
                return;

        print(depth, "* Service: port=%hu", idmef_service_get_port(service));
        
        if ( idmef_string(idmef_service_get_name(service)) )
                print(0, " (%s)", idmef_string(idmef_service_get_name(service)));
        
        if ( idmef_string(idmef_service_get_protocol(service)) )
                print(0, " protocol=%s", idmef_string(idmef_service_get_protocol(service)));
        
        switch ( idmef_service_get_type(service) ) {
        case web_service:
                process_web_service(idmef_service_get_web(service));
                break;

        case snmp_service:
                process_snmp_service(idmef_service_get_snmp(service));
                break;

        default:
                /* nop */;
        }

        print(0, "\n");
}



static void process_source(int depth, idmef_source_t *source)
{
        const char *spoofed;

        spoofed = idmef_spoofed_to_string(idmef_source_get_spoofed(source));
        if ( spoofed )
                print(depth, "* Source spoofed: %s\n", spoofed);

        if ( idmef_string(idmef_source_get_interface(source)) )
                print(depth, "* Source interface=%s\n", idmef_string(idmef_source_get_interface(source)));
        
        process_node(depth, idmef_source_get_node(source));
        process_service(depth, idmef_source_get_service(source));
        process_process(depth, idmef_source_get_process(source));
        process_user(depth, idmef_source_get_user(source));
}



static void process_file_access(int depth, idmef_file_access_t *file_access) 
{
	idmef_string_t *permission;
	int header;

	print(depth, "Access: ");

	header = 0;
	permission = NULL;
	while ( (permission = idmef_file_access_get_next_permission(file_access, permission)) ) {
		if ( ! header ) {
			print(depth, " permission: ");
			header = 1;
		}

		print(depth, "%s ", idmef_string(permission));
	}

	process_userid(0, idmef_file_access_get_userid(file_access));
}



static void process_file_linkage(int depth, idmef_linkage_t *linkage) 
{
	print(depth, "Linkage: %s",
	      idmef_linkage_category_to_string(idmef_linkage_get_category(linkage)));

	if ( idmef_string(idmef_linkage_get_name(linkage)) )
		print(0, " name=%s", idmef_string(idmef_linkage_get_name(linkage)));

	if ( idmef_string(idmef_linkage_get_path(linkage)) )
		print(0, " path=%s", idmef_string(idmef_linkage_get_path(linkage)));

	if ( idmef_linkage_get_file(linkage) )
		process_file(depth, idmef_linkage_get_file(linkage));
}




static void process_inode(int depth, idmef_inode_t *inode) 
{
        if ( ! inode )
                return;
        
        print(depth, "* Inode:");

        if ( idmef_inode_get_number(inode) )
                print(0, " number=%u", idmef_inode_get_number(inode));

        if ( idmef_inode_get_major_device(inode) )
                print(0, " major=%u", idmef_inode_get_major_device(inode));

        if ( idmef_inode_get_minor_device(inode) )
                print(0, " minor=%u", idmef_inode_get_minor_device(inode));

        if ( idmef_inode_get_c_major_device(inode) )
                print(0, " c_major=%u", idmef_inode_get_c_major_device(inode));

        if ( idmef_inode_get_c_minor_device(inode) )
                print(0, " c_minor=%u", idmef_inode_get_c_minor_device(inode));

        print(0, "\n");
        
        process_time(" ctime=", idmef_inode_get_change_time(inode));
}




static void process_file(int depth, idmef_file_t *file) 
{
	idmef_file_access_t *file_access;
	idmef_linkage_t *file_linkage;

        print(0, "* ");

        print(depth, "File %s: ",
	      idmef_file_category_to_string(idmef_file_get_category(file)));

        if ( idmef_string(idmef_file_get_fstype(file)) )
                print(0, " fstype=%s", idmef_string(idmef_file_get_fstype(file)));

        if ( idmef_string(idmef_file_get_name(file)) )
                print(0, " name=%s", idmef_string(idmef_file_get_name(file)));

        if ( idmef_string(idmef_file_get_path(file)) )
                print(0, " path=%s", idmef_string(idmef_file_get_path(file)));
        
        if ( idmef_file_get_data_size(file) )
                print(0, " dsize=%u", idmef_file_get_data_size(file));

        if ( idmef_file_get_disk_size(file) )
                print(0, " disk-size=%u", idmef_file_get_disk_size(file));

        print(0, "\n");
        
        process_time("* ctime=", idmef_file_get_create_time(file));
        process_time("* mtime=", idmef_file_get_modify_time(file));
        process_time("* atime=", idmef_file_get_access_time(file));

	file_access = NULL;
	while ( (file_access = idmef_file_get_next_file_access(file, file_access)) ) {
		process_file_access(depth, file_access);
	}

	file_linkage = NULL;
	while ( (file_linkage = idmef_file_get_next_file_linkage(file, file_linkage)) ) {
		process_file_linkage(depth, file_linkage);
	}

        process_inode(depth, idmef_file_get_inode(file));
}




static void process_target(int depth, idmef_target_t *target)
{
        idmef_file_t *file;

        print(0, "* Target decoy: %s\n", 
	      idmef_spoofed_to_string(idmef_target_get_decoy(target)));
        
        if ( idmef_string(idmef_target_get_interface(target)) )
                print(0, "* Target Interface: %s\n", idmef_string(idmef_target_get_interface(target)));
        
        process_node(0, idmef_target_get_node(target));
        process_service(0, idmef_target_get_service(target));
        process_process(0, idmef_target_get_process(target));
        process_user(0, idmef_target_get_user(target));

	file = NULL;
	while ( (file = idmef_target_get_next_file(target, file)) ) {
		process_file(0, file);
        }
}



static void process_analyzer(idmef_analyzer_t *analyzer) 
{
        if ( ! analyzer )
                return;
        
        if ( idmef_analyzer_get_analyzerid(analyzer) )
                print(0, "* Analyzer ID: %llu\n", idmef_analyzer_get_analyzerid(analyzer));
        
        if ( idmef_string(idmef_analyzer_get_model(analyzer)) )
                print(0, "* Analyzer model: %s\n", idmef_string(idmef_analyzer_get_model(analyzer)));

        if ( idmef_string(idmef_analyzer_get_version(analyzer)) )
                print(0, "* Analyzer version: %s\n", idmef_string(idmef_analyzer_get_version(analyzer)));

        if ( idmef_string(idmef_analyzer_get_class(analyzer)) )
                print(0, "* Analyzer class: %s\n", idmef_string(idmef_analyzer_get_class(analyzer)));
        
        if ( idmef_string(idmef_analyzer_get_manufacturer(analyzer)) )
                print(0, "* Analyzer manufacturer: %s\n", idmef_string(idmef_analyzer_get_manufacturer(analyzer)));

        if ( idmef_string(idmef_analyzer_get_ostype(analyzer)) )
                print(0, "* Analyzer OS type: %s\n", idmef_string(idmef_analyzer_get_ostype(analyzer)));
        
        if ( idmef_string(idmef_analyzer_get_osversion(analyzer)) )
                print(0, "* Analyzer OS version: %s\n", idmef_string(idmef_analyzer_get_osversion(analyzer)));

        if ( idmef_analyzer_get_node(analyzer) )
                process_node(0, idmef_analyzer_get_node(analyzer));

        if ( idmef_analyzer_get_process(analyzer) )
                process_process(0, idmef_analyzer_get_process(analyzer));
}



static void process_classification(idmef_classification_t *classification) 
{
        print(0, "* Classification type: %s\n",
	      idmef_classification_origin_to_string(idmef_classification_get_origin(classification)));

        print(0, "* Classification: %s\n",
	      idmef_string(idmef_classification_get_name(classification)));
        
        if ( idmef_string(idmef_classification_get_url(classification)) )
                print(0, "* Classification URL: %s\n", 
		      idmef_string(idmef_classification_get_url(classification)));
}



static void process_data(idmef_additional_data_t *ad) 
{
        const char *tmp;
        idmef_data_t *data;
        unsigned char buf[128];
        
        data = idmef_additional_data_get_data(ad);
        
        tmp = idmef_additionaldata_data_to_string(ad, buf, sizeof(buf));
        if ( ! tmp )
                return;
        
        if ( idmef_additional_data_get_type(ad) == byte )
                tmp = "<FIXME: binary data>";
        
	if ( idmef_data_get_len(data) <= 80 )
                print(0, "* %s: %s\n", 
		      idmef_string(idmef_additional_data_get_meaning(ad)), tmp);
        else
                print(0, "* %s:\n%s\n", 
		      idmef_string(idmef_additional_data_get_meaning(ad)), tmp);
}




static void process_impact(idmef_impact_t *impact) 
{
        if ( ! impact )
                return;
        
        print(0, "* Impact severity: %s\n",
	      idmef_impact_severity_to_string(idmef_impact_get_severity(impact)));

        print(0, "* Impact completion: %s\n",
	      idmef_impact_completion_to_string(idmef_impact_get_completion(impact)));

        print(0, "* Impact type: %s\n", 
	      idmef_impact_type_to_string(idmef_impact_get_type(impact)));

        print(0, "* Impact description: %s\n", 
	      idmef_string(idmef_impact_get_description(impact)));
}



static void process_confidence(idmef_confidence_t *confidence) 
{
        if ( ! confidence )
                return;
        
        print(0, "* Confidence rating: %s\n",
	      idmef_confidence_rating_to_string(idmef_confidence_get_rating(confidence)));

        if ( idmef_confidence_get_rating(confidence) == numeric )
                print(0, "* Confidence value: %f\n", idmef_confidence_get_confidence(confidence));
}




static void process_action(idmef_action_t *action) 
{
        print(0, "* Action category: %s\n",
	      idmef_action_category_to_string(idmef_action_get_category(action)));

        print(0, "* Action description: %s\n",
	      idmef_string(idmef_action_get_description(action)));
}




static void process_assessment(idmef_assessment_t *assessment) 
{
        idmef_action_t *action;

        if ( ! assessment )
                return;
        
        process_impact(idmef_assessment_get_impact(assessment));

        print(0, "*\n");

        process_confidence(idmef_assessment_get_confidence(assessment));

	action = NULL;
	while ( (action = idmef_assessment_get_next_action(assessment, action)) ) {
		print(0, "*\n");
		process_action(action);
	}

        print(0, "*\n");
}





static void process_alert(idmef_alert_t *alert) 
{
        idmef_source_t *source;
        idmef_target_t *target;
        idmef_classification_t *classification;
        idmef_additional_data_t *data;
	int header;

        print(0, "********************************************************************************\n");
        print(0, "* Alert: ident=%llu\n", idmef_alert_get_ident(alert));

	classification = NULL;
	while ( (classification = idmef_alert_get_next_classification(alert, classification)) ) {
		process_classification(classification);
		print(0, "*\n");
	}
        
        process_time("* Creation time", idmef_alert_get_create_time(alert));
        process_time("* Detection time", idmef_alert_get_detect_time(alert));
        process_time("* Analyzer time", idmef_alert_get_analyzer_time(alert));

        process_analyzer(idmef_alert_get_analyzer(alert));

        print(0, "*\n");

        process_assessment(idmef_alert_get_assessment(alert));

	header = 0;
	source = NULL;
	while ( (source = idmef_alert_get_next_source(alert, source)) ) {
		if ( ! header ) {
			print(0, "*** Source information ********************************************************\n");
			header = 1;
		}

		process_source(0, source);
	}

	header = 0;
	target = NULL;
	while ( (target = idmef_alert_get_next_target(alert, target)) ) {
		if ( ! header ) {
			print(0, "*\n*** Target information ********************************************************\n");
			header = 1;
		}

		process_target(0, target);
	}

	header = 0;
	data = NULL;
	while ( (data = idmef_alert_get_next_additional_data(alert, data)) ) {
		if ( ! header ) {
			print(0, "*\n*** Additional data within the alert  ******************************************\n");
			header = 1;
		}

		process_data(data);
	}

        print(0, "*\n********************************************************************************\n\n");
}





static void process_heartbeat(idmef_heartbeat_t *heartbeat) 
{
	idmef_additional_data_t *data;

        print(0, "********************************************************************************\n");
        print(0, "* Heartbeat: ident=%llu\n", idmef_heartbeat_get_ident(heartbeat));
        
        process_analyzer(idmef_heartbeat_get_analyzer(heartbeat));
        process_time("* Creation time", idmef_heartbeat_get_create_time(heartbeat));
        process_time("* Analyzer time", idmef_heartbeat_get_analyzer_time(heartbeat));

	data = NULL;
	while ( (data = idmef_heartbeat_get_next_additional_data(heartbeat, data)) ) {
		process_data(data);

	}

        print(0, "*\n********************************************************************************\n\n");
}




static void process_message(const idmef_message_t *message) 
{
        switch ( idmef_message_get_type(message) ) {

        case idmef_alert_message:
                process_alert(idmef_message_get_alert(message));
                break;

        case idmef_heartbeat_message:
                process_heartbeat(idmef_message_get_heartbeat(message));
                break;

        default:
                log(LOG_ERR, "unknow message type: %d.\n", idmef_message_get_type(message));
                break;
        }

        fflush(out_fd);
}



/*
 * plugin configuration stuff
 */
static int set_logfile(prelude_option_t *opt, const char *arg) 
{
        out_fd = fopen(arg, "a+");
        if ( ! out_fd ) {
                log(LOG_ERR, "error opening %s in append mode.\n", arg);
                return prelude_option_error;
        }
        
        logfile = strdup(arg);
        
        return prelude_option_success;
}



static int get_logfile(char *buf, size_t size) 
{
        snprintf(buf, size, "%s", logfile);
        return prelude_option_success;  
}



static int set_output_stderr(prelude_option_t *opt, const char *arg) 
{
        out_stderr = 1;
        return prelude_option_success;
}



static int get_output_stderr(char *buf, size_t size) 
{
        snprintf(buf, size, "%s", (out_stderr == 1) ? "enabled" : "disabled");
        return prelude_option_success;
}




static int set_textmod_state(prelude_option_t *opt, const char *arg) 
{
        int ret;
        
        if ( enabled == 1 ) {
                ret = plugin_unsubscribe((plugin_generic_t *) &plugin);
                if ( ret < 0 )
                        return prelude_option_error;
                enabled = 0;
        } else {
                
                /*
                 * prelude-getopt call callback for sub-option first,
                 * so we have a way to handle dependancy.
                 */
                if ( ! out_fd && ! out_stderr )
                        /*
                         * no suboption set - do nothing.
                         */
                        return prelude_option_success;
                
                ret = plugin_subscribe((plugin_generic_t *) &plugin);
                if ( ret < 0 )
                        return prelude_option_error;
                
                enabled = 1;
        }
        
        return prelude_option_success;
}



static int get_textmod_state(char *buf, size_t size) 
{
        snprintf(buf, size, "%s", (enabled == 1) ? "enabled" : "disabled");
        return prelude_option_success;
}



plugin_generic_t *plugin_init(int argc, char **argv)
{
	prelude_option_t *opt;
        
        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 0, "textmod",
                                 "Option for the textmod plugin", no_argument,
                                 set_textmod_state, get_textmod_state);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'l', "logfile",
                           "Specify logfile to use", required_argument,
                           set_logfile, get_logfile);
        
        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 's', "stderr",
                           "Dump alert to stderr", no_argument,
                           set_output_stderr, get_output_stderr);
        
        plugin_set_name(&plugin, "TextMod");
        plugin_set_author(&plugin, "Yoann Vandoorselaere");
        plugin_set_contact(&plugin, "yoann@mandrakesoft.com");
        plugin_set_desc(&plugin, "Write alert to a file, or to stderr if requested");
	plugin_set_running_func(&plugin, process_message);
     
	return (plugin_generic_t *) &plugin;
}

