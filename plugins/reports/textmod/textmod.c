/*****
*
* Copyright (C) 2002-2004 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <string.h>
#include <stdarg.h>
#include <libprelude/list.h>
#include <libprelude/idmef.h>
#include <libprelude/idmef-util.h>

#include "report.h"
#include "idmef-util.h"


typedef struct {
        FILE *fd;
        char *logfile;
} textmod_plugin_t;



static plugin_report_t textmod_plugin;


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



static void process_time(textmod_plugin_t *plugin, const char *type, idmef_time_t *time) 
{
        char utc_time[MAX_UTC_DATETIME_SIZE], ntpstamp[MAX_NTP_TIMESTAMP_SIZE];

        if ( ! time )
                return;
        
        idmef_time_get_timestamp(time, utc_time, sizeof(utc_time));
        idmef_time_get_ntp_timestamp(time, ntpstamp, sizeof(ntpstamp));

        print(plugin, 0, "%s: %s (%s)\n", type, ntpstamp, utc_time);
}



static void process_address(textmod_plugin_t *plugin, int depth, idmef_address_t *address) 
{
        print(plugin, 0, "* Addr[%s]:", idmef_address_category_to_string(idmef_address_get_category(address)));
        
        if ( idmef_string(idmef_address_get_address(address)) )
                print(plugin, 0, " %s", idmef_string(idmef_address_get_address(address)));

        if ( idmef_string(idmef_address_get_netmask(address)) )
                print(plugin, 0, "/%s", idmef_string(idmef_address_get_netmask(address)));

        if ( idmef_string(idmef_address_get_vlan_name(address)) )
                print(plugin, 0, " vlan=%s", idmef_string(idmef_address_get_vlan_name(address)));

        if ( idmef_address_get_vlan_num(address) )
                print(plugin, 0, " vnum=%u", idmef_address_get_vlan_num(address));

        print(plugin, 0, "\n");
}




static void process_node(textmod_plugin_t *plugin, int depth, idmef_node_t *node) 
{
        idmef_address_t *address;

        if ( ! node )
                return;

        print(plugin, 0, "* Node[%s]:", idmef_node_category_to_string(idmef_node_get_category(node)));

        if ( idmef_string(idmef_node_get_name(node)) )
                print(plugin, depth, " name:%s", idmef_string(idmef_node_get_name(node)));

        if ( idmef_string(idmef_node_get_location(node)) )
                print(plugin, depth, " location:%s", idmef_string(idmef_node_get_location(node)));

        print(plugin, 0, "\n");

	address = NULL;
	while ( (address = idmef_node_get_next_address(node, address)) ) {
		process_address(plugin, depth + 1, address);
	}
}




static void process_userid(textmod_plugin_t *plugin, int depth, idmef_userid_t *userid) 
{
        const char *type;
        
        print(plugin, 0, "*");
        print(plugin, depth, "");
        
        if ( idmef_string(idmef_userid_get_name(userid)) )
                print(plugin, 0, " name=%s", idmef_string(idmef_userid_get_name(userid)));

        print(plugin, 0, " number=%u", idmef_userid_get_number(userid));

        type = idmef_userid_type_to_string(idmef_userid_get_type(userid));
        if ( type )
                print(plugin, 0, " type=%s\n", type);
}



static void process_user(textmod_plugin_t *plugin, int depth, idmef_user_t *user) 
{
        const char *category;
        idmef_userid_t *userid;

        if ( ! user )
                return;

        category = idmef_user_category_to_string(idmef_user_get_category(user));
        if ( category )
                print(plugin, 0, "* %s user: \n", category);

	userid = NULL;
	while ( (userid = idmef_user_get_next_userid(user, userid)) ) 
		process_userid(plugin, depth + 1, userid);
}




static void process_process(textmod_plugin_t *plugin, int depth, idmef_process_t *process)
{
        int header;
	idmef_string_t *string;

        if ( ! process )
                return;

        print(plugin, depth, "* Process: pid=%u", idmef_process_get_pid(process));
        
        if ( idmef_string(idmef_process_get_name(process)) )
                print(plugin, 0, " name=%s", idmef_string(idmef_process_get_name(process)));
        
        if ( idmef_string(idmef_process_get_path(process)) )
                print(plugin, 0, " path=%s", idmef_string(idmef_process_get_path(process)));

	header = 0;
	string = NULL;
	while ( (string = idmef_process_get_next_arg(process, string)) ) {
		if ( ! header ) {
			print(plugin, depth, " arg: ");
			header = 1;
		}

		print(plugin, depth, "%s ", idmef_string(string));
	}

	header = 0;
	string = NULL;
	while ( (string = idmef_process_get_next_env(process, string)) ) {
		if ( ! header ) {
			print(plugin, depth, " env: ");
			header = 1;
		}

		print(plugin, depth, "%s ", idmef_string(string));
	}

        print(plugin, 0, "\n");
}




static void process_snmp_service(textmod_plugin_t *plugin, idmef_snmpservice_t *snmp) 
{
        if ( idmef_string(idmef_snmpservice_get_oid(snmp)) )
                print(plugin, 0, " oid=%s", idmef_string(idmef_snmpservice_get_oid(snmp)));

        if ( idmef_string(idmef_snmpservice_get_command(snmp)) )
                print(plugin, 0, " command=%s", idmef_string(idmef_snmpservice_get_command(snmp)));

        if ( idmef_string(idmef_snmpservice_get_community(snmp)) )
                print(plugin, 0, " community=%s", idmef_string(idmef_snmpservice_get_community(snmp)));
}




static void process_web_service(textmod_plugin_t *plugin, idmef_webservice_t *web) 
{        
        if ( ! web )
                return;

        if ( idmef_string(idmef_webservice_get_url(web)) )
                print(plugin, 0, " url=%s", idmef_string(idmef_webservice_get_url(web)));

        if ( idmef_string(idmef_webservice_get_cgi(web)) )
                print(plugin, 0, " cgi=%s", idmef_string(idmef_webservice_get_cgi(web)));

        if ( idmef_string(idmef_webservice_get_http_method(web)) )
                print(plugin, 0, " http method=%s", idmef_string(idmef_webservice_get_http_method(web)));
}



static void process_service(textmod_plugin_t *plugin, int depth, idmef_service_t *service) 
{
        if ( ! service )
                return;

        print(plugin, depth, "* Service: port=%hu", idmef_service_get_port(service));
        
        if ( idmef_string(idmef_service_get_name(service)) )
                print(plugin, 0, " (%s)", idmef_string(idmef_service_get_name(service)));
        
        if ( idmef_string(idmef_service_get_protocol(service)) )
                print(plugin, 0, " protocol=%s", idmef_string(idmef_service_get_protocol(service)));
        
        switch ( idmef_service_get_type(service) ) {

        case IDMEF_SERVICE_TYPE_WEB:
                process_web_service(plugin, idmef_service_get_web(service));
                break;

        case IDMEF_SERVICE_TYPE_SNMP:
                process_snmp_service(plugin, idmef_service_get_snmp(service));
                break;

        default:
                /* nop */;
        }

        print(plugin, 0, "\n");
}



static void process_source(textmod_plugin_t *plugin, int depth, idmef_source_t *source)
{
        const char *spoofed;

        spoofed = idmef_source_spoofed_to_string(idmef_source_get_spoofed(source));
        if ( spoofed )
                print(plugin, depth, "* Source spoofed: %s\n", spoofed);

        if ( idmef_string(idmef_source_get_interface(source)) )
                print(plugin, depth, "* Source interface=%s\n", idmef_string(idmef_source_get_interface(source)));
        
        process_node(plugin, depth, idmef_source_get_node(source));
        process_service(plugin, depth, idmef_source_get_service(source));
        process_process(plugin, depth, idmef_source_get_process(source));
        process_user(plugin, depth, idmef_source_get_user(source));
}



static void process_file_access(textmod_plugin_t *plugin, int depth, idmef_file_access_t *file_access) 
{
	int header;
	idmef_string_t *permission;

	print(plugin, depth, "Access: ");

	header = 0;
	permission = NULL;
	while ( (permission = idmef_file_access_get_next_permission(file_access, permission)) ) {
		if ( ! header ) {
			print(plugin, depth, " permission: ");
			header = 1;
		}

		print(plugin, depth, "%s ", idmef_string(permission));
	}

	process_userid(plugin, depth + 1, idmef_file_access_get_userid(file_access));
}



static void process_file_linkage(textmod_plugin_t *plugin, int depth, idmef_linkage_t *linkage) 
{
	print(plugin, depth, "Linkage: %s",
	      idmef_linkage_category_to_string(idmef_linkage_get_category(linkage)));

	if ( idmef_string(idmef_linkage_get_name(linkage)) )
		print(plugin, 0, " name=%s", idmef_string(idmef_linkage_get_name(linkage)));

	if ( idmef_string(idmef_linkage_get_path(linkage)) )
		print(plugin, 0, " path=%s", idmef_string(idmef_linkage_get_path(linkage)));

	if ( idmef_linkage_get_file(linkage) )
		process_file(plugin, depth, idmef_linkage_get_file(linkage));
}




static void process_inode(textmod_plugin_t *plugin, int depth, idmef_inode_t *inode) 
{
        if ( ! inode )
                return;
        
        print(plugin, depth, "* Inode:");

        if ( idmef_inode_get_number(inode) )
                print(plugin, 0, " number=%u", idmef_inode_get_number(inode));

        if ( idmef_inode_get_major_device(inode) )
                print(plugin, 0, " major=%u", idmef_inode_get_major_device(inode));

        if ( idmef_inode_get_minor_device(inode) )
                print(plugin, 0, " minor=%u", idmef_inode_get_minor_device(inode));

        if ( idmef_inode_get_c_major_device(inode) )
                print(plugin, 0, " c_major=%u", idmef_inode_get_c_major_device(inode));

        if ( idmef_inode_get_c_minor_device(inode) )
                print(plugin, 0, " c_minor=%u", idmef_inode_get_c_minor_device(inode));

        print(plugin, 0, "\n");
        
        process_time(plugin, " ctime=", idmef_inode_get_change_time(inode));
}




static void process_file(textmod_plugin_t *plugin, int depth, idmef_file_t *file) 
{
	idmef_linkage_t *file_linkage;
	idmef_file_access_t *file_access;

        print(plugin, 0, "* ");

        print(plugin, depth, "File %s: ",
	      idmef_file_category_to_string(idmef_file_get_category(file)));

        print(plugin, 0, " fstype=%s", idmef_file_fstype_to_string(idmef_file_get_fstype(file)));

        if ( idmef_string(idmef_file_get_name(file)) )
                print(plugin, 0, " name=%s", idmef_string(idmef_file_get_name(file)));

        if ( idmef_string(idmef_file_get_path(file)) )
                print(plugin, 0, " path=%s", idmef_string(idmef_file_get_path(file)));
        
        if ( idmef_file_get_data_size(file) )
                print(plugin, 0, " dsize=%u", idmef_file_get_data_size(file));

        if ( idmef_file_get_disk_size(file) )
                print(plugin, 0, " disk-size=%u", idmef_file_get_disk_size(file));

        print(plugin, 0, "\n");
        
        process_time(plugin, "* ctime=", idmef_file_get_create_time(file));
        process_time(plugin, "* mtime=", idmef_file_get_modify_time(file));
        process_time(plugin, "* atime=", idmef_file_get_access_time(file));
        
	file_access = NULL;
	while ( (file_access = idmef_file_get_next_file_access(file, file_access)) )
		process_file_access(plugin, depth, file_access);

	file_linkage = NULL;
	while ( (file_linkage = idmef_file_get_next_file_linkage(file, file_linkage)) )
		process_file_linkage(plugin, depth, file_linkage);

        process_inode(plugin, depth, idmef_file_get_inode(file));
}




static void process_target(textmod_plugin_t *plugin, int depth, idmef_target_t *target)
{
        idmef_file_t *file;

        print(plugin, 0, "* Target decoy: %s\n", 
	      idmef_target_decoy_to_string(idmef_target_get_decoy(target)));
        
        if ( idmef_string(idmef_target_get_interface(target)) )
                print(plugin, 0, "* Target Interface: %s\n", idmef_string(idmef_target_get_interface(target)));
        
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
        
        if ( idmef_analyzer_get_analyzerid(analyzer) )
                print(plugin, 0, "* Analyzer ID: %llu\n", idmef_analyzer_get_analyzerid(analyzer));
        
        if ( idmef_string(idmef_analyzer_get_model(analyzer)) )
                print(plugin, 0, "* Analyzer model: %s\n", idmef_string(idmef_analyzer_get_model(analyzer)));

        if ( idmef_string(idmef_analyzer_get_version(analyzer)) )
                print(plugin, 0, "* Analyzer version: %s\n", idmef_string(idmef_analyzer_get_version(analyzer)));

        if ( idmef_string(idmef_analyzer_get_class(analyzer)) )
                print(plugin, 0, "* Analyzer class: %s\n", idmef_string(idmef_analyzer_get_class(analyzer)));
        
        if ( idmef_string(idmef_analyzer_get_manufacturer(analyzer)) )
                print(plugin, 0, "* Analyzer manufacturer: %s\n", idmef_string(idmef_analyzer_get_manufacturer(analyzer)));

        if ( idmef_string(idmef_analyzer_get_ostype(analyzer)) )
                print(plugin, 0, "* Analyzer OS type: %s\n", idmef_string(idmef_analyzer_get_ostype(analyzer)));
        
        if ( idmef_string(idmef_analyzer_get_osversion(analyzer)) )
                print(plugin, 0, "* Analyzer OS version: %s\n", idmef_string(idmef_analyzer_get_osversion(analyzer)));

        if ( idmef_analyzer_get_node(analyzer) )
                process_node(plugin, 0, idmef_analyzer_get_node(analyzer));

        if ( idmef_analyzer_get_process(analyzer) )
                process_process(plugin, 0, idmef_analyzer_get_process(analyzer));
}



static void process_classification(textmod_plugin_t *plugin, idmef_classification_t *classification) 
{
        print(plugin, 0, "* Classification type: %s\n",
	      idmef_classification_origin_to_string(idmef_classification_get_origin(classification)));

        print(plugin, 0, "* Classification: %s\n",
	      idmef_string(idmef_classification_get_name(classification)));
        
        if ( idmef_string(idmef_classification_get_url(classification)) )
                print(plugin, 0, "* Classification URL: %s\n", 
		      idmef_string(idmef_classification_get_url(classification)));
}



static void process_data(textmod_plugin_t *plugin, idmef_additional_data_t *ad) 
{
        size_t dlen;
        const char *tmp;
        idmef_data_t *data;
        unsigned char buf[128];

        dlen = sizeof(buf);
        data = idmef_additional_data_get_data(ad);
        
        tmp = idmef_additionaldata_data_to_string(ad, buf, &dlen);
        if ( ! tmp )
                return;
        
        if ( idmef_additional_data_get_type(ad) == IDMEF_ADDITIONAL_DATA_TYPE_BYTE )
                tmp = "<FIXME: binary data>";
        
	if ( dlen <= 80 )
                print(plugin, 0, "* %s: %s\n", 
		      idmef_string(idmef_additional_data_get_meaning(ad)), tmp);
        else
                print(plugin, 0, "* %s:\n%s\n", 
		      idmef_string(idmef_additional_data_get_meaning(ad)), tmp);
}




static void process_impact(textmod_plugin_t *plugin, idmef_impact_t *impact) 
{
        if ( ! impact )
                return;
        
        print(plugin, 0, "* Impact severity: %s\n",
	      idmef_impact_severity_to_string(idmef_impact_get_severity(impact)));

        print(plugin, 0, "* Impact completion: %s\n",
	      idmef_impact_completion_to_string(idmef_impact_get_completion(impact)));

        print(plugin, 0, "* Impact type: %s\n", 
	      idmef_impact_type_to_string(idmef_impact_get_type(impact)));

        print(plugin, 0, "* Impact description: %s\n", 
	      idmef_string(idmef_impact_get_description(impact)));
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
        print(plugin, 0, "* Action category: %s\n",
	      idmef_action_category_to_string(idmef_action_get_category(action)));

        print(plugin, 0, "* Action description: %s\n",
	      idmef_string(idmef_action_get_description(action)));
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
        idmef_source_t *source;
        idmef_target_t *target;
        idmef_classification_t *classification;
        idmef_additional_data_t *data;
	int header;

        print(plugin, 0, "********************************************************************************\n");
        print(plugin, 0, "* Alert: ident=%llu\n", idmef_alert_get_ident(alert));

	classification = NULL;
	while ( (classification = idmef_alert_get_next_classification(alert, classification)) ) {
		process_classification(plugin, classification);
		print(plugin, 0, "*\n");
	}
        
        process_time(plugin, "* Creation time", idmef_alert_get_create_time(alert));
        process_time(plugin, "* Detection time", idmef_alert_get_detect_time(alert));
        process_time(plugin, "* Analyzer time", idmef_alert_get_analyzer_time(alert));

        process_analyzer(plugin, idmef_alert_get_analyzer(alert));

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
	idmef_additional_data_t *data;

        print(plugin, 0, "********************************************************************************\n");
        print(plugin, 0, "* Heartbeat: ident=%llu\n", idmef_heartbeat_get_ident(heartbeat));
        
        process_analyzer(plugin, idmef_heartbeat_get_analyzer(heartbeat));
        process_time(plugin, "* Creation time", idmef_heartbeat_get_create_time(heartbeat));
        process_time(plugin, "* Analyzer time", idmef_heartbeat_get_analyzer_time(heartbeat));

	data = NULL;
	while ( (data = idmef_heartbeat_get_next_additional_data(heartbeat, data)) )
                process_data(plugin, data);

        print(plugin, 0, "*\n********************************************************************************\n\n");
}




static int textmod_run(prelude_plugin_instance_t *pi, idmef_message_t *message) 
{
        textmod_plugin_t *plugin = prelude_plugin_instance_get_data(pi);
        
        switch ( idmef_message_get_type(message) ) {

        case IDMEF_MESSAGE_TYPE_ALERT:
                process_alert(plugin, idmef_message_get_alert(message));
                break;

        case IDMEF_MESSAGE_TYPE_HEARTBEAT:
                process_heartbeat(plugin, idmef_message_get_heartbeat(message));
                break;

        default:
                log(LOG_ERR, "unknow message type: %d.\n", idmef_message_get_type(message));
                break;
        }

        fflush(plugin->fd);

        return 0;
}




static int textmod_init(prelude_plugin_instance_t *pi)
{
        FILE *fd;
        textmod_plugin_t *plugin = prelude_plugin_instance_get_data(pi);
        
        if ( ! plugin->logfile ) {
                log(LOG_ERR, "no logfile specified.\n");
                return -1;
        }

        if ( strcmp(plugin->logfile, "stderr") == 0 )
                fd = stderr;
        else {
                fd = fopen(plugin->logfile, "a+");
                if ( ! fd ) {
                        log(LOG_ERR, "error opening %s in append mode.\n", plugin->logfile);
                        return -1;
                }
        }

        plugin->fd = fd;

        return 0;
}




static int textmod_activate(prelude_plugin_instance_t *pi, prelude_option_t *opt, const char *arg) 
{
        textmod_plugin_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return prelude_option_error;
        }

        prelude_plugin_instance_set_data(pi, new);
        
        return prelude_option_success;
}




static void textmod_destroy(prelude_plugin_instance_t *pi)
{
        textmod_plugin_t *plugin = prelude_plugin_instance_get_data(pi);

        if ( plugin->fd )
                fclose(plugin->fd);

        if ( plugin->logfile )
                free(plugin->logfile);
        
        free(plugin);
}



prelude_plugin_generic_t *prelude_plugin_init(void)
{
	prelude_option_t *opt;
        
        opt = prelude_plugin_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 0, "textmod",
                                        "Option for the textmod plugin", optionnal_argument,
                                        textmod_activate, NULL);
        
        prelude_plugin_set_activation_option((void *) &textmod_init, opt, textmod_init);
        
        prelude_plugin_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'l', "logfile",
                                  "Specify logfile to use", required_argument,
                                  textmod_set_logfile, textmod_get_logfile);

        prelude_plugin_set_name(&textmod_plugin, "TextMod");
        prelude_plugin_set_author(&textmod_plugin, "Yoann Vandoorselaere");
        prelude_plugin_set_contact(&textmod_plugin, "yoann@prelude-ids.org");
        prelude_plugin_set_desc(&textmod_plugin, "Write alert to a file, or to stderr if requested");
        prelude_plugin_set_destroy_func(&textmod_plugin, textmod_destroy);

        report_plugin_set_running_func(&textmod_plugin, textmod_run);
        
	return (void *) &textmod_plugin;
}

