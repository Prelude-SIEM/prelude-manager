/*****
*
* Copyright (C) 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <stdarg.h>
#include <libprelude/list.h>
#include <libprelude/idmef-tree.h>

#include "report.h"
#include "idmef-util.h"

static void process_file(int depth, const idmef_file_t *file);


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

        va_start(ap, fmt);
        
        do_print(out_fd, depth, fmt, ap);

        if ( out_stderr )
                do_print(stderr, depth, fmt, ap);

        va_end(ap);
}




static void process_time(const char *type, const idmef_time_t *time) 
{
        char utc_time[MAX_UTC_DATETIME_SIZE], ntpstamp[MAX_NTP_TIMESTAMP_SIZE];

        if ( ! time )
                return;
        
        idmef_get_timestamp(time, utc_time, sizeof(utc_time));
        idmef_get_ntp_timestamp(time, ntpstamp, sizeof(ntpstamp));

        print(0, "%s: %s (%s)\n", type, ntpstamp, utc_time);
}



static void process_address(int depth, const idmef_address_t *addr) 
{
        print(0, "* Addr[%s]:", idmef_address_category_to_string(addr->category));
        
        if ( idmef_string(&addr->address) )
                print(0, " %s", idmef_string(&addr->address));

        if ( idmef_string(&addr->netmask) )
                print(0, "/%s", idmef_string(&addr->netmask));

        if ( idmef_string(&addr->vlan_name) )
                print(0, " vlan=%s", idmef_string(&addr->vlan_name));

        if ( addr->vlan_num )
                print(0, " vnum=%d", addr->vlan_num);

        print(0, "\n");
}




static void process_node(int depth, const idmef_node_t *node) 
{
        idmef_address_t *addr;
        struct list_head *tmp;
        
        if ( ! node )
                return;

        print(0, "* Node[%s]:", idmef_node_category_to_string(node->category));
        
        if ( idmef_string(&node->name) )
                print(depth, " name:%s", idmef_string(&node->name));

        if ( idmef_string(&node->location) )
                print(depth, " location:%s", idmef_string(&node->location));

        list_for_each(tmp, &node->address_list) {
                addr = list_entry(tmp, idmef_address_t, list);
                process_address(depth + 1, addr);
        }

        print(0, "\n");
}




static void process_userid(int depth, const idmef_userid_t *uid) 
{
        const char *type;
        
        print(0, "*");
        print(depth, "");
        
        if ( idmef_string(&uid->name) )
                print(0, " name=%s", idmef_string(&uid->name));
        
        print(0, " number=%d", uid->number);


        type = idmef_userid_type_to_string(uid->type);
        if ( type )
                print(0, " type=%s\n", type);
}



static void process_user(int depth, const idmef_user_t *user) 
{
        idmef_userid_t *uid;
        const char *category;
        struct list_head *tmp;
        
        if ( ! user )
                return;

        category = idmef_user_category_to_string(user->category);
        if ( category )
                print(0, "* %s user: \n", category);
        
        list_for_each(tmp, &user->userid_list) {
                uid = list_entry(tmp, idmef_userid_t, list);
                process_userid(depth + 1, uid);
        }
}




static void process_process(int depth, const idmef_process_t *process)
{
        if ( ! process )
                return;

        print(depth, "* Process: pid=%u", process->pid);
        
        if ( idmef_string(&process->name) )
                print(0, " name=%s", idmef_string(&process->name));
        
        if ( idmef_string(&process->path) )
                print(0, " path=%s", idmef_string(&process->path));

        print(0, "\n");
}




static void process_snmp_service(const idmef_snmpservice_t *snmp) 
{
        if ( idmef_string(&snmp->oid) )
                print(0, " oid=%s", idmef_string(&snmp->oid));

        if ( idmef_string(&snmp->command) )
                print(0, " command=%s", idmef_string(&snmp->command));

        if ( idmef_string(&snmp->community) )
                print(0, " community=%s", idmef_string(&snmp->community));
}




static void process_web_service(const idmef_webservice_t *web) 
{        
        if ( ! web )
                return;

        if ( idmef_string(&web->url) )
                print(0, " url=%s", idmef_string(&web->url));

        if ( idmef_string(&web->cgi) )
                print(0, " cgi=%s", idmef_string(&web->cgi));

        if ( idmef_string(&web->http_method) )
                print(0, " http method=%s", idmef_string(&web->http_method));
}



static void process_service(int depth, const idmef_service_t *service) 
{
        if ( ! service )
                return;

        print(depth, "* Service: port=%d", service->port);
        
        if ( idmef_string(&service->name) )
                print(0, " (%s)", idmef_string(&service->name));
        
        if ( idmef_string(&service->protocol) )
                print(0, " protocol=%s", idmef_string(&service->protocol));
        
        switch (service->type) {
        case web_service:
                process_web_service(service->specific.web);
                break;

        case snmp_service:
                process_snmp_service(service->specific.snmp);
                break;

        default:
                break;
        }

        print(0, "\n");
}



static void process_source(int depth, const idmef_source_t *source)
{
        const char *spoofed;

        spoofed = idmef_source_spoofed_to_string(source->spoofed);
        if ( spoofed )
                print(depth, "* Source spoofed: %s\n", spoofed);

        if ( idmef_string(&source->interface) )
                print(depth, "* Source interface=%s", idmef_string(&source->interface));
        
        process_node(depth, source->node);
        process_service(depth, source->service);
        process_process(depth, source->process);
        process_user(depth, source->user);
}



static void process_file_access(int depth, const struct list_head *head) 
{
        struct list_head *tmp;
        idmef_file_access_t *access;

        list_for_each(tmp, head) {
                access = list_entry(tmp, idmef_file_access_t, list);

                print(depth, "Access: %s", access->permission);
                process_userid(0, &access->userid);
        }
}



static void process_file_linkage(int depth, const struct list_head *head) 
{
        struct list_head *tmp;
        idmef_linkage_t *linkage;

        list_for_each(tmp, head) {
                linkage = list_entry(tmp, idmef_linkage_t, list);

                print(depth, "Linkage: %s", idmef_linkage_category_to_string(linkage->category));

                if ( idmef_string(&linkage->name) )
                        print(0, " name=%s", idmef_string(&linkage->name));

                if ( idmef_string(&linkage->path) )
                        print(0, " path=%s", idmef_string(&linkage->path));

                if ( linkage->file )
                        process_file(depth, linkage->file);
                
                print(0, "\n");
        }
}




static void process_inode(int depth, const idmef_inode_t *inode) 
{
        print(depth, "Inode:");

        if ( inode->number )
                print(0, " number=%d", inode->number);

        if ( inode->major_device )
                print(0, " major=%d", inode->major_device);

        if ( inode->minor_device )
                print(0, " minor=%d", inode->minor_device);

        if ( inode->c_major_device )
                print(0, " c_major=%d", inode->c_major_device);

        if ( inode->c_minor_device )
                print(0, " c_minor=%d", inode->c_minor_device);
        
        process_time(" ctime=", &inode->change_time);
}




static void process_file(int depth, const idmef_file_t *file) 
{
        print(0, "* ");
        print(depth, "File %s: ", idmef_file_category_to_string(file->category));

        if ( idmef_string(&file->fstype) )
                print(0, " fstype=%s", idmef_string(&file->fstype));

        if ( idmef_string(&file->name) )
                print(0, " name=%s", idmef_string(&file->name));

        if ( idmef_string(&file->path) )
                print(0, " path=%s", idmef_string(&file->path));

        process_time(" ctime=", file->create_time);
        process_time(" mtime=", file->modify_time);
        process_time(" atime=", file->access_time);

        if ( file->data_size )
                print(0, " dsize=%u", file->data_size);

        if ( file->disk_size )
                print(0, " disk-size=%u", file->disk_size);

        process_file_access(depth, &file->file_access_list);
        process_file_linkage(depth, &file->file_linkage_list);
        process_inode(depth, file->inode);
}




static void process_target(int depth, const idmef_target_t *target)
{
        idmef_file_t *file;
        struct list_head *tmp;
        
        print(0, "* Target decoy: %s\n", idmef_target_decoy_to_string(target->decoy));
        
        if ( idmef_string(&target->interface) )
                print(0, "* Target Interface: %s\n", idmef_string(&target->interface));
        
        process_node(0, target->node);
        process_service(0, target->service);
        process_process(0, target->process);
        process_user(0, target->user);

        list_for_each(tmp, &target->file_list) {
                file = list_entry(tmp, idmef_file_t, list);
                process_file(0, file);
        }
}



static void process_analyzer(const idmef_analyzer_t *analyzer) 
{
        if ( idmef_string(&analyzer->model) )
                print(0, "* Analyzer model: %s\n", idmef_string(&analyzer->model));

        if ( idmef_string(&analyzer->version) )
                print(0, "* Analyzer version: %s\n", idmef_string(&analyzer->version));

        if ( idmef_string(&analyzer->class) )
                print(0, "* Analyzer class: %s\n", idmef_string(&analyzer->class));
        
        if ( idmef_string(&analyzer->manufacturer) )
                print(0, "* Analyzer manufacturer: %s\n", idmef_string(&analyzer->manufacturer));

        if ( idmef_string(&analyzer->ostype) )
                print(0, "* Analyzer OS type: %s\n", idmef_string(&analyzer->ostype));
        
        if ( idmef_string(&analyzer->osversion) )
                print(0, "* Analyzer OS version: %s\n", idmef_string(&analyzer->osversion));
}



static void process_classification(const idmef_classification_t *class) 
{
        print(0, "* Classification type: %s\n", idmef_classification_origin_to_string(class->origin));
        print(0, "* Classification: %s\n", idmef_string(&class->name));
        
        if ( idmef_string(&class->url) )
                print(0, "* Classification URL: %s\n", idmef_string(&class->url));
}



static void process_data(const idmef_additional_data_t *ad) 
{
        int size;
        char buf[1024];
        const char *ptr;
        
        size = sizeof(buf);
        
        ptr = idmef_additional_data_to_string(ad, buf, &size);
        if ( ! ptr )
                return;
        
        if ( size <= 80 )
                print(0, "* %s: %s\n", idmef_string(&ad->meaning), ptr);
        else
                print(0, "* %s:\n%s\n", idmef_string(&ad->meaning), ptr);
}




static void process_impact(const idmef_impact_t *impact) 
{
        if ( ! impact )
                return;
        
        print(0, "* Impact severity: %s\n", idmef_impact_severity_to_string(impact->severity));
        print(0, "* Impact completion: %s\n", idmef_impact_completion_to_string(impact->completion));
        print(0, "* Impact type: %s\n", idmef_impact_type_to_string(impact->type));
        print(0, "* Impact description: %s\n", idmef_string(&impact->description));
}



static void process_confidence(const idmef_confidence_t *confidence) 
{
        if ( ! confidence )
                return;
        
        print(0, "* Confidence rating: %s\n", idmef_confidence_rating_to_string(confidence->rating));

        if ( confidence->rating == numeric )
                print(0, "* Confidence value: %f\n", confidence->confidence);
}




static void process_action(const idmef_action_t *action) 
{
        print(0, "* Action category: %s\n", idmef_action_category_to_string(action->category));
        print(0, "* Action description: %s\n", idmef_string(&action->description));
}




static void process_assessment(const idmef_assessment_t *assessment) 
{
        struct list_head *tmp;
        idmef_action_t *action;

        if ( ! assessment )
                return;
        
        process_impact(assessment->impact);
        print(0, "*\n");
        process_confidence(assessment->confidence);
        
        list_for_each(tmp, &assessment->action_list) {
                print(0, "*\n");
                action = list_entry(tmp, idmef_action_t, list);
                process_action(action);
        }

        print(0, "*\n");
}





static void process_alert(idmef_alert_t *alert) 
{
        struct list_head *tmp;
        const idmef_source_t *source;
        const idmef_target_t *target;
        const idmef_classification_t *class;
        const idmef_additional_data_t *data;

        print(0, "********************************************************************************\n");
        print(0, "* Alert: ident=%llu\n", alert->ident);
        
        list_for_each(tmp, &alert->classification_list) {
                class = list_entry(tmp, idmef_classification_t, list);
                process_classification(class);
                print(0, "*\n");
        }
        
        process_time("* Creation time", &alert->create_time);
        process_time("* Detection time", alert->detect_time);
        process_time("* Analyzer time", alert->analyzer_time);
        process_analyzer(&alert->analyzer);

        print(0, "*\n");
        process_assessment(alert->assessment);
        
        if ( ! list_empty(&alert->source_list) )
                print(0, "*** Source informations ********************************************************\n");
        
        list_for_each(tmp, &alert->source_list) {
                source = list_entry(tmp, idmef_source_t, list);
                process_source(0, source);
        }

        if ( ! list_empty(&alert->target_list) ) 
                print(0, "*\n*** Target informations ********************************************************\n");

        list_for_each(tmp, &alert->target_list) {
                target = list_entry(tmp, idmef_target_t, list);
                process_target(0, target);
        }        

        if ( ! list_empty(&alert->additional_data_list) )
                print(0, "*\n*** Additional data within the alert  ******************************************\n");
        
        list_for_each(tmp, &alert->additional_data_list) {
                data = list_entry(tmp, idmef_additional_data_t, list);
                process_data(data);
        }
        print(0, "*\n********************************************************************************\n\n");
}





static void process_heartbeat(const idmef_heartbeat_t *heartbeat) 
{
        struct list_head *tmp;
        const idmef_additional_data_t *data;

        print(0, "* Heartbeat ");
        
        process_analyzer(&heartbeat->analyzer);
        process_time("Creation time", &heartbeat->create_time);
        process_time("Analyzer time", heartbeat->analyzer_time);

        list_for_each(tmp, &heartbeat->additional_data_list) {
                data = list_entry(tmp, idmef_additional_data_t, list);
                process_data(data);
        }
}




static void process_message(const idmef_message_t *msg) 
{
        switch (msg->type) {

        case idmef_alert_message:
                process_alert(msg->message.alert);
                break;

        case idmef_heartbeat_message:
                process_heartbeat(msg->message.heartbeat);
                break;

        default:
                log(LOG_ERR, "unknow message type: %d.\n", msg->type);
                break;
        }

        fflush(out_fd);
}



/*
 * plugin configuration stuff
 */
static int set_logfile(const char *arg) 
{
        out_fd = fopen(arg, "a+");
        if ( ! out_fd ) {
                log(LOG_ERR, "error opening %s in append mode.\n", arg);
                return prelude_option_error;
        }
        
        logfile = arg;
        
        return prelude_option_success;
}



static int get_logfile(char *buf, size_t size) 
{
        snprintf(buf, size, "%s", logfile);
        return prelude_option_success;  
}



static int set_output_stderr(const char *arg) 
{
        out_stderr = 1;
        return prelude_option_success;
}



static int get_output_stderr(char *buf, size_t size) 
{
        snprintf(buf, size, "%s", (out_stderr == 1) ? "enabled" : "disabled");
        return prelude_option_success;
}




static int set_textmod_state(const char *arg) 
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

