/*****
*
* Copyright (C) 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <string.h>
#include <stdarg.h>
#include <libprelude/list.h>
#include <libprelude/idmef-tree.h>

#include <libxml/parser.h>

#include "report.h"
#include "idmef-util.h"


static void process_file(xmlNodePtr parent, const idmef_file_t *file);


static int format = 0;
static int enabled = 0;
static int no_buffering = 0;
static plugin_report_t plugin;
static xmlDtdPtr idmef_dtd = NULL;
static xmlOutputBufferPtr out_fd = NULL, out_stderr;



static int file_write(void *context, const char *buf, int len) 
{
        return fwrite(buf, 1, len, context);
}



static void idmef_attr_uint64(xmlNodePtr node, const char *attr, uint64_t ident) 
{
        char buf[64];

        if ( ! ident )
                return;
        
        snprintf(buf, sizeof(buf), "%llu", ident);
        xmlSetProp(node, attr, buf);
}


static void idmef_attr_uint32(xmlNodePtr node, const char *attr, uint32_t num) 
{
        char buf[64];

        if ( ! num )
                return;
        
        snprintf(buf, sizeof(buf), "%u", num);
        xmlSetProp(node, attr, buf);
}



static void idmef_content_string(xmlNodePtr node, const char *tag, const char *content) 
{
        if ( ! content )
                return;

        xmlNewChild(node, NULL, tag, content);
}



static void idmef_attr_string(xmlNodePtr node, const char *attr, const char *content) 
{
        if ( ! content )
                return;

        xmlSetProp(node, attr, content);
}



static void idmef_content_uint32(xmlNodePtr node, const char *tag, uint32_t content) 
{
        char buf[64];
        
        if ( ! content )
                return;

        snprintf(buf, sizeof(buf), "%u", content);
        
        xmlNewChild(node, NULL, tag, buf);
}




static void process_string_list(xmlNodePtr parent, const char *type, const struct list_head *list) 
{
        struct list_head *tmp;
        idmef_string_item_t *item;

        if ( list_empty(list) )
                return;
                
        list_for_each(tmp, list) {
                item = list_entry(tmp, idmef_string_item_t, list);
                xmlNewChild(parent, NULL, type, idmef_string(&item->string));
        }
}


static void process_time(xmlNodePtr parent, const char *type, const idmef_time_t *time) 
{
        xmlNodePtr new;
        char utc_time[MAX_UTC_DATETIME_SIZE], ntpstamp[MAX_NTP_TIMESTAMP_SIZE];

        if ( ! time )
                return;

        idmef_get_timestamp(time, utc_time, sizeof(utc_time));
        idmef_get_ntp_timestamp(time, ntpstamp, sizeof(ntpstamp));
        
        new = xmlNewChild(parent, NULL, type, utc_time);
        if ( ! new )
                return;
        
        xmlSetProp(new, "ntpstamp", ntpstamp);
}



static void process_address(xmlNodePtr parent, const idmef_address_t *addr) 
{
        xmlNodePtr new;

        new = xmlNewChild(parent, NULL, "Address", NULL);
        if ( ! new )
                return;
        
        idmef_attr_uint64(new, "ident", addr->ident);
        idmef_attr_string(new, "category", idmef_address_category_to_string(addr->category));
        idmef_attr_string(new, "vlan-name", idmef_string(&addr->vlan_name));
        idmef_attr_uint32(new, "vlan-num", addr->vlan_num);
        idmef_content_string(new, "address", idmef_string(&addr->address));
        idmef_content_string(new, "netmask", idmef_string(&addr->netmask));
}




static void process_node(xmlNodePtr parent, const idmef_node_t *node) 
{
        xmlNodePtr new;
        idmef_address_t *addr;
        struct list_head *tmp;
        
        if ( ! node )
                return;

        new = xmlNewChild(parent, NULL, "Node", NULL);
        if ( ! new )
                return;
        
        idmef_attr_uint64(new, "ident", node->ident);
        idmef_attr_string(new, "category", idmef_node_category_to_string(node->category));
        idmef_content_string(new, "name", idmef_string(&node->name));
        idmef_content_string(new, "location", idmef_string(&node->location));
        
        list_for_each(tmp, &node->address_list) {
                addr = list_entry(tmp, idmef_address_t, list);
                process_address(new, addr);
        }
}



static void process_userid(xmlNodePtr parent, const idmef_userid_t *uid) 
{
        xmlNodePtr new;

        new = xmlNewChild(parent, NULL, "UserId", NULL);
        if ( ! new )
                return;
        
        idmef_attr_uint64(new, "ident", uid->ident);
        idmef_attr_string(new, "type", idmef_userid_type_to_string(uid->type));
        idmef_content_string(new, "name", idmef_string(&uid->name));
        idmef_content_uint32(new, "number", uid->number);
}



static void process_user(xmlNodePtr parent, const idmef_user_t *user) 
{
        xmlNodePtr new;
        idmef_userid_t *uid;
        struct list_head *tmp;
        
        if ( ! user )
                return;

        new = xmlNewChild(parent, NULL, "User", NULL);
        if ( ! new )
                return;
        
        idmef_attr_uint64(new, "ident", user->ident);
        idmef_attr_string(new, "category", idmef_user_category_to_string(user->category));
                
        list_for_each(tmp, &user->userid_list) {
                uid = list_entry(tmp, idmef_userid_t, list);
                process_userid(new, uid);
        }
}




static void process_process(xmlNodePtr parent, const idmef_process_t *process)
{
        xmlNodePtr new;
        
        if ( ! process )
                return;

        new = xmlNewChild(parent, NULL, "Process", NULL);
        if ( ! new )
                return;
        
        idmef_attr_uint64(new, "ident", process->ident);
        idmef_content_string(new, "name", idmef_string(&process->name));
        idmef_content_uint32(new, "pid", process->pid);
        idmef_content_string(new, "path", idmef_string(&process->path));
        
        process_string_list(new, "arg", &process->arg_list);
        process_string_list(new, "env", &process->env_list);
}




static void process_snmp_service(xmlNodePtr parent, const idmef_snmpservice_t *snmp) 
{
        xmlNodePtr new;

        if ( ! snmp )
                return;

        new = xmlNewChild(parent, NULL, "SNMPService", NULL);
        if ( ! new )
                return;
        
        idmef_content_string(new, "oid", idmef_string(&snmp->oid));
        idmef_content_string(new, "community", idmef_string(&snmp->community));
        idmef_content_string(new, "command", idmef_string(&snmp->command));
}




static void process_web_service(xmlNodePtr parent, const idmef_webservice_t *web) 
{
        xmlNodePtr new;
        
        if ( ! web )
                return;

        new = xmlNewChild(parent, NULL, "WebService", NULL);

        idmef_content_string(new, "url", idmef_string(&web->url));
        idmef_content_string(new, "cgi", idmef_string(&web->cgi));
        idmef_content_string(new, "http-method", idmef_string(&web->http_method));

        process_string_list(new, "arg", &web->arg_list);
}



static void process_service(xmlNodePtr parent, const idmef_service_t *service) 
{
        xmlNodePtr new;
        
        if ( ! service )
                return;

        new = xmlNewChild(parent, NULL, "Service", NULL);
        if ( ! new )
                return;
        
        idmef_attr_uint64(new, "ident", service->ident);
        idmef_content_string(new, "name", idmef_string(&service->name));
        idmef_content_uint32(new, "port", service->port);
        idmef_content_string(new, "protocol", idmef_string(&service->protocol));
        
        switch (service->type) {
                
        case snmp_service:
                process_snmp_service(new, service->specific.snmp);
                break;

        case web_service:
                process_web_service(new, service->specific.web);
                break;

        default:
                break;
        }
}



static void process_source(xmlNodePtr parent, const idmef_source_t *source)
{
        xmlNodePtr new;

        new = xmlNewChild(parent, NULL, "Source", NULL);
        if ( ! new )
                return;
        
        idmef_attr_uint64(new, "ident", source->ident);
        idmef_attr_string(new, "spoofed", idmef_source_spoofed_to_string(source->spoofed));
        idmef_attr_string(new, "interface", idmef_string(&source->interface));
        
        process_node(new, source->node);
        process_user(new, source->user);
        process_process(new, source->process);
        process_service(new, source->service);
}



static void process_file_access(xmlNodePtr parent, const struct list_head *head) 
{
        xmlNodePtr new;
        struct list_head *tmp;
        idmef_file_access_t *access;
        
        list_for_each(tmp, head) {
                access = list_entry(tmp, idmef_file_access_t, list);

                new = xmlNewChild(parent, NULL, "FileAccess", NULL);
                if ( ! new )
                        return;
        
                process_userid(new, &access->userid);
                process_string_list(new, "permission", &access->permission_list);
        }
}



static void process_file_linkage(xmlNodePtr parent, const struct list_head *head) 
{
        xmlNodePtr new;
        struct list_head *tmp;
        idmef_linkage_t *linkage;
        
        
        list_for_each(tmp, head) {
                linkage = list_entry(tmp, idmef_linkage_t, list);
                
                new = xmlNewChild(parent, NULL, "Linkage", NULL);
                if ( ! new )
                        return;
                
                idmef_attr_string(new, "category", idmef_linkage_category_to_string(linkage->category));
                idmef_content_string(new, "name", idmef_string(&linkage->name));
                idmef_content_string(new, "path", idmef_string(&linkage->path));
                process_file(new, linkage->file);
        }
}




static void process_inode(xmlNodePtr parent, const idmef_inode_t *inode) 
{
        xmlNodePtr new;
        
        if ( ! inode )
                return;

        new = xmlNewChild(parent, NULL, "Inode", NULL);
        if ( ! new )
                return;
        
        process_time(new, "change-time", inode->change_time);

        idmef_content_uint32(new, "number", inode->number);
        idmef_content_uint32(new, "major-device", inode->major_device);
        idmef_content_uint32(new, "minor-device", inode->minor_device);
        idmef_content_uint32(new, "c-major-device", inode->c_major_device);
        idmef_content_uint32(new, "c-minor-devide", inode->c_minor_device);
}




static void process_file(xmlNodePtr parent, const idmef_file_t *file) 
{
        xmlNodePtr new;

        new = xmlNewChild(parent, NULL, "File", NULL);
        if ( ! new )
                return;
        
        idmef_attr_uint64(new, "ident", file->ident);
        idmef_attr_string(new, "category", idmef_file_category_to_string(file->category));
        idmef_attr_string(new, "fstype", idmef_string(&file->fstype));

        idmef_content_string(new, "name", idmef_string(&file->name));
        idmef_content_string(new, "path", idmef_string(&file->path));

        process_time(new, "create-time", file->create_time);
        process_time(new, "modify-time", file->modify_time);
        process_time(new, "access-time", file->access_time);

        idmef_content_uint32(new, "data-size", file->data_size);
        idmef_content_uint32(new, "disk-size", file->disk_size);
        
        process_file_access(new, &file->file_access_list);
        process_file_linkage(new, &file->file_linkage_list);
        process_inode(new, file->inode);
}




static void process_target(xmlNodePtr parent, const idmef_target_t *target)
{
        xmlNodePtr new;
        idmef_file_t *file;
        struct list_head *tmp;

        new = xmlNewChild(parent, NULL, "Target", NULL);
        if ( ! new )
                return;
        
        idmef_attr_uint64(new, "ident", target->ident);
        idmef_attr_string(new, "decoy", idmef_target_decoy_to_string(target->decoy));
        idmef_attr_string(new, "interface", idmef_string(&target->interface));
        
        process_node(new, target->node);
        process_user(new, target->user);
        process_process(new, target->process);
        process_service(new, target->service);

        list_for_each(tmp, &target->file_list) {
                file = list_entry(tmp, idmef_file_t, list);
                process_file(new, file);
        }
}



static void process_analyzer(xmlNodePtr parent, const idmef_analyzer_t *analyzer) 
{
        xmlNodePtr new;

        new = xmlNewChild(parent, NULL, "Analyzer", NULL);
        if ( ! new )
                return;
        
        idmef_attr_uint64(new, "analyzerid", analyzer->analyzerid);
        idmef_attr_string(new, "manufacturer", idmef_string(&analyzer->manufacturer));
        idmef_attr_string(new, "model", idmef_string(&analyzer->model));
        idmef_attr_string(new, "version", idmef_string(&analyzer->version));
        idmef_attr_string(new, "class", idmef_string(&analyzer->class));
        idmef_attr_string(new, "ostype", idmef_string(&analyzer->ostype));
        idmef_attr_string(new,         "osversion", idmef_string(&analyzer->osversion));

        process_node(new, analyzer->node);
        process_process(new, analyzer->process);
}



static void process_classification(xmlNodePtr parent, const idmef_classification_t *class) 
{
        xmlNodePtr new;

        new = xmlNewChild(parent, NULL, "Classification", NULL);
        if ( ! new )
                return;
        
        idmef_attr_string(new, "origin", idmef_classification_origin_to_string(class->origin));
        idmef_content_string(new, "name", idmef_string(&class->name));
        idmef_content_string(new, "url", idmef_string(&class->url));
}



static void process_data(xmlNodePtr parent, const idmef_additional_data_t *ad) 
{
        size_t size;
        char buf[1024];
        xmlNodePtr new;
        const char *ptr;

        size = sizeof(buf);
        
        ptr = idmef_additional_data_to_string(ad, buf, &size);
        if ( ! ptr )
                return;
        
        new = xmlNewChild(parent, NULL, "AdditionalData", ptr);
        if ( ! new )
                return;
        
        idmef_attr_string(new, "type", idmef_additional_data_type_to_string(ad->type));
        idmef_attr_string(new, "meaning", idmef_string(&ad->meaning));
}




static void process_impact(xmlNodePtr parent, const idmef_impact_t *impact) 
{
        xmlNodePtr new;
        
        if ( ! impact )
                return;

        new = xmlNewChild(parent, NULL, "Impact", idmef_string(&impact->description));
        if ( ! new )
                return;
        
        idmef_attr_string(new, "severity", idmef_impact_severity_to_string(impact->severity));
        idmef_attr_string(new, "completion", idmef_impact_completion_to_string(impact->completion));
        idmef_attr_string(new, "type", idmef_impact_type_to_string(impact->type));
}



static void process_confidence(xmlNodePtr parent, const idmef_confidence_t *confidence) 
{
        char buf[64];
        xmlNodePtr new;
        
        if ( ! confidence )
                return;

        if ( confidence->rating == numeric ) {
                snprintf(buf, sizeof(buf), "%f", confidence->confidence);
                new = xmlNewChild(parent, NULL, "Confidence", buf);
        } else
                new = xmlNewChild(parent, NULL, "Confidence", NULL);

        if ( ! new )
                return;
        
        idmef_attr_string(new, "rating", idmef_confidence_rating_to_string(confidence->rating));
}




static void process_action(xmlNodePtr parent, const idmef_action_t *action) 
{
        xmlNodePtr new;

        new = xmlNewChild(parent, NULL, "Action", idmef_string(&action->description));
        if ( ! new )
                return;
        
        idmef_attr_string(new, "category", idmef_action_category_to_string(action->category));
}




static void process_assessment(xmlNodePtr parent, const idmef_assessment_t *assessment) 
{
        xmlNodePtr new;
        struct list_head *tmp;
        idmef_action_t *action;

        if ( ! assessment )
                return;

        new = xmlNewChild(parent, NULL, "Assessment", NULL);
        if ( ! new )
                return;
        
        process_impact(new, assessment->impact);
        
        list_for_each(tmp, &assessment->action_list) {
                action = list_entry(tmp, idmef_action_t, list);
                process_action(new, action);
        }
        
        process_confidence(new, assessment->confidence);
}





static void process_alert(xmlNodePtr root, idmef_alert_t *alert) 
{
        xmlNodePtr new;
        struct list_head *tmp;
        const idmef_source_t *source;
        const idmef_target_t *target;
        const idmef_classification_t *class;
        const idmef_additional_data_t *data;

        new = xmlNewChild(root, NULL, "Alert", NULL);
        if ( ! new )
                return;
        
        idmef_attr_uint64(new, "ident", alert->ident);

        process_analyzer(new, &alert->analyzer);
        process_time(new, "CreateTime", &alert->create_time);
        process_time(new, "DetectTime", alert->detect_time);
        process_time(new, "AnalyzerTime", alert->analyzer_time);
        
        list_for_each(tmp, &alert->source_list) {
                source = list_entry(tmp, idmef_source_t, list);
                process_source(new, source);
        }
        
        list_for_each(tmp, &alert->target_list) {
                target = list_entry(tmp, idmef_target_t, list);
                process_target(new, target);
        }        

        list_for_each(tmp, &alert->classification_list) {
                class = list_entry(tmp, idmef_classification_t, list);
                process_classification(new, class);
        }
        
        process_assessment(new, alert->assessment);
        
        list_for_each(tmp, &alert->additional_data_list) {
                data = list_entry(tmp, idmef_additional_data_t, list);
                process_data(new, data);
        }
}





static void process_heartbeat(xmlNodePtr idmefmsg, const idmef_heartbeat_t *heartbeat) 
{
        char buf[256];
        xmlNodePtr hb;
        struct list_head *tmp;
        const idmef_additional_data_t *data;
        
        hb = xmlNewChild(idmefmsg, NULL, "Heartbeat", NULL);
        if ( ! hb )
                return;
        
        snprintf(buf, sizeof(buf), "%llu", heartbeat->ident);
        xmlSetProp(hb, "ident", buf);
        
        process_analyzer(hb, &heartbeat->analyzer);
        process_time(hb, "CreateTime", &heartbeat->create_time);
        process_time(hb, "AnalyzerTime", heartbeat->analyzer_time);

        list_for_each(tmp, &heartbeat->additional_data_list) {
                data = list_entry(tmp, idmef_additional_data_t, list);
                process_data(hb, data);
        }        
}



static void validate_dtd(xmlDoc *doc) 
{
        xmlValidCtxt validation_context;
        
        validation_context.doc = doc;
        validation_context.userData = (void *) stderr;
        validation_context.error = (xmlValidityErrorFunc) fprintf;
        validation_context.warning = (xmlValidityWarningFunc) fprintf;
        
        xmlValidateDtd(&validation_context, doc, idmef_dtd);
}



static void dump_to_buffer(xmlDoc *doc, xmlOutputBufferPtr out) 
{
        xmlNodeDumpOutput(out, doc, doc->children, 0, format, NULL);

	xmlOutputBufferWriteString(out, "\n");
        
        xmlOutputBufferFlush(out);
}



static void dump_document(xmlDoc *doc) 
{
        if ( out_fd )
                dump_to_buffer(doc, out_fd);

        if ( out_stderr )
                dump_to_buffer(doc, out_stderr);
                
        if ( idmef_dtd )
                validate_dtd(doc);
}



static void process_message(const idmef_message_t *msg) 
{
        xmlNodePtr root;
        xmlDoc *document;
         
        document = xmlNewDoc("1.0");
        if ( ! document ) {
                log(LOG_ERR, "error creating XML document.\n");
                return;
        }
        
        root = xmlNewDocNode(document, NULL, "IDMEF-Message", NULL);
        if ( ! root ) {
                xmlFreeDoc(document);
                return;
        }
        
        xmlDocSetRootElement(document, root);
                 
        switch (msg->type) {

        case idmef_alert_message:
                process_alert(root, msg->message.alert);
                break;

        case idmef_heartbeat_message:
                process_heartbeat(root, msg->message.heartbeat);
                break;

        default:
                log(LOG_ERR, "unknow message type: %d.\n", msg->type);
                xmlFreeDoc(document);
                return;
        }

        dump_document(document);
        
        xmlFreeDoc(document);
}




static int set_xmlmod_state(prelude_option_t *opt, const char *arg) 
{
        int ret;
        
        if ( enabled == 1 ) {
                ret = plugin_unsubscribe((plugin_generic_t *) &plugin);
                if ( ret < 0 )
                        return prelude_option_error;
                enabled = 0;
        } else {
                
                ret = plugin_subscribe((plugin_generic_t *) &plugin);
                if ( ret < 0 )
                        return prelude_option_error;
                
                enabled = 1;
        }
        
        return prelude_option_success;
}



static int get_xmlmod_state(char *buf, size_t size) 
{
        snprintf(buf, size, "%s", (enabled == 1) ? "enabled" : "disabled");
        return prelude_option_success;
}



static int set_output_file(prelude_option_t *option, const char *arg)
{
        int ret;
        FILE *fd;

        fd = fopen(arg, "a+");
        if ( ! fd ) {
                log(LOG_ERR, "error opening %s for writing.\n", arg);
                return prelude_option_error;
        }
        

        if ( no_buffering ) {
                ret = setvbuf(fd, NULL, _IONBF, 0);
                if ( ret != 0)
                      log(LOG_ERR, "error opening %s for writing.\n", arg);
        }

        out_fd = xmlAllocOutputBuffer(NULL);
        if ( ! out_fd ) {
                log(LOG_ERR, "error creating an XML output buffer.\n");
                return prelude_option_error;
        }
        
        out_fd->context = fd;
        out_fd->writecallback = file_write;
        out_fd->closecallback = NULL;  /* No close callback */
        
        return prelude_option_success;
}



static int set_output_stderr(prelude_option_t *option, const char *arg)
{
        out_stderr = xmlAllocOutputBuffer(NULL);
        if ( ! out_stderr ) {
                log(LOG_ERR, "error creating an XML output buffer.\n");
                return prelude_option_error;
        }
        
        out_stderr->context = stderr;
        out_stderr->writecallback = file_write;
        out_stderr->closecallback = NULL;  
        
        return prelude_option_success;
}



static int set_dtd_check(prelude_option_t *option, const char *arg)
{        
        if ( ! arg ) 
                arg = IDMEF_DTD;
                
        idmef_dtd = xmlParseDTD(NULL, arg);
        if ( ! idmef_dtd ) {
                log(LOG_ERR, "error loading IDMEF DTD %s.\n", arg);
                return prelude_option_error;
        }

        return prelude_option_success;
}



static int enable_formatting(prelude_option_t *option, const char *arg)
{
        format = 1;
        return prelude_option_success;
}



static int disable_buffering(prelude_option_t *option, const char *arg)
{
        no_buffering = 1;
        return prelude_option_success;
}



plugin_generic_t *plugin_init(int argc, char **argv)
{
	prelude_option_t *opt, *output_file_opt;
        
        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 0, "xmlmod",
                                 "Option for the xmlmod plugin", no_argument,
                                 set_xmlmod_state, get_xmlmod_state);

        output_file_opt = prelude_option_add(opt, CLI_HOOK|CFG_HOOK, 'l', "logfile",
                           "Specify output file to use", required_argument,
                           set_output_file, NULL);

        /* 
         * Ensure that this option callback will be call last so that options that may change
         * the behavior of the log file descriptor will be taken into account before actually
         * opening it.
         */
        prelude_option_set_priority(output_file_opt, option_run_last);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK, 's', "stderr",
                           "Dump alert to stderr", no_argument, set_output_stderr, NULL);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK, 'v', "validate",
                           "Validate IDMEF XML output against DTD", optionnal_argument,
                           set_dtd_check, NULL);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK, 'f', "format",
                           "Format XML output so that it is readable", no_argument,
                           enable_formatting, NULL);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK, 'd', "disable-buffering",
                           "Disable output file buffering to prevent truncated tags", no_argument,
                           disable_buffering, NULL);
       
        plugin_set_name(&plugin, "XmlMod");
        plugin_set_author(&plugin, "Yoann Vandoorselaere");
        plugin_set_contact(&plugin, "yoann@mandrakesoft.com");
        plugin_set_desc(&plugin, "Convert from Prelude internal format to IDMEF-XML format");
	plugin_set_running_func(&plugin, process_message);
        
	return (plugin_generic_t *) &plugin;
}

