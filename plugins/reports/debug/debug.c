/*****
*
* Copyright (C) 2002 Krzysztof Zaraska <kzaraska@student.uci.agh.edu.pl>
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
#include <time.h>
#include <stdlib.h>

#include <inttypes.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libprelude/list.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/idmef-tree-func.h>

#include "config.h"
#include "report.h"
#include "idmef-util.h"


static void dump_idmef_list_idmef_classification_t_func(const char *name, const struct list_head *list);
static void dump_idmef_list_idmef_additional_data_t_func(const char *name, const struct list_head *list);
static void dump_idmef_list_idmef_webservice_arg_t_func(const char *name, const struct list_head *list);
static void dump_idmef_list_idmef_process_arg_t_func(const char *name, const struct list_head *list);
static void dump_idmef_list_idmef_address_t_func(const char *name, const struct list_head *list);
static void dump_idmef_list_idmef_userid_t_func(const char *name, const struct list_head *list);
static void dump_idmef_list_idmef_process_env_t_func(const char *name, const struct list_head *list);
static void dump_idmef_list_idmef_action_t_func(const char *name, const struct list_head *list);
static void dump_idmef_list_idmef_alertident_t_func(const char *name, const struct list_head *list);
static void dump_idmef_list_idmef_source_t_func(const char *name, const struct list_head *list);
static void dump_idmef_list_idmef_target_t_func(const char *name, const struct list_head *list);
static void dump_idmef_list_idmef_file_access_t_func(const char *name, const struct list_head *list);
static void dump_idmef_list_idmef_file_access_permission_t_func(const char *name, const struct list_head *list);
static void dump_idmef_list_idmef_linkage_t_func(const char *name, const struct list_head *list);



typedef struct {
	struct list_head list;
	
	char *data;
} concat_string_t; 



#define dump_idmef_message(msg) dump_idmef_message_func(#msg, &(msg))
#define dump_idmef_message_ptr(ptr) dump_idmef_message_func(#ptr, ptr)
#define dump_idmef_heartbeat(heartbeat) dump_idmef_heartbeat_func(#heartbeat, &(heartbeat))
#define dump_idmef_heartbeat_ptr(ptr) dump_idmef_heartbeat_func(#ptr, ptr)
#define dump_idmef_alert(alert) dump_idmef_alert_func(#alert, &(alert))
#define dump_idmef_alert_ptr(ptr) dump_idmef_alert_func(#ptr, ptr)
#define dump_idmef_overflow_alert(alert) dump_idmef_overflow_alert_func(#alert, &(alert))
#define dump_idmef_overflow_alert_ptr(ptr) dump_idmef_overflow_alert_func(#ptr, ptr)
#define dump_idmef_correlation_alert(alert) dump_idmef_correlation_alert_func(#alert, &(alert))
#define dump_idmef_correlation_alert_ptr(ptr) dump_idmef_correlation_alert_func(#ptr, ptr)
#define dump_idmef_tool_alert(alert) dump_idmef_tool_alert_func(#alert, &(alert))
#define dump_idmef_tool_alert_ptr(ptr) dump_idmef_tool_alert_ptr(#ptr, &(ptr))
#define dump_idmef_alertident(ident) dump_idmef_alertident_func(#ident, &(ident))
#define dump_idmef_alertident_ptr(ptr) dump_idmef_alertident_func(#ptr, ptr)
#define dump_idmef_classification(cl) dump_idmef_classification_func(#cl, &(cl))
#define dump_idmef_classification_ptr(ptr) dump_idmef_classification_func(#ptr, ptr)
#define dump_idmef_additional_data(data) dump_idmef_additional_data_func(#data, &(data))
#define dump_idmef_additional_data_ptr(ptr) dump_idmef_additional_data_func(#ptr, ptr)
#define dump_idmef_additional_data_list_ptr(list) dump_idmef_list_ptr(#list, idmef_additional_data_t, list)
#define dump_idmef_additional_data_list(list) dump_idmef_list_ptr(#list, idmef_additional_data_t, &list)
#define dump_idmef_analyzer(anal) dump_idmef_analyzer_func(#anal, &(anal))
#define dump_idmef_analyzer_ptr(ptr) dump_idmef_analyzer_func(#ptr, ptr))
#define dump_idmef_assessment(ass) dump_idmef_assessment_func(#ass, &(ass))
#define dump_idmef_assessment_ptr(ptr) dump_idmef_assessment_func(#ptr, ptr)
#define dump_idmef_confidence(conf) dump_idmef_confidence_func(#conf, &(conf))
#define dump_idmef_confidence_ptr(ptr) dump_idmef_confidence_func(#ptr, ptr)
#define dump_idmef_action(action) dump_idmef_action_func(#action, &(action))
#define dump_idmef_action_ptr(ptr) dump_idmef_action_func(#ptr, ptr)
#define dump_idmef_impact(imp) dump_idmef_impact_func(#imp, &(imp))
#define dump_idmef_impact_ptr(ptr) dump_idmef_impact_func(#ptr, ptr)
#define dump_idmef_target(tgt) dump_idmef_target_func(#tgt, &(tgt))
#define dump_idmef_target_ptr(ptr) dump_idmef_target_func(#ptr, ptr)
#define dump_idmef_target_list_ptr(list) dump_idmef_list_ptr(#list, idmef_target_t, list)
#define dump_idmef_target_list(list) dump_idmef_list_ptr(#list, idmef_target_t, &list)
#define dump_idmef_source(src) dump_idmef_source_func(#src, &(src))
#define dump_idmef_source_ptr(ptr) dump_idmef_source_func(#ptr, ptr)
#define dump_idmef_source_list_ptr(list) dump_idmef_list_ptr(#list, idmef_source_t, list)
#define dump_idmef_source_list(list) dump_idmef_list_ptr(#list, idmef_source_t, &list)
#define dump_idmef_service(serv) dump_idmef_service_func(#serv, &(serv))
#define dump_idmef_service_ptr(ptr) dump_idmef_service_func(#ptr, ptr)
#define dump_idmef_snmpservice(serv) dump_idmef_snmpservice(#serv, &(serv))
#define dump_idmef_snmpservice_ptr(ptr) dump_idmef_snmpservice_func(#ptr, ptr)
#define dump_idmef_webservice(serv) dump_idmef_webservice_func(#serv, &(serv))
#define dump_idmef_webservice_ptr(ptr) dump_idmef_webservice_func(#ptr, ptr)
#define dump_idmef_webservice_arg(item) dump_idmef_webservice_arg_ptr(#item, &item)
#define dump_idmef_webservice_arg_ptr(item) dump_idmef_webservice_arg_ptr(#item, item)
#define dump_idmef_file(file) dump_idmef_file_func(#file, &(file))
#define dump_idmef_file_ptr(ptr) dump_idmef_file_func(#ptr, ptr)
#define dump_idmef_linkage(link) dump_idmef_linkage_func(#link, &(link))
#define dump_idmef_linkage_ptr(ptr) dump_idmef_linkage_func(#ptr, ptr)
#define dump_idmef_file_access(file) dump_idmef_file_access_func(#file, &(file))
#define dump_idmef_file_access_ptr(ptr) dump_idmef_file_access_func(#ptr, ptr)
#define dump_idmef_inode(inode) dump_idmef_inode_func(#inode, &(inode))
#define dump_idmef_inode_ptr(ptr) dump_idmef_inode_func(#ptr, ptr)
#define dump_idmef_process(proc) dump_idmef_process_func(#proc, &(proc))
#define dump_idmef_process_ptr(ptr) dump_idmef_process_func(#ptr, ptr)
#define dump_idmef_user(user) dump_idmef_user_func(#user, &(user))
#define dump_idmef_user_ptr(ptr) dump_idmef_user_func(#ptr, ptr)
#define dump_idmef_userid(userid) dump_idmef_userid_func(#userid, &(userid))
#define dump_idmef_userid_ptr(ptr) dump_idmef_userid_func(#ptr, ptr)
#define dump_idmef_node(node) dump_idmef_node_func(#node, &(node))
#define dump_idmef_node_ptr(ptr) dump_idmef_node_func(#ptr, ptr)
#define dump_idmef_address(addr) dump_idmef_address_func(#addr, &(addr))
#define dump_idmef_address_ptr(ptr) dump_idmef_address_func(#ptr, ptr)


#define dump_float(x) dump_float_func(#x, &(x))
#define dump_int(x) dump_int_func(#x, &(x))
#define dump_uint16(x) dump_uint16_func(#x, &(x))
#define dump_uint32(x) dump_uint32_func(#x, &(x))
#define dump_uint64(x) dump_uint64_func(#x, &(x))
#define dump_idmef_time(t) dump_idmef_time_func(#t, &(t));
#define dump_idmef_time_ptr(ptr) dump_idmef_time_func(#ptr, ptr);
#define dump_idmef_enum_func(name, val) dump_idmef_enum_func_casted(name, (const int *) val)
#define dump_idmef_enum(val) dump_idmef_enum_func_casted(#val, (const int *) &val)
#define dump_idmef_string(str) dump_idmef_string_func(#str, &(str))
#define dump_idmef_string_ptr(ptr) dump_idmef_string_func(#ptr, ptr)
#define dump_string(str) printf("%s%s == %s", prefix, #str, str ? str : "NULL" )
#define dump_idmef_string_item(item) dump_idmef_string_item_func(#item, &(item))
#define dump_idmef_string_item_ptr(ptr) dump_idmef_string_item_func(#ptr, ptr)

#define dump_idmef_list_ptr(name, type, list) do { \
	dump_idmef_list_##type##_func(name, list);      \
} while (0)

#define dump_idmef_list(name, type, list) do {                        \
	dump_idmef_list_##type##_func(name, (const struct list_head *) &(list)); \
} while (0)

#define dump_member(name, parent, type, what) \
	dump_##type##_func(concat(name, concat(".", #what)),  &(parent->what))

#define dump_member_ptr(name, parent, type, what) \
	dump_##type##_func(concat(name, concat("->", #what)), parent->what)

#define dump_idmef_ptr(ptr, type) do {               \
	if ((ptr)) dump_idmef_##type##((*ptr));  \
	else printf("%s%s == NULL\n", prefix, #ptr); \
} while(0)




#define create_list_func(type, cb) \
static void dump_idmef_list_##type##_func(const char *list_name, const struct list_head *list_ptr) \
{\
	struct list_head *tmp;\
	type *entry;\
	int i;\
	char buf[1024];\
	\
	i = 0;\
	\
	if (!wide_format) printf("%s%s:\n", prefix, list_name);\
	\
	if (!wide_format) add_prefix();\
	\
	list_for_each(tmp, list_ptr) {\
		if (!wide_format) snprintf(buf, 1024, "[%d]", i);\
		else snprintf(buf, 1024, "%s[%d]", list_name, i);\
		entry = list_entry(tmp, type, list);\
		cb(buf, entry);\
	}\
	\
	if (!wide_format) delete_prefix();\
}




static plugin_report_t plugin;

static int enabled = 0;
static int silent = 0;
static int verbose = 0;
static int aggresive = 0;
static int wide_format = 0;
static int total_alerts = 0;
static int total_heartbeats = 0;
static char prefix[1024];
static int prefix_len = 0;
static LIST_HEAD(concat_list);



static void make_prefix(void)
{
	int i;
	
	for ( i = 0; i < prefix_len; i++ )
                prefix[i] = ' ';
        
	prefix[prefix_len] = '\0';
}


static void add_prefix(void) 
{
	prefix_len++;
	make_prefix();
}



static void delete_prefix(void) 
{
	if ( prefix_len-- )
                make_prefix();
}



static char *concat(const char *s1, const char *s2) 
{
	char *buf;
	int s1len, s2len;	
	concat_string_t *entry;

	s1len = strlen(s1);
	s2len = strlen(s2);
	
	buf = calloc(1, s1len + s2len + 1);
        if ( ! buf ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }
        
        strncpy(buf, s1, s1len);
	strncat(buf, s2, s2len);
	buf[s1len + s2len] = '\0';
	
	entry = calloc(1, sizeof(concat_string_t));
	if ( ! entry ) {
		log(LOG_ERR, "memory exhausted.\n");
		return NULL;
	}

	entry->data = buf;
	
	list_add(&entry->list, &concat_list);
	
	return buf;
}



static void concat_cleanup(void)
{
        concat_string_t *entry;
	struct list_head *tmp, *n;
	
	list_for_each_safe(tmp, n, &concat_list) {
		entry = list_entry(tmp, concat_string_t, list);
		free(entry->data);
		list_del(&(entry->list));
	}
}




static void dump_idmef_string_func(char *name, const idmef_string_t *str)
{
        if ( ! str ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }

        if ( ! str->string ) {
                if ( str->len > 0 ) 
                        printf("%s[WARNING] %s.string == NULL and %s.len = %d\n", prefix, name, name, str->len); 
                else 
                        printf("%s%s: (empty string)\n", prefix, name);

                return;
        }
        
        if ( str->len > 0 ) {	
                if ( strlen(str->string) + 1 != str->len ) {
                        printf("%s[WARNING] %s.len = %d, strlen(%s.string)+1 = %d\n", 
                               prefix, name, str->len, name, strlen(str->string)+1);

                } else if ( verbose && ! aggresive ) 
                        printf("%s%s: %s\n", prefix, name, str->string); 
        } else 
                printf("%s[WARNING] %s.len is zero, but %s.string != NULL\n", prefix, name, name);

        if ( aggresive )
                printf("%s%s: %s\n", prefix, name, str->string); 
} 



static void dump_idmef_enum_func_casted(char *name, const int *val)
{
        if ( ! val ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        if ( *val == 0 ) 
                printf("%s[WARNING] %s == 0 (default value, may be uninitialized)\n", prefix, name); 
        
        else if ( verbose )
                printf("%s%s: %d (0x%0x)\n", prefix, name, *val, *val);
}



static void dump_idmef_time_func(const char *name, const idmef_time_t *idmef_time)
{
	struct tm *t = NULL;

        if ( ! idmef_time ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }

        if ( ! idmef_time->sec ) {
                printf("%s%s is zero\n", prefix, name);
                return;
        }
        
        t = localtime((const time_t *) &(idmef_time->sec));
        if ( verbose )
                printf("%s%s: %4d-%02d-%02d %02d:%02d:%02d.%05d (0x%x.0x%x)\n", 
                       prefix, name, t->tm_year + 1900, t->tm_mon, t->tm_mday, 
                       t->tm_hour, t->tm_min, t->tm_sec, idmef_time->usec, 
                       idmef_time->sec, idmef_time->usec); 
} 




static void dump_int_func(const char *name, const int *x)
{
        if ( ! x ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        if ( verbose )
                printf("%s%s == %d (0x%x)\n", prefix, name, *x, *x);
}



static void dump_uint16_func(const char *name, const uint16_t *x)
{
        if ( ! x ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
         
        if ( verbose )
                printf("%s%s == %hd (0x%hx)\n", prefix, name, *x, *x);
}



static void dump_uint32_func(const char *name, const uint32_t *x)
{
        if ( ! x ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        if ( verbose )
                printf("%s%s == %u (0x%x)\n", prefix, name, *x, *x);
}



static void dump_uint64_func(const char *name, const uint64_t *x)
{
        if ( ! x ) {
              printf("%s%s == NULL\n", prefix, name);
              return;
        }
        
        if ( verbose )
                printf("%s%s == %lld (0x%llx)\n", prefix, name, *x, *x);
}




static void dump_float_func(const char *name, const float *x)
{
        if ( ! x ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        if ( verbose )
                printf("%s%s == %f\n", prefix, name, *x);
}




static void dump_idmef_address_func(const char *name, const idmef_address_t *address)
{
        if ( ! address ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, address, uint64, ident);
        dump_member(name, address, idmef_enum, category);
        dump_member(name, address, idmef_string, vlan_name);
        dump_member(name, address, int, vlan_num);
        dump_member(name, address, idmef_string, address);
        dump_member(name, address, idmef_string, netmask);
}



static void dump_idmef_node_func(const char *name, const idmef_node_t *node)
{
        if ( ! node ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, node, uint64, ident);
        dump_member(name, node, idmef_enum, category);
        dump_member(name, node, idmef_string, location);
        dump_member(name, node, idmef_string, name);
        dump_idmef_list(concat(name, ".address_list"), idmef_address_t, node->address_list);
} 




static void dump_idmef_userid_func(const char *name, const idmef_userid_t *userid)
{
        if ( ! userid ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, userid, uint64, ident);
        dump_member(name, userid, idmef_enum, type);
        dump_member(name, userid, idmef_string, name);
        dump_member(name, userid, uint32, number);
}



static void dump_idmef_user_func(const char *name, const idmef_user_t *user)
{
        if ( ! user ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, user, uint64, ident);
        dump_member(name, user, idmef_enum, category);
        dump_idmef_list(concat(name, ".userid_list"), idmef_userid_t, user->userid_list);
}



static void dump_idmef_string_item_func(const char *name, const idmef_string_item_t *item)
{
        if ( ! item ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, item, idmef_string, string);
}



static void dump_idmef_process_func(const char *name, const idmef_process_t *proc)
{
        if ( ! proc ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, proc, uint64, ident); 
        dump_member(name, proc, idmef_string, name); 
        dump_member(name, proc, uint32, pid); 
        dump_member(name, proc, idmef_string, path); 
        dump_idmef_list(concat(name, ".arg_list"), idmef_process_arg_t, proc->arg_list); 
        dump_idmef_list(concat(name, ".env_list"), idmef_process_env_t, proc->env_list);
} 




static void dump_idmef_inode_func(const char *name, const idmef_inode_t *inode)
{
        if ( ! inode ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member_ptr(name, inode, idmef_time, change_time); 
        dump_member(name, inode, uint32, number); 
        dump_member(name, inode, uint32, major_device); 
        dump_member(name, inode, uint32, minor_device); 
        dump_member(name, inode, uint32, c_major_device); 
        dump_member(name, inode, uint32, c_minor_device);
}



static void dump_idmef_file_access_func(const char *name, const idmef_file_access_t *fa)
{
        if ( ! fa ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, fa, idmef_userid, userid);
        dump_idmef_list(concat(name, ".permission_list"), idmef_file_access_permission_t, fa->permission_list); 
}



static void dump_idmef_file_func(const char *name, const idmef_file_t *file)
{
        if ( ! file ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, file, uint64, ident);
        dump_member(name, file, idmef_enum, category);
        dump_member(name, file, idmef_string, fstype);
        dump_member(name, file, idmef_string, name);
        dump_member(name, file, idmef_string, path);
        dump_member_ptr(name, file, idmef_time, create_time);
        dump_member_ptr(name, file, idmef_time, modify_time);
        dump_member_ptr(name, file, idmef_time, access_time);
        dump_member(name, file, uint32, data_size);
        dump_member(name, file, uint32, disk_size);
        
        dump_idmef_list(concat(name, ".file_access_list"), idmef_file_access_t, file->file_access_list); 
        dump_idmef_list(concat(name, ".file_linkage_list"), idmef_linkage_t, file->file_linkage_list); 
        
        dump_member_ptr(name, file, idmef_inode, inode);
}



static void dump_idmef_linkage_func(const char *name, const idmef_linkage_t *link)
{
        if ( ! link ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, link, idmef_enum, category);
        dump_member(name, link, idmef_string, name);
        dump_member(name, link, idmef_string, path);
        dump_member_ptr(name, link, idmef_file, file);
}




static void dump_idmef_webservice_arg_func(const char *name, const idmef_webservice_arg_t *arg)
{
        if ( ! arg ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }

        dump_member(name, arg, idmef_string, arg);
}




static void dump_idmef_webservice_func(const char *name, const idmef_webservice_t *web)
{
        if ( ! web ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, web, idmef_string, url);
        dump_member(name, web, idmef_string, cgi);
        dump_member(name, web, idmef_string, http_method);
        dump_idmef_list(concat(name, ".arg_list"), idmef_webservice_arg_t, web->arg_list);
} 




static void dump_idmef_snmpservice_func(const char *name, const idmef_snmpservice_t *snmp)
{
        if ( ! snmp ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, snmp, idmef_string, oid); 
        dump_member(name, snmp, idmef_string, community); 
        dump_member(name, snmp, idmef_string, command);
}




static void dump_idmef_service_func(const char *name, const idmef_service_t *serv)
{
        if ( ! serv ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, serv, uint64, ident);
        dump_member(name, serv, idmef_string, name);
        dump_member(name, serv, uint16, port);
        dump_member(name, serv, idmef_string, portlist);
        dump_member(name, serv, idmef_string, protocol);
        dump_member(name, serv, idmef_enum, type);

	switch (serv->type) { 

        case web_service:
                dump_idmef_webservice_func(concat(name, ".specific->web"),
                                           serv->specific.web); 
                break;

        case snmp_service:
                dump_idmef_snmpservice_func(concat(name, ".specific->snmp"), 
                			    serv->specific.snmp);
                break; 

        default:
                break; 
        }
} 




static void dump_idmef_source_func(const char *name, const idmef_source_t *src)
{
        if ( ! src ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, src, uint64, ident);
        dump_member(name, src, idmef_enum, spoofed);
        dump_member(name, src, idmef_string, interface);
        dump_member_ptr(name, src, idmef_user, user);
        dump_member_ptr(name, src, idmef_node, node);
        dump_member_ptr(name, src, idmef_process, process);
        dump_member_ptr(name, src, idmef_service, service);
}	




static void dump_idmef_target_func(const char *name, const idmef_target_t *tgt)
{
        if ( ! tgt ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, tgt, uint64, ident);
        dump_member(name, tgt, idmef_enum, decoy);
        dump_member(name, tgt, idmef_string, interface);
        dump_member_ptr(name, tgt, idmef_user, user);
        dump_member_ptr(name, tgt, idmef_node, node);
        dump_member_ptr(name, tgt, idmef_process, process);
        dump_member_ptr(name, tgt, idmef_service, service);
}




static void dump_idmef_impact_func(const char *name, const idmef_impact_t *impact)
{
        if ( ! impact ) {
               printf("%s%s == NULL\n", prefix, name);
               return; 
        }
        
        dump_member(name, impact, idmef_enum, severity);
        dump_member(name, impact, idmef_enum, completion);
        dump_member(name, impact, idmef_enum, type);
        dump_member(name, impact, idmef_string, description);
}



static void dump_idmef_action_func(const char *name, const idmef_action_t *action)
{
        if ( ! action ) {
                 printf("%s%s == NULL\n", prefix, name);
                 return;
        }
        
        dump_member(name, action, idmef_enum, category);
        dump_member(name, action, idmef_string, description);
}



static void dump_idmef_confidence_func(const char *name, const idmef_confidence_t *conf)
{
        if ( ! conf ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }   
        
        dump_member(name, conf, idmef_enum, rating);
        dump_member(name, conf, float, confidence);
}



static void dump_idmef_assessment_func(const char *name, const idmef_assessment_t *ass)
{
        if ( ! ass ) {
                printf("%s%s == NULL\n", prefix, name);
                return;   
        }
        
        dump_member_ptr(name, ass, idmef_impact, impact);
        dump_idmef_list(concat(name, ".action_list"), idmef_action_t, ass->action_list); 
        dump_member_ptr(name, ass, idmef_confidence, confidence);
}




static void dump_idmef_analyzer_func(const char *name, const idmef_analyzer_t *anal)
{
        if ( ! anal ) {
                printf("%s%s == NULL\n", prefix, name);
                return;    
        }
        
        dump_member(name, anal, idmef_string, manufacturer);
        dump_member(name, anal, idmef_string, model);
        dump_member(name, anal, idmef_string, version);
        dump_member(name, anal, idmef_string, class);
        dump_member(name, anal, idmef_string, ostype);
        dump_member(name, anal, idmef_string, osversion);
}




static void dump_idmef_additional_data_func(const char *name, const idmef_additional_data_t *data)
{
        if ( ! data ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, data, idmef_enum, type);
        dump_member(name, data, idmef_string, meaning);

        /*
         * FIXME: use idmef_additional_data_to_string.
         * dump_member(name, data, idmef_string, data);
         */
}




static void dump_idmef_classification_func(const char *name, const idmef_classification_t *cl)
{
        if ( ! cl ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, cl, idmef_enum, origin);
        dump_member(name, cl, idmef_string, name);
        dump_member(name, cl, idmef_string, url);
}




static void dump_idmef_alertident_func(const char *name, const idmef_alertident_t *ident)
{
        if ( ! ident ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, ident, uint64, alertident);
        dump_member(name, ident, uint64, analyzerid);
}




static void dump_idmef_tool_alert_func(const char *name, const idmef_tool_alert_t *alert)
{
        if ( ! alert ) {
                printf("%s%s == NULL\n", prefix, name);
                return; 
        }
        
        dump_member(name, alert, idmef_string, name);
        dump_member(name, alert, idmef_string, command);
        dump_idmef_list(concat(name, ".alertident_list"), idmef_alertident_t, alert->alertident_list);
}




static void dump_idmef_correlation_alert_func(const char *name, const idmef_correlation_alert_t *alert)
{
        if ( ! alert ) {
                printf("%s%s == NULL\n", prefix, name);
                return; 
        }
        
        dump_member(name, alert, idmef_string, name);
        dump_idmef_list(concat(name, ".alertident_list"), idmef_alertident_t, alert->alertident_list);
}




static void dump_idmef_overflow_alert_func(const char *name, const idmef_overflow_alert_t *alert)
{
	int i;

        if ( ! alert ) {
                printf("%s%s == NULL\n", prefix, name);
                return; 
        }
        
        dump_member(name, alert, idmef_string, program);

        if ( verbose ) {
                printf("%s%s.buffer: ", prefix, name);

                for ( i = 0; i < alert->size; i++ ) 
                        printf("%02X ", alert->buffer[i]);
                
                printf("\n");
        }
}




static void dump_idmef_alert_func(const char *name, const idmef_alert_t *alert)
{
        if ( ! alert ) {
                printf("%s%s == NULL\n", prefix, name);
                return; 
        }
        
        dump_member(name, alert, uint64, ident);
        dump_member_ptr(name, alert, idmef_assessment, assessment);
        dump_member(name, alert, idmef_analyzer, analyzer);
        dump_member(name, alert, idmef_time, create_time);
        dump_member_ptr(name, alert, idmef_time, detect_time);
        dump_member_ptr(name, alert, idmef_time, analyzer_time);
        
        dump_idmef_list(concat(name, ".source_list"), idmef_source_t, alert->source_list);
        dump_idmef_list(concat(name, ".target_list"), idmef_target_t, alert->target_list);
        dump_idmef_list(concat(name, ".classification_list"), idmef_classification_t, alert->classification_list);
        dump_idmef_list(concat(name, ".additional_data_list"), idmef_additional_data_t, alert->additional_data_list);
        dump_member(name, alert, idmef_enum, type);
        
        switch (alert->type) {
        case idmef_tool_alert: 
                dump_idmef_tool_alert_func(concat(name, ".detail->tool_alert"),
                                           alert->detail.tool_alert); 
                break;

        case idmef_correlation_alert:
                dump_idmef_correlation_alert_func(concat(name, ".detail->correlation_alert"),
                                                  alert->detail.correlation_alert);
                break;

        case idmef_overflow_alert:
                dump_idmef_overflow_alert_func(concat(name, ".detail->overflow_alert"),
                                               alert->detail.overflow_alert);
                break;

        default:
                break;
        }
}




static void dump_idmef_heartbeat_func(const char *name, const idmef_heartbeat_t *heartbeat)
{
        if ( ! heartbeat ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, heartbeat, uint64, ident);
        dump_member(name, heartbeat, idmef_analyzer, analyzer);
        dump_member(name, heartbeat, idmef_time, create_time);
        dump_member_ptr(name, heartbeat, idmef_time, analyzer_time);		
        dump_idmef_list(concat(name, ".additional_data_list"), idmef_additional_data_t, 
                        heartbeat->additional_data_list);
}




static void dump_idmef_message_func(const char *name, const idmef_message_t *msg) 
{
        if ( ! msg ) {
                printf("%s%s == NULL\n", prefix, name);
                return;
        }
        
        dump_member(name, msg, idmef_string, version);
        dump_member(name, msg, idmef_enum, type);
        
        switch (msg->type) {

        case idmef_alert_message:
                dump_idmef_alert_func(concat(name, ".message->alert"),
                                      msg->message.alert);
                break;
        
        case idmef_heartbeat_message:
                dump_idmef_heartbeat_func(concat(name, ".message->heartbeat"),
                                          msg->message.heartbeat);
                break;

        default:
        	printf("[ERROR] %s.type = %d, message type unknown\n",
        		name, msg->type);
                break;
        }
}




/* create_list_func(idmef_string_item_t, dump_idmef_string_item_func); */
create_list_func(idmef_file_access_permission_t, dump_idmef_string_item_func);
create_list_func(idmef_address_t, dump_idmef_address_func);
create_list_func(idmef_process_env_t, dump_idmef_string_item_func);
create_list_func(idmef_process_arg_t, dump_idmef_string_item_func);
create_list_func(idmef_file_access_t, dump_idmef_file_access_func);
create_list_func(idmef_linkage_t, dump_idmef_linkage_func);
create_list_func(idmef_webservice_arg_t, dump_idmef_webservice_arg_func);
create_list_func(idmef_source_t, dump_idmef_source_func);
create_list_func(idmef_target_t, dump_idmef_target_func);
create_list_func(idmef_action_t, dump_idmef_action_func);
create_list_func(idmef_additional_data_t, dump_idmef_additional_data_func);
create_list_func(idmef_classification_t, dump_idmef_classification_func);
create_list_func(idmef_alertident_t, dump_idmef_alertident_func);
create_list_func(idmef_userid_t, dump_idmef_userid_func);





static void handle_alert(const idmef_message_t *msg) 
{
	if (silent) {
        	switch (msg->type) {
        		case idmef_alert_message:
				printf("alert received, count = %d\n", ++total_alerts);
                		break;
        
        		case idmef_heartbeat_message:
				printf("heartbeat received, count = %d\n", ++total_heartbeats);
				break;

        		default:
        			printf("unknown message received\n");
				break;
        	}
	} else {	
		printf("----------------------------------------------------\n");
		dump_idmef_message_ptr(msg);
		concat_cleanup();
	}
}




static void cleanup(void)
{
	/* do nothing */
}



static int make_verbose(prelude_option_t *opt, const char *optarg)
{
	verbose = 1;
        return prelude_option_success;
}


static int make_silent(prelude_option_t *opt, const char *optarg)
{
	silent = 1;
        return prelude_option_success;
}



static int make_aggresive(prelude_option_t *opt, const char *optarg)
{
	aggresive = 1;
        return prelude_option_success;
}



static int use_wide_format(prelude_option_t *opt, const char *optarg)
{
	wide_format = 1;
        return prelude_option_success;
}



static int set_debug_state(prelude_option_t *opt, const char *arg) 
{
        int ret;
        
        if ( enabled ) {   

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



static int get_debug_state(char *buf, size_t size) 
{
        snprintf(buf, size, "%s", (enabled == 1) ? "enabled" : "disabled");
        return prelude_option_success;
}



plugin_generic_t *plugin_init(int argc, char **argv)
{
	prelude_option_t *opt;
        
        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 0, "debug",
                                 "Option for the debug plugin", no_argument,
                                 set_debug_state, get_debug_state);

        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 's', "silent",
                           "Be silent, only output confirmation of receiving alert", no_argument,
                           make_silent, NULL);

        
        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'v', "verbose",
                           "Be verbose, print value of each element", no_argument,
                           make_verbose, NULL);
        
        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'a', "aggressive",
                           "Be aggressive, print strings even if consistency checks fail (may lead to crash)", no_argument,
                           make_aggresive, NULL);

	prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'w', "wide-format",
                           "Use wide format for lists", no_argument,
                           use_wide_format, NULL);       

        plugin_set_name(&plugin, "Debug");
        plugin_set_desc(&plugin, "Validate IDMEF tree. For use when testing sensors code.");
	plugin_set_running_func(&plugin, handle_alert);
	plugin_set_closing_func(&plugin, cleanup);
	     
	return (plugin_generic_t *) &plugin;
}


