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
#include <time.h>
#include <stdlib.h>

#include <inttypes.h>
#include <sys/types.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libprelude/list.h>

#include "config.h"
#include "report.h"
#include "idmef-util.h"

static plugin_report_t plugin;

static int enabled = 0;
static int verbose = 0;


typedef enum {
	source = 0,
	target = 1,
} type_t;

typedef union {
	u_int32_t addr;
	struct in_addr s_in_addr;
} ipv4_address_t;

typedef struct {
	struct list_head list;
	
	ipv4_address_t ipv4_addr;
	const char *address;
	const char *netmask;
} address_t;

struct list_head source_list;
struct list_head target_list;

u_int32_t get_address(address_t *addr) 
{
	return addr->ipv4_addr.addr;
}

char *get_address_as_text(address_t *addr) 
{
	return inet_ntoa(addr->ipv4_addr.s_in_addr);
}

/* FIXME: netmask parameter ignored */
static int add_address(struct list_head *list, const char *address, const char *netmask) 
{
	address_t *addr;
	
	addr = malloc(sizeof(address_t));
	if (!addr) {
		log(LOG_ERR, "out of memory\n");
		return -1;
	}
	
	addr->ipv4_addr.addr = inet_addr(address);
	
	list_add_tail(&addr->list, list);
	
	return 1;
} 

static void display_address(type_t type, idmef_address_t *addr) 
{
	if (addr->category != ipv4_addr) {
		log(LOG_INFO, "unsupported address category: %s\n", 
			idmef_address_category_to_string(addr->category));
	}
	
	switch (type) {
		case source: 
			add_address(&source_list, addr->address, addr->netmask);
			break;
		case target:
			add_address(&target_list, addr->address, addr->netmask);
			break;
		default: 
			log(LOG_INFO, "unsupported address type\n");
			break;
	}
}


static void display_node(type_t type, idmef_node_t *node) 
{
	struct list_head *tmp;
	idmef_address_t *addr;

	list_for_each(tmp, &node->address_list) {
		addr = list_entry(tmp, idmef_address_t, list);
		display_address(type, addr);
	}
}

static void display_source(idmef_source_t *src) 
{
	type_t type;
	
	type = source;
	
	if (src->node) display_node(type, src->node);
	else log(LOG_INFO, "unsupported source type\n");
}

static void display_target(idmef_target_t *tgt) 
{
	type_t type;
	
	type = target;
	
	if (tgt->node) display_node(type, tgt->node);
	else log(LOG_INFO, "unsopported target type\n");
	
}



static void display_alert(idmef_alert_t *alert) {
	struct list_head *tmp;
	idmef_source_t *source;
	idmef_target_t *target;

	address_t *addr;
	
	int i;

	INIT_LIST_HEAD(&source_list);
	INIT_LIST_HEAD(&target_list);

	list_for_each(tmp, &alert->source_list) {
		source = list_entry(tmp, idmef_source_t, list);
		display_source(source);
	}

	list_for_each(tmp, &alert->target_list) {
		target = list_entry(tmp, idmef_target_t, list);
		display_target(target);
	}

	i = 0;
	list_for_each(tmp, &source_list) {
		addr = list_entry(tmp, address_t, list);
		log(LOG_INFO, "SOURCE: %d %s\n", i++, get_address_as_text(addr));
	}

	i = 0;
	list_for_each(tmp, &target_list) {
		addr = list_entry(tmp, address_t, list);
		log(LOG_INFO, "TARGET: %d %s\n", i++, get_address_as_text(addr));
	}
	
	/* Alert processed, clean up */
	list_for_each(tmp, &source_list) 
		list_del(tmp);
		
	list_for_each(tmp, &target_list)
		list_del(tmp);

}

static void handle_alert(const idmef_message_t *msg) {
	struct tm *t;
	time_t ct;

	ct = time(NULL);
	t = localtime(&ct);
	
	switch(msg->type) {
		case idmef_alert_message:
			log(LOG_INFO, "%02d:%02d:%02d alert received: id=%llu, analyzer id=%llu\n", 
			t->tm_hour, t->tm_min, t->tm_sec,  
			msg->message.alert->ident,
			msg->message.alert->analyzer.analyzerid);
			
			if (verbose)
				display_alert(msg->message.alert);
			
			break;
			
		case idmef_heartbeat_message:
			log(LOG_INFO, "%02d:%02d:%02s: heartbeat received: id=%llu, analyzer id=%llu\n", 
			t->tm_hour, t->tm_min, t->tm_sec, 
			msg->message.heartbeat->ident,
			msg->message.heartbeat->analyzer.analyzerid);
			break;
			
		default: log(LOG_INFO, "%02d:%02d:%02s: unknown message (type=%d) received \n", 
			 t->tm_hour, t->tm_min, t->tm_sec, msg->type);
		         break;
	}

}

static void cleanup(void) {
}

static void enable_plugin(const char *optarg) {
	enabled = 1;
}

static void make_verbose(const char *optarg) {
	verbose = 1;
}

static void print_help(const char *optarg) {
    fprintf(stderr, "Usage for mydebug:\n");
    fprintf(stderr, "-v --verbose verbose mode");
}

static int set_debug_state(const char *arg) 
{
        int ret;
        
        if ( enabled == 1 ) {   
                ret = plugin_unsubscribe((plugin_generic_t *) &plugin);
                if ( ret < 0 )
                        return prelude_option_error;
                enabled = 0;
        }

        else {                
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



plugin_generic_t *plugin_init(int argc, char **argv) {
	prelude_option_t *opt;
        
        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 0, "debug",
                                 "Option for the debug plugin", no_argument,
                                 set_debug_state, get_debug_state);
        
        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'v', "verbose",
                           "Be verbose, output detailed information", no_argument,
                           make_verbose, NULL);

        plugin_set_name(&plugin, "Debug");
        plugin_set_desc(&plugin, "Will output alerts to stdout.");
	plugin_set_running_func(&plugin, handle_alert);
	plugin_set_closing_func(&plugin, cleanup);
     
	return (plugin_generic_t *) &plugin;
}

