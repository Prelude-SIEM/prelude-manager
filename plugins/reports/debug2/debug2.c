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
#include <libprelude/idmef.h>

#include "config.h"
#include "report.h"
#include "idmef-util.h"


typedef struct {
	struct list_head list;
	char *name;
	idmef_object_t *object;
} object_t;

LIST_HEAD(object_list);

plugin_report_t plugin;

static int enabled = 0;

#define BUFSIZE 32768

static int iterator(idmef_value_t *val, void *extra)
{
	char buf[BUFSIZE];
	char *name = extra;
	int ret;
	
	ret = idmef_value_to_string(val, buf, BUFSIZE);
	printf("%s: %s\n", name, ( ret < 0 ) ? "cannot convert to char *" : buf);
	
	return 0;	
}


static void handle_alert (const idmef_message_t *msg)
{
	struct list_head *tmp;
	object_t *entry;
	idmef_value_t *val;
	
	printf("debug2: --- START OF MESSAGE\n");

	list_for_each(tmp, &object_list) {
		entry = list_entry(tmp, object_t, list);

		val = idmef_message_get(msg, entry->name);
		if ( val )
			idmef_value_iterate(val, entry->name, iterator);
		else
			printf("%s = NULL!\n", entry->name);
			
		idmef_value_destroy(val);
	}
	
	printf("debug2: --- END OF MESSAGE\n");
}

static int set_object(prelude_option_t *opt, const char *arg)
{
	object_t *object;
	char *numeric;

	object = calloc(1, sizeof(object_t));
	if ( ! object ) {
		log(LOG_ERR, "out of memory\n");
		return prelude_option_error;
	}

	object->name = strdup(arg);
	
	object->object = idmef_object_new("%s", arg);
	if (! object->object) {
		log(LOG_ERR, "object \"%s\" not found", arg);
		return prelude_option_error;
	}
	
	list_add_tail(&object->list, &object_list);

	printf("debug2: object %s [%s]\n", 
		idmef_object_get_name(object->object),
		(numeric = idmef_object_get_numeric(object->object)));
	
	free(numeric);
	
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
        
        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 0, "debug2",
                                 "Option for the debug plugin", no_argument,
                                 set_debug_state, get_debug_state);

	prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'o', "object",
	                           "IDMEF object name", required_argument,
	                                   set_object, NULL); 

        plugin_set_name(&plugin, "Debug2");
        plugin_set_desc(&plugin, "Test plugin.");
	plugin_set_running_func(&plugin, handle_alert);
	
	printf("BUFSIZE=%d\n", BUFSIZE);
	     
	return (plugin_generic_t *) &plugin;
}


