/*****
*
* Copyright (C) 2002 Krzysztof Zaraska <kzaraska@student.uci.agh.edu.pl>
* Copyright (C) 2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libprelude/prelude-inttypes.h>
#include <libprelude/prelude-list.h>
#include <libprelude/idmef.h>

#include "config.h"
#include "report.h"

#define BUFSIZE 32768


prelude_plugin_generic_t *debug2_LTX_prelude_plugin_init(void);


typedef struct {
	prelude_list_t list;
	char *name;
	idmef_object_t *object;
} debug_object_t;


typedef struct {
        prelude_list_t object_list;
} debug_plugin_t;


static plugin_report_t debug_plugin;


static int iterator(idmef_value_t *val, void *extra)
{
        int ret;
	char buf[BUFSIZE];
	char *name = extra;
	
	ret = idmef_value_to_string(val, buf, sizeof(buf));
	printf("%s: %s\n", name, ( ret < 0 ) ? "cannot convert to char *" : buf);
	
	return 0;	
}


static int debug_run(prelude_plugin_instance_t *pi, idmef_message_t *msg)
{
        idmef_value_t *val;
	prelude_list_t *tmp;
	debug_object_t *entry;
	debug_plugin_t *plugin = prelude_plugin_instance_get_data(pi);
        
	printf("debug2: --- START OF MESSAGE\n");

	prelude_list_for_each(tmp, &plugin->object_list) {
		entry = prelude_list_entry(tmp, debug_object_t, list);

		val = idmef_object_get(msg, entry->object);
                if ( ! val ) {
                        printf("%s = NULL!\n", entry->name);
                        continue;
                }
                
                idmef_value_iterate(val, entry->name, iterator);
                idmef_value_destroy(val);
        }
	
	printf("debug2: --- END OF MESSAGE\n");

        return 0;
}



static int debug_set_object(void *context, prelude_option_t *option, const char *arg)
{
	char *numeric;
	debug_object_t *object;
        debug_plugin_t *plugin = prelude_plugin_instance_get_data(context);

	object = calloc(1, sizeof(*object));
	if ( ! object ) {
		log(LOG_ERR, "memory exhausted.\n");
		return prelude_option_error;
	}

	object->name = strdup(arg);
	
	object->object = idmef_object_new("%s", arg);
	if ( ! object->object ) {
		log(LOG_ERR, "object \"%s\" not found", arg);
		return prelude_option_error;
	}
	
	prelude_list_add_tail(&object->list, &plugin->object_list);

	printf("debug2: object %s [%s]\n", 
		idmef_object_get_name(object->object),
		(numeric = idmef_object_get_numeric(object->object)));
	
	free(numeric);
	
	return prelude_option_success;
}



static int debug_new(void *context, prelude_option_t *opt, const char *arg) 
{
        debug_plugin_t *new;
        
        new = malloc(sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return prelude_option_error;
        }

        PRELUDE_INIT_LIST_HEAD(&new->object_list);
        prelude_plugin_instance_set_data(context, new);

        prelude_plugin_subscribe(context);
        
        return prelude_option_success;
}



static void debug_destroy(prelude_plugin_instance_t *pi)
{
        debug_object_t *object;
        prelude_list_t *tmp, *bkp;
        debug_plugin_t *plugin = prelude_plugin_instance_get_data(pi);

        prelude_list_for_each_safe(tmp, bkp, &plugin->object_list) {
                object = prelude_list_entry(tmp, debug_object_t, list);

                prelude_list_del(&object->list);
                
                free(object->name);
                idmef_object_destroy(object->object);
                
                free(object);
        }
        
        
        free(plugin);
}




prelude_plugin_generic_t *debug2_LTX_prelude_plugin_init(void)
{
	prelude_option_t *opt;
        
        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 0, "debug2",
                                 "Option for the debug plugin", optionnal_argument,
                                 debug_new, NULL);

        prelude_plugin_set_activation_option((void *) &debug_plugin, opt, NULL);
        
        prelude_option_add(opt, CLI_HOOK|CFG_HOOK|WIDE_HOOK, 'o', "object",
                           "IDMEF object name", required_argument,
                           debug_set_object, NULL);

        prelude_plugin_set_name(&debug_plugin, "Debug2");
        prelude_plugin_set_desc(&debug_plugin, "Test plugin.");
        prelude_plugin_set_destroy_func(&debug_plugin, debug_destroy);
        report_plugin_set_running_func(&debug_plugin, debug_run);
	     
	return (void *) &debug_plugin;
}


