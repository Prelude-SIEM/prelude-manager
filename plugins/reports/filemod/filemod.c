/*****
*
* Copyright (C) 1998 - 2000 Vandoorselaere Yoann <yoann@mandrakesoft.com>
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
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>

#include "config.h"
#include "report.h"

#define plural(number) (number > 1) ? "s" : ""

static FILE *fd;
static char *logfile = NULL;



static void print_address(idmef_address_t *addr) 
{
        printf("Address: %s\n", addr->address);
}




static void print_source(idmef_source_t *source) 
{
        struct list_head *tmp;
        idmef_address_t *addr;

        list_for_each(tmp, &source->node.address_list) {
                addr = list_entry(tmp, idmef_address_t, list);
                print_address(addr);
        }
                        
        
        fprintf(fd, "Service port: %u\n", source->service.port);
        fprintf(fd, "Service name: %s\n", source->service.name);
        fprintf(fd, "Protocol: %s\n", source->service.protocol);
}




/*
 *
 */
static void filemod_run(idmef_alert_t *alert)
{
        int i;
        struct list_head *tmp;
        idmef_classification_t *class;
        idmef_additional_data_t *data;
        idmef_source_t *source;
        idmef_target_t *target;

        fd = stdout;
        
        fprintf(fd, "\n*** Alert information ***\n");
        fprintf(fd, "Ident: %s\n", alert->ident);
        fprintf(fd, "Impact: %s\n", alert->impact);
        fprintf(fd, "Action: %s\n", alert->action);
        

        fprintf(fd, "\n*** Source information ***\n");
        list_for_each(tmp, &alert->source_list) {
                target = list_entry(tmp, idmef_target_t, list);
                print_source(target);
        }
        
        fprintf(fd, "\n*** Target information ***\n");
        list_for_each(tmp, &alert->target_list) {
                target = list_entry(tmp, idmef_target_t, list);
                print_source(target);
        }
        
        fprintf(fd, "\n*** Classification information ***\n");
        list_for_each(tmp, &alert->classification_list) {
                class = list_entry(tmp, idmef_classification_t, list);
                fprintf(stdout, "Origin: %s\nName: %s\nUrl: %s\n", class->origin, class->name, class->url);
        }
        
        fprintf(fd, "\n*** Additional data ***\n");
        list_for_each(tmp, &alert->additional_data_list) {
                data = list_entry(tmp, idmef_additional_data_t, list);
                fprintf(stdout, "%s: %s\n", data->meaning, data->data);
        }
        
        fflush(fd);
}



static void filemod_close(void) 
{
        fclose(fd);
}



/*
 * Configuration stuff.
 */

static plugin_report_t plugin;



static void print_help(const char *optarg) 
{
        fprintf(stderr, "Usage for %s :\n", plugin_name(&plugin));
        fprintf(stderr, "\t -f --logfile (default=disabled) "
                "Path to the file where %s should do reporting.\n\n", plugin_name(&plugin));
}



static void set_logfile(const char *optarg) 
{
        logfile = strdup(optarg);
}



int plugin_init(unsigned int id)
{
        plugin_option_t opts[] = {
                { "logfile", required_argument, NULL, 'f', set_logfile },
                { "help", no_argument, NULL, 'h', print_help           },
                { 0, 0, 0, 0 },
        };
    
        plugin_set_name(&plugin, "FileMod");
        plugin_set_author(&plugin, "Yoann Vandoorselaere");
        plugin_set_contact(&plugin, "yoann@mandrakesoft.com");
        plugin_set_desc(&plugin, "Will log all alert to a file.");
        plugin_set_running_func(&plugin, filemod_run);
        plugin_set_closing_func(&plugin, filemod_close);
        
        plugin_config_get((plugin_generic_t *)&plugin, opts, PRELUDE_MANAGER_CONF);        
        if ( ! logfile )
                return -1;
                
        fd = fopen(logfile, "a");
        if ( ! fd ) {
                log(LOG_ERR, "error opening %s for appending.\n", logfile);
                return -1;
        }
        
	return plugin_register((plugin_generic_t *)&plugin);
}












