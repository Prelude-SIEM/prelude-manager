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
#include <errno.h>

#include "config.h"
#include "report.h"

#define plural(number) (number > 1) ? "s" : ""

static char *program = NULL;


/*
 *
 */
static void execmod_run(alert_t *alert, report_infos_t *rinfos) {
        int i;
        char msg[1024];
        plugin_generic_t *p = alert_plugin(alert);

        
        i = snprintf(msg, sizeof(msg), "Date\t: %s\n", rinfos->date_start);
        if ( rinfos->date_end )
                i += snprintf(msg + i, sizeof(msg) - i, " - %s\n", rinfos->date_end);
        else
                i += snprintf(msg + i, sizeof(msg) - i, "\n");
         
        snprintf(msg + i, sizeof(msg) - i, "Plugin\t: %s\n", plugin_name(p));
        snprintf(msg + i, sizeof(msg) - i, "Author\t: %s\n", plugin_author(p));
        snprintf(msg + i, sizeof(msg) - i, "Contact\t: %s\n", plugin_contact(p));
        snprintf(msg + i, sizeof(msg) - i, "description\t: %s\n", plugin_desc(p));
        snprintf(msg + i, sizeof(msg) - i, "kind\t\t: %s\n", rinfos->kind);
        snprintf(msg + i, sizeof(msg) - i, "received\t: %d time%s\n", alert_count(alert), plural(alert_count(alert)));
        snprintf(msg + i, sizeof(msg) - i, "message\t\t: %s\n\n", alert_message(alert));

        i = execlp(program, msg, NULL);
        if ( i < 0 )
                log(LOG_ERR, "couldn't exec %s.\n", program);
}



static plugin_report_t plugin;



static void print_help(const char *optarg) 
{
        fprintf(stderr, "Usage for %s :\n", plugin_name(&plugin));
        fprintf(stderr, "\t -p --program Program to execute.\n\n");
}



static void set_program(const char *optarg) 
{
        program = strdup(optarg);
}



int plugin_init(unsigned int id)
{
        plugin_option_t opts[] = {
                { "program", required_argument, NULL, 'p', set_program },
                { "help", no_argument, NULL, 'h', print_help           },
                { 0, 0, 0, 0 },
        };
        
    
        plugin_set_name(&plugin, "ExecMod");        
        plugin_set_author(&plugin, "Yoann Vandoorselaere");
        plugin_set_contact(&plugin, "yoann@mandrakesoft.com");
        plugin_set_desc(&plugin, "Will log all alert to a file.");
        plugin_set_running_func(&plugin, execmod_run);
        plugin_set_closing_func(&plugin, NULL);

        plugin_config_get((plugin_generic_t *)&plugin, opts, PRELUDE_REPORT_CONF);

        if ( ! program )
                return -1;
        
        return plugin_register((plugin_generic_t *)&plugin);
}












