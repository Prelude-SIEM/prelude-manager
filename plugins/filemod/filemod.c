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


/*
 *
 */
static void filemod_run(alert_t *alert, report_infos_t *rinfos) {
        int i;
        
        fprintf(fd, "\n\n*** %s", rinfos->date_start);

        if ( rinfos->date_end ) {
                fprintf(fd, " - %s\n", rinfos->date_end);
        } else
                fprintf(fd, "\n");

        fprintf(fd, "Plugin\t: %s\n", plugin_name(alert_plugin(alert)));
        fprintf(fd, "Author\t: %s\n", plugin_author(alert_plugin(alert)));
        fprintf(fd, "Contact\t: %s\n", plugin_contact(alert_plugin(alert)));
        fprintf(fd, "description\t: %s\n", plugin_desc(alert_plugin(alert)));
        fprintf(fd, "kind\t\t: %s\n", rinfos->kind);
        fprintf(fd, "received\t: %d time%s\n", alert_count(alert), plural(alert_count(alert)));
        fprintf(fd, "message\t\t: %s\n\n", alert_message(alert));
        
        if ( rinfos->pktdump ) 
                for ( i = 0; rinfos->pktdump[i] != NULL; i++) 
                        fprintf(fd, "%s\n", rinfos->pktdump[i]);
        
        if ( rinfos->hexdump ) {
                fprintf(fd, "\nData hexadecimal dump follow :\n");
                
                for ( i = 0; rinfos->hexdump[i] != NULL; i++ ) 
                        fprintf(fd, "%s\n", rinfos->hexdump[i]);
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
        
        plugin_config_get((plugin_generic_t *)&plugin, opts, PRELUDE_REPORT_CONF);
        
        if ( ! logfile )
                return -1;
        
        fd = fopen(logfile, "a");
        if ( ! fd ) {
                log(LOG_ERR, "error opening %s for appending.\n", logfile);
                return -1;
        }
        
	return plugin_register((plugin_generic_t *)&plugin);
}












