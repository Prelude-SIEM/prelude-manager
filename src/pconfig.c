/*****
*
* Copyright (C) 1999, 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>

#include <libprelude/prelude-log.h>
#include <libprelude/prelude-path.h>
#include <libprelude/config-engine.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>
#include <libprelude/daemonize.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-client.h>
#include <libprelude/prelude-client-mgr.h>
#include <libprelude/prelude-getopt.h>
#include <libprelude/prelude-list.h>

#include "config.h"
#include "pconfig.h"
#include "relaying.h"
#include "ssl.h"




struct report_config config;



static int print_version(prelude_option_t *opt, const char *arg) 
{
        printf("prelude-manager %s\n", VERSION);
        return prelude_option_end;
}


static int get_version(char *buf, size_t size) 
{
        snprintf(buf, size, "prelude-manager %s", VERSION);
        return prelude_option_success;
}


static int set_daemon_mode(prelude_option_t *opt, const char *arg) 
{
        prelude_daemonize(config.pidfile);
        prelude_log_use_syslog();
        return prelude_option_success;
}


static int set_pidfile(prelude_option_t *opt, const char *arg) 
{
        config.pidfile = strdup(arg);
        return prelude_option_success;
}



static int set_parent_manager(prelude_option_t *opt, const char *arg) 
{
        int ret;
        
        ret = manager_parent_setup_from_cfgline(arg);
        if ( ret < 0 )
                return prelude_option_error;

        return prelude_option_success;
}



static int set_child_manager(prelude_option_t *opt, const char *arg) 
{
        int ret;

        ret = manager_children_setup_from_cfgline(arg);
        if ( ret < 0 )
                return prelude_option_error;
        
        return prelude_option_success;
}




static int set_sensor_listen_address(prelude_option_t *opt, const char *arg) 
{
        char *ptr = strdup(arg);
        
        config.addr = ptr;
        
        ptr = strchr(ptr, ':');
        if ( ptr ) {
                *ptr = '\0';
                config.port = atoi(ptr + 1);
        }
        
        return prelude_option_success;
}




static int set_admin_listen_address(prelude_option_t *opt, const char *arg) 
{
        char *ptr = strdup(arg);
        
        config.admin_server_addr = ptr;
        
        ptr = strchr(ptr, ':');
        if ( ptr ) {
                *ptr = '\0';
                config.admin_server_port = atoi(ptr + 1);
        }
        
        return prelude_option_success;
}



static int print_help(prelude_option_t *opt, const char *arg) 
{
        prelude_option_print(CLI_HOOK, 25);
        return prelude_option_end;
}



int pconfig_init(int argc, char **argv) 
{
        int ret;
        prelude_option_t *opt;
        
	/* Default */
	config.addr = "127.0.0.1";
	config.port = 5554;
        config.admin_server_port = 5555;
        config.pidfile = NULL;

        prelude_option_add(NULL, CLI_HOOK, 'h', "help",
                           "Print this help", no_argument, print_help, NULL);
        
        prelude_option_add(NULL, CLI_HOOK|WIDE_HOOK, 'v', "version",
                           "Print version number", no_argument, print_version, get_version);

        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'd', "daemon",
                           "Run in daemon mode", no_argument, set_daemon_mode, NULL);
        
        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'P', "pidfile",
                                 "Write Prelude PID to pidfile", required_argument, set_pidfile, NULL);
        /*
         * we want this option to be processed before -d.
         */
        prelude_option_set_priority(opt, option_run_first);
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'r', "parent-managers",
                           "List of managers address:port pair where messages should be sent to",
                           required_argument, set_parent_manager, NULL);

        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'c', "child-managers",
                           "List of managers address:port pair where messages should be gathered from",
                           required_argument, set_child_manager, NULL);
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 's', "sensors-srvr", 
                           "Address the sensors server should listen on (addr:port)", required_argument,
                           set_sensor_listen_address, NULL);

        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'a', "admin-srvr",
                           "Address the admin server should listen on (addr:port)", required_argument,
                           set_admin_listen_address, NULL);

        prelude_set_program_name("prelude-manager");
        
        ret = prelude_option_parse_arguments(NULL, PRELUDE_MANAGER_CONF, argc, argv);
        if ( ret == prelude_option_end )
                exit(0);

        return ret;
}
