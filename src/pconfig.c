/*****
*
* Copyright (C) 1999 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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

#include <libprelude/common.h>
#include <libprelude/config-engine.h>
#include <libprelude/plugin-common.h>
#include <libprelude/plugin-common-prv.h>
#include <libprelude/daemonize.h>

#include <inttypes.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-client-mgr.h>
#include <libprelude/prelude-getopt.h>

#include "config.h"
#include "pconfig.h"
#include "ssl.h"


struct report_config config;
prelude_client_mgr_t *relay_managers = NULL;


static int print_version(const char *arg) 
{
        printf("prelude-manager %s\n", VERSION);
        return prelude_option_end;
}


static int get_version(char *buf, size_t size) 
{
        snprintf(buf, size, "prelude-manager %s", VERSION);
        return prelude_option_success;
}


static int set_daemon_mode(const char *arg) 
{
        config.daemonize = 1;
        return prelude_option_success;
}


static int set_pidfile(const char *arg) 
{
        config.pidfile = arg;
        return prelude_option_success;
}


static int set_relay_manager(const char *arg) 
{
        relay_managers = prelude_client_mgr_new("relay", arg);
        if ( ! relay_managers )
                return prelude_option_error;

        return prelude_option_success;
}


static int set_sensor_listen_address(const char *arg) 
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




static int set_admin_listen_address(const char *arg) 
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



static int print_help(const char *arg) 
{
        prelude_option_print(CLI_HOOK, 25);
        return prelude_option_end;
}



int pconfig_init(int argc, char **argv) 
{
        int ret;
        
	/* Default */
	config.addr = "unix";
	config.port = 5554;
        config.admin_server_port = 5555;
	config.daemonize = 0;
        config.pidfile = NULL;

        prelude_option_add(NULL, CLI_HOOK, 'h', "help",
                           "Print this help", no_argument, print_help, NULL);

        prelude_option_add(NULL, CLI_HOOK|WIDE_HOOK, 'v', "version",
                           "Print version number", no_argument, print_version, get_version);

        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'd', "daemon",
                           "Run in daemon mode", no_argument, set_daemon_mode, NULL);

        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'P', "pidfile",
                           "Write Prelude PID to pidfile", required_argument, set_pidfile, NULL);

        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'r', "relay-manager",
                           "List of address:port pair where sensors messages should be relayed",
                           required_argument, set_relay_manager, NULL);
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 's', "sensors-srvr", 
                           "Address the sensors server should listen on (addr:port)", required_argument,
                           set_sensor_listen_address, NULL);

        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'a', "admin-srvr",
                           "Address the admin server should listen on (addr:port)", required_argument,
                           set_admin_listen_address, NULL);

        ret = prelude_option_parse_arguments(NULL, PRELUDE_MANAGER_CONF, argc, argv);
        if ( ret == prelude_option_end )
                exit(0);

        return ret;
}




void manager_relay_msg_if_needed(prelude_msg_t *msg) 
{
        if ( relay_managers )
                prelude_client_mgr_broadcast(relay_managers, msg);
}















