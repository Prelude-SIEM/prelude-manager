/*****
*
* Copyright (C) 1999-2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

#include <libprelude/prelude-inttypes.h>
#include <libprelude/idmef.h>
#include <libprelude/prelude-log.h>
#include <libprelude/config-engine.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-getopt.h>
#include <libprelude/prelude-plugin.h>
#include <libprelude/daemonize.h>
#include <libprelude/prelude-connection.h>
#include <libprelude/prelude-connection-mgr.h>
#include <libprelude/prelude-linked-object.h>

#include "config.h"
#include "libmissing.h"
#include "pconfig.h"
#include "server-generic.h"
#include "reverse-relaying.h"
#include "plugin-report.h"



struct report_config config;



static int print_version(void *context, prelude_option_t *opt, const char *arg) 
{
        printf("prelude-manager %s\n", VERSION);
        return prelude_option_end;
}


static int get_version(void *context, prelude_option_t *opt, char *buf, size_t size) 
{
        snprintf(buf, size, "prelude-manager %s", VERSION);
        return prelude_option_success;
}


static int set_daemon_mode(void *context, prelude_option_t *opt, const char *arg) 
{
        prelude_daemonize(config.pidfile);
        prelude_log_use_syslog();
        return prelude_option_success;
}


static int set_pidfile(void *context, prelude_option_t *opt, const char *arg) 
{
        config.pidfile = strdup(arg);
        return prelude_option_success;
}




static int set_reverse_relay(void *context, prelude_option_t *opt, const char *arg) 
{
        return reverse_relay_create_initiator(arg);
}




static int set_sensor_listen_address(void *context, prelude_option_t *opt, const char *arg) 
{
        char *ptr = strdup(arg);
        
        config.addr = ptr;
        
        ptr = strrchr(ptr, ':');
        if ( ptr ) {
                *ptr = '\0';
                config.port = atoi(ptr + 1);
        }
        
        return prelude_option_success;
}



static int set_report_plugin_failover(void *context, prelude_option_t *opt, const char *arg)
{
        int ret;
        
        ret = report_plugin_activate_failover(arg);
        if ( ret == 0 )
                log(LOG_INFO, "- Failover capability enabled for reporting plugin %s.\n", arg);

        return ret;
}



static int set_dh_bits(void *context, prelude_option_t *opt, const char *arg) 
{
        config.dh_bits = atoi(arg);
        return 0;
}


static int set_dh_regenerate(void *context, prelude_option_t *opt, const char *arg) 
{
        config.dh_regenerate = atoi(arg) * 60 * 60;
        return 0;
}



static int print_help(void *context, prelude_option_t *opt, const char *arg) 
{
        prelude_option_print(NULL, CLI_HOOK, 25);
        return prelude_option_end;
}



int pconfig_init(int argc, char **argv) 
{
        prelude_option_t *opt;
        
	/* Default */
	config.addr = NULL;
	config.port = 5554;
        config.pidfile = NULL;
        config.dh_regenerate = 24 * 60 * 60;
        
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

        prelude_option_add(NULL, CFG_HOOK, 0, "dh-parameters-regenerate",
                           "How often to regenerate the Diffie Hellman parameters (in hours)",
                           required_argument, set_dh_regenerate, NULL);

        prelude_option_add(NULL, CFG_HOOK, 0, "dh-prime-length",
                           "Size of the Diffie Hellman prime (768, 1024, 2048, 3072 or 4096)",
                           required_argument, set_dh_bits, NULL);
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'c', "child-managers",
                           "List of managers address:port pair where messages should be gathered from",
                           required_argument, set_reverse_relay, NULL);
        
        prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 's', "sensors-srvr", 
                           "Address the sensors server should listen on (addr:port)", required_argument,
                           set_sensor_listen_address, NULL);

        opt = prelude_option_add(NULL, CLI_HOOK|CFG_HOOK, 'f', "failover",
                                 "Enable failover for specified report plugin", required_argument,
                                 set_report_plugin_failover, NULL);
        
        prelude_option_set_priority(opt, option_run_last);

        return 0;
}
