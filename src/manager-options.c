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

#include <libprelude/prelude.h>
#include <libprelude/daemonize.h>
#include <libprelude/prelude-log.h>

#include "config.h"
#include "libmissing.h"
#include "manager-options.h"
#include "report-plugins.h"
#include "reverse-relaying.h"


manager_config_t config;
static const char *config_file = PRELUDE_MANAGER_CONF;



static int set_conf_file(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{       
        config_file = strdup(optarg);
        return 0;
}


static int print_version(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        fprintf(stderr, "prelude-manager %s\n", VERSION);
        return prelude_error(PRELUDE_ERROR_EOF);
}


static int set_daemon_mode(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        prelude_daemonize(config.pidfile);
        prelude_log_set_flags(prelude_log_get_flags() | PRELUDE_LOG_FLAGS_SYSLOG);
        return 0;
}


static int set_pidfile(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        config.pidfile = strdup(arg);
        return 0;
}




static int set_reverse_relay(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        return reverse_relay_create_initiator(arg);
}




static int set_listen_address(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        char *ptr = strdup(arg);
        
        config.addr = ptr;

        /*
         * if the address string start with unix, then don't try to
         * read the port number since a path can follow unix after the ':' separator.
         */
        if ( strncmp(ptr, "unix", 4) == 0 )
                return 0;
        
        ptr = strrchr(ptr, ':');
        if ( ptr ) {
                *ptr = '\0';
                config.port = atoi(ptr + 1);
        }
        
        return 0;
}



static int set_report_plugin_failover(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        int ret;
        
        ret = report_plugin_activate_failover(arg);
        if ( ret == 0 )
                prelude_log(PRELUDE_LOG_INFO, "- Failover capability enabled for reporting plugin %s.\n", arg);

        return ret;
}



static int set_dh_bits(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        config.dh_bits = atoi(arg);
        return 0;
}


static int set_dh_regenerate(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        config.dh_regenerate = atoi(arg) * 60 * 60;
        return 0;
}



static int print_help(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        prelude_option_print(NULL, PRELUDE_OPTION_TYPE_CLI, 25);
        return prelude_error(PRELUDE_ERROR_EOF);
}



int manager_options_init(prelude_option_t *manager_root_optlist, void *rootopt) 
{
        prelude_option_t *opt;
        
        /* Default */
        config.addr = NULL;
        config.port = 5554;
        config.pidfile = NULL;
        config.dh_regenerate = 24 * 60 * 60;
        
        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CLI, 'h', "help",
                           "Print this help", PRELUDE_OPTION_ARGUMENT_NONE, print_help, NULL);
        
        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CLI, 'v', "version",
                           "Print version number", PRELUDE_OPTION_ARGUMENT_NONE, print_version, NULL);

        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'd',
                           "daemon", "Run in daemon mode", PRELUDE_OPTION_ARGUMENT_NONE, set_daemon_mode, NULL);
        
        prelude_option_add(rootopt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'P',
                           "pidfile", "Write Prelude PID to pidfile", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_pidfile, NULL);
        
        /*
         * we want this option to be processed before -d.
         */
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_FIRST);
        
        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CLI, 'c', "config",
                           "Configuration file to use", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_conf_file, NULL);

        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CFG, 0, "dh-parameters-regenerate",
                           "How often to regenerate the Diffie Hellman parameters (in hours)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_dh_regenerate, NULL);
        
        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CFG, 0, "dh-prime-length",
                           "Size of the Diffie Hellman prime (768, 1024, 2048, 3072 or 4096)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_dh_bits, NULL);
        
        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'c', "child-managers",
                           "List of managers address:port pair where messages should be gathered from",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_reverse_relay, NULL);
        
        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'l', "listen", 
                           "Address the sensors server should listen on (addr:port)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_listen_address, NULL);
        
        prelude_option_add(rootopt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'f', "failover",
                           "Enable failover for specified report plugin",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_report_plugin_failover, NULL);
        
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_LAST);

        return 0;
}
