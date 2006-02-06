/*****
*
* Copyright (C) 1999, 2000, 2001, 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
*
* This file is part of the Prelude-Manager program.
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

#include "config.h"
#include "libmissing.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <pwd.h>
#include <grp.h>

#include <libprelude/prelude.h>
#include <libprelude/daemonize.h>
#include <libprelude/prelude-log.h>

#include "server-generic.h"
#include "sensor-server.h"
#include "manager-options.h"
#include "report-plugins.h"
#include "reverse-relaying.h"


#define DEFAULT_MANAGER_ADDR "0.0.0.0"
#define DEFAULT_MANAGER_PORT 4690


manager_config_t config;
extern prelude_client_t *manager_client;



static int set_conf_file(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        config.config_file = strdup(optarg);
        return 0;
}


static int print_version(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        fprintf(stderr, "prelude-manager %s\n", VERSION);
        exit(0);
}


static int set_daemon_mode(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        prelude_daemonize(config.pidfile);
        prelude_log_set_flags(prelude_log_get_flags() | PRELUDE_LOG_FLAGS_SYSLOG);
        return 0;
}



static int set_debug_mode(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        prelude_log_t priority = PRELUDE_LOG_DEBUG;
                
        if ( arg )
                priority = atoi(arg);
        
        prelude_log_set_debug_level(priority);

        return 0;
}


static int set_pidfile(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        config.pidfile = strdup(arg);
        return 0;
}



static int add_server(const char *addr, unsigned int port)
{
        int ret;
        
        config.nserver++;

        config.server = _prelude_realloc(config.server, sizeof(*config.server) * config.nserver);        
        if ( ! config.server )
                return -1;
        
        config.server[config.nserver - 1] = sensor_server_new();
        if ( ! config.server[config.nserver - 1] )
                return -1;
        
        ret = server_generic_bind((server_generic_t *) config.server[config.nserver - 1], addr, port);
        if ( ret < 0 )
                prelude_perror(ret, "error initializing server on %s:%u", addr, port);
        
        return ret;
}



static int set_reverse_relay(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        int ret;
        
        if ( config.nserver == 0 ) {
                ret = add_server(DEFAULT_MANAGER_ADDR, DEFAULT_MANAGER_PORT);
                if ( ret < 0 )
                        return ret;
        }
        
        return reverse_relay_create_initiator(arg);
}




static int set_listen_address(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        char *ptr;
        unsigned int port = 4690;
                
        if ( strncmp(arg, "unix", 4) != 0 ) {
                
                ptr = strrchr(arg, ':');
                if ( ptr ) {
                        *ptr = '\0';
                        port = atoi(ptr + 1);
                }
        }

        return add_server(arg, port);
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



static int set_user(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        int ret;
        uid_t uid;
        const char *p;
        struct passwd *pw;

        for ( p = optarg; isdigit((int) *p); p++ );
        
        if ( *p == 0 )
                uid = atoi(optarg);
        else {
                pw = getpwnam(optarg);
                if ( ! pw ) {
                        prelude_log(PRELUDE_LOG_ERR, "could not lookup user '%s'.\n", optarg);
                        return -1;
                }

                uid = pw->pw_uid;
        }

        ret = setuid(uid);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "change to UID %d failed: %s.\n", (int) uid, strerror(errno));
                return ret;
        }
        
        return 0;
}


static int set_group(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        int ret;
        gid_t gid;
        const char *p;
        struct group *grp;

        for ( p = optarg; isdigit((int) *p); p++ );

        if ( *p == 0 )
                gid = atoi(optarg);
        else {
                grp = getgrnam(optarg);
                if ( ! grp ) {
                        prelude_log(PRELUDE_LOG_ERR, "could not lookup group '%s'.\n", optarg);
                        return -1;
                }

                gid = grp->gr_gid;
        }

        ret = setgid(gid);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "change to GID %d failed: %s.\n", (int) gid, strerror(errno));
                return ret;
        }

        ret = setgroups(1, &gid);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "removal of ancillary groups failed: %s.\n", strerror(errno));
                return ret;
        }

        return 0;
}



static int print_help(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context) 
{
        prelude_option_print(NULL, PRELUDE_OPTION_TYPE_CLI, 25, stderr);
        return prelude_error(PRELUDE_ERROR_EOF);
}



int manager_options_init(prelude_option_t *rootopt, int *argc, char **argv) 
{
        int ret;
        prelude_string_t *err;
        prelude_option_t *init_first, *opt;
        prelude_option_warning_t old_warnings;
        
        /* Default */
        config.nserver = 0;
        config.server = NULL;
        config.pidfile = NULL;
        config.dh_regenerate = 24 * 60 * 60;
        config.config_file = PRELUDE_MANAGER_CONF;

        prelude_option_new_root(&init_first);
        
        prelude_option_add(init_first, &opt, PRELUDE_OPTION_TYPE_CLI, 'h', "help",
                           "Print this help", PRELUDE_OPTION_ARGUMENT_NONE, print_help, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);
        
        prelude_option_add(init_first, &opt, PRELUDE_OPTION_TYPE_CLI, 0, "config",
                           "Configuration file to use", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_conf_file, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);

        prelude_option_add(rootopt, &opt, PRELUDE_OPTION_TYPE_CLI, 'v', "version",
                           "Print version number", PRELUDE_OPTION_ARGUMENT_NONE, print_version, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);

        prelude_option_add(rootopt, &opt, PRELUDE_OPTION_TYPE_CLI, 'D', "debug-level",
                           "Run in debug mode", PRELUDE_OPTION_ARGUMENT_OPTIONAL, set_debug_mode, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);
        
        prelude_option_add(rootopt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'd',
                           "daemon", "Run in daemon mode", PRELUDE_OPTION_ARGUMENT_NONE, set_daemon_mode, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_FIRST);
        
        prelude_option_add(rootopt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'P',
                           "pidfile", "Write Prelude PID to pidfile", PRELUDE_OPTION_ARGUMENT_REQUIRED,
                           set_pidfile, NULL);
        
        /*
         * we want this option to be processed before -d.
         */
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);

        
        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CFG, 0, "user",
                           "Set the user ID used by prelude-manager", PRELUDE_OPTION_ARGUMENT_REQUIRED, set_user, NULL);
        
        prelude_option_add(rootopt, &opt, PRELUDE_OPTION_TYPE_CFG, 0, "group",
                           "Set the group ID used by prelude-manager", PRELUDE_OPTION_ARGUMENT_REQUIRED, set_group, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_FIRST);
        
        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CFG, 0, "dh-parameters-regenerate",
                           "How often to regenerate the Diffie Hellman parameters (in hours)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_dh_regenerate, NULL);
        
        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CFG, 0, "dh-prime-length",
                           "Size of the Diffie Hellman prime (768, 1024, 2048, 3072 or 4096)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_dh_bits, NULL);
        
        prelude_option_add(rootopt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'c', "child-managers",
                           "List of managers address:port pair where messages should be gathered from",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_reverse_relay, NULL);
        /*
         * necessary since the reverse relay need to be setup only once one
         * server object has been created.
         */
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_LAST);
        
        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'l', "listen", 
                           "Address the sensors server should listen on (addr:port)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_listen_address, NULL);
        
        prelude_option_add(rootopt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'f', "failover",
                           "Enable failover for specified report plugin",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_report_plugin_failover, NULL);
        
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_LAST);


        /*
         * Some plugin might require manager_client to be already initialized,
         * for example the relaying plugin. We need to process theses option
         * first so that --help will be recognized even throught the initialization
         * fail.
         *
         * We can't delay the error checking of manager_client initialization either since
         * prelude_client_init() also need to know the configuration file that will be used.
         */

        prelude_option_set_warnings(0, &old_warnings);

        ret = prelude_option_read(init_first, &config.config_file, argc, argv, &err, NULL);        
        if ( ret < 0 && prelude_error_get_code(ret) != PRELUDE_ERROR_EOF )
                prelude_perror(ret, "error processing prelude-manager options");
        
        prelude_option_set_warnings(old_warnings, NULL);
        
        return ret;
}



int manager_options_read(prelude_option_t *manager_root_optlist, int *argc, char **argv)
{
        int ret;
        prelude_string_t *err;
        
        ret = prelude_option_read(manager_root_optlist, &config.config_file, argc, argv, &err, manager_client);        
        if ( ret < 0 ) {
                if ( err )
                        prelude_log(PRELUDE_LOG_WARN, "Option error: %s.\n", prelude_string_get_string(err));

                else if ( prelude_error_get_code(ret) != PRELUDE_ERROR_EOF )
                        prelude_perror(ret, "error processing prelude-manager options");
                
                return -1;
        }
        
        if ( config.nserver == 0 )
                ret = add_server(DEFAULT_MANAGER_ADDR, DEFAULT_MANAGER_PORT);

        return ret;
}
