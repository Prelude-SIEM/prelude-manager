/*****
*
* Copyright (C) 1999-2018 CS-SI. All Rights Reserved.
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
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
*****/

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <netdb.h>
#include <arpa/inet.h>

#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
# include <pwd.h>
# include <grp.h>
#endif

#include <libprelude/prelude.h>
#include <libprelude/daemonize.h>
#include <libprelude/prelude-log.h>

#include "bufpool.h"
#include "server-generic.h"
#include "sensor-server.h"
#include "manager-options.h"
#include "report-plugins.h"


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
        int ret;

        ret = prelude_daemonize(config.pidfile);
        if ( ret < 0 )
                return ret;

        prelude_log_set_flags(prelude_log_get_flags() | PRELUDE_LOG_FLAGS_SYSLOG);
        ev_default_fork();

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



static server_generic_t *add_server(void)
{
        config.nserver++;

        config.server = realloc(config.server, sizeof(*config.server) * config.nserver);
        if ( ! config.server )
                return NULL;

        config.server[config.nserver - 1] = sensor_server_new();
        if ( ! config.server[config.nserver - 1] )
                return NULL;

        return config.server[config.nserver - 1];
}


static int add_server_default(void)
{
        int ret;
        char buf[128];
        server_generic_t *server;
        struct addrinfo *ai, *ai_start, hints;

        memset(&hints, 0, sizeof(hints));

        hints.ai_flags = AI_PASSIVE;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_family = AF_UNSPEC;

#ifdef AI_ADDRCONFIG
        /*
         * Only look up addresses using address types for which a local
         * interface is configured.
         */
        hints.ai_flags |= AI_ADDRCONFIG;
#endif

        snprintf(buf, sizeof(buf), "%u", DEFAULT_MANAGER_PORT);

        ret = getaddrinfo(NULL, buf, &hints, &ai);
        if ( ret != 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error getting default machine address: %s.\n",
                            (ret == EAI_SYSTEM) ? strerror(errno) : gai_strerror(ret));
                return -1;
        }

        for ( ai_start = ai; ai != NULL; ai = ai->ai_next ) {
                if ( ! inet_ntop(ai->ai_family, prelude_sockaddr_get_inaddr(ai->ai_addr), buf, sizeof(buf)) ) {
                        prelude_log(PRELUDE_LOG_ERR, "address to string translation failed: %s.\n", strerror(errno));
                        break;
                }

                server = add_server();
                if ( ! server )
                        break;

                ret = server_generic_bind_numeric(server, ai->ai_addr, ai->ai_addrlen, DEFAULT_MANAGER_PORT);
                if ( ret < 0 ) {
                        inet_ntop(ai->ai_family, prelude_sockaddr_get_inaddr(ai->ai_addr), buf, sizeof(buf));
                        prelude_perror(ret, "error initializing server on %s:%u", buf, DEFAULT_MANAGER_PORT);
                        break;
                }
        }

        if ( config.nserver == 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "could not find any address to listen on.\n");
                return -1;
        }

        freeaddrinfo(ai_start);

        return ret;
}



static int set_listen_address(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        int ret;
        char *ptr;
        server_generic_t *server;
        unsigned int port = DEFAULT_MANAGER_PORT;

        if ( strncmp(arg, "unix", 4) != 0 ) {

                ptr = strrchr(arg, ':');
                if ( ptr ) {
                        *ptr = '\0';
                        port = atoi(ptr + 1);
                }
        }

        server = add_server();
        if ( ! server )
                return -1;

        ret = server_generic_bind(server, arg, port);
        if ( ret < 0 )
                prelude_perror(ret, "error initializing server on %s:%u", arg, port);

        return ret;
}



static int set_report_plugin_failover(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        int ret;

        ret = report_plugin_activate_failover(arg);
        if ( ret == 0 )
                prelude_log(PRELUDE_LOG_INFO, "Failover capability enabled for reporting plugin %s.\n", arg);

        return ret;
}



static int set_connection_timeout(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        config.connection_timeout = atoi(arg);
        return 0;
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


static int set_tls_options(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        config.tls_options = strdup(arg);
        return 0;
}


static char *const2char(const char *val)
{
        union {
                const char *ro;
                char *rw;
        } uval;

        uval.ro = val;

        return uval.rw;
}


static int set_sched_priority(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        unsigned int i;
        char *name, *prio, *value = const2char(arg);
        struct {
                const char *name;
                unsigned int priority;
        } tbl[] = {
                { "high", 5 },
                { "medium", 3 },
                { "low", 2 }
        };

        while ( (name = strsep(&value, " ")) ) {
                prio = strchr(name, ':');
                if ( ! prio ) {
                        prelude_log(PRELUDE_LOG_ERR, "could not find colon delimiter in: '%s'.\n", name);
                        return -1;
                }

                *prio++ = 0;

                for ( i = 0; i < sizeof(tbl) / sizeof(*tbl); i++ ) {
                        if ( strcmp(name, tbl[i].name) == 0 ) {
                                tbl[i].priority = atoi(prio);
                                break;
                        }
                }

                if ( i == sizeof(tbl) / sizeof(*tbl) ) {
                        prelude_log(PRELUDE_LOG_ERR, "priority '%s' does not exist.\n", name);
                        *prio = ':';
                        return -1;
                }

                *prio = ':';
        }

        idmef_message_scheduler_set_priority(tbl[0].priority, tbl[1].priority, tbl[2].priority);
        return 0;
}


static int set_sched_buffer_size(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        char *eptr = NULL;
        unsigned long int value;

        value = strtoul(arg, &eptr, 10);
        if ( value == ULONG_MAX || eptr == arg ) {
                prelude_log(PRELUDE_LOG_ERR, "Invalid buffer size specified: '%s'.\n", arg);
                return -1;
        }

        if ( *eptr == 'K' || *eptr == 'k' )
                value = value * 1024;

        else if ( *eptr == 'M' || *eptr == 'm' )
                value = value * 1024 * 1024;

        else if ( *eptr == 'G' || *eptr == 'g' )
                value = value * 1024 * 1024 * 1024;

        else if ( eptr != arg ) {
                prelude_log(PRELUDE_LOG_ERR, "Invalid buffer suffix specified: '%s'.\n", arg);
                return -1;
        }

        bufpool_set_disk_threshold(value);
        return 0;
}



#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
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
#endif



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
        memset(&config, 0, sizeof(config));

        config.dh_regenerate = 24 * 60 * 60;
        config.connection_timeout = 10;
        config.config_file = PRELUDE_MANAGER_CONF;
        config.tls_options = NULL;

        prelude_option_new_root(&init_first);

        prelude_option_add(init_first, &opt, PRELUDE_OPTION_TYPE_CLI, 'h', "help",
                           "Print this help", PRELUDE_OPTION_ARGUMENT_NONE, print_help, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_IMMEDIATE);

        prelude_option_add(rootopt, &opt, PRELUDE_OPTION_TYPE_CLI, 0, "config",
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


#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CFG, 0, "user",
                           "Set the user ID used by prelude-manager", PRELUDE_OPTION_ARGUMENT_REQUIRED, set_user, NULL);

        prelude_option_add(rootopt, &opt, PRELUDE_OPTION_TYPE_CFG, 0, "group",
                           "Set the group ID used by prelude-manager", PRELUDE_OPTION_ARGUMENT_REQUIRED, set_group, NULL);
        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_FIRST);
#endif

        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CFG, 0, "connection-timeout",
                           "Number of seconds a client has to successfully authenticate (default 10)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_connection_timeout, NULL);

        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CFG, 0, "tls-options",
                           "TLS ciphers, key exchange methods, protocols, macs, and compression options",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_tls_options, NULL);

        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CFG, 0, "dh-parameters-regenerate",
                           "How often to regenerate the Diffie Hellman parameters (in hours)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_dh_regenerate, NULL);

        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CFG, 0, "dh-prime-length",
                           "Size of the Diffie Hellman prime (768, 1024, 2048, 3072 or 4096)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_dh_bits, NULL);

        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CFG, 0, "sched-priority",
                           NULL, PRELUDE_OPTION_ARGUMENT_REQUIRED, set_sched_priority, NULL);

        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CFG, 0, "sched-buffer-size",
                           NULL, PRELUDE_OPTION_ARGUMENT_REQUIRED, set_sched_buffer_size, NULL);

        prelude_option_add(rootopt, NULL, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'l', "listen",
                           "Address the sensors server should listen on (addr:port)",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_listen_address, NULL);

        prelude_option_add(rootopt, &opt, PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG, 'f', "failover",
                           "Enable failover for specified report plugin",
                           PRELUDE_OPTION_ARGUMENT_REQUIRED, set_report_plugin_failover, NULL);

        prelude_option_set_priority(opt, PRELUDE_OPTION_PRIORITY_LAST);


        /*
         * Some plugins might require manager_client to be already initialized,
         * for example the relaying plugin. We need to process these options
         * first so that --help will be recognized even though the initialization
         * fails.
         *
         * We can't delay the error checking of manager_client initialization either since
         * prelude_client_init() also needs to know the configuration file that will be used.
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
                if ( prelude_error_get_code(ret) == PRELUDE_ERROR_EOF )
                        return -1;

                if ( err )
                        prelude_log(PRELUDE_LOG_WARN, "Option error: %s.\n", prelude_string_get_string(err));
                else
                        prelude_perror(ret, "error processing options");

                return -1;
        }

        while ( ret < *argc )
                prelude_log(PRELUDE_LOG_WARN, "Unhandled command line argument: '%s'.\n", argv[ret++]);

        if ( config.nserver == 0 )
                ret = add_server_default();

        return ret;
}
