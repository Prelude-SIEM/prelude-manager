/*****
*
* Copyright (C) 1998-2005 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <syslog.h>
#include <signal.h>
#include <assert.h>
#include <pthread.h>
#include <sys/time.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>

#include "prelude-manager.h"
#include "server-generic.h"
#include "sensor-server.h"
#include "manager-options.h"
#include "decode-plugins.h"
#include "report-plugins.h"
#include "filter-plugins.h"
#include "idmef-message-scheduler.h"
#include "reverse-relaying.h"
#include "manager-auth.h"
#include "config.h"


#define MANAGER_MODEL "Prelude Manager"
#define MANAGER_CLASS "Manager"
#define MANAGER_MANUFACTURER "The Prelude Team http://www.prelude-ids.org"
#define DEFAULT_ANALYZER_NAME "prelude-manager"

extern manager_config_t config;

prelude_client_t *manager_client;
server_generic_t *sensor_server = NULL;

static size_t nserver = 0;
static char **global_argv;
static volatile sig_atomic_t got_sighup = 0;



/*
 * all function called here should be signal safe.
 */
static void handle_signal(int sig) 
{        
        prelude_log(PRELUDE_LOG_INFO, "Caught signal %d.\n", sig);

        /*
         * stop the sensor server.
         */
        sensor_server_stop(sensor_server);
}



static void handle_sighup(int signo)
{
        handle_signal(signo);
        got_sighup = 1;
}



static void init_manager_server(void) 
{
        int ret;
        
        nserver++;
        
        ret = manager_auth_init(manager_client, config.dh_bits, config.dh_regenerate);
	if ( ret < 0 )
                exit(1);
        
        ret = server_generic_bind((server_generic_t *) sensor_server, config.addr, config.port);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "Error initializing prelude-manager server.\n");
                exit(1);
        }
}




static void restart_manager(void) 
{
        int ret;
        
        prelude_log(PRELUDE_LOG_WARN, "- Restarting Prelude Manager (%s).\n", global_argv[0]);
        
        ret = execvp(global_argv[0], global_argv);
        if ( ret < 0 ) 
                prelude_log(LOG_ERR, "Error restarting Prelude Manager (%s).\n", global_argv[0]);
}



static int fill_analyzer_infos(void)
{
        int ret;
        prelude_string_t *str;
        idmef_analyzer_t *local = NULL;

        local = prelude_client_get_analyzer(manager_client);
        assert(local);

        ret = prelude_string_new_constant(&str, VERSION);
        if ( ret < 0 )
                return ret;
        idmef_analyzer_set_version(local, str);
        
        ret = prelude_string_new_constant(&str, MANAGER_MODEL);
        if ( ret < 0 )
                return ret;
        idmef_analyzer_set_model(local, str);

        ret = prelude_string_new_constant(&str, MANAGER_CLASS);
        if ( ret < 0 )
                return ret;
        idmef_analyzer_set_class(local, str);

        ret = prelude_string_new_constant(&str, MANAGER_MANUFACTURER);
        if ( ret < 0 )
                return ret;
        idmef_analyzer_set_manufacturer(local, str);

        return 0;
}



static void heartbeat_cb(prelude_client_t *client, idmef_message_t *idmef)
{
        idmef_message_process(idmef);
}



int main(int argc, char **argv)
{
        int ret;
        prelude_string_t *err;
        struct sigaction action;
        prelude_option_t *manager_root_optlist;
        
        prelude_init(&argc, argv);
        
        global_argv = argv;
        prelude_option_new_root(&manager_root_optlist);
        
        /*
         * make sure we ignore sighup until acceptable.
         */
        action.sa_flags = 0;
        action.sa_handler = SIG_IGN;
        sigemptyset(&action.sa_mask);
        sigaction(SIGHUP, &action, NULL);
        
        /*
         * Initialize plugin first.
         */
        PRELUDE_PLUGIN_SET_PRELOADED_SYMBOLS();

        ret = report_plugins_init(REPORT_PLUGIN_DIR, manager_root_optlist);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "error initializing reporting plugins.\n");
                return -1;
        }
        prelude_log(PRELUDE_LOG_INFO, "- Initialized %d reporting plugins.\n", ret);

        ret = decode_plugins_init(DECODE_PLUGIN_DIR, manager_root_optlist);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "error initializing decoding plugins.\n");
                return -1;
        }
        prelude_log(PRELUDE_LOG_INFO, "- Initialized %d decoding plugins.\n", ret);

        ret = filter_plugins_init(FILTER_PLUGIN_DIR, manager_root_optlist);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "error initializing filtering plugins.\n");
                return -1;
        }
        prelude_log(PRELUDE_LOG_INFO, "- Initialized %d filtering plugins.\n", ret);
        
        sensor_server = sensor_server_new();
        
        ret = manager_options_init(manager_root_optlist, &argc, argv);
        if ( ret < 0 )
                return -1;

        ret = prelude_client_new(&manager_client, DEFAULT_ANALYZER_NAME, config.config_file);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating prelude-client object");                
                return -1;
        }
        
        fill_analyzer_infos();
        prelude_client_set_heartbeat_cb(manager_client, heartbeat_cb);
        prelude_client_set_flags(manager_client,  prelude_client_get_flags(manager_client) | PRELUDE_CLIENT_FLAGS_ASYNC_SEND);
        prelude_client_set_flags(manager_client, prelude_client_get_flags(manager_client) & ~PRELUDE_CLIENT_FLAGS_CONNECT);

        ret = prelude_client_init(manager_client);
        if ( ret < 0 ) {
                prelude_perror(ret, "error starting prelude-client");
                
                if ( prelude_client_is_setup_needed(ret) )
                        prelude_client_print_setup_error(manager_client);

                return ret;
        }
        
        ret = prelude_option_read(manager_root_optlist, &config.config_file, &argc, argv, &err, manager_client);
        if ( ret < 0 ) {
                if ( err )
                        prelude_log(PRELUDE_LOG_WARN, "error parsing options: %s.\n", prelude_string_get_string(err));

                else if ( prelude_error_get_code(ret) != PRELUDE_ERROR_EOF )
                        prelude_perror(ret, "error processing prelude-manager options");
                
                return -1;
        }
                
        ret = idmef_message_scheduler_init();
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't initialize alert scheduler.\n");
                return -1;
        }
        
        ret = prelude_client_start(manager_client);
        if ( ret < 0 ) {
                prelude_perror(ret, "error starting prelude-client");                
                return -1;
        }

        /*
         * start server
         */
        init_manager_server();
        
        /*
         * setup signal handling
         */
        action.sa_flags = 0;
        sigemptyset(&action.sa_mask);
        action.sa_handler = handle_signal;
        
        signal(SIGPIPE, SIG_IGN);
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGABRT, &action, NULL);
        sigaction(SIGQUIT, &action, NULL);
        
        action.sa_handler = handle_sighup;
        sigaction(SIGHUP, &action, NULL);
        
        server_generic_start(&sensor_server, nserver);
        
                
        /*
         * we won't get here unless a signal is caught.
         */
        server_generic_close(sensor_server);
        
        idmef_message_scheduler_exit();

        if ( got_sighup )
                restart_manager();
        
        if ( config.pidfile )
                unlink(config.pidfile);
        
	exit(0);	
}
