/*****
*
* Copyright (C) 1998-2005 PreludeIDS Technologies. All Rights Reserved.
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


#define MANAGER_MODEL "Prelude Manager"
#define MANAGER_CLASS "Concentrator"
#define MANAGER_MANUFACTURER "http://www.prelude-ids.com"
#define DEFAULT_ANALYZER_NAME "prelude-manager"

extern manager_config_t config;

prelude_client_t *manager_client;

static char **global_argv;
static volatile sig_atomic_t got_signal = 0;



/*
 * all function called here should be signal safe.
 */
static void handle_signal(int sig) 
{
        size_t i;
        
        /*
         * stop the sensor server.
         */
        for ( i = 0; i < config.nserver; i++ )
                sensor_server_stop(config.server[i]);

        got_signal = sig;
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
        struct sigaction action;
        prelude_option_t *manager_root_optlist;
        
        prelude_init(&argc, argv);
        
        global_argv = argv;
        prelude_option_new_root(&manager_root_optlist);
        
        /*
         * make sure we ignore sighup until acceptable.
         */        
#ifdef SA_INTERRUPT
        action.sa_flags = SA_INTERRUPT;
#else
        action.sa_flags = 0;
#endif
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
        prelude_log(PRELUDE_LOG_DEBUG, "- Initialized %d reporting plugins.\n", ret);

        ret = decode_plugins_init(DECODE_PLUGIN_DIR, manager_root_optlist);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "error initializing decoding plugins.\n");
                return -1;
        }
        prelude_log(PRELUDE_LOG_DEBUG, "- Initialized %d decoding plugins.\n", ret);

        ret = filter_plugins_init(FILTER_PLUGIN_DIR, manager_root_optlist);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "error initializing filtering plugins.\n");
                return -1;
        }
        prelude_log(PRELUDE_LOG_DEBUG, "- Initialized %d filtering plugins.\n", ret);
        
        
        ret = manager_options_init(manager_root_optlist, &argc, argv);
        if ( ret < 0 )
                return -1;

        ret = prelude_client_new(&manager_client, DEFAULT_ANALYZER_NAME);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating prelude-client object");                
                return -1;
        }
        
        fill_analyzer_infos();
        prelude_client_set_heartbeat_cb(manager_client, heartbeat_cb);
        prelude_client_set_flags(manager_client, prelude_client_get_flags(manager_client) & ~PRELUDE_CLIENT_FLAGS_CONNECT);
        prelude_client_set_config_filename(manager_client, config.config_file);
        
        ret = prelude_client_init(manager_client);
        if ( ret < 0 ) {
                prelude_perror(ret, "error initializing prelude-client");
                return ret;
        }

        ret = manager_options_read(manager_root_optlist, &argc, argv);
        if ( ret < 0 )
                return -1;
        
        ret = prelude_client_start(manager_client);
        if ( ret < 0 ) {
                prelude_perror(ret, "error starting prelude-client");                
                return -1;
        }

        ret = reverse_relay_init();
        if ( ret < 0 )
                return -1;

        /*
         * prelude_client_start() should send it's initial heartbeat
         * before the scheduler start handling IDMEF messages, so that we don't refcount
         * the shared manager_client analyzer object from two different thread.
         */
        ret = idmef_message_scheduler_init();
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "couldn't initialize alert scheduler.\n");
                return -1;
        }
        
        /*
         * start server
         */
        ret = manager_auth_init(manager_client, config.dh_bits, config.dh_regenerate);        
	if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "%s\n", prelude_client_get_setup_error(manager_client));
                return -1;
        }
        
        /*
         * setup signal handling
         */
        sigaction(SIGPIPE, &action, NULL);
        
        action.sa_handler = handle_signal;
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGABRT, &action, NULL);
        sigaction(SIGQUIT, &action, NULL);
        sigaction(SIGHUP, &action, NULL);
        
        server_generic_start(config.server, config.nserver);
                
        /*
         * we won't get there unless a signal is caught.
         */
        if ( got_signal )
                prelude_log(PRELUDE_LOG_WARN, "signal %d received, %s prelude-manager.\n",
                            got_signal, (got_signal == SIGHUP) ? "will restart" : "terminating");
        
        idmef_message_scheduler_exit();

        if ( got_signal == SIGHUP )
                restart_manager();
        
        if ( config.pidfile )
                unlink(config.pidfile);
        
	exit(0);	
}
