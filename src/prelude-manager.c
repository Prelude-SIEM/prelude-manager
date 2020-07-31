/*****
*
* Copyright (C) 1998-2020 CS GROUP - France. All Rights Reserved.
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
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>

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
#define MANAGER_MANUFACTURER "https://www.prelude-siem.com"
#define DEFAULT_ANALYZER_NAME "prelude-manager"

extern manager_config_t config;

prelude_client_t *manager_client;
struct ev_loop *manager_event_loop, *manager_worker_loop;

static char **global_argv;
static volatile sig_atomic_t got_signal = 0;



/*
 * all function called here should be signal safe.
 */
static RETSIGTYPE handle_signal(int sig)
{
        got_signal = sig;
}



#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
static void restart_manager(void)
{
        int ret;

        prelude_log(PRELUDE_LOG_INFO, "Restarting Prelude Manager (%s).\n", global_argv[0]);

        ret = execvp(global_argv[0], global_argv);
        if ( ret < 0 )
                prelude_log(PRELUDE_LOG_ERR, "Error restarting Prelude Manager (%s).\n", global_argv[0]);
}
#endif



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
        int ret;
        prelude_string_t *str;

        ret = idmef_heartbeat_new_messageid(idmef_message_get_heartbeat(idmef), &str);
        if ( ret < 0 )
                return;

        prelude_ident_generate(prelude_client_get_unique_ident(client), str);
        idmef_message_process(idmef);
}



static void sig_cb(struct ev_loop *loop, struct ev_signal *s, int revent)
{
#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        if ( s->signum == SIGHUP )
                signal(SIGHUP, SIG_IGN);
#endif

        handle_signal(s->signum);
        ev_break(manager_event_loop, EVBREAK_ALL);

        return;
}


static void add_signal(int signo, struct sigaction *action)
{
        ev_signal *s = malloc(sizeof(*s));
        ev_signal_init(s, sig_cb, signo);
        ev_signal_start(manager_event_loop, s);
}


static const char *get_restart_string(void)
{
#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        if ( got_signal == SIGHUP )
                return "will restart";
#endif

        return "terminating";
}


int main(int argc, char **argv)
{
        int ret;
        struct sigaction action;
        prelude_option_t *manager_root_optlist;

        prelude_init(&argc, argv);

        manager_event_loop = ev_default_loop(EVFLAG_AUTO);
        if ( ! manager_event_loop ) {
                prelude_log(PRELUDE_LOG_ERR, "error initializing libev.\n");
                return -1;
        }

        manager_worker_loop = ev_loop_new(EVFLAG_AUTO);
        if ( ! manager_worker_loop ) {
                prelude_log(PRELUDE_LOG_ERR, "error creating scheduler event loop.\n");
                return -1;
        }


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

#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        action.sa_handler = SIG_IGN;
        sigemptyset(&action.sa_mask);
        sigaction(SIGHUP, &action, NULL);
#endif

        /*
         * Initialize plugin first.
         */
        PRELUDE_PLUGIN_SET_PRELOADED_SYMBOLS();

        ret = report_plugins_init(REPORT_PLUGIN_DIR, manager_root_optlist);
        if ( ret < 0 )
                return -1;
        prelude_log(PRELUDE_LOG_DEBUG, "Initialized %d reporting plugins.\n", ret);

        ret = decode_plugins_init(DECODE_PLUGIN_DIR, manager_root_optlist);
        if ( ret < 0 )
                return -1;
        prelude_log(PRELUDE_LOG_DEBUG, "Initialized %d decoding plugins.\n", ret);

        ret = filter_plugins_init(FILTER_PLUGIN_DIR, manager_root_optlist);
        if ( ret < 0 )
                return -1;
        prelude_log(PRELUDE_LOG_DEBUG, "Initialized %d filtering plugins.\n", ret);

        sensor_server_init();

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
         * start server
         */
        ret = manager_auth_init(manager_client, config.tls_options, config.dh_bits, config.dh_regenerate);
        if ( ret < 0 ) {
                if ( ret != -2 )
                        prelude_log(PRELUDE_LOG_WARN, "%s\n", prelude_client_get_setup_error(manager_client));

                return -1;
        }

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
         * setup signal handling
         */
#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        sigaction(SIGPIPE, &action, NULL);
#endif

        action.sa_handler = handle_signal;
        add_signal(SIGINT, &action);
        add_signal(SIGTERM, &action);
        add_signal(SIGABRT, &action);

#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        add_signal(SIGQUIT, &action);
        add_signal(SIGHUP, &action);
#endif

        server_generic_start(config.server, config.nserver);

        /*
         * we won't get there unless a signal is caught.
         */
        if ( got_signal )
                prelude_log(PRELUDE_LOG_WARN, "signal %d received, %s prelude-manager.\n",
                            got_signal, get_restart_string());

        idmef_message_scheduler_exit();
        prelude_client_destroy(manager_client, PRELUDE_CLIENT_EXIT_STATUS_FAILURE);

        report_plugins_close();

        /*
         * De-Initialize the Prelude library. This has the side effect of flushing
         * the Prelude asynchronous stack.
         */
        prelude_deinit();

#if ! ((defined _WIN32 || defined __WIN32__) && !defined __CYGWIN__)
        if ( got_signal == SIGHUP )
                restart_manager();
#endif

        if ( config.pidfile )
                unlink(config.pidfile);

        exit(0);
}

