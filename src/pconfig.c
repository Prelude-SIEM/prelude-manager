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

#include "libmissing.h"
#include "config.h"
#include "pconfig.h"
#include "ssl.h"


struct report_config config;
prelude_client_mgr_t *relay_managers = NULL;


static void configure_admin_server(config_t *cfg) 
{
        const char *ret;

        if ( ! config.admin_server_addr ) {
                ret = config_get(cfg, "Prelude Manager", "admin-addr");
                config.admin_server_addr = (ret) ? strdup(ret) : NULL;
        }
        
        if ( config.admin_server_port == 0 ) {        
                ret = config_get(cfg, "Prelude Manager", "admin-port");
                config.admin_server_port = (ret) ? atoi(ret) : 5555;
        }
}



static void configure_relay(config_t *cfg) 
{
        const char *ret;

        ret = config_get(cfg, "Prelude Manager", "relay-manager");        
        if ( ret )
                relay_managers = prelude_client_mgr_new("relay", ret);
}




static void configure_listen_address(config_t *cfg) 
{
        const char *ret;
        
        if ( config.addr )
                return;

        ret = config_get(cfg, "Prelude Manager", "listen");
        config.addr = (ret) ? strdup(ret) : "unix";
}



static void configure_listen_port(config_t *cfg) 
{
        const char *ret;
        
        if ( config.port != 0 )
                return;
        
        ret = config_get(cfg, "Prelude Manager", "port");
        config.port = (ret) ? atoi(ret) : 5554;
}



static void configure_as_daemon(config_t *cfg) 
{
        const  char *ret;
        
        ret = config_get(cfg, "Prelude Manager", "daemon");
        if ( ret ) {
                if ( strcmp(ret, "true") == 0 ) {
                        config.daemonize = 1;
                        prelude_log_use_syslog();
                }
        }
}



static void configure_quiet(config_t *cfg) 
{
        const char *ret;
        
        ret = config_get(cfg, "Prelude Manager", "quiet");
        if ( ret ) {
                if ( strcmp(ret, "true") == 0 ) 
                        prelude_log_use_syslog();
        }

}




static void print_help(void) 
{
        fprintf(stderr, "Usage :\n");
        fprintf(stderr, "\t-v --version Printf version number.\n");
        fprintf(stderr, "\t-l --listen Listen address.\n");
        fprintf(stderr, "\t-p --port Listen port.\n");
        fprintf(stderr, "\t-q --quiet Quiet mode.\n");
        fprintf(stderr, "\t-d --daemonize Run in daemon mode.\n");
        fprintf(stderr, "\t-P --pidfile [pidfile] Write PID to pidfile.\n");
        
        fprintf(stderr, "\t-u --user Create user.\n");

        fprintf(stderr, "\nUsage (plugin help):\n\n");
        fprintf(stderr, "\t-m --plugin <name> <option> to set/get plugin specific options.\n\n");

        plugin_set_args(0, NULL);
        plugins_print_opts(REPORT_PLUGIN_DIR);
        plugins_print_opts(DB_PLUGIN_DIR);
}



int pconfig_init(int argc, char **argv)
{
	int c;
        config_t *cfg;

        struct option opts[] = {
                { "version", no_argument, NULL, 'v'       },
                { "quiet", no_argument, NULL, 'q'         },
                { "daemonize", no_argument, NULL, 'd'     },
                { "pidfile", required_argument, NULL, 'P' },
                { "listen", required_argument, NULL, 'l'  },
                { "port", required_argument, NULL, 'p'    },
                { "help", no_argument, NULL, 'h'          },
                { 0, 0, 0, 0 }
        };

        
	/* Default */
	config.addr = NULL;
        config.admin_server_addr = NULL;
	config.port = 0;
        config.admin_server_port = 0;
	config.daemonize = 0;
        config.pidfile = NULL;
      
	while ( (c = getopt_long(argc, argv, "l:p:qdhvm:P:", opts, NULL)) != -1 ) {

		switch (c) {
                    
                case 'l':
                        config.addr = optarg;
                        break;
                case 'p':
                        config.port = atoi(optarg);
                        break;
                case 'q':
                        prelude_log_use_syslog();
                        break;
                case 'd':
                        config.daemonize = 1;
                        prelude_log_use_syslog();
                        break;

                case 'P':
                        config.pidfile = optarg;
                        break;

                case 'h':
                        plugin_set_args(argc, argv);
                        print_help();
                        exit(0);

                case 'v':
                        printf("\n%s version %s.\n\n", PACKAGE, VERSION);
                        exit(0);

                case 'm':
                        plugin_set_args(argc, argv);
                        goto end;

                default:
                        return -1;
		}
	}

 end:

        cfg = config_open(PRELUDE_MANAGER_CONF);
        if ( ! cfg ) {
                log(LOG_ERR, "couldn't open config file %s.\n", PRELUDE_MANAGER_CONF);
                return -1;
        }
        
        configure_listen_address(cfg);
        if ( strcmp(config.addr, "unix") != 0 ) 
                configure_listen_port(cfg);
        
        configure_as_daemon(cfg);
        configure_quiet(cfg);
        configure_relay(cfg);
        configure_admin_server(cfg);
        
        config_close(cfg);
        
        return 0;
}





void manager_relay_msg_if_needed(prelude_msg_t *msg) 
{
        if ( relay_managers )
                prelude_client_mgr_broadcast(relay_managers, msg);
}















