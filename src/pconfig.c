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
#include <libprelude/auth-common.h>
#include <libprelude/daemonize.h>

#include "libmissing.h"
#include "config.h"
#include "pconfig.h"
#include "ssl.h"


struct report_config config;
int config_quiet;


static void configure_listen_address(config_t *cfg) 
{
        const char *ret;
        
        if ( config.addr )
                return;

        ret = config_get(cfg, "Prelude Manager", "listen");
        if ( ! ret )
                config.addr = "unix";
        else
                config.addr = strdup(ret);
}



static void configure_listen_port(config_t *cfg) 
{
        const char *ret;
        
        if ( config.port != 0 )
                return;
        
        ret = config_get(cfg, "Prelude Manager", "port");
        if ( ! ret )
                config.port = 5554;
        else
                config.port = atoi(ret);
}



static void configure_as_daemon(config_t *cfg) 
{
        const  char *ret;
        
        ret = config_get(cfg, "Prelude Manager", "daemon");
        if ( ret ) {
                if ( strcmp(ret, "true") == 0 ) {
                        config.daemonize = 1;
                        config_quiet = 1;
                }
        }
}



static void configure_quiet(config_t *cfg) 
{
        const char *ret;
        
        ret = config_get(cfg, "Prelude Manager", "quiet");
        if ( ret ) {
                if ( strcmp(ret, "true") == 0 )
                        config_quiet = 1;
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
#ifdef HAVE_SSL
        fprintf(stderr, "\t-c --certificate Create the Prelude Manager certificate.\n");
        fprintf(stderr, "\t-n --not-crypt Specify that the key should be stored\n"
                "\t   as is (not encrypted) on the local hardisk. This will prevent\n"
                "\t   you to be asked for a password each time you run the Manager.\n");
        fprintf(stderr, "\t-w --wait Wait for Prelude client public key.\n");
#endif

        fprintf(stderr, "\nUsage (plugin help):\n\n");
        fprintf(stderr, "\t-m --plugin <name> <option> to set/get plugin specific options.\n\n");

        plugin_set_args(0, NULL);
        plugins_print_opts(REPORT_PLUGIN_DIR);
}



int pconfig_init(int argc, char **argv)
{
	int c;
        config_t *cfg;
        int crypt_key = 1;
#ifdef HAVE_SSL
        int wait_cert = 0;
        int creat_cert = 0;
#endif
        struct option opts[] = {
                { "version", no_argument, NULL, 'v'       },
                { "quiet", no_argument, NULL, 'q'         },
                { "daemonize", no_argument, NULL, 'd'     },
                { "pidfile", required_argument, NULL, 'P' },
                { "listen", required_argument, NULL, 'l'  },
                { "port", required_argument, NULL, 'p'    },
                { "help", no_argument, NULL, 'h'          },
#ifdef HAVE_SSL
                { "certificate", no_argument, NULL, 'c'   },
                { "wait", no_argument, NULL, 'w'          },
                { "not-crypt", no_argument, NULL, 'n'     },
#endif
                { 0, 0, 0, 0 }
        };

        
	/* Default */
	config.addr = NULL;
	config.port = 0;
	config_quiet = 0;
	config.daemonize = 0;
        config.pidfile = NULL;
      
	while ( (c = getopt_long(argc, argv, "l:p:uqdhvcnwm:P:", opts, NULL)) != -1 ) {

		switch (c) {
                    
                case 'l':
                        config.addr = optarg;
                        break;
                case 'p':
                        config.port = atoi(optarg);
                        break;
                case 'q':
                        config_quiet = 1;
                        break;
                case 'd':
                        config_quiet = 1;
                        config.daemonize = 1;
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

#ifdef HAVE_SSL
		case 'c':
                        creat_cert = 1;
			break;

                case 'n':
                        crypt_key = 0;
                        break;

		case 'w':
                        wait_cert = 1;
                        break;

                default:
                        return -1;
#endif
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

        config_close(cfg);
        
        return 0;
}

















