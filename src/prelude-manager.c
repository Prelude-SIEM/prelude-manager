/*****
*
* Copyright (C) 1998,1999,2000, 2002, 2003 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <inttypes.h>
#include <assert.h>
#include <pthread.h>
#include <sys/time.h>

#include <libprelude/list.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/plugin-common.h>
#include <libprelude/prelude-log.h>
#include <libprelude/daemonize.h>
#include <libprelude/config-engine.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/threads.h>
#include <libprelude/idmef.h>
#include <libprelude/prelude-client.h>

#include "server-generic.h"
#include "sensor-server.h"
#include "pconfig.h"
#include "plugin-decode.h"
#include "plugin-report.h"
#include "plugin-filter.h"
#include "idmef-message-scheduler.h"
#include "relaying.h"



static size_t nserver = 0;
server_generic_t *sensor_server;
extern struct report_config config;


/*
 * all function called here should be signal safe.
 */
static void cleanup(int sig) 
{        
        log(LOG_INFO, "Caught signal %d.\n", sig);

        /*
         * stop the sensor server.
         */
        sensor_server_close(sensor_server);
        
        /*
         * close the scheduler.
         */
        idmef_message_scheduler_exit();

        if ( config.pidfile )
                unlink(config.pidfile);
        
        exit(0);
}



static void init_manager_server(void) 
{        
        /*
         * Initialize the sensors server.
         */
        nserver++;

        sensor_server = sensor_server_new(config.addr, config.port);
        if ( ! sensor_server ) {
                log(LOG_INFO, "- couldn't start sensor server.\n");
                exit(1);
        }
}




int main(int argc, char **argv)
{
        int ret;
        struct sigaction action;

        /*
         * Initialize plugin first.
         */
        ret = report_plugins_init(REPORT_PLUGIN_DIR, argc, argv);
        if ( ret < 0 ) {
                log(LOG_INFO, "error initializing reporting plugins.\n");
                return -1;
        }
        log(LOG_INFO, "- Initialized %d reporting plugins.\n", ret);

        ret = decode_plugins_init(DECODE_PLUGIN_DIR, argc, argv);
        if ( ret < 0 ) {
                log(LOG_INFO, "error initializing decoding plugins.\n");
                return -1;
        }
        log(LOG_INFO, "- Initialized %d decoding plugins.\n", ret);


        ret = filter_plugins_init(FILTER_PLUGIN_DIR, argc, argv);
        if ( ret < 0 ) {
                log(LOG_INFO, "error initializing filtering plugins.\n");
                return -1;
        }
        log(LOG_INFO, "- Initialized %d filtering plugins.\n", ret);
        

        ret = pconfig_init(argc, argv);
        if ( ret < 0 )
                exit(1);
        
        ret = manager_idmef_ident_init();
        if ( ret < 0 )
                exit(1);
        
        action.sa_flags = 0;
        sigemptyset(&action.sa_mask);
        action.sa_handler = cleanup;

        /*
         * start server
         */
        init_manager_server();

        signal(SIGPIPE, SIG_IGN);
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGABRT, &action, NULL);
        sigaction(SIGQUIT, &action, NULL);

        manager_relay_init();
        server_generic_start(&sensor_server, nserver);
        
	exit(0);	
}
