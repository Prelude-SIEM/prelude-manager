/*****
*
* Copyright (C) 1998,1999,2000, 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <libprelude/plugin-common.h>
#include <libprelude/prelude-log.h>
#include <libprelude/daemonize.h>
#include <libprelude/config-engine.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/threads.h>

#include "server-generic.h"
#include "sensor-server.h"
#include "admin-server.h"
#include "pconfig.h"
#include "plugin-decode.h"
#include "plugin-report.h"
#include "plugin-db.h"
#include "idmef-util.h"
#include "idmef-message-scheduler.h"

#define sensor_server server[0]
#define admin_server server[1]

static size_t nserver = 0;
static server_generic_t *server[2];
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
        admin_server_close(admin_server);
        
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

        log(LOG_INFO, "- sensors server started (listening on %s:%d).\n",
            config.addr, config.port);

        /*
         * Initialize the admin server if specified.
         */
        if ( config.admin_server_addr ) {
                
                admin_server = admin_server_new(config.admin_server_addr, config.admin_server_port);
                if ( ! admin_server ) {
                        log(LOG_INFO, "- couldn't start administration server.\n");
                        exit(1);
                }

                log(LOG_INFO, "- administration server started (listening on %s:%d).\n",
                    config.admin_server_addr, config.admin_server_port);

                nserver++;
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

        ret = db_plugins_init(DB_PLUGIN_DIR, argc, argv);
        if ( ret < 0 ) {
                log(LOG_INFO, "error initializing database plugins.\n");
                return -1;
        }
        log(LOG_INFO, "- Initialized %d database plugins.\n", ret);

        ret = decode_plugins_init(DECODE_PLUGIN_DIR, argc, argv);
        if ( ret < 0 ) {
                log(LOG_INFO, "error initializing decoding plugins.\n");
                return -1;
        }
        log(LOG_INFO, "- Initialized %d decoding plugins.\n", ret);


        ret = pconfig_init(argc, argv);
        if ( ret < 0 )
                exit(1);
        
        ret = idmef_ident_init();
        if ( ret < 0 )
                exit(1);
        
        action.sa_flags = 0;
        sigemptyset(&action.sa_mask);
        action.sa_handler = cleanup;

        /*
         * start server
         */
        init_manager_server();
        
        sigaction(SIGINT, &action, NULL);
        sigaction(SIGTERM, &action, NULL);
        sigaction(SIGABRT, &action, NULL);
        sigaction(SIGQUIT, &action, NULL);
        
         
        /*
         * Start prelude as a daemon if asked.
         */
        if ( config.daemonize == 1 ) {
                ret = prelude_daemonize(config.pidfile);
                if ( ret < 0 )
                        return -1;
        }

        server_generic_start(server, nserver);
        
	exit(0);	
}
