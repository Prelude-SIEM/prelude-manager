/*****
*
* Copyright (C) 1998,1999,2000 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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

#include <libprelude/list.h>
#include <libprelude/plugin-common.h>
#include <libprelude/common.h>
#include <libprelude/daemonize.h>
#include <libprelude/config-engine.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>


#include "pconfig.h"
#include "server.h"
#include "plugin-decode.h"
#include "plugin-report.h"
#include "plugin-db.h"


extern struct report_config config;


static void cleanup(int sig) 
{
        log(LOG_INFO, "Caught signal %d.\n", sig);
        /*
         * Now we reset the signal
         * we caught to it's default behavior
         */
        signal(sig, SIG_DFL);

#if 0
        /*
         *
         */
        manager_server_close();
        
        /*
         *
         */
        report_plugins_close();
#endif   

        if ( config.pidfile )
                unlink(config.pidfile);

        /*
         * We resend the signal we just caught,
         * this time, it is directly handled
         * by the kernel.
         */
        raise(sig);
}


#if 0
static void *admin_server_start(void) 
{
        manager_server_t *admsrv;

        admsrv = manager_server_new(config.admin_server_addr, config.admin_server_port);
        if ( ! admsrv )
                return NULL;

        manager_server_start(admsrv);

        
}
#endif



int main(int argc, char **argv)
{
        int ret;
        manager_server_t *sensors_server;
        
        if ( pconfig_init(argc, argv) < 0 )
                exit(1);


        do_init(report_plugins_init(REPORT_PLUGIN_DIR),
                "Initializing report plugins");

        do_init(db_plugins_init(DB_PLUGIN_DIR),
                "Initializing database plugins");
        
        do_init_nofail(decode_plugins_init(DECODE_PLUGIN_DIR),
                       "Initializing decode plugins.");

        ret = idmef_ident_init();
        if ( ret < 0 )
                exit(1);
        
        signal(SIGTERM, cleanup);
        signal(SIGINT, cleanup);
        signal(SIGTERM, cleanup);
        signal(SIGSEGV, cleanup);

        /*
         * Start prelude as a daemon if asked.
         */
        if ( config.daemonize == 1 )
                do_init(daemon_start(config.pidfile),
                        "Starting Prelude Report as a daemon.");

        do_init(1, "Starting Manager server");
        sensors_server = manager_server_start(config.addr, config.port);
        assert(sensors_server);
        manager_server_close(sensors_server);

        report_plugins_close();
        idmef_ident_exit();
        
	exit(0);	
}












