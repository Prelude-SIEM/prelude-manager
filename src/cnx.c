/*****
*
* Copyright (C) 1998 - 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <unistd.h>
#include <syslog.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>

#include <libprelude/list.h>
#include <libprelude/socket-op.h>
#include <libprelude/plugin-common.h>
#include <libprelude/alert.h>
#include <libprelude/alert-common.h>
#include <libprelude/common.h>
#include <libprelude/config-engine.h>

#include "auth.h"
#include "cnx.h"
#include "pconfig.h"
#include "ssl.h"


static ssize_t (*my_read)(int fd, void *buf, size_t count);
extern struct list_head __report_plugins;
extern struct report_config config;


/*
 *
 */
static int wait_raw_report(int socket) 
{
#if 0
        int ret;
        alert_t alert;
        report_infos_t rinfos;
        plugin_generic_t plugin;

        alert_plugin(&alert) = &plugin;
        
        while ( 1 ) {            
                ret = alert_read(socket, &alert, my_read);
                if ( ret <= 0 )
                        return ret;
                
                report_infos_get(&alert, &rinfos);
                report_plugins_run(&alert, &rinfos);
                report_infos_free(&rinfos);
                
                alert_free(&alert, 1);

        }
#endif

        return 0;
}



/*
 *
 */

static int set_options(const char *optbuf) 
{
        if ( strstr(optbuf, "use_ssl=yes;") ) {
#ifndef HAVE_SSL
                goto unavaillable;
#else
                log(LOG_INFO, "\t- Client requested SSL communication.\n");
                config.use_ssl = 1;
#endif          
        } else {
#ifdef HAVE_SSL
                log(LOG_INFO, "\t- Client requested non encrypted communication.\n");
#endif
                config.use_ssl = 0;
        }

        return 0;
        
#if ! defined(HAVE_SSL)
 unavaillable:
        log(LOG_INFO, "\t- Client requested unavaillable option.\n");
        return -1;
#endif
}




static int setup_connection(int sock) 
{
        char *buf;
        int ret, len;
        const char *ssl;
        
#ifdef HAVE_SSL
        ssl = "supported";
#else
        ssl = "unsupported";
#endif

        len = snprintf(buf, sizeof(buf), "ssl=%s;\n", ssl);

        ret = socket_write_delimited(sock, buf, ++len, write);
        if ( ret < 0 ) {
                log(LOG_ERR, "error writing config to Prelude client.\n");
                return -1;
        }
        
        ret = socket_read_delimited(sock, (void **)&buf, read);
        if ( ret < 0 ) {
                log(LOG_ERR, "error reading Prelude client config string.\n");
                return -1;
        }


        return set_options(buf);
}




/*
 *
 */
int handle_inet_connection(int sock, struct sockaddr *addr, unsigned int *addrlen) 
{
        int ret;
        char *from;

	from = strdup(inet_ntoa(((struct sockaddr_in *)addr)->sin_addr));
	if ( ! from )
		return -1;

        log(LOG_INFO, "new connection from %s.\n", from);

        ret = setup_connection(sock);
        if ( ret < 0 )
                goto err;
        
        my_read = read;
        
#ifdef HAVE_SSL
        if ( config.use_ssl == 1 ) {
                my_read = ssl_read;
                
                ret = ssl_auth_client(sock);
                if ( ret < 0 ) {
                        log(LOG_INFO, "SSL authentication failed with %s.\n", from);
                        goto err;
                }
                
                log(LOG_INFO, "SSL authentication suceeded with %s.\n", from);
        } else
                
#endif
                if ( auth_check(sock) < 0 ) 
                        goto err;
                
        ret = wait_raw_report(sock);

        log(LOG_INFO, "closing connection with %s.\n", from);
        free(from);

        return ret;

  err:
         log(LOG_INFO, "closing connection with %s.\n", from);
         free(from);
         close(sock);
         return -1;
}


/*
 *
 */
int handle_unix_connection(int sock, struct sockaddr *addr, unsigned int *addrlen) 
{
        int ret;
        
        log(LOG_INFO, "new local connection.\n");

        my_read = read;
        ret = wait_raw_report(sock);

        log(LOG_INFO, "closing local connection.\n");

        return ret;
}














