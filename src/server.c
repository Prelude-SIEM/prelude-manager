/*****
*
* Copyright (C) 1999,2000 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <syslog.h>
#include <sys/poll.h>
#include <libxml/parser.h>

#include <libprelude/common.h>
#include <libprelude/socket-op.h>
#include <libprelude/alert-id.h>
#include <libprelude/alert-read.h>
#include <libprelude/config-engine.h>
#include <libprelude/plugin-common.h>

#include "pconfig.h"
#include "config.h"
#include "server.h"
#include "server-logic.h"
#include "auth.h"
#include "ssl.h"
#include "plugin-decode.h"


extern struct report_config config;
static ssize_t (*my_read)(int fd, void *buf, size_t count);


/*
 *
 */
static int data_available_cb(int fd) 
{
        uint8_t tag;
        xmlNodePtr idmef_msg;
        alert_container_t *ac;
        
        ac = prelude_alert_read(fd, &tag);
        if ( ! ac )
                return -1;

        if ( tag == ID_IDMEF_ALERT ) {
                /*
                 * Special case where we should directly
                 * contact the DB subsystem.
                 */
                free(ac);
                return -1;
        } else {
                idmef_msg = decode_plugins_run(ac, tag);
        }
        
        free(ac);

        return 0;
}



/*
 *
 */
static int set_options(const char *optbuf) 
{
        if ( strstr(optbuf, "use_ssl=yes;") ) {

#ifndef HAVE_SSL
                goto unavailable;
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
        
 unavailable:
        log(LOG_INFO, "\t- Client requested unavailable option.\n");
        return -1;
        
#endif
}




static int setup_connection(int sock) 
{
        char buf[1024];
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




#ifdef HAVE_TCPD_H

#include <tcpd.h>

int allow_severity = LOG_INFO, deny_severity = LOG_NOTICE;


/*
 *
 */
static int tcpd_auth(int clnt_sock) 
{
        int ret;
        struct request_info request;
        
        request_init(&request, RQ_DAEMON, "prelude-manager", RQ_FILE, clnt_sock, 0);
        
        fromhost(&request);

        ret = hosts_access(&request);
        if ( ! ret ) {
                syslog(deny_severity,
                       "prelude-manager: refused connect from %s", eval_client(&request));
                return -1;
        }

        syslog(allow_severity, "prelude-manager: connect from %s", eval_client(&request));
        
        return 0;
}
#endif



/*
 *
 */
static int setup_inet_connection(int sock, struct sockaddr *addr, unsigned int *addrlen) 
{
        int ret;
        const char *from;

        from = inet_ntoa(((struct sockaddr_in *)addr)->sin_addr);
        
#ifdef HAVE_TCPD_H
        ret = tcpd_auth(sock);
        if ( ret < 0 )
                return -1;
#endif

        log(LOG_INFO, "new connection from %s.\n", from);

        ret = setup_connection(sock);
        if ( ret < 0 )
                return -1;
        
        my_read = read;
        
#ifdef HAVE_SSL
        if ( config.use_ssl == 1 ) {
                my_read = ssl_read;
                
                ret = ssl_auth_client(sock);
                if ( ret < 0 ) {
                        log(LOG_INFO, "SSL authentication failed with %s.\n", from);
                        return -1;
                }
                
                log(LOG_INFO, "SSL authentication suceeded with %s.\n", from);
        } else
                
#endif
                if ( auth_check(sock) < 0 ) 
                        return -1;

        return 0;
}




/*
 *
 */
static int setup_unix_connection(int sock, struct sockaddr *addr, unsigned int *addrlen) 
{        
        log(LOG_INFO, "new local connection.\n");

        my_read = read;
        
        return 0;
}



/*
 *
 */
static int wait_connection(int sock, struct sockaddr *addr, unsigned int addrlen, int unix_sock) 
{
        int ret, client;
        
        while ( 1 ) {
                
                client = accept(sock, addr, &addrlen);
                if ( client < 0 ) {
                        log(LOG_ERR, "couldn't accept connection.\n");
                        manager_server_close();
                        continue;
                }
                
                if ( unix_sock )
                        ret = setup_unix_connection(client, addr, &addrlen);
                else
                        ret = setup_inet_connection(client, addr, &addrlen);
                
                if ( ret < 0 )
                        close(client);

                server_process_requests(client);
        }
        
        return 0;
}



/*
 *
 */
static int generic_server(int sock, struct sockaddr *addr, size_t alen) 
{
        int ret;
        
        ret = bind(sock, addr, alen);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't bind to socket.\n");
                return -1;
        }
        
        ret = listen(sock, 10);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't listen on socket.\n");
                return -1;
        }
        
        return 0;
}




/*
 * If the UNIX socket already exist, check if it is in use.
 * if it is not, delete it.
 *
 * FIXME: Using connect for this is dirty.
 *
 * return 1 if the socket is already in use.
 * return 0 if the socket is unused.
 * retuir -1 on error.
 */
static int is_unix_socket_already_used(int sock, struct sockaddr *addr, int addrlen) 
{
        int ret;
        
        ret = access(UNIX_SOCK, F_OK);
        if ( ret < 0 )
                return 0;
        
        ret = connect(sock, addr, addrlen);
        if ( ret == 0 ) {
                log(LOG_INFO, "Prelude Manager UNIX socket is already used. Exiting.\n");
                return 1;
        }

        /*
         * The unix socket exist on the file system,
         * but no one use it... Delete it.
         */
        ret = unlink(UNIX_SOCK);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't delete UNIX socket.\n");
                return -1;
        }
        
        return 0;
}



/*
 *
 */
static int unix_server_start(void) 
{
        int ret, sock;
        struct sockaddr_un addr;
        
        log(LOG_INFO, "\tStarting Unix Manager server.\n");

        sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if ( sock < 0 ) {
		fprintf(stderr, "socket: %s.\n", strerror(errno));
		return -1;
	}
        
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, UNIX_SOCK, sizeof(addr.sun_path));
        
        ret = is_unix_socket_already_used(sock, (struct sockaddr *)&addr, sizeof(addr));
        if ( ret == 1 || ret == -1 ) {
                close(sock);
                return -1;
        }
        
        ret = generic_server(sock, (struct sockaddr *) &addr, sizeof(addr));
        if ( ret < 0 ) {
                close(sock);
                return -1;
        }

        return wait_connection(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_un), 1);
}



/*
 *
 */
static int inet_server_start(void) 
{
        int ret, on = 1, sock;
        struct sockaddr_in addr;

        log(LOG_INFO, "\tStarting Tcp Manager server.\n" );
        
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if ( sock < 0 ) {
                log(LOG_ERR, "couldn't create socket.\n");
                return -1;
        }
        
        addr.sin_family = AF_INET;
        addr.sin_port = htons(config.port);
        addr.sin_addr.s_addr = inet_addr(config.addr);
        
        ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't set SO_REUSEADDR socket option.\n");
                return -1;
        }

        ret = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(int));
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't set SO_KEEPALIVE socket option.\n");
                return -1;
        }
        
        ret = generic_server(sock, (struct sockaddr *) &addr, sizeof(addr));
        if ( ret < 0 ) {
                close(sock);
                return -1;
        }

#ifdef HAVE_SSL
        ret = ssl_init_server();
            /*
	if ( ret < 0 ) {
                close(sock);
                return -1;
        }
            */
#endif

        ret = auth_init();
        if ( ret < 0 ) {
                close(sock);
                return -1;
        }
        
        return wait_connection(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0);
}




/*
 *
 */
int manager_server_start(void)
{
	int ret;

        server_logic_init(data_available_cb);
        
        ret = strcmp(config.addr, "unix");

        if ( ret == 0 )
                ret = unix_server_start();
        else 
                ret = inet_server_start();
        
        return ret;
}



void manager_server_close(void) 
{
        int ret;
        
        ret = strcmp(config.addr, "unix");
        if (ret == 0 ) 
                unlink(UNIX_SOCK);
}










