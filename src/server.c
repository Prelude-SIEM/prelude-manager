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
#include <sys/wait.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <syslog.h>
#include <signal.h>
#include <sys/poll.h>


#include <libprelude/common.h>
#include <libprelude/config-engine.h>

#include "pconfig.h"
#include "config.h"
#include "server.h"
#include "auth.h"
#include "cnx.h"
#include "ssl.h"


static int sock;

extern struct report_config config;
static int (*handle_connection)(int sock, struct sockaddr *addr, unsigned int *addrlen);



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
        
        request_init(&request, RQ_DAEMON, "prelude-report", RQ_FILE, clnt_sock, 0);
        
        fromhost(&request);

        ret = hosts_access(&request);
        if ( ! ret ) {
                syslog(deny_severity,
                       "prelude-report: refused connect from %s", eval_client(&request));
                return -1;
        }

        syslog(allow_severity, "prelude-report: connect from %s", eval_client(&request));
        
        return 0;
}
#endif



/*
 *
 */
static int wait_connection(struct sockaddr *addr, unsigned int addrlen, int unix_sock) 
{
        int ret, client;
        
        while ( 1 ) {
                client = accept(sock, addr, &addrlen);
                if ( client < 0 ) {
                        log(LOG_ERR, "couldn't accept connection.\n");
                        report_server_close();
                        return -1;
                }
                
#ifdef HAVE_TCPD_H
                if ( ! unix_sock ) {
                        ret = tcpd_auth(client);
                        if ( ret < 0 ) {
                                close(client);
                                continue;
                        }
                }
#endif
		ret = fork();
                if ( ret < 0 ) {
                        log(LOG_ERR, "couldn't fork.\n");
                        report_server_close();
                        return -1;
                }
                
                if ( ret == 0 ) {
                        close(sock);
                        ret = handle_connection(client, addr, &addrlen);
                        close(client);
                        exit(ret);
                }
                close(client);
        }
        
        return 0;
}



/*
 *
 */
static void child_exit(int sig) 
{
        wait(NULL);
}



/*
 *
 */
static int generic_server(struct sockaddr *addr, size_t alen) 
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

        signal(SIGCHLD, child_exit);
        
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
                log(LOG_INFO, "Report server UNIX socket is already used. Exiting.\n");
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
        int ret;
        struct sockaddr_un addr;
        
        log(LOG_INFO, "\tStarting Unix report server.\n");

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
        
        ret = generic_server((struct sockaddr *) &addr, sizeof(addr));
        if ( ret < 0 ) {
                close(sock);
                return -1;
        }

        return wait_connection((struct sockaddr *)&addr, sizeof(struct sockaddr_un), 1);
}



/*
 *
 */
static int inet_server_start(void) 
{
        int ret, on = 1;
        struct sockaddr_in addr;

        log(LOG_INFO, "\tStarting Tcp report server.\n" );
        
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
        
        ret = generic_server((struct sockaddr *) &addr, sizeof(addr));
        if ( ret < 0 ) {
                close(sock);
                return -1;
        }

#ifdef HAVE_SSL
        ret = ssl_init_server();
	if ( ret < 0 ) {
                close(sock);
                return -1;
        }
#endif

        ret = auth_init();
        if ( ret < 0 ) {
                close(sock);
                return -1;
        }
        
        return wait_connection((struct sockaddr *)&addr, sizeof(struct sockaddr_in), 0);
}




/*
 *
 */
int report_server_start(void) {
	int ret;
        
        ret = strcmp(config.addr, "unix");

        if ( ret == 0 ) {

                handle_connection = handle_unix_connection;
                ret = unix_server_start();

        } else {

                handle_connection = handle_inet_connection;
                ret = inet_server_start();

        }
        
        return ret;
}



void report_server_close(void) 
{
        int ret;
        
        close(sock);
        
        ret = strcmp(config.addr, "unix");
        if (ret == 0 ) 
                unlink(UNIX_SOCK);
}










