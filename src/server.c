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
#include <parser.h>
#include <assert.h>

#include <libprelude/common.h>
#include <libprelude/socket-op.h>
#include <libprelude/alert-id.h>
#include <libprelude/config-engine.h>
#include <libprelude/plugin-common.h>

#include "config.h"
#include "ssl.h"

#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>

#include "pconfig.h"
#include "server.h"
#include "server-logic.h"
#include "auth.h"
#include "plugin-decode.h"



#define UNIX_SOCK "/var/lib/prelude/socket"

        
static server_t *manager_srvr;
extern struct report_config config;


static int server_read_connection_cb(prelude_io_t *src, void **clientdata) 
{
        int ret;
        uint32_t dlen;
        uint8_t tag, priority;

        printf("read cb\n");
        
        ret = prelude_msg_read((prelude_msg_t **) clientdata, src);
        if ( ret < 0 )
                return -1; /* an error occured */

        if ( ret == 0 )
                return 0;  /* message not fully read yet */

        /*
         * If we get there, we have a whole message.
         */
        alert_schedule(*clientdata, src);
        *clientdata = NULL;
        
        return 0;
}




static int server_close_connection_cb(prelude_io_t *pio, void *clientdata) 
{
        int ret;
        
        log(LOG_INFO, "closing connection with %s.\n", "");

        prelude_io_close(pio);
        prelude_io_destroy(pio);

        if ( clientdata )
                prelude_msg_destroy(clientdata);
        
        return ret;
}




static prelude_io_t *handle_normal_connection(int fd, const char *addr) 
{
        int ret;
        prelude_io_t *pio;

        ret = prelude_auth_recv(fd, addr);
        if ( ret < 0 ) {
                log(LOG_INFO, "Plaintext authentication failed with %s.\n", addr);
                return NULL;
        }

        log(LOG_INFO, "Plaintext authentication succeed with %s.\n", addr);

        pio = prelude_io_new();
        if ( ! pio )
                return NULL;

        prelude_io_set_socket_io(pio, fd);

        return pio;
}




static prelude_io_t *handle_ssl_connection(int sock, const char *addr) 
{
#ifdef HAVE_SSL
        SSL *ssl;
        prelude_io_t *pio;
        
        ssl = ssl_auth_client(sock);
        if ( ! ssl ) {
                log(LOG_INFO, "SSL authentication failed with %s.\n", addr);
                return NULL;
        }
        
        log(LOG_INFO, "SSL authentication succeed with %s.\n", addr);

        pio = prelude_io_new();
        if ( ! pio )
                return NULL;

        prelude_io_set_ssl_io(pio, ssl);
        
        return pio;
#else
        log(LOG_INFO, "Client requested unavailable option : SSL.\n");
        return NULL;
#endif
}






static prelude_io_t *setup_connection(int sock, const char *addr) 
{
        int ret, len;
        const char *ssl;
        prelude_io_t *pio;
        char *ptr, buf[1024];
        
#ifdef HAVE_SSL
        ssl = "supported";
#else
        ssl = "unsupported";
#endif
        
        len = snprintf(buf, sizeof(buf), "ssl=%s;\n", ssl);

        
        ret = socket_write_delimited(sock, buf, ++len, write);
        if ( ret < 0 ) {
                log(LOG_ERR, "error writing config to Prelude client.\n");
                return NULL;
        }
        
        ret = socket_read_delimited(sock, (void **)&ptr, read);
        if ( ret < 0 ) {
                log(LOG_ERR, "error reading Prelude client config string.\n");
                return NULL;
        }
        
        if ( strstr(ptr, "use_ssl=yes;") ) 
                pio = handle_ssl_connection(sock, addr);
        else 
                pio = handle_normal_connection(sock, addr);
        
        free(ptr);

        return pio;
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
static prelude_io_t *setup_inet_connection(int sock, struct sockaddr_in *addr) 
{
        int ret;
        const char *from;
        prelude_io_t *pio;
        
        from = inet_ntoa(((struct sockaddr_in *)addr)->sin_addr);
              
#ifdef HAVE_TCPD_H
        ret = tcpd_auth(sock);
        if ( ret < 0 )
                return NULL;
#endif
        
        log(LOG_INFO, "new connection from %s.\n", from);

        pio = setup_connection(sock, from);
        if ( ! pio ) {
                log(LOG_INFO, "closing connection with %s.\n", from);
                return NULL;
        }
        
        return pio;
}




/*
 *
 */
static prelude_io_t *setup_unix_connection(int sock, struct sockaddr_un *addr)
{
        prelude_io_t *pio;
        
        log(LOG_INFO, "new UNIX connection.\n");
        
        pio = handle_normal_connection(sock, "unix");
        if ( ! pio )
                log(LOG_INFO, "closing unix connection.\n");

        return pio;
}



/*
 *
 */
static int wait_connection(int sock, struct sockaddr *addr, socklen_t addrlen, int unix_sock) 
{
        int ret;
        int client;
        prelude_io_t *pio;
        
        while ( 1 ) {
                
                client = accept(sock, addr, &addrlen);
                if ( client < 0 ) {
                        log(LOG_ERR, "couldn't accept connection.\n");
                        manager_server_close();
                        continue;
                }
                
                if ( unix_sock )
                        pio = setup_unix_connection(client, (struct sockaddr_un *)addr);
                else
                        pio = setup_inet_connection(client, (struct sockaddr_in *)addr);
                
                if ( ! pio ) {
                        close(client);
                        continue;
                }

                ret = fcntl(client, F_SETFL, O_NONBLOCK);
                if ( ret < 0 ) {
                        log(LOG_ERR, "couldn't set non blocking mode for client.\n");
                        prelude_io_close(pio);
                        prelude_io_destroy(pio);
                }
                
                ret = server_logic_process_requests(manager_srvr, pio, NULL);
                if ( ret < 0 ) {
                        log(LOG_ERR, "queueing client FD for server logic processing failed.\n");
                        close(sock);
                        continue;
                }
                
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
                log(LOG_ERR, "couldn't create socket.\n");
		return -1;
	}
        
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, UNIX_SOCK, sizeof(addr.sun_path));
        
        ret = is_unix_socket_already_used(sock, (struct sockaddr *) &addr, sizeof(addr));
        if ( ret == 1 || ret == -1 ) {
                close(sock);
                return -1;
        }
        
        ret = generic_server(sock, (struct sockaddr *) &addr, sizeof(addr));
        if ( ret < 0 ) {
                close(sock);
                return -1;
        }

        return wait_connection(sock, (struct sockaddr *) &addr, sizeof(addr), 1);
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
                goto err;
        }

        ret = setsockopt(sock, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(int));
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't set SO_KEEPALIVE socket option.\n");
                goto err;
        }
        
        ret = generic_server(sock, (struct sockaddr *) &addr, sizeof(addr));
        if ( ret < 0 )
                goto err;

#ifdef HAVE_SSL
        ret = ssl_init_server();
	if ( ret < 0 )
                goto err;
#endif
        
        return wait_connection(sock, (struct sockaddr *) &addr, sizeof(addr), 0);

 err:
        close(sock);
        return -1;
}




/*
 *
 */
int manager_server_start(void)
{
	int ret;
        
        manager_srvr = server_logic_new(server_read_connection_cb, server_close_connection_cb);
        if ( ! manager_srvr ) {
                log(LOG_ERR, "couldn't setup Manager server.\n");
                return -1;
        }
        
        ret = alert_scheduler_init();
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't initialize alert scheduler.\n");
                return -1;
        }
        
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

        alert_scheduler_exit();
}










