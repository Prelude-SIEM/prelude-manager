/*****
*
* Copyright (C) 1999-2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <stdarg.h>
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
#include <assert.h>
#include <sys/stat.h>
#include <signal.h>

#include <libprelude/common.h>
#include <libprelude/prelude-log.h>
#include <libprelude/config-engine.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-message-id.h>
#include <libprelude/extract.h>
#include <libprelude/prelude-client.h>
#include <libprelude/prelude-inet.h>
#include <libprelude/prelude-error.h>

#include "config.h"
#include "libmissing.h"
#include "manager-auth.h"
#include "pconfig.h"
#include "server-logic.h"
#include "server-generic.h"


struct server_generic {

        int sock;

        size_t sa_len;
        struct sockaddr *sa;
        
        size_t clientlen;
        struct server_logic *logic;
        server_generic_read_func_t *read;
        server_generic_close_func_t *close;
        server_generic_accept_func_t *accept;
};


struct server_generic_client {
        SERVER_GENERIC_OBJECT;
};



static volatile sig_atomic_t continue_processing = 1;





static int send_auth_result(server_generic_client_t *client, int result)
{
        int ret;
                
        if ( ! client->msg ) {
                client->msg = prelude_msg_new(1, 0, PRELUDE_MSG_AUTH, 0);
                if ( ! client->msg )
                        return -1;

                prelude_msg_set(client->msg, result, 0, NULL);
        }
        
        ret = prelude_msg_write(client->msg, client->fd); 
        if ( ret < 0 ) {
		if ( prelude_error_get_code(ret) == PRELUDE_ERROR_EAGAIN ) {
			server_logic_notify_write_enable((server_logic_client_t *) client);
			return 0;
		}

		log(LOG_ERR, "error writing auth result message: %s.\n", prelude_strerror(ret));
		prelude_msg_destroy(client->msg);
		return -1;
        }

        prelude_msg_destroy(client->msg);

        client->msg = NULL;
                
        return (client->state & SERVER_GENERIC_CLIENT_STATE_AUTHENTICATED) ? 0 : -1;
}




/*
 * Read the message sent by the Prelude Manager client.
 * This message should contain information about the kind of
 * connection wanted, and the authentication data.
 *
 * Once we finish reading the message, we start the authentication process.
 */
static int authenticate_client(server_generic_t *server, server_generic_client_t *client) 
{
        int ret;

        if ( ! client->msg && ! (client->state & SERVER_GENERIC_CLIENT_STATE_AUTHENTICATED) ) {
                ret = manager_auth_client(client, client->fd);
                if ( ret == 0 )
                        return ret;
                
                if ( ret < 0 ) {
                        server_generic_log_client(client, "TLS authentication failed.\n");
                        return send_auth_result(client, PRELUDE_MSG_AUTH_FAILED);
                }
                
                client->state |= SERVER_GENERIC_CLIENT_STATE_AUTHENTICATED;
                
                return send_auth_result(client, PRELUDE_MSG_AUTH_SUCCEED);
        }

        if ( client->msg )
                return send_auth_result(client, -1);
        
        if ( server->sa->sa_family == AF_UNIX && ! (client->state & SERVER_GENERIC_CLIENT_STATE_ACCEPTED) ) {
                ret = manager_auth_disable_encryption(client, client->fd);
                if ( ret <= 0 )
                        return ret;

                server_generic_log_client(client, "disabled encryption on local UNIX connection.\n");
        }

        client->state |= SERVER_GENERIC_CLIENT_STATE_ACCEPTED;
        
        return server->accept(client);
}




static int write_connection_cb(void *sdata, server_logic_client_t *ptr)
{        
        server_logic_notify_write_disable(ptr);
        return authenticate_client(sdata, (server_generic_client_t *) ptr);
}




/*
 * callback called by server-logic when data is available for reading.
 * We direct the message either to the authentication process either
 * to the real data handling function.
 *
 * If the authentication function return -1 (error), this will cause
 * server-logic to call the close_connection_cb callback.
 */
static int read_connection_cb(void *sdata, server_logic_client_t *ptr) 
{
        int ret = 0;
        server_generic_t *server = sdata;
        server_generic_client_t *client = (server_generic_client_t *) ptr;

        do {    
                if ( client->state & SERVER_GENERIC_CLIENT_STATE_ACCEPTED )
                        ret = server->read(client);
                else
                        ret = authenticate_client(server, client);
                
                if ( ret == -2 )
                        return 0;
                
        } while ( ret == 0 && prelude_io_pending(client->fd) > 0 );
        
        return ret;
}



/*
 * callback called by server-logic when a connection should be closed.
 * if the authentication process succeed for this connection, call
 * the real close() callback function.
 */
static int close_connection_cb(void *sdata, server_logic_client_t *ptr) 
{
        server_generic_t *server = sdata;
        server_generic_client_t *client = (server_generic_client_t *) ptr;
        
        /*
         * layer above server-generic are permited to set fd to NULL so
         * that they can take control over the connection FD.
         */
        if ( client->fd ) {
                server_generic_log_client(client, "closing connection.\n");
                prelude_io_close(client->fd);
                prelude_io_destroy(client->fd);
        }
        
        free(client->addr);
        
        if ( client->state & SERVER_GENERIC_CLIENT_STATE_ACCEPTED ) 
                server->close(client);
        
        free(ptr);
        
        return 0;
}





#ifdef HAVE_TCP_WRAPPERS

#include <tcpd.h>

int allow_severity = LOG_INFO, deny_severity = LOG_NOTICE;


/*
 *
 */
static int tcpd_auth(server_generic_client_t *cdata, int clnt_sock) 
{
        int ret;
        struct request_info request;
        
        request_init(&request, RQ_DAEMON, "prelude-manager", RQ_FILE, clnt_sock, 0);
        
        fromhost(&request);

        ret = hosts_access(&request);
        if ( ! ret ) {
                server_generic_log_client(cdata, "tcp wrapper refused connection.\n", cdata->addr);
                return -1;
        }

        server_generic_log_client(cdata, "tcp wrapper accepted connection.\n");
        
        return 0;
}

#endif




/*
 * put client socket in non blocking mode and
 * create a prelude_io object for IO abstraction.
 *
 * Tell server-logic to handle event on the newly accepted client.
 */
static int setup_client_socket(server_generic_t *server,
                               server_generic_client_t *cdata, int client) 
{
        int ret;
        
#ifdef HAVE_TCP_WRAPPERS
        if ( server->sa->sa_family != AF_UNIX ) {
                ret = tcpd_auth(cdata, client);
                if ( ret < 0 )
                        return -1;
        } else
                server_generic_log_client(cdata, "accepted connection.\n");
#else
        server_generic_log_client(cdata, "accepted connection.\n");
#endif
        /*
         * set client socket non blocking.
         */
        ret = fcntl(client, F_SETFL, O_NONBLOCK);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't set non blocking mode for client.\n");
                return -1;
        }

        cdata->fd = prelude_io_new();
        if ( ! cdata->fd ) 
                return -1;

        prelude_io_set_sys_io(cdata->fd, client);
               
        cdata->msg = NULL;
        cdata->state = 0;
        
        return 0;
}




static int accept_connection(server_generic_t *server, server_generic_client_t *cdata) 
{
        int sock;
        socklen_t addrlen;

#ifndef HAVE_IPV6
        struct sockaddr_in addr;
#else
        struct sockaddr_in6 addr;
#endif
        
        addrlen = sizeof(addr);
        
        sock = accept(server->sock, (struct sockaddr *) &addr, &addrlen);
        if ( sock < 0 ) {
                log(LOG_ERR, "accept returned an error.\n");
                return -1;
        }
        
        if ( server->sa->sa_family == AF_UNIX ) 
                cdata->addr = strdup("unix");
        else {         
                void *in_addr;
                char out[128];
                const char *str;
                struct sockaddr *sa = (struct sockaddr *) &addr;

#ifdef HAVE_IPV6
                cdata->port = ntohs(addr.sin6_port);
#else
		cdata->port = ntohs(addr.sin_port);
#endif
                in_addr = prelude_inet_sockaddr_get_inaddr(sa);
                
                str = prelude_inet_ntop(sa->sa_family, in_addr, out, sizeof(out));
                if ( str )                
                        cdata->addr = strdup(str);
        }

        if ( ! cdata->addr ) {
                close(sock);
                return -1;
        }

        return sock;
}






static int handle_connection(server_generic_t *server) 
{
        int ret, client;
        server_generic_client_t *cdata;
        
        cdata = calloc(1, server->clientlen);
        if ( ! cdata ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        cdata->client_type = "unknown";

        client = accept_connection(server, cdata);                
        if ( client < 0 ) {
                log(LOG_ERR, "couldn't accept connection.\n");
                free(cdata);
                return -1;
        }
                
        ret = setup_client_socket(server, cdata, client);
        if ( ret < 0 ) {
                free(cdata);
                close(client);
                return -1;
        }
        
        ret = server_logic_process_requests(server->logic, (server_logic_client_t *) cdata);
        if ( ret < 0 ) {
                log(LOG_ERR, "queueing client FD for server logic processing failed.\n");
                prelude_io_close(cdata->fd);
                prelude_io_destroy(cdata->fd);
                free(cdata->addr);
                free(cdata);
                return -1;
        }

        return 0;
}






/*
 * Wait for client to connect on the Prelude Manager.
 */
static int wait_connection(server_generic_t **server, size_t nserver)
{
        int i, active_fd;
        struct pollfd pfd[nserver];
        
        for ( i = 0; i < nserver; i++ ) {                
                pfd[i].events = POLLIN;
                pfd[i].fd = server[i]->sock;
        } 
        
        while ( continue_processing ) {

                active_fd = poll(pfd, nserver, -1);                
                if ( active_fd < 0 )
                        continue;

                for ( i = 0; i < nserver && active_fd > 0; i++ ) {
                        if ( pfd[i].revents & POLLIN ) {
                                active_fd--;
                                handle_connection(server[i]);
                        }
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
static int is_unix_socket_already_used(int sock, struct sockaddr_un *sa, int addrlen) 
{
        int ret;
        
        ret = access(sa->sun_path, F_OK);
        if ( ret < 0 )
                return 0;
        
        ret = connect(sock, (struct sockaddr *) sa, addrlen);
        if ( ret == 0 ) {
                log(LOG_INFO, "Prelude Manager UNIX socket is already used. Exiting.\n");
                return 1;
        }
        
        /*
         * The unix socket exist on the file system,
         * but no one use it... Delete it.
         */
        ret = unlink(sa->sun_path);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't delete UNIX socket.\n");
                return -1;
        }
        
        return 0;
}



/*
 *
 */
static int unix_server_start(server_generic_t *server) 
{
        int ret;
        struct sockaddr_un *sa = (struct sockaddr_un *) server->sa;
        
        server->sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if ( server->sock < 0 ) {
                log(LOG_ERR, "couldn't create socket.\n");
		return -1;
	}
        
        ret = is_unix_socket_already_used(server->sock, sa, server->sa_len);
        if ( ret == 1 || ret < 0  ) {
                close(server->sock);
                return -1;
        }

        ret = generic_server(server->sock, server->sa, server->sa_len);
        if ( ret < 0 ) {
                close(server->sock);
                return -1;
        }

        /*
         * Everyone should be able to access the filesystem object
         * representing our socket.
         */
        ret = chmod(sa->sun_path, S_IRWXU|S_IRWXG|S_IRWXO);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't set permission for UNIX socket.\n");
                return -1;
        }
        
        return 0;
}




/*
 *
 */
static int inet_server_start(server_generic_t *server,
                             const char *saddr, struct sockaddr *addr, socklen_t addrlen) 
{
        int ret, on = 1;
        
        server->sock = socket(server->sa->sa_family, SOCK_STREAM, IPPROTO_TCP);
        if ( server->sock < 0 ) {
                log(LOG_ERR, "couldn't create socket.\n");
                return -1;
        }
        
        ret = setsockopt(server->sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't set SO_REUSEADDR socket option.\n");
                goto err;
        }

        ret = setsockopt(server->sock, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(int));
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't set SO_KEEPALIVE socket option.\n");
                goto err;
        }
        
        ret = generic_server(server->sock, addr, addrlen);
        if ( ret < 0 )
                goto err;

        return 0;

 err:
        close(server->sock);
        return -1;
}




static int resolve_addr(server_generic_t *server, const char *addr, uint16_t port) 
{
        int ret;
        prelude_addrinfo_t *ai, hints;
        char service[sizeof("00000")];

        memset(&hints, 0, sizeof(hints));
        
        hints.ai_family = PF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        snprintf(service, sizeof(service), "%u", port);
        
        ret = prelude_inet_getaddrinfo(addr, service, &hints, &ai);        
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't resolve %s.\n", addr);
                return -1;
        }
        
        ret = prelude_inet_addr_is_loopback(ai->ai_family, prelude_inet_sockaddr_get_inaddr(ai->ai_addr));
        if ( ret == 0 ) {
                ai->ai_family = AF_UNIX;
                ai->ai_addrlen = sizeof(struct sockaddr_un);
        }
        
        server->sa = malloc(ai->ai_addrlen);
        if ( ! server->sa ) {
                log(LOG_ERR, "memory exhausted.\n");
                prelude_inet_freeaddrinfo(ai);
                return -1;
        }

        server->sa_len = ai->ai_addrlen;
        server->sa->sa_family = ai->ai_family;
        
        if ( ai->ai_family != AF_UNIX )
                memcpy(server->sa, ai->ai_addr, ai->ai_addrlen);
        else {
                struct sockaddr_un *un = (struct sockaddr_un *) server->sa;
                prelude_connection_get_socket_filename(un->sun_path, sizeof(un->sun_path), port);
        }
        
        prelude_inet_freeaddrinfo(ai);

        return 0;
}




/*
 *
 */
server_generic_t *server_generic_new(const char *saddr, uint16_t port,
                                     size_t clientlen, server_generic_accept_func_t *acceptf,
                                     server_generic_read_func_t *readf, server_generic_close_func_t *closef)
{
        int ret;
        char out[128];
        void *in_addr;
        server_generic_t *server;
                
        server = malloc(sizeof(*server));
        if ( ! server ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        server->read = readf;
        server->accept = acceptf;
        server->close = closef;
        server->clientlen = clientlen;
        
        ret = resolve_addr(server, saddr, port);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't resolve %s.\n", saddr);
                return NULL;
        }
        
        server->logic = server_logic_new(server, read_connection_cb, write_connection_cb, close_connection_cb);
        if ( ! server->logic ) {
                log(LOG_ERR, "couldn't initialize server pool.\n");
                free(server);
                return NULL;
        }
        
        if ( server->sa->sa_family == AF_UNIX )
                ret = unix_server_start(server);
        else 
                ret = inet_server_start(server, saddr, server->sa, server->sa_len);
        
        if ( ret < 0 ) {
                server_logic_stop(server->logic);
                free(server);
                return NULL;
        }

        if ( server->sa->sa_family == AF_UNIX )
                snprintf(out, sizeof(out), "unix socket");
        else {
                assert(in_addr = prelude_inet_sockaddr_get_inaddr(server->sa));
                prelude_inet_ntop(server->sa->sa_family, in_addr, out, sizeof(out));
        }
        
        log(LOG_INFO, "- sensors server started (listening on %s port %d).\n", out, port);

        return server;
}




void server_generic_start(server_generic_t **server, size_t nserver) 
{
        wait_connection(server, nserver);
}




void server_generic_stop(server_generic_t *server)
{
        continue_processing = 0;
}



void server_generic_close(server_generic_t *server) 
{
        close(server->sock);
        
        if ( server->sa->sa_family == AF_UNIX )                 
                unlink(((struct sockaddr_un *)server->sa)->sun_path);
        
        server_logic_stop(server->logic);
}



void server_generic_process_requests(server_generic_t *server, server_generic_client_t *client)
{
        server_logic_process_requests(server->logic, (server_logic_client_t *) client);
}



void server_generic_log_client(server_generic_client_t *cnx, const char *fmt, ...)
{
        va_list ap;
        char buf[1024];
        
        va_start(ap, fmt);
        vsnprintf(buf, sizeof(buf), fmt, ap);
        va_end(ap);
        
        if ( cnx->port )
                log(LOG_INFO, "[%s:%u %s:0x%" PRIx64 "]: %s",
                    cnx->addr, cnx->port, cnx->client_type, cnx->ident, buf);
        else
                log(LOG_INFO, "[unix %s:0x%" PRIx64 "]: %s",
                    cnx->client_type, cnx->ident, buf);
}




const char *server_generic_get_addr_string(server_generic_client_t *client, char *buf, size_t size)
{
        int ret;

        *buf = 0;
        
        ret = snprintf(buf, size, "%s", client->addr);
        if ( ret < 0 || ret >= size )
                return buf;
        
        if ( client->port ) {
                ret += snprintf(buf + ret, size - ret, ":%u", client->port);
                if ( ret < 0 || ret >= size )
                        return buf;
        }

        if ( client->ident )
                snprintf(buf + ret, size - ret, " %s:0x%" PRIx64, client->client_type, client->ident);        
        
        return buf;
}
