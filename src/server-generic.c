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
#include <assert.h>
#include <sys/stat.h>

#include <libprelude/common.h>
#include <libprelude/config-engine.h>
#include <libprelude/plugin-common.h>

#include "config.h"
#include "auth.h"
#include "ssl.h"

#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-message-id.h>
#include <libprelude/prelude-auth.h>

#include "pconfig.h"
#include "server-logic.h"
#include "server-generic.h"


#define UNIX_SOCK "/var/lib/prelude/socket"



struct server_generic {
        int sock;
        int unix_srvr;
        size_t clientlen;
        struct server_logic *logic;
        server_generic_read_func_t *read;
        server_generic_close_func_t *close;
        server_generic_accept_func_t *accept;
};



struct server_generic_client {
        SERVER_GENERIC_OBJECT;
};




/*
 * Generate a configuration message containing
 * the kind of connection the Manager support.
 */
static prelude_msg_t *generate_config_message(void)
{
        prelude_msg_t *msg;

        msg = prelude_msg_new(2, 0, PRELUDE_MSG_AUTH, 0);
        if ( ! msg )
                return NULL;        

        prelude_msg_set(msg, PRELUDE_MSG_AUTH_HAVE_PLAINTEXT, 0, NULL);
        
#ifdef HAVE_SSL
        prelude_msg_set(msg, PRELUDE_MSG_AUTH_HAVE_SSL, 0, NULL);
#endif
        
        return msg;
}


/*
 * Start the SSL authentication process.
 */
static int handle_ssl_connection(prelude_io_t *fd, const char *addr) 
{
#ifdef HAVE_SSL
        SSL *ssl;
        
        ssl = ssl_auth_client(prelude_io_get_fd(fd));
        if ( ! ssl ) {
                log(LOG_INFO, "SSL authentication failed with %s.\n", addr);
                return -1;
        }
        
        log(LOG_INFO, "SSL authentication succeed with %s.\n", addr);
        
        prelude_io_set_ssl_io(fd, ssl);
        
        return 0;
#else
        log(LOG_INFO, "Client requested unavailable option : SSL.\n");
        return -1;
#endif
}




static int send_plaintext_authentication_result(prelude_io_t *fd, uint8_t tag)
{
        int ret;
        prelude_msg_t *msg;
        
        msg = prelude_msg_new(1, 0, PRELUDE_MSG_AUTH, 0);
        if ( ! msg )
                return -1;
        
        prelude_msg_set(msg, tag, 0, NULL);
        ret = prelude_msg_write(msg, fd);
        prelude_msg_destroy(msg);

        return ret;
}




/*
 * Read authentication information contained in the passed message.
 * Then try to authenticate the peer.
 */
static int handle_plaintext_connection(prelude_msg_t *msg, prelude_io_t *fd, const char *addr)
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        const char *user = NULL, *pass = NULL;

        while ( (ret = prelude_msg_get(msg, &tag, &len, &buf)) > 0 ) {
                
                switch (tag) {
                        
                case PRELUDE_MSG_AUTH_USERNAME:
                        user = buf;
                        break;
                        
                case PRELUDE_MSG_AUTH_PASSWORD:
                        pass = buf;
                        break;
                        
                default:
                        log(LOG_INFO, "Invalid authentication message from %s.\n", addr);
                        return -1;
                }
        }
        
        if ( ! user || ! pass || ret < 0 ) {
                log(LOG_INFO, "Invalid authentication message from %s.\n", addr);
                return -1;
        }
        
        ret = prelude_auth_check(MANAGER_AUTH_FILE, user, pass);
        if ( ret < 0 ) {
                log(LOG_INFO, "Plaintext authentication failed with %s.\n", addr);
                return send_plaintext_authentication_result(fd, PRELUDE_MSG_AUTH_FAILED);
        }

        log(LOG_INFO, "Plaintext authentication succeed with %s.\n", addr);

        return send_plaintext_authentication_result(fd, PRELUDE_MSG_AUTH_SUCCEED);
}




/*
 * Either plaintext, either SSL.
 * call the necessary authentication function.
 */
static int handle_connection(prelude_msg_t *msg, server_generic_client_t *client) 
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t dlen;
        
        tag = prelude_msg_get_tag(msg);

        if ( tag != PRELUDE_MSG_AUTH ) {
                log(LOG_INFO, "expected authentication tag got (%d).\n", tag);
                return -1;
        }

        ret = prelude_msg_get(msg, &tag, &dlen, &buf);
        if ( ret <= 0 )
                return -1;
        
        switch (tag) {

        case PRELUDE_MSG_AUTH_SSL:
                ret = handle_ssl_connection(client->fd, client->addr);
                break;
                
        case PRELUDE_MSG_AUTH_PLAINTEXT:
                ret = handle_plaintext_connection(msg, client->fd, client->addr);
                break;

        default:
                log(LOG_INFO, "Invalid authentication tag (%d).\n", tag);
                return -1;
        }


        return ret;
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
        prelude_msg_status_t status;

        status = prelude_msg_read(&client->msg, client->fd);
        
        if ( status == prelude_msg_finished ) {                

                ret = handle_connection(client->msg, client);
                if ( ret < 0 )
                        return -1;
                
                prelude_msg_destroy(client->msg);
                client->msg = NULL;
                client->is_authenticated = 1;

                return server->accept(client);
        }
        
        else if ( status == prelude_msg_unfinished )
                return 0;
        
        return -1;
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
        server_generic_t *server = sdata;
        server_generic_client_t *client = (server_generic_client_t *) ptr;
        
        if ( client->is_authenticated )
                return server->read(client);
        else 
                /*
                 * -1 will result in close_connection_cb to be called.
                 */
                return authenticate_client(server, client);
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
        
        if ( server->unix_srvr )
                log(LOG_INFO, "closing connection on UNIX socket.\n");
        else {
                log(LOG_INFO, "closing connection with %s.\n", client->addr);
        }

        free(client->addr);
        
        prelude_io_close(client->fd);
        prelude_io_destroy(client->fd);

        if ( client->is_authenticated )
                server->close(client);

        free(ptr);
        
        return 0;
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
                log(LOG_INFO, "refused connection from %s.\n", eval_client(&request));
                return -1;
        }

        log(LOG_INFO, "accepted connection from %s.\n", eval_client(&request));
        
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
        
#ifdef HAVE_TCPD_H
        ret = tcpd_auth(client);
        if ( ret < 0 )
                return -1;
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
        cdata->is_authenticated = 0;
        
        return 0;
}





/*
 * Wait for client to connect on the Prelude Manager.
 */
static int wait_connection(server_generic_t *server)
{
        int ret, client;
        socklen_t addrlen;
        prelude_msg_t *msg;
        struct sockaddr_in addr;
        server_generic_client_t *cdata;

        addrlen = sizeof(addr);
        
        msg = generate_config_message();
        if ( ! msg )
                return -1;
        
        while ( 1 ) {
                cdata = malloc(server->clientlen);
                if ( ! cdata ) {
                        log(LOG_ERR, "memory exhausted.\n");
                        continue;
                }

                if ( server->unix_srvr ) {
                        client = accept(server->sock, NULL, NULL);
                        cdata->addr = strdup("unix");
                } else {
                        client = accept(server->sock, (struct sockaddr *) &addr, &addrlen);
                        cdata->addr = strdup(inet_ntoa(addr.sin_addr));
                }
                
                if ( client < 0 ) {
                        log(LOG_ERR, "couldn't accept connection.\n");
                        free(cdata);
                        continue;
                }
                
                ret = setup_client_socket(server, cdata, client);
                if ( ret < 0 ) {
                        free(cdata);
                        close(client);
                        continue;
                }
                
                ret = prelude_msg_write(msg, cdata->fd);
                if ( ret < 0 ) {
                        log(LOG_ERR, "couldn't send configuration message.\n");
                        prelude_io_close(cdata->fd);
                        prelude_io_destroy(cdata->fd);
                        free(cdata->addr);
                        free(cdata);
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
        }
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
static int unix_server_start(server_generic_t *server) 
{
        int ret;
        struct sockaddr_un addr;
                
        server->sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if ( server->sock < 0 ) {
                log(LOG_ERR, "couldn't create socket.\n");
		return -1;
	}
        
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, UNIX_SOCK, sizeof(addr.sun_path));
        
        ret = is_unix_socket_already_used(server->sock, (struct sockaddr *) &addr, sizeof(addr));
        if ( ret == 1 || ret < 0  ) {
                close(server->sock);
                return -1;
        }
        
        ret = generic_server(server->sock, (struct sockaddr *) &addr, sizeof(addr));
        if ( ret < 0 ) {
                close(server->sock);
                return -1;
        }

        /*
         * Everyone should be able to access the filesystem object
         * representing our socket.
         */
        ret = chmod(UNIX_SOCK, S_IRWXU|S_IRWXG|S_IRWXO);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't set permission for UNIX socket.\n");
                return -1;
        }
        
        return 0;
}




/*
 *
 */
static int inet_server_start(server_generic_t *server, const char *saddr, uint16_t port) 
{
        int ret, on = 1;
        struct sockaddr_in addr;
        
        server->sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if ( server->sock < 0 ) {
                log(LOG_ERR, "couldn't create socket.\n");
                return -1;
        }
        
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = inet_addr(saddr);

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
        
        ret = generic_server(server->sock, (struct sockaddr *) &addr, sizeof(addr));
        if ( ret < 0 )
                goto err;

#ifdef HAVE_SSL
        ret = ssl_init_server();
	if ( ret < 0 )
                goto err;
#endif

        return 0;

 err:
        close(server->sock);
        return -1;
}




/*
 *
 */
server_generic_t *server_generic_new(const char *addr, uint16_t port,
                                     size_t clientlen, server_generic_accept_func_t *acceptf,
                                     server_generic_read_func_t *readf, server_generic_close_func_t *closef)
{
        int ret;
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
        
        server->logic = server_logic_new(server, read_connection_cb, close_connection_cb);
        if ( ! server->logic ) {
                log(LOG_ERR, "couldn't initialize server pool.\n");
                free(server);
                return NULL;
        }
        
        ret = strcmp(addr, "unix");
        if ( ret == 0 ) {
                server->unix_srvr = 1;
                ret = unix_server_start(server);
        } else {
                server->unix_srvr = 0;
                ret = inet_server_start(server, addr, port);
        }

        if ( ret < 0 ) {
                server_logic_stop(server->logic);
                free(server);
                return NULL;
        }
        
        return server;
}




void server_generic_start(server_generic_t *server) 
{
        wait_connection(server);
}




void server_generic_close(server_generic_t *server) 
{
        server_logic_stop(server->logic);

        if ( server->unix_srvr )
                unlink(UNIX_SOCK);
}










