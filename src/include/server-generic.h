/*****
*
* Copyright (C) 2000, 2001, 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
*
* This file is part of the Prelude-Manager program.
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

#ifndef _MANAGER_SERVER_GENERIC_H
#define _MANAGER_SERVER_GENERIC_H


#include <gnutls/gnutls.h>
#include <libprelude/prelude-inttypes.h>


#define SERVER_GENERIC_CLIENT_STATE_AUTHENTICATED  0x01
#define SERVER_GENERIC_CLIENT_STATE_ACCEPTED       0x02
#define SERVER_GENERIC_CLIENT_STATE_FLUSHING       0x04
#define SERVER_GENERIC_CLIENT_STATE_CLOSING        0x08
#define SERVER_GENERIC_CLIENT_STATE_CLOSED         0x10

#ifdef HAVE_IPV6
# define SERVER_SOCKADDR_TYPE struct sockaddr_in6
#else
# define SERVER_SOCKADDR_TYPE struct sockaddr_in
#endif

#define EV_PERIODIC_ENABLE 0
#define EV_STAT_ENABLE 0
#define EV_IDLE_ENABLE 0
#define EV_FORK_ENABLE 0
#define EV_EMBED_ENABLE 0

#include "ev.h"

#define SERVER_GENERIC_OBJECT        \
        ev_io evio;                  \
        ev_timer evtimer;            \
        prelude_io_t *fd;            \
        prelude_msg_t *msg;          \
        int state;                   \
        uint64_t ident;              \
        prelude_connection_permission_t permission; \
        gnutls_alert_description alert; \
        SERVER_SOCKADDR_TYPE sa; \
        server_generic_t *server


typedef struct server_generic server_generic_t;
typedef struct server_generic_client server_generic_client_t;


/*
 * Callback function type for accepting a connection.
 */
typedef int (server_generic_accept_func_t)(server_generic_client_t *client);


/*
 * Callback function type for closing a connection.
 */
typedef int (server_generic_close_func_t)(server_generic_client_t *client);


/*
 * Callback function type for reading a connection.
 */
typedef int (server_generic_read_func_t)(server_generic_client_t *client);


/*
 * Callback function type for writing a connection.
 */
typedef int (server_generic_write_func_t)(server_generic_client_t *client);



server_generic_t *server_generic_new(size_t serverlen,
                                     server_generic_accept_func_t *accept,
                                     server_generic_read_func_t *read,
                                     server_generic_write_func_t *write,
                                     server_generic_close_func_t *close);

int server_generic_bind(server_generic_t *server, const char *addr, unsigned int port);

int server_generic_bind_numeric(server_generic_t *server, struct sockaddr *sa, socklen_t len, unsigned int port);

void server_generic_start(server_generic_t **server, size_t nserver);

void server_generic_destroy(server_generic_t *server);

void server_generic_stop(server_generic_t *server);

int server_generic_process_requests(server_generic_t *server, server_generic_client_t *client);

void server_generic_log_client(server_generic_client_t *cnx, prelude_log_t priority, const char *fmt, ...);

void server_generic_client_set_analyzerid(server_generic_client_t *client, uint64_t analyzerid);

int server_generic_client_set_permission(server_generic_client_t *client, prelude_connection_permission_t permission);

int server_generic_client_get_state(server_generic_client_t *client);

void server_generic_client_set_state(server_generic_client_t *client, int state);

void server_generic_remove_client(server_generic_t *server, server_generic_client_t *client);

void server_generic_notify_event(void);

void server_generic_notify_write_enable(server_generic_client_t *client);

void server_generic_notify_write_disable(server_generic_client_t *client);

#endif /* _MANAGER_SERVER_GENERIC_H */


