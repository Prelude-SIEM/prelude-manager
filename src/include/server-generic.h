/*****
*
* Copyright (C) 2000-2004 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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

#ifndef _MANAGER_SERVER_GENERIC_H
#define _MANAGER_SERVER_GENERIC_H


#include <inttypes.h>


#define log_client(cnx, args...) do {                                                                    \
        if ( cnx->port )                                                                                 \
               log(LOG_INFO, "[%s:%u, %s:0x%llx] - ", cnx->addr, cnx->port, cnx->client_type, cnx->ident); \
        else                                                                                             \
               log(LOG_INFO, "[unix, %s:0x%llx] - ", cnx->client_type, cnx->ident);                        \
                                                                                                         \
        log(LOG_INFO, args);                                                                             \
} while (0)



#define SERVER_GENERIC_OBJECT        \
        SERVER_LOGIC_CLIENT_OBJECT;  \
        prelude_msg_t *msg;          \
        int is_authenticated;        \
        int is_ssl;                  \
        char *addr;                  \
        uint16_t port;               \
        char *client_type;           \
        uint64_t ident;              \
        prelude_client_t *client


typedef struct server_generic server_generic_t;
typedef struct server_generic_client server_generic_client_t;


/*
 * Callback function type for accepting a connection.
 */
typedef int (server_generic_accept_func_t)(server_generic_client_t *client);


/*
 * Callback function type for closing a connection.
 */
typedef void (server_generic_close_func_t)(server_generic_client_t *client);


/*
 * Callback function type for reading a connection.
 */
typedef int (server_generic_read_func_t)(server_generic_client_t *client);



server_generic_t *server_generic_new(const char *addr, uint16_t port,
                                     size_t serverlen,
                                     server_generic_accept_func_t *accept,
                                     server_generic_read_func_t *read,
                                     server_generic_close_func_t *close);


int server_generic_add_client(server_generic_t *server, prelude_client_t *client);

void server_generic_start(server_generic_t **server, size_t nserver);

void server_generic_close(server_generic_t *server);

void server_generic_stop(server_generic_t *server);

#endif /* _MANAGER_SERVER_GENERIC_H */


