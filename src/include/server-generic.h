/*****
*
* Copyright (C) 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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

#include <inttypes.h>


#define SERVER_GENERIC_OBJECT        \
        SERVER_LOGIC_CLIENT_OBJECT;  \
        prelude_msg_t *msg;          \
        int is_authenticated;        \
        int is_ssl;                  \
        char *addr;


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

void server_generic_start(server_generic_t *server);

void server_generic_close(server_generic_t *server);
