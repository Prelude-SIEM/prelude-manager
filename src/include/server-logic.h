/*****
*
* Copyright (C) 2001 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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

#define SERVER_LOGIC_CLIENT_OBJECT \
        prelude_io_t *fd


typedef struct server_logic server_logic_t;
typedef struct server_logic_client server_logic_client_t;


/*
 * Callback function type for closing a connection.
 */
typedef int (server_logic_close_t)(void *sdata, server_logic_client_t *client);


/*
 * Callback function type for handling data on a connection.
 */
typedef int (server_logic_read_t)(void *sdata, server_logic_client_t *client);


/*
 *
 */
void server_logic_stop(server_logic_t *server);


/*
 *
 */
int server_logic_process_requests(server_logic_t *server, server_logic_client_t *client);


/*
 *
 */
server_logic_t *server_logic_new(void *sdata, server_logic_read_t *s_read, server_logic_close_t *s_close);











