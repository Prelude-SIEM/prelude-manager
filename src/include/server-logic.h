/*****
*
* Copyright (C) 2001, 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
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

#ifndef _MANAGER_SERVER_LOGIC_H
#define _MANAGER_SERVER_LOGIC_H

#include <pthread.h>

#define SERVER_LOGIC_CLIENT_OBJECT \
        prelude_io_t *fd;          \
        int key;                   \
        void *set;                 


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


typedef int (server_logic_write_t)(void *sdata, server_logic_client_t *client);



/*
 *
 */
void server_logic_set_max_connection(server_logic_t *server, unsigned int max);

/*
 *
 */
void server_logic_set_max_fd_by_thread(server_logic_t *server, unsigned int max);

/*
 *
 */
void server_logic_set_min_running_thread(server_logic_t *server, unsigned int min);


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
server_logic_t *server_logic_new(void *sdata, server_logic_read_t *s_read,
                                 server_logic_write_t *s_write, server_logic_close_t *s_close);


/*
 *
 */
int server_logic_remove_client(server_logic_client_t *client);


void server_logic_notify_write_enable(server_logic_client_t *fd);

void server_logic_notify_write_disable(server_logic_client_t *fd);

#endif /* _MANAGER_SERVER_LOGIC_H */







