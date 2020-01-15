/*****
*
* Copyright (C) 2001-2020 CS-SI. All Rights Reserved.
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
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
*****/

#ifndef _MANAGER_SENSOR_SERVER_H
#define _MANAGER_SENSOR_SERVER_H

#include "idmef-message-scheduler.h"
#include "reverse-relaying.h"


typedef struct {
        prelude_list_t list;
        prelude_msg_t *msg;
        uint32_t write_index;
} sensor_msg_t;



typedef struct {
        SERVER_GENERIC_OBJECT;
        prelude_list_t list;

        idmef_queue_t *queue;
        prelude_connection_t *cnx;
        prelude_bool_t we_connected;
        prelude_list_t write_msg_list;

        uint32_t instance_id;
} sensor_fd_t;


server_generic_t *sensor_server_new(void);

int sensor_server_broadcast_admin_command(uint64_t *analyzerid, prelude_msg_t *msg);

int sensor_server_add_client(server_generic_t *server, server_generic_client_t **client, prelude_connection_t *cnx);

int sensor_server_write_client(server_generic_client_t *dst, prelude_msg_t *msg);

int sensor_server_init(void);

prelude_list_t *sensor_server_get_list(uint64_t analyzerid);

#endif /* _MANAGER_SENSOR_SERVER_H */
