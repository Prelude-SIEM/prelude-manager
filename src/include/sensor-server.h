/*****
*
* Copyright (C) 2001, 2002 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

#ifndef _MANAGER_SENSOR_SERVER_H
#define _MANAGER_SENSOR_SERVER_H

void sensor_server_close(server_generic_t *server);

server_generic_t *sensor_server_new(const char *addr, uint16_t port);

int sensor_server_broadcast_admin_command(uint64_t *analyzerid, prelude_msg_t *msg);

#endif /* _MANAGER_SENSOR_SERVER_H */
