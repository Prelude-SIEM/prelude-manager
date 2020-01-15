/*****
*
* Copyright (C) 2004-2020 CS-SI. All Rights Reserved.
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

#ifndef _MANAGER_TLS_AUTH_H
#define _MANAGER_TLS_AUTH_H

#include "server-generic.h"


int manager_auth_disable_encryption(server_generic_client_t *client, prelude_io_t *pio);

int manager_auth_client(server_generic_client_t *client, prelude_io_t *pio, gnutls_alert_description_t *alert);

int manager_auth_init(prelude_client_t *client, const char *tlsopts, int dh_bits, int dh_regenerate);


#endif /* _MANAGER_TLS_AUTH_H */
