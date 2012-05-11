/*****
*
* Copyright (C) 2004-2012 CS-SI. All Rights Reserved.
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

#ifndef _MANAGER_TLS_AUTH_H
#define _MANAGER_TLS_AUTH_H

#include "server-generic.h"


int manager_auth_disable_encryption(server_generic_client_t *client, prelude_io_t *pio);

int manager_auth_client(server_generic_client_t *client, prelude_io_t *pio, gnutls_alert_description *alert);

int manager_auth_init(prelude_client_t *client, const char *tlsopts, int dh_bits, int dh_regenerate);


#endif /* _MANAGER_TLS_AUTH_H */
