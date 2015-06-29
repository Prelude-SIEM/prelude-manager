/*****
*
* Copyright (C) 2004-2015 CS-SI. All Rights Reserved.
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

#ifndef _MANAGER_REVERSE_RELAYING_H
#define _MANAGER_REVERSE_RELAYING_H

#include "server-generic.h"

typedef struct reverse_relay_receiver reverse_relay_receiver_t;


void reverse_relay_set_receiver_dead(reverse_relay_receiver_t *rrr);

int reverse_relay_set_receiver_alive(reverse_relay_receiver_t *rrr, server_generic_client_t *client);

int reverse_relay_new_receiver(reverse_relay_receiver_t **rrr, server_generic_client_t *client, uint64_t analyzerid);

reverse_relay_receiver_t *reverse_relay_search_receiver(uint64_t analyzerid);

void reverse_relay_send_prepared(void);

void reverse_relay_send_receiver(idmef_message_t *idmef);

int reverse_relay_set_initiator_dead(prelude_connection_t *cnx);

int reverse_relay_create_initiator(const char *arg);

int reverse_relay_init(void);

#endif
