/*****
*
* Copyright (C) 2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

int reverse_relay_tell_receiver_alive(prelude_connection_t *cnx);

int reverse_relay_tell_dead(prelude_connection_t *cnx);

int reverse_relay_add_receiver(prelude_connection_t *cnx);

prelude_connection_t *reverse_relay_search_receiver(const char *addr);

void reverse_relay_send_msg(idmef_message_t *idmef);

int reverse_relay_create_initiator(const char *arg);

int reverse_relay_init_initiator(void);
