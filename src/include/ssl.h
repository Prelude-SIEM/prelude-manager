/*****
*
* Copyright (C) 1998 - 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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

int ssl_auth_client(int socket);

int ssl_init_server(void);

void ssl_close_session(void);

ssize_t ssl_read(int fd, void *buf, size_t count);

ssize_t ssl_write(int fd, const void *buf, size_t count);

int ssl_create_certificate(config_t *cfg, int crypt_key);

int ssl_register_client(config_t *cfg, int crypt_key);


