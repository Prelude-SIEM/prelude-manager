/*****
*
* Copyright (C) 2007-2020 CS-SI. All Rights Reserved.
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

typedef struct bufpool bufpool_t;


void bufpool_destroy(bufpool_t *bp);

int bufpool_new(bufpool_t **bp, const char *filename);

size_t bufpool_get_message_count(bufpool_t *bp);

int bufpool_get_message(bufpool_t *bp, prelude_msg_t **msg);

int bufpool_add_message(bufpool_t *bp, prelude_msg_t *msg);

void bufpool_set_disk_threshold(size_t threshold);

void bufpool_print_stats(void);
