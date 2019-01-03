/*****
*
* Copyright (C) 2001-2019 CS-SI. All Rights Reserved.
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

#ifndef _MANAGER_IDMEF_MESSAGE_SCHEDULER_H
#define _MANAGER_IDMEF_MESSAGE_SCHEDULER_H

typedef struct idmef_queue idmef_queue_t;

int idmef_message_scheduler_init(void);
void idmef_message_scheduler_exit(void);

int idmef_message_schedule(idmef_queue_t *queue, prelude_msg_t *msg);

void idmef_message_process(idmef_message_t *idmef);

idmef_queue_t *idmef_message_scheduler_queue_new(prelude_client_t *client);

void idmef_message_scheduler_queue_destroy(idmef_queue_t *queue);


void idmef_message_scheduler_stop_processing(void);

void idmef_message_scheduler_start_processing(void);

void idmef_message_scheduler_set_priority(unsigned int high, unsigned int medium, unsigned int low);

#endif /* _MANAGER_IDMEF_MESSAGE_SCHEDULER_H */
