/*****
*
* Copyright (C) 2001, 2002, 2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

#ifndef _MANAGER_IDMEF_MESSAGE_SCHEDULER_H
#define _MANAGER_IDMEF_MESSAGE_SCHEDULER_H

typedef struct idmef_queue idmef_queue_t;

int idmef_message_scheduler_init(void);
void idmef_message_scheduler_exit(void);
int idmef_message_schedule(idmef_queue_t *queue, prelude_msg_t *msg);

idmef_queue_t *idmef_message_scheduler_queue_new(void);
void idmef_message_scheduler_queue_destroy(idmef_queue_t *queue);

#endif /* _MANAGER_IDMEF_MESSAGE_SCHEDULER_H */
