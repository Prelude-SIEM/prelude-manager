/*****
*
* Copyright (C) 2001-2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

#ifndef _MANAGER_PLUGIN_DECODE_H
#define _MANAGER_PLUGIN_DECODE_H


#include <libprelude/prelude-io.h>
#include <libprelude/prelude-msg.h>
#include <libprelude/prelude-option.h>
#include <libprelude/prelude-plugin.h>


typedef struct {
        PRELUDE_PLUGIN_GENERIC;
        uint8_t decode_id;
        int (*run)(prelude_msg_t *ac, idmef_message_t *idmef);
} plugin_decode_t;


#define decode_plugin_set_running_func(p, f) (p)->run = (f)


int decode_plugins_init(const char *dirname, int argc, char **argv);

void decode_plugins_free_data(void);

int decode_plugins_run(uint8_t plugin_id, prelude_msg_t *pmsg, idmef_message_t *idmef);

#endif /* _MANAGER_PLUGIN_DECODE_H */
