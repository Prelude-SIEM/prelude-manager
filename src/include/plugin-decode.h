/*****
*
* Copyright (C) 2001 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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

#ifndef PLUGIN_DECODE_H
#define PLUGIN_DECODE_H


typedef struct {
        PLUGIN_GENERIC;
        uint8_t decode_id;
        xmlNodePtr (*run)(alert_container_t *ac);
} plugin_decode_t;


#define plugin_run_func(p) (p)->run

#define plugin_set_running_func(p, f) plugin_run_func(p) = (f)


int plugin_init(unsigned int id);

void decode_plugins_init(const char *dirname);

xmlNodePtr decode_plugins_run(alert_container_t *alert, uint8_t tag);

#endif
