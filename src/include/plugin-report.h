/*****
*
* Copyright (C) 1998 - 2000, 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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

#ifndef PLUGIN_REPORT_H
#define PLUGIN_REPORT_H


#include <libprelude/idmef-tree.h>
#include <libprelude/idmef-tree-func.h>

typedef struct {
        PLUGIN_GENERIC;
        void (*run)(const idmef_message_t *message);
        void (*close)(void);
} plugin_report_t;


#define plugin_run_func(p) (p)->run

#define plugin_close_func(p) (p)->close

#define plugin_set_running_func(p, f) plugin_run_func(p) = (f)

#define plugin_set_closing_func(p, f) plugin_close_func(p) = (f)



int report_plugins_init(const char *dirname, int argc, char **argv);

void report_plugins_run(const idmef_message_t *message);

void report_plugins_close(void);

plugin_generic_t *plugin_init(int argc, char **argv);

#endif
