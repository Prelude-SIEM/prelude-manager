/*****
*
* Copyright (C) 1998 - 2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

#ifndef _MANAGER_PLUGIN_REPORT_H
#define _MANAGER_PLUGIN_REPORT_H


#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-getopt.h>
#include <libprelude/prelude-plugin.h>


typedef struct {
        PRELUDE_PLUGIN_GENERIC;

        int state;
        const char *bkpfile;
        
        int (*run)(prelude_plugin_instance_t *pi, idmef_message_t *message);
        void (*close)(prelude_plugin_instance_t *pi);
} plugin_report_t;


#define report_plugin_set_running_func(p, f) (p)->run = (f)

#define report_plugin_set_closing_func(p, f) (p)->close = (f)


int report_plugins_available(void);

int report_plugins_init(const char *dirname, int argc, char **argv);

void report_plugins_run(idmef_message_t *message);

void report_plugins_close(void);

#endif /* _MANAGER_PLUGIN_REPORT_H */
