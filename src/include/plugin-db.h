/*****
*
* Copyright (C) 2001, 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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

#ifndef PLUGIN_DB_H
#define PLUGIN_DB_H

#define DB_INSERT_END ((void *)0x1)

typedef struct {
        PLUGIN_GENERIC;
        char *(*db_escape)(const char *input);
        int (*db_insert)(const char *table, const char *fields, const char *value);
        void (*close)(void);
} plugin_db_t;

#define plugin_escape_func(p) (p)->db_escape

#define plugin_insert_func(p) (p)->db_insert

#define plugin_close_func(p) (p)->close


#define plugin_set_escape_func(p, f) plugin_escape_func(p) = (f)

#define plugin_set_insert_func(p, f) plugin_insert_func(p) = (f)

#define plugin_set_closing_func(p, f) plugin_close_func(p) = (f)



int db_plugins_init(const char *dirname, int argc, char **argv);


char *db_plugin_escape(const char *string);

void db_plugin_insert(const char *table, const char *fields, const char *fmt, ...);

void db_plugins_run(idmef_message_t *idmef);

void db_plugins_close(void);

plugin_generic_t *plugin_init(int argc, char **argv);

#endif




