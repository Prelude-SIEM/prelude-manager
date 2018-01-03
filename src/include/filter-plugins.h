/*****
*
* Copyright (C) 2002-2018 CS-SI. All Rights Reserved.
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

#ifndef _MANAGER_PLUGIN_FILTER_H
#define _MANAGER_PLUGIN_FILTER_H

prelude_bool_t filter_plugins_available(manager_filter_category_t type);

int filter_plugins_init(const char *dirname, void *data);

int filter_plugins_run_by_category(idmef_message_t *msg, manager_filter_category_t cat);

int filter_plugins_run_by_plugin(idmef_message_t *message, prelude_plugin_instance_t *plugin);


#endif /* _MANAGER_PLUGIN_FILTER_H */


