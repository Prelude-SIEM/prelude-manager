/*****
*
* Copyright (C) 2000-2017 CS-SI. All Rights Reserved.
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

#ifndef _MANAGER_PCONFIG_H
#define _MANAGER_PCONFIG_H

#include "server-generic.h"

int manager_options_init(prelude_option_t *manager_root_optlist, int *argc, char **argv);

int manager_options_read(prelude_option_t *manager_root_optlist, int *argc, char **argv);

typedef struct manager_config {

        const char *pidfile;
        const char *config_file;
        const char *tls_options;

        int dh_bits;
        int dh_regenerate;
        int connection_timeout;

        size_t nserver;
        server_generic_t **server;
} manager_config_t;

#endif /* _MANAGER_PCONFIG_H */
