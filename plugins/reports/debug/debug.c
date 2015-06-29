/*****
*
* Copyright (C) 2004-2015 CS-SI. All Rights Reserved.
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

#include "config.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libprelude/idmef.h>
#include <libprelude/idmef-message-print.h>

#include "prelude-manager.h"


int debug_LTX_prelude_plugin_version(void);
int debug_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *data);


typedef struct {
        prelude_list_t list;
        idmef_path_t *path;
} debug_object_t;


typedef struct {
        char *logfile;
        prelude_io_t *fd;
        prelude_list_t path_list;
} debug_plugin_t;


struct iterator_data {
        debug_object_t *object;
        debug_plugin_t *plugin;
};


static int iterator(idmef_value_t *val, void *extra)
{
        int ret;
        prelude_string_t *out;
        struct iterator_data *data = extra;

        ret = prelude_string_new(&out);
        if ( ret < 0 ) {
                prelude_perror(ret, "error creating string object");
                return -1;
        }

        ret = prelude_string_sprintf(out, "%s: ", idmef_path_get_name(data->object->path, -1));
        if ( ret < 0 ) {
                prelude_perror(ret, "error writing string");
                return -1;
        }

        ret = idmef_value_to_string(val, out);
        if ( ret < 0 ) {
                prelude_perror(ret, "error converting generic value to string");
                return -1;
        }

        prelude_string_cat(out, "\n");

        prelude_io_write(data->plugin->fd, prelude_string_get_string(out), prelude_string_get_len(out));
        prelude_string_destroy(out);

        return 0;
}


static int debug_run(prelude_plugin_instance_t *pi, idmef_message_t *msg)
{
        int ret;
        idmef_value_t *val;
        prelude_list_t *tmp;
        debug_object_t *entry;
        struct iterator_data cbdata;
        debug_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        if ( prelude_list_is_empty(&plugin->path_list) ) {
                idmef_message_print(msg, plugin->fd);
                return 0;
        }

        prelude_list_for_each(&plugin->path_list, tmp) {
                entry = prelude_list_entry(tmp, debug_object_t, list);

                ret = idmef_path_get(entry->path, msg, &val);
                if ( ret < 0 ) {
                        prelude_perror(ret, "error getting value for object '%s'", idmef_path_get_name(entry->path, -1));
                        continue;
                }

                if ( ret == 0 )
                        continue; /* no match */

                cbdata.object = entry;
                cbdata.plugin = plugin;

                idmef_value_iterate(val, iterator, &cbdata);
                idmef_value_destroy(val);
        }

        return 0;
}


static void destroy_filter_path(debug_plugin_t *plugin)
{
        debug_object_t *object;
        prelude_list_t *tmp, *bkp;

        prelude_list_for_each_safe(&plugin->path_list, tmp, bkp) {
                object = prelude_list_entry(tmp, debug_object_t, list);

                prelude_list_del(&object->list);
                idmef_path_destroy(object->path);

                free(object);
        }
}


static int set_filter_path(debug_plugin_t *plugin, const char *path)
{
        int ret = 0;
        debug_object_t *elem;
        char *ptr, *start, *dup;

        start = dup = strdup(path);
        if ( ! dup )
                return prelude_error_from_errno(errno);

        destroy_filter_path(plugin);

        while ( (ptr = strsep(&dup, ", \t")) ) {
                if ( *ptr == '\0' )
                        continue;

                elem = malloc(sizeof(*elem));
                if ( ! elem ) {
                        ret = prelude_error_from_errno(errno);
                        break;
                }

                ret = idmef_path_new_fast(&elem->path, ptr);
                if ( ret < 0 ) {
                        free(elem);
                        break;
                }

                prelude_list_add_tail(&plugin->path_list, &elem->list);
        }

        free(start);
        return ret;
}


static int debug_set_object(prelude_option_t *option, const char *arg, prelude_string_t *err, void *context)
{
        debug_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        return set_filter_path(plugin, arg);
}



static int debug_set_logfile(prelude_option_t *option, const char *arg, prelude_string_t *err, void *context)
{
        FILE *fd;
        char *old;
        debug_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);

        if ( strcmp(arg, "-") == 0 )
                fd = stdout;

        else {
                fd = fopen(arg, "a+");
                if ( ! fd ) {
                        prelude_string_sprintf(err, "error opening %s for writing: %s", arg, strerror(errno));
                        return -1;
                }
        }

        old = plugin->logfile;
        plugin->logfile = strdup(arg);
        if ( ! plugin->logfile ) {
                if ( fd != stdout )
                        fclose(fd);

                return prelude_error_from_errno(errno);
        }

        if ( old )
                free(old);

        if ( prelude_io_get_fdptr(plugin->fd) != stdout )
                fclose(prelude_io_get_fdptr(plugin->fd));

        prelude_io_set_file_io(plugin->fd, fd);

        return 0;
}



static int debug_get_logfile(prelude_option_t *opt, prelude_string_t *out, void *context)
{
        debug_plugin_t *plugin;
        plugin = prelude_plugin_instance_get_plugin_data(context);
        return prelude_string_set_ref(out, plugin->logfile);
}



static int debug_new(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        int ret;
        debug_plugin_t *new;

        new = malloc(sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);

        ret = prelude_io_new(&new->fd);
        if ( ret < 0 ) {
                free(new);
                return ret;
        }

        new->logfile = strdup("-");
        if ( ! new->logfile ) {
                prelude_io_destroy(new->fd);
                free(new);
                return prelude_error_from_errno(errno);
        }

        prelude_io_set_file_io(new->fd, stdout);

        prelude_list_init(&new->path_list);
        prelude_plugin_instance_set_plugin_data(context, new);

        return 0;
}



static void debug_destroy(prelude_plugin_instance_t *pi, prelude_string_t *err)
{
        FILE *fd;
        debug_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        fd = prelude_io_get_fdptr(plugin->fd);
        if ( fd != stdout )
                prelude_io_close(plugin->fd);

        prelude_io_destroy(plugin->fd);

        destroy_filter_path(plugin);

        free(plugin->logfile);
        free(plugin);
}



int debug_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *rootopt)
{
        int ret;
        prelude_option_t *opt;
        static manager_report_plugin_t debug_plugin;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;

        ret = prelude_option_add(rootopt, &opt, hook, 0, "debug", "Option for the debug plugin",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, debug_new, NULL);
        if ( ret < 0 )
                return ret;

        prelude_plugin_set_activation_option(pe, opt, NULL);

        ret = prelude_option_add(opt, NULL, hook, 'o', "object",
                                 "Name of IDMEF object to print (no object provided will print the entire message)",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, debug_set_object, NULL);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 'l', "logfile",
                                 "Specify output file to use (default to stdout)",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, debug_set_logfile, debug_get_logfile);
        if ( ret < 0 )
                return ret;

        prelude_plugin_set_name(&debug_plugin, "Debug");
        prelude_plugin_set_destroy_func(&debug_plugin, debug_destroy);
        manager_report_plugin_set_running_func(&debug_plugin, debug_run);

        prelude_plugin_entry_set_plugin(pe, (void *) &debug_plugin);

        return 0;
}



int debug_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}
