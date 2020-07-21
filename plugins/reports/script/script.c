/*****
*
* Copyright (C) 2018-2020 CS-SI. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoannv@gmail.com>
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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>

#include "prelude-manager.h"


int script_LTX_prelude_plugin_version(void);
int script_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *data);


#define SCRIPT_ARG_ID_PATH   0
#define SCRIPT_ARG_ID_STRING 1


typedef struct {
        PRELUDE_LINKED_OBJECT;
        idmef_path_t *path;
} script_arg_t;


typedef struct {
        size_t argno;
        prelude_list_t arglist;
} script_plugin_t;



static char *empty_const = "";



static int do_exec(char * const *argv)
{
        int ret;
        char *envp[] = { NULL };

        pid_t pid = fork();
        if ( pid < 0 )
                prelude_log(PRELUDE_LOG_ERR, "error forking process for '%s' execution: %s\n", argv[0], strerror(errno));

        else if ( pid > 0 )
                return 0;

        ret = execve(argv[0], argv, envp);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error executing '%s': %s\n", argv[0], strerror(errno));
                exit(1);
        }

        return 1; /* This point is never reached */
}


static int script_arg_resolve(script_arg_t *obj, idmef_message_t *msg, char **out)
{
        int ret;
        prelude_string_t *str;
        idmef_value_t *value = NULL;

        ret = idmef_path_get(obj->path, msg, &value);
        if ( ret <= 0 )
                return ret;

        ret = prelude_string_new(&str);
        if ( ret < 0 ) {
                idmef_value_destroy(value);
                return ret;
        }

        ret = idmef_value_to_string(value, str);
        if ( ret < 0 )
                goto error;

        ret = prelude_string_get_string_released(str, out);
        if ( ret < 0 )
                goto error;

    error:
        idmef_value_destroy(value);
        prelude_string_destroy(str);

        return ret;
}



static int make_argv(script_plugin_t *plugin, idmef_message_t *msg, char ***out)
{
        int ret = 0;
        size_t n = 0;
        char **argv;
        prelude_list_t *tmp;
        prelude_linked_object_t *obj;
        prelude_string_t *tmpstr;

        *out = argv = calloc(sizeof(*argv), plugin->argno + 1);
        if ( ! argv ) {
                prelude_log(PRELUDE_LOG_ERR, "memory exhausted\n");
                return -1;
        }

        prelude_list_for_each(&plugin->arglist, tmp) {
                obj = prelude_linked_object_get_object(tmp);

                argv[n] = empty_const;
                if ( prelude_linked_object_get_id(obj) == SCRIPT_ARG_ID_PATH )
                        ret = script_arg_resolve((script_arg_t *) obj, msg, &argv[n]);

                else if ( prelude_string_get_len((prelude_string_t *) obj) ) {
                        ret = prelude_string_clone((prelude_string_t *) obj, &tmpstr);
                        if ( ret < 0 )
                                return ret;

                        ret = prelude_string_get_string_released(tmpstr, &argv[n]);
                        prelude_string_destroy(tmpstr);
                }

                if ( ret < 0 )
                        return ret;

                n++;
        }

        return ret;
}



static int script_run(prelude_plugin_instance_t *pi, idmef_message_t *msg)
{
        int ret;
        size_t i;
        char **argv, *ptr;
        script_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        ret = make_argv(plugin, msg, &argv);
        if ( ret < 0 )
                prelude_log(PRELUDE_LOG_ERR, "error formatting arguments: %s\n", prelude_strerror(ret));
        else
                do_exec(argv);

        for ( i = 0; i <= plugin->argno; i++ ) {
                ptr = argv[i];
                if  ( ptr && ptr != empty_const )
                        free(ptr);
        }

        free(argv);
        return 0;
}


static int script_arg_add(script_plugin_t *plugin, const char *path)
{
        int ret;
        script_arg_t *new;

        new = malloc(sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);

        ret = idmef_path_new_fast(&new->path, path);
        if ( ret < 0 )
                return ret;

        prelude_linked_object_set_id((prelude_linked_object_t *) new, SCRIPT_ARG_ID_PATH);
        prelude_linked_object_add_tail(&plugin->arglist, (prelude_linked_object_t *) new);

        return 0;
}


static void script_arg_destroy(script_arg_t *object)
{
        prelude_linked_object_del((prelude_linked_object_t *) object);
        idmef_path_destroy(object->path);
        free(object);
}



static int script_set_command(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        int ret;
        const char *ptr;
        prelude_string_t *s;
        script_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);

        while ( (ptr = strsep((char **) &optarg, " ")) ) {
                plugin->argno++;

                if ( *ptr == '$' ) {
                        ret = script_arg_add(plugin, ptr + 1);
                        if ( ret < 0 )
                                return ret;

                        continue;
                }

                ret = prelude_string_new_dup(&s, ptr);
                if ( ret < 0 )
                        return ret;

                prelude_linked_object_set_id((prelude_linked_object_t *) s, SCRIPT_ARG_ID_STRING);
                prelude_linked_object_add_tail(&plugin->arglist, (prelude_linked_object_t *) s);
        }

        return 0;
}



static int script_new(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        int ret;
        script_plugin_t *new;
        struct sigaction sa;

        sa.sa_handler = SIG_IGN;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;

        ret = sigaction(SIGCHLD, &sa, 0);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error calling sigaction: %s\n", strerror(errno));
                return -1;
        }

        new = calloc(1, sizeof(*new));
        if ( ! new )
                return prelude_error_from_errno(errno);

        prelude_list_init(&new->arglist);
        prelude_plugin_instance_set_plugin_data(context, new);
        return 0;
}



static void script_destroy(prelude_plugin_instance_t *pi, prelude_string_t *err)
{
        prelude_list_t *tmp, *bkp;
        prelude_linked_object_t *obj;
        script_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        prelude_list_for_each_safe(&plugin->arglist, tmp, bkp) {
                obj = prelude_linked_object_get_object(tmp);

                if ( prelude_linked_object_get_id(obj) == SCRIPT_ARG_ID_PATH )
                        script_arg_destroy((script_arg_t *) obj);
                else
                        prelude_string_destroy((prelude_string_t *) obj);
        }

        free(plugin);
}



int script_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *rootopt)
{
        int ret;
        prelude_option_t *opt;
        static manager_report_plugin_t script_plugin;
        int hook = PRELUDE_OPTION_TYPE_CFG;

        ret = prelude_option_add(rootopt, &opt, PRELUDE_OPTION_TYPE_CFG, 0, "script", "Option for the script plugin",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, script_new, NULL);
        if ( ret < 0 )
                return ret;

        prelude_plugin_set_activation_option(pe, opt, NULL);

        ret = prelude_option_add(opt, NULL, hook, 0, "command",
                                 "Command line to use for the script",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, script_set_command, NULL);
        if ( ret < 0 )
                return ret;

        prelude_plugin_set_name(&script_plugin, "Script");
        prelude_plugin_set_destroy_func(&script_plugin, script_destroy);
        manager_report_plugin_set_running_func(&script_plugin, script_run);

        prelude_plugin_entry_set_plugin(pe, (void *) &script_plugin);

        return 0;
}



int script_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}
