/*****
*
* Copyright (C) 1998-2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/time.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#include <libprelude/prelude-message-buffered.h>
#include <libprelude/idmef.h>
#include <libprelude/idmef-message-write.h>
#include <libprelude/prelude-linked-object.h>
#include <libprelude/prelude-log.h>
#include <libprelude/common.h>

#include "plugin-report.h"
#include "plugin-filter.h"
#include "pmsg-to-idmef.h"


#define FAILOVER_RETRY_TIMEOUT 10 * 60
#define REPORT_PLUGIN_FAILOVER MANAGER_FIFO_DIR "/high-priority-fifo"


typedef struct {
        
        prelude_list_t list;

        int failover_enabled;
        struct timeval last_try;
        
        prelude_io_t *failover_fd;
        prelude_plugin_instance_t *pi;

} plugin_failover_t;



static prelude_msgbuf_t *failover_msgbuf = NULL;
static PRELUDE_LIST_HEAD(report_plugins_instance);




static void get_failover_filename(prelude_plugin_instance_t *pi, char *buf, size_t size)
{
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);
        
        snprintf(buf, size, MANAGER_FIFO_DIR "/%s.%s",
                 plugin->name, prelude_plugin_instance_get_name(pi));
}




static prelude_msg_t *write_msgbuf_cb(prelude_msgbuf_t *msgbuf)
{
        prelude_io_t *fd = prelude_msgbuf_get_data(msgbuf);
        prelude_msg_t *msg = prelude_msgbuf_get_msg(msgbuf);

        prelude_msg_write(msg, fd);
        prelude_msg_recycle(msg);
        
        return msg;
}




static int setup_msgbuf_if_needed(void)
{
        if ( failover_msgbuf )
                return 0;
        
        failover_msgbuf = prelude_msgbuf_new(0);
        if ( ! failover_msgbuf )
                return -1;

        prelude_msgbuf_set_callback(failover_msgbuf, write_msgbuf_cb);

        return 0;
}



static int enable_report_plugin_failover(prelude_plugin_instance_t *pi, plugin_failover_t *pf)
{
        int fd, ret;
        char filename[256];
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);
        
        if ( ! prelude_plugin_instance_have_init_func(pi) ) {
                log(LOG_ERR, "plugin %s doesn't support failover.\n", plugin->name);
                return -1;
        }
        
        get_failover_filename(pi, filename, sizeof(filename));
        
        fd = prelude_open_persistant_tmpfile(filename, O_WRONLY|O_APPEND, S_IRUSR|S_IWUSR);
        if ( fd < 0 ) {
                log(LOG_ERR, "couldn't open %s in append mode.\n", filename);
                return -1;
        }
        
        pf->failover_fd = prelude_io_new();
        if ( ! pf->failover_fd ) {
                close(fd);
                return -1;
        }
        
        prelude_io_set_sys_io(pf->failover_fd, fd);

        ret = setup_msgbuf_if_needed();
        if ( ret < 0 ) {
                prelude_io_close(pf->failover_fd);
                prelude_io_destroy(pf->failover_fd);
                return -1;
        }
        
        return 0;
}




static int flush_failed_message(prelude_plugin_instance_t *pi, plugin_failover_t *pf, prelude_io_t *fd)
{
        int ret = 0;
        idmef_message_t *idmef;
        prelude_msg_t *msg = NULL;
        prelude_msg_status_t status;
        
        while ( (status = prelude_msg_read(&msg, fd)) == prelude_msg_finished ) {
                idmef = pmsg_to_idmef(msg);
                if ( ! idmef )
                        return -1;
                
                ret = prelude_plugin_run(pi, plugin_report_t, run, pi, idmef);
                if ( ret < 0 && pf->failover_fd ) {
                        pf->failover_enabled = 1;
                        return -1;
                }

                prelude_msg_destroy(msg);
                msg = NULL;
                
                ret++;
        }

        assert(status == prelude_msg_eof);
        ftruncate(prelude_io_get_fd(pf->failover_fd), 0);
        
        return ret;
}




static int try_recovering_from_failover(prelude_plugin_instance_t *pi, plugin_failover_t *pf)
{
        int ret, fd;
        prelude_io_t *pio;
        char filename[256];
                
        ret = prelude_plugin_instance_call_init_func(pi);
        if ( ret < 0 )
                return -1;
        
        get_failover_filename(pi, filename, sizeof(filename));
        
        fd = open(filename, O_RDONLY);
        if ( fd < 0 ) {
                log(LOG_ERR, "couldn't open %s for reading.\n", filename);
                return -1;
        }
                
        pio = prelude_io_new();
        if ( ! pio )
                return -1;

        prelude_io_set_sys_io(pio, fd);

        ret = flush_failed_message(pi, prelude_plugin_instance_get_private_data(pi), pio);
        
        prelude_io_close(pio);
        prelude_io_destroy(pio);
        
        return ret;
}



static int try_recovering_from_failover_if_needed(prelude_plugin_instance_t *pi, plugin_failover_t *pf)
{
        int elapsed, ret;
        struct timeval now;
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);
        
        gettimeofday(&now, NULL);
        elapsed = now.tv_sec - pf->last_try.tv_sec;
        
        if ( elapsed < FAILOVER_RETRY_TIMEOUT ) 
                return -1;

        ret = try_recovering_from_failover(pi, pf);
        pf->last_try.tv_sec = now.tv_sec;

        if ( ret >= 0 )
                log(LOG_INFO, "- Plugin %s[%s] recovered from failover: %u message flushed.\n",
                    plugin->name, prelude_plugin_instance_get_name(pi), ret);
        
        return (ret < 0) ? -1 : 0;
}



static plugin_failover_t *setup_plugin_failover(prelude_plugin_instance_t *pi)
{
        int ret;
        struct stat st;
        char filename[256];
        plugin_failover_t *new;
        
        new = calloc(1, sizeof(*new));
        if ( ! new ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }

        ret = enable_report_plugin_failover(pi, new);
        if ( ret < 0 ) {
                free(new);
                return NULL;
        }
        
        ret = stat(filename, &st);
        if ( ret == 0 && st.st_size > 0 ) {

                ret = try_recovering_from_failover(pi, new);
                if ( ret < 0 ) {
                        free(new);
                        return NULL;
                }
        }
        
        return new;
}



/*
 *
 */
static int subscribe(prelude_plugin_instance_t *pi) 
{
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);
        
        log(LOG_INFO, "- Subscribing %s[%s] to active reporting plugins.\n",
            plugin->name, prelude_plugin_instance_get_name(pi));

        prelude_plugin_add(pi, &report_plugins_instance, NULL);

        return 0;
}


static void unsubscribe(prelude_plugin_instance_t *pi) 
{
        prelude_plugin_generic_t *plugin = prelude_plugin_instance_get_plugin(pi);
        
        log(LOG_INFO, "- Un-subscribing %s[%s] from active reporting plugins.\n",
            plugin->name, prelude_plugin_instance_get_name(pi));

        prelude_plugin_del(pi);
}



static void failover_write(plugin_failover_t *pf, idmef_message_t *idmef)
{        
        prelude_msgbuf_set_data(failover_msgbuf, pf->failover_fd);
        idmef_write_message(failover_msgbuf, idmef);
        prelude_msgbuf_mark_end(failover_msgbuf);
}



static void failover_init(prelude_plugin_generic_t *pg, prelude_plugin_instance_t *pi, plugin_failover_t *pf)
{
        pf->failover_enabled = 1;
        gettimeofday(&pf->last_try, NULL);
                        
        log(LOG_INFO, "- Plugin %s[%s] failure: enabling failover.\n",
            pg->name, prelude_plugin_instance_get_name(pi));
}




/*
 * Start all plugins of kind 'list'.
 */
void report_plugins_run(idmef_message_t *idmef)
{
        int ret;
        prelude_list_t *tmp;
        plugin_failover_t *pf;
        prelude_plugin_generic_t *pg;
        prelude_plugin_instance_t *pi;
        
        ret = filter_plugins_run_by_category(idmef, FILTER_CATEGORY_REPORTING);
        if ( ret < 0 ) 
                return;
        
        prelude_list_for_each(tmp, &report_plugins_instance) {

                pi = prelude_linked_object_get_object(tmp, prelude_plugin_instance_t);
                pg = prelude_plugin_instance_get_plugin(pi);
                pf = prelude_plugin_instance_get_private_data(pi);
                
                ret = filter_plugins_run_by_plugin(idmef, pi);
                if ( ret < 0 ) 
                        continue;

                if ( pf && pf->failover_enabled ) {
                        ret = try_recovering_from_failover_if_needed(pi, pf);
                        if ( ret == 0 )
                                pf->failover_enabled = 0;
                        else {
                                failover_write(pf, idmef);
                                continue;
                        }
                }
                                        
                ret = prelude_plugin_run(pi, plugin_report_t, run, pi, idmef);
                if ( ret < 0 && pf ) {
                        failover_init(pg, pi, pf);
                        failover_write(pf, idmef);
                }
        }
}




/*
 * Close all report plugins.
 */
void report_plugins_close(void)
{
        prelude_list_t *tmp;
        plugin_report_t *plugin;
        prelude_plugin_instance_t *pi;
                
        prelude_list_for_each(tmp, &report_plugins_instance) {
                pi = prelude_linked_object_get_object(tmp, prelude_plugin_instance_t);
                plugin = (plugin_report_t *) prelude_plugin_instance_get_plugin(pi);
                
                if ( plugin->close )
                        plugin->close(pi);
        }
}



/*
 * Open the plugin directory (dirname),
 * and try to load all plugins located in it.
 */
int report_plugins_init(const char *dirname, int argc, char **argv)
{
        int ret;
        
	ret = access(dirname, F_OK);
	if ( ret < 0 ) {
		if ( errno == ENOENT )
			return 0;
		log(LOG_ERR, "can't access %s.\n", dirname);
		return -1;
	}

        ret = prelude_plugin_load_from_dir(dirname, subscribe, unsubscribe);

        /*
         * don't return an error if the report directory doesn't exist.
         * this could happen as it's normal to not use report plugins on
         * certain system.
         */
        if ( ret < 0 && errno != ENOENT ) {
                log(LOG_ERR, "couldn't load plugin subsystem.\n");
                return -1;
        }
        
        return ret;
}




/**
 * report_plugins_available:
 *
 * Returns: 0 if there is active REPORT plugins, -1 otherwise.
 */
int report_plugins_available(void) 
{
        return prelude_list_empty(&report_plugins_instance) ? -1 : 0;
}



int report_plugin_activate_failover(const char *plugin)
{
        int ret;
        char pname[256], iname[256];
        plugin_failover_t *failover;
        prelude_plugin_instance_t *pi;
        
        ret = sscanf(plugin, "%255[^[][%255[^]]", pname, iname);

        pi = prelude_plugin_search_instance_by_name(pname, (ret == 2) ? iname : NULL);
        if ( ! pi ) {
                log(LOG_ERR, "couldn't find plugin %s.\n", plugin);
                return -1;
        }

        failover = setup_plugin_failover(pi);
        if ( ! failover )
                return -1;

        prelude_plugin_instance_set_private_data(pi, failover);

        return 0;
}




