/*****
*
* Copyright (C) 1998 - 2000 Vandoorselaere Yoann <yoann@mandrakesoft.com>
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
#include <stdarg.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <dirent.h>

#include "config.h"
#include "report.h"
#include "html.h"


/*
 * Html in C is really... dirty ?
 * Generated html is inspired from PhpSys html output.
 */


static char *htmldir = NULL;
static char htmldoc[PATH_MAX], htmldocdir[PATH_MAX];
static char latest[PATH_MAX];
static FILE *fd = NULL;
static long pages = 0;



static int create_dir(const char *dirname) 
{
        int ret;
        
        ret = mkdir(dirname, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH);
        if ( ret < 0 && errno != EEXIST ) {
                log(LOG_ERR, "couldn't create %s\n", dirname);
                return -1;
        }
        
        return 0;
}



static FILE *setup_htmldoc(void) 
{
        int ret;
        FILE *fd;
        
        ret = access(htmldir, F_OK);
        if ( ret < 0 ) {
                pages = -1;
                ret = create_dir(htmldir);
                if ( ret < 0 )
                        return NULL;
        }

        snprintf(htmldocdir, sizeof(htmldocdir), "%s/%ld", htmldir, ++pages);
        ret = create_dir(htmldocdir);
        if ( ret < 0 ) 
                goto err;
        
        if ( pages > 0 && unlink(latest) < 0 ) {
                log(LOG_ERR, "couldn't delete %s\n", latest);
                goto err;
        }
        
        ret = symlink(htmldocdir, latest);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't create link %s -> %s\n", latest, htmldocdir);
                goto err;
        }

        snprintf(htmldoc, sizeof(htmldoc), "%s/index.html", htmldocdir);
        fd = fopen(htmldoc, "w");
        if ( ! fd ) {
                log(LOG_ERR, "error opening %s\n", htmldoc);
                goto err;
        }

        create_host_index(fd, pages);
        
        return fd;

 err:
        pages--;
        return NULL;
}




static void html_run(alert_t *alert, report_infos_t *rinfos) 
{
        static int i = 0;
        struct timeval tv;
        char buf[PATH_MAX];

        if ( ! fd && !(fd = setup_htmldoc()) ) 
                return;
        
        /*
         * Fd could be NULL in case there is no more
         * free space on the hard disk.
         */ 
        if ( i++ == 100 ) {
                i = 0;      
                fclose(fd);
                fd = setup_htmldoc();
                if ( ! fd ) 
                        return;
        }

        gettimeofday(&tv, NULL);
        snprintf(buf, sizeof(buf), "%s/%ld-%ld.html", htmldocdir, tv.tv_sec, tv.tv_usec);
        create_detailled_report(alert, rinfos, buf);

        snprintf(buf, sizeof(buf), "../%ld/%ld-%ld.html", pages, tv.tv_sec, tv.tv_usec);
        update_host_index(fd, alert, rinfos, buf, pages);
}



static void html_close(void) 
{
        free(htmldir);
        if ( fd )
                fclose(fd);
}



static plugin_report_t plugin;



static void print_help(const char *optarg) 
{
        fprintf(stderr, "Usage for %s :\n", plugin_name(&plugin));
        fprintf(stderr, "\t-d --htmldir Tell where the html report should be stored.\n\n");
}



static void set_htmldir(const char *optarg) 
{
        htmldir = strdup(optarg);
}



int plugin_init(unsigned int id)
{
        int ret;
        char buf[PATH_MAX];
        plugin_option_t opts[] = {
                { "htmldir", required_argument, NULL, 'd', set_htmldir },
                { "help", no_argument, NULL, 'h', print_help           },
                { 0, 0, 0, 0 },
        };

        plugin_set_name(&plugin, "HtmlMod");
        plugin_set_author(&plugin, "Yoann Vandoorselaere");
        plugin_set_contact(&plugin, "yoann@mandrakesoft.com");
        plugin_set_desc(&plugin, "This plugin issue HTML report");
        plugin_set_running_func(&plugin, html_run);
        plugin_set_closing_func(&plugin, html_close);

        plugin_config_get((plugin_generic_t *)&plugin, opts, PRELUDE_REPORT_CONF);

        if ( ! htmldir )
                return -1;
        
        snprintf(latest, sizeof(latest), "%s/latest", htmldir);

        ret = readlink(latest, buf, sizeof(buf));
        if ( ret > 0 ) {
                char *ptr;
                
                buf[ret] = '\0';
                ptr = strrchr(buf, '/');
                if ( ! ptr ) {
                        log(LOG_ERR, "couldn't find trailling / in %s.\n", buf);
                        return -1;
                }
                
                pages = atoi(ptr + 1);
        }

        /*
         * create default page if symlink does not exist.
         */
        else if ( ret < 0 ) {
                                                
                if ( errno == ENOENT ) {
                        if ( ! (fd = setup_htmldoc()) )
                                return -1;
                } else 
                        return -1;
        }
        
	return plugin_register((plugin_generic_t *)&plugin);
}












