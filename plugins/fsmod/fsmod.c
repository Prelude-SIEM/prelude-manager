/*****
*
* Copyright (C) 1998 - 2001 Vandoorselaere Yoann <yoann@mandrakesoft.com>
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
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>

#include <arpa/inet.h>

#include "report.h"



static char *fspath = NULL;


static int write_host_infos(const struct ip *ip, const struct tcphdr *tcp) 
{
        char *ptr;
        char buf[5];
        
        if ( ! ip )
                return -1;
        
        ptr = inet_ntoa(ip->ip_src);
        mkdir(ptr, 0);
        chdir(ptr);
        
        if ( tcp ) {
                snprintf(buf, sizeof(buf), "%d", ntohs(tcp->th_sport));
                ptr = buf;
        } else 
                ptr = "NA";
        
        mkdir(ptr, 0);
        chdir(ptr);
        
        ptr = inet_ntoa(ip->ip_dst);
        mkdir(ptr, 0);
        chdir(ptr);
        
        if ( tcp ) {
                snprintf(buf, sizeof(buf), "%d", ntohs(tcp->th_dport));
                ptr = buf;
        } else 
                ptr = "NA"; 
        
        mkdir(ptr, 0);
        chdir(ptr);

        return 0;
}



static void fs_run(alert_t *alert, report_infos_t *rinfos)
{
        int i;
        struct ip *ip = NULL;
        struct tcphdr *tcp = NULL;
        Packet_t *p = alert->packet;
        static char filename[NAME_MAX];

        for (i = 0; p[i].proto != p_end && (ip == NULL || tcp == NULL); i++) {
                if ( p[i].proto == p_ip )
                        ip = &p[i].p.ip->ip_hdr;

                if ( p[i].proto == p_tcp )
                        tcp = &p[i].p.tcp->tcp_hdr;
        }

        i = write_host_infos(ip, tcp);
        if ( i < 0 )
                return;
        
        snprintf(filename, sizeof(filename), "%ld-%ld", alert->time_start, alert->time_end);
        fclose(fopen(filename, "w"));
        chdir(fspath);
}



static void fs_close(void) 
{
        free(fspath);
}


static void print_help(const char *pname) 
{
        fprintf(stderr, "Usage for %s :\n", pname);
        fprintf(stderr, "\t -e --enable Enable this plugin.\n");
        fprintf(stderr, "\t -f --fs-path (default=disabled) "
                "Path for the filesystem reporting module to report in.\n\n");
}



static int check_opts(char *pname) 
{
        char **argv;
        config_t *cfg;        
        int c, argc, enable = 0;
        struct option opts[] = {
                { "enable", no_argument, NULL, 'e' },
                { "fs-path", required_argument, NULL, 'f' },
                { "help", no_argument, NULL, 'h' },
                { 0, 0, 0, 0 },
        };

        plugin_get_opts(pname, &argc, &argv);
        
        while ( (c = getopt_long(argc, argv, "f:eh", opts, NULL)) != -1 ) {
                switch (c) {
                case 'e':
                        enable = 1;
                        break;
                        
                case 'f':
                        fspath = strdup(optarg);
                        break;

                case 'h':
                        print_help(pname);
                        break;
                        
                default:
                        return -1;
                }
        }

        if ( (! enable || ! fspath ) && (cfg = config_open(PRELUDE_CONF)) ) {
                const char *str;

                if ( ! enable ) {
                        if ( (str = config_get(cfg, pname, "enable")) ) {
                                if ( strcmp(str, "yes") == 0 )
                                        enable = 1;
                        } else {
                                config_close(cfg);
                                return -1;
                        }
                }
                
                if ( ! fspath && (str = config_get(cfg, pname, "fspath") ))
                        fspath = strdup(str);

                config_close(cfg);
        }
        
        return (enable == 1 && fspath) ? 0 : -1;
}



int plugin_init(unsigned int id) {
        int ret;
        static plugin_report_t plugin;
        
        plugin_set_name(&plugin, "FsMod");        
        ret = check_opts(plugin.name);
        if ( ret < 0 )
                return -1;

        ret = chdir(fspath);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't change working directory to %s.\n", fspath);
                free(fspath);
                return -1;
        }

        plugin_set_name(&plugin, "FsMod");
        plugin_set_author(&plugin, "Yoann Vandoorselaere");
        plugin_set_contact(&plugin, "yoann@mandrakesoft.com");
        plugin_set_desc(&plugin, "Use the filesystem as a database to store report.");
        plugin_set_running_func(&plugin, fs_run);
        plugin_set_closing_func(&plugin, fs_close);
        
	plugin_register((plugin_generic_t *)&plugin);

        return 0;
}












