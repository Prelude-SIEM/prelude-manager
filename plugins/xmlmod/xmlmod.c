/*****
*
* Copyright (C) 2001 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
* Written by Yoann Vandoorselaere <yoann@mandrakesoft.com>
*
*****/


#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>

#include "report.h"


#define MAX_ALERT_BY_FILE 1000


static FILE *fd = NULL;
static const char *xmldir = NULL;



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



static FILE *create_xml_document(void)
{
        int ret;
        FILE *fd;
        char buf[1024];
        struct timeval tv;
        
        ret = access(xmldir, F_OK);
        if ( ret < 0 ) {
                ret = create_dir(xmldir);
                if ( ret < 0 )
                        return NULL;
        }
        
        gettimeofday(&tv, NULL);
        snprintf(buf, sizeof(buf), "%s/alert-%ld-%ld.xml", xmldir, tv.tv_sec, tv.tv_usec);

        fd = fopen(buf, "w");
        if ( ! fd ) {
                log(LOG_ERR, "error opening %s\n", buf);
                return NULL;
        }

        return fd;
}


static void do_indent(int space) 
{
        int i;

        for (i = 0; i < space; i++)
                fwrite(" ", 1, 1, fd);
}




static void xml_write(int indent, const char *tag, const char *content, ...) 
{
        do_indent(indent);

        if ( content ) {
                va_list ap;
                
                fwrite("<", 1, 1, fd);
                fwrite(tag, 1, strlen(tag), fd);
                fwrite(">", 1, 1, fd);
                
                va_start(ap, content);
                vfprintf(fd, content, ap);
                va_end(ap);
        }
        
        fwrite("</", 1, 2, fd);
        fwrite(tag, 1, strlen(tag), fd);
        fwrite(">\n", 1, 2, fd);
}




static void xml_start_tag(int indent, const char *tag) 
{
        do_indent(indent);
        
        fwrite("<", 1, 1, fd);
        fwrite(tag, 1, strlen(tag), fd);
        fwrite(">\n", 1, 2, fd);
}



static void xml_end_tag(int indent, const char *tag) 
{
        do_indent(indent);
        
        fwrite("</", 1, 2, fd);
        fwrite(tag, 1, strlen(tag), fd);
        fwrite(">\n", 1, 2, fd);
}



static int create_plugin_infos(alert_t *alert) 
{
        xml_start_tag(4, "plugin infos");
        
        xml_write(6, "name", "%s", plugin_name(alert_plugin(alert)));
        xml_write(6, "author", "%s", plugin_author(alert_plugin(alert)));
        xml_write(6, "contact", "%s", plugin_contact(alert_plugin(alert)));
        xml_write(6, "description", "%s", plugin_desc(alert_plugin(alert)));
        
        xml_end_tag(4, "plugin infos");

        return 0;
}



static int create_alert_infos(alert_t *alert, report_infos_t *rinfos) 
{
        xml_start_tag(4, "alert infos");

        xml_write(6, "kind", "%s", rinfos->kind);
        xml_write(6, "quick description", "%s", alert_quickmsg(alert));
        xml_write(6, "date start", "%s", rinfos->date_start);

        if ( rinfos->date_end )
                xml_write(6, "date end", "%s", rinfos->date_end);

        xml_write(6, "received", "%u", alert_count(alert));
        xml_write(6, "message", "%s", alert_message(alert));

        xml_end_tag(4, "alert infos");
        
        return 0;
}



static int create_packet_infos(report_infos_t *rinfos) 
{
        int i;

        xml_start_tag(4, "packet infos");

        if ( rinfos->sh )
                xml_write(6, "src host", "%s", rinfos->sh);
        else
                xml_write(6, "src host", "N/A");
        
        if ( rinfos->sp )
                xml_write(6, "src port", "%u", rinfos->sp);
        else
                xml_write(6, "src port", "N/A");

        if ( rinfos->dh )
                xml_write(6, "dst host", "%s", rinfos->dh);
        else
                xml_write(6, "dst host", "N/A");
        
        if ( rinfos->dp )
                xml_write(6, "dst port", "%u", rinfos->dp);
        else
                xml_write(6, "dst port", "N/A");

        
        if ( rinfos->pktdump ) {
                for ( i = 0; rinfos->pktdump[i] != NULL; i++ ) 
                        xml_write(6, "content", "%s", rinfos->pktdump[i]);
        }

        if ( rinfos->hexdump ) {
                for ( i = 0; rinfos->hexdump[i] != NULL; i++ )
                        xml_write(6, "hexcontent", "%s", rinfos->hexdump[i]);
        }

        xml_end_tag(4, "packet infos");
        
        return 0;
}



static void xmlmod_run(alert_t *report, report_infos_t *rinfos)
{
        int ret;
        static int count = 0;
        
        if ( ! fd ) {
                if ( ! (fd = create_xml_document() ) )
                        return;

                xml_start_tag(0, "?xml version= \"1.0\" encoding=\"iso-8859-1\" ?");
                xml_start_tag(0, "alerts");
        } else
                fseek(fd, - strlen("</alerts>\n"), SEEK_END);

        xml_start_tag(2, "alert");
        
        ret = create_plugin_infos(report);
        if ( ret < 0 )
                return;

        ret = create_alert_infos(report, rinfos);
        if ( ret < 0 )
                return;

        ret = create_packet_infos(rinfos);
        if ( ret < 0 )
                return;
        
        xml_end_tag(2, "alert");
        xml_end_tag(0, "alerts");
        
        fflush(fd);
        
        if ( ++count == MAX_ALERT_BY_FILE ) {
                fclose(fd);
                count = 0;
                fd = NULL;
        }
}



static plugin_report_t plugin;



static void print_help(const char *optarg) 
{
        fprintf(stderr, "Usage for %s :\n", plugin_name(&plugin));
        fprintf(stderr, "\t -d --xmldir Tell where the XML report should be stored.\n\n");
}



static void set_xmldir(const char *optarg) 
{
        xmldir = strdup(optarg);
}




int plugin_init(unsigned int id)
{
        plugin_option_t opts[] = {
                { "xmldir", required_argument, NULL, 'e', set_xmldir },
                { "help", no_argument, NULL, 'h', print_help         },
                { 0, 0, 0, 0 },
        };
    
        plugin_set_name(&plugin, "XmlMod");        
        plugin_set_author(&plugin, "Yoann Vandoorselaere");
        plugin_set_contact(&plugin, "yoann@mandrakesoft.com");
        plugin_set_desc(&plugin, "Will log all alert to an XML file.");
        plugin_set_running_func(&plugin, xmlmod_run);
        plugin_set_closing_func(&plugin, NULL);

        plugin_config_get((plugin_generic_t *) &plugin, opts, PRELUDE_REPORT_CONF);

        if ( ! xmldir )
                return -1;
        
        return plugin_register((plugin_generic_t *)&plugin);
}




