/*
 *  Copyright (C) 2000 Yoann Vandoorselaere.
 *
 *  This program is free software; you can redistribute it and/or modify 
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  Authors: Yoann Vandoorselaere <yoann@mandrakesoft.com>
 *
 */
#include <stdio.h>

#include "packet.h"
#include "report.h"
#include "html.h"

#define plural(number) (number > 1) ? "s" : ""


static int offset = 0;



static int start_document(FILE *fd) 
{
        return fprintf(fd,
                       "<html><head></head>\n"
                       "<body bgcolor=\"#fefefe\" link=\"#486591\" vlink=\"#6f6c81\">\n"
                       "<table width=\"800\" align=\"center\" cellpadding=\"0\" cellspacing=\"10\">\n"
                       "<tr><td width=\"50%%\" valign=\"top\">\n");
}



static int end_document(FILE *fd) 
{
        return fprintf(fd, "</td></tr></table></body></html>\n");
}




static int start_table(FILE *fd, const char *name, int col) 
{
        int ret;
        
        ret = fprintf(fd,
                      "<table width=\"800\" bgcolor=\"#000000\" border=\"0\" "
                      "cellpadding=\"1\" cellspacing=\"0\" align=\"center\">\n"
                      "<tr><td>\n"
                      "<table width=\"800\" bgcolor=\"#e6e6e6\" border=\"0\" "
                      "cellpadding=\"2\" cellspacing=\"0\" align=\"center\">\n");

        if ( name ) {
                ret += fprintf(fd, "<tr bgcolor=\"#486591\"><td colspan=\"%d\""
                               "align=\"left\">\n<font color=\"#fefefe\"><b>"
                               "&nbsp;&nbsp;%s&nbsp;&nbsp;</b></font></tr></td>\n"
                               "<tr><td colspan=\"%d\" align=\"center\">&nbsp;</td></tr>\n",
                               col, name, col);
        }
        
        return ret;
}



static int end_table(FILE *fd, int col) 
{
        return fprintf(fd,
                       "<tr><td colspan=\"%d\" align=\"center\">&nbsp;</td></tr>\n"
                       "</table></tr></td></table>\n", col);
}



static void create_link_if_needed(FILE *fd, int pages) 
{
        if ( ! pages ) {
                offset -= fprintf(fd,
                                  "<center>"
                                  "Previous&nbsp;&nbsp;"
                                  "<a href=../%d/index.html>Next</a>&nbsp;&nbsp;"
                                  "<a href=../latest/index.html>Latest</a>"
                                  "</center>", pages + 1);
        } else {
                offset -= fprintf(fd,
                                  "<center>"
                                  "<a href=../%d/index.html>Previous</a>&nbsp;&nbsp;"
                                  "<a href=../%d/index.html>Next</a>&nbsp;&nbsp;"
                                  "<a href=../latest/index.html>Latest</a>"
                                  "</center>", pages - 1, pages + 1);
        }
}



static void write_host_infos(FILE *fd, report_infos_t *rinfo)
{        
        if ( rinfo->sh )
                fprintf(fd, "<td align=\"center\"><a href=http://whois.arin.net/cgi-bin/whois.pl?"
                        "queryinput=%s&B1=Submit><font size=\"-1\">%s</font></a></td>",
                        rinfo->sh, rinfo->sh);
        else
                fprintf(fd, "<td align=\"center\"><font size=\"-1\">N/A</font></td>");
        
        if ( rinfo->sp )
                fprintf(fd, "<td align=\"center\"><font size=\"-1\">%d</font></td>", rinfo->sp);
        else
                fprintf(fd, "<td align=\"center\"><font size=\"-1\">N/A</font></td>");

        fprintf(fd, "<td align=\"center\"><font size=\"-1\">%s</font></td>",
                (rinfo->dh) ? rinfo->dh : "N/A");
        
        if ( rinfo->dp )
                fprintf(fd, "<td align=\"center\"><font size=\"-1\">%d</font></td>", rinfo->dp);
        else
                fprintf(fd, "<td align=\"center\"><font size=\"-1\">N/A</font></td>");
}



void create_host_index(FILE *fd, int pages) 
{
        start_document(fd);

        start_table(fd, NULL, 0);

        fprintf(fd,
                "<tr bgcolor=\"#486591\">\n"
                "<th><font color=\"#fefefe\"><b>&nbsp;&nbsp;Date&nbsp;&nbsp;</b></font></th>\n"
                "<th><font color=\"#fefefe\"><b>&nbsp;&nbsp;Attack&nbsp;&nbsp;</b></font></th>\n"
                "<th><font color=\"#fefefe\"><b>&nbsp;&nbsp;Source Host&nbsp;&nbsp;</b></font></th>\n"
                "<th><font color=\"#fefefe\"><b>&nbsp;&nbsp;Source Port&nbsp;&nbsp;</b></font></th>\n"
                "<th><font color=\"#fefefe\"><b>&nbsp;&nbsp;Target Host&nbsp;&nbsp;</b></font></th>\n"
                "<th><font color=\"#fefefe\"><b>&nbsp;&nbsp;Target Port&nbsp;&nbsp;</b></font></th>\n"
                "</tr>\n");

        offset = 0;
        offset -= end_table(fd, 6);
        create_link_if_needed(fd, pages);
        offset -= end_document(fd);
                
        fflush(fd);
}



void update_host_index(FILE *fd, alert_t *alert,
                       report_infos_t *rinfos, const char *link, int pages)
{
        int ret;
        
        ret = fseek(fd, offset, SEEK_CUR);
        if ( ret < 0 ) {
                log(LOG_ERR, "fseek.\n");
                return;
        }
        
        fprintf(fd, "<tr><td align=\"center\" nowarp><a href=%s><font size=\"-1\" color=\"%s\">%s",
                link, (alert->kind == normal) ? "red" : "black", rinfos->date_start);


        if ( rinfos->date_end )
                fprintf(fd, " - %s", rinfos->date_end);
        
        fprintf(fd, "</font></a></td>\n"
                "<td align=\"center\"><font size=\"-1\">%s</font></td>\n", alert->quickmsg);
        
        write_host_infos(fd, rinfos);

        fprintf(fd, "</tr>\n");
        
        offset = 0;
        
        offset -= end_table(fd, 6);
        create_link_if_needed(fd, pages);
        offset -= end_document(fd);
        fflush(fd);
}



static void output_plugin_infos(FILE *fd, alert_t *alert) 
{
        start_table(fd, "Detection Plugin Information", 2);

        fprintf(fd,
                "<tr><th align=\"left\">Name</th><td><font size=\"-1\">%s</font></td></tr>\n"
                "<tr><th align=\"left\">Author</th><td><font size=\"-1\">%s</font></td></tr>\n"
                "<tr><th align=\"left\">Contact</th><td><font size=\"-1\"><a href=mailto:%s>%s"
                "</a></font></td></tr>\n<tr><th align=\"left\">Description</th><td>"
                "<font size=\"-1\">%s</font></td></tr>\n",
                plugin_name(alert_plugin(alert)), plugin_author(alert_plugin(alert)),
                plugin_contact(alert_plugin(alert)), plugin_contact(alert_plugin(alert)),
                plugin_desc(alert_plugin(alert)));

        end_table(fd, 2);
}



static void output_report_infos(FILE *fd, alert_t *alert, report_infos_t *rinfos) 
{
        start_table(fd, "Report Information", 2);

        fprintf(fd,
                "<tr><th align=\"left\">Quick Description</th><td><font size=\"-1\">%s</font></td></tr>\n"
                "<tr><th align=\"left\">Date</th><td><font size=\"-1\">%s",
                alert->quickmsg, rinfos->date_start);

        if ( rinfos->date_end != 0 )
                fprintf(fd, " - %s", rinfos->date_end);

        fprintf(fd,
                "</font></td></tr>\n"
                "<tr><th align=left>Kind</th><td><font size=\"-1\">%s</font></td></tr>\n"
                "<tr><th align=left>Received</th><td><font size=\"-1\">%d time%s</font></td></tr>\n"
                "<tr><th align=left>Message</th><td><font size=\"-1\">%s</font></td></tr>\n",
                rinfos->kind, alert->count, plural(alert->count), alert->message);

        end_table(fd, 2);
}



static void output_pktdump(FILE *fd, char **pktdump) 
{
        int i;
        
        start_table(fd, "Packet Dump", 1);
        fprintf(fd, "<tr><td colspan=\"1\" align=\"left\"><pre>\n");

        for ( i = 0; pktdump[i] != NULL; i++)
                fprintf(fd, "%s\n", pktdump[i]);
        
        fprintf(fd, "</pre></td></tr>\n");
        end_table(fd, 1);
}



static void output_hexdump(FILE *fd, char **hexdump) 
{
        char c;
        int i, j, index;
        struct {
                char c;
                char *replacement_sequence;
        } *tmp, replacement[] = {
                { '<', "&lt;"  },
                { '>', "&gt;"  },
                { '&', "&amp;" },
                { 0, NULL   },
        };
        
        start_table(fd, "Hexadecimal Dump of data section", 1);
        fprintf(fd, "<tr><td colspan=\"1\" align=\"left\"><pre>\n");
        
        for ( i = 0; hexdump[i] != NULL; i++ ) {
                index = 0;

                /*
                 * Certain character have to be escaped even inside a <pre> tag.
                 *
                 * The code could have been simpler outputing one character a time,
                 * but we try to optimize the number of fprintf() call.
                 */
                for ( j = 0; hexdump[i][j] != '\0'; j++ ) {
                        for (tmp = replacement; tmp->c != 0; tmp++ ) {
                                if ( hexdump[i][j] == tmp->c ) {
                                        c = hexdump[i][j];
                                        hexdump[i][j] = '\0';
                                        fprintf(fd, "%s", hexdump[i] + index);
                                        fprintf(fd, "%s", tmp->replacement_sequence);
                                        hexdump[i][j] = c;
                                        index = j + 1; 
                                }
                        }                        
                }
                fprintf(fd, "%s\n", hexdump[i] + index);
        }
        
        fprintf(fd, "</pre></td></tr>\n");
        end_table(fd, 1);
}




void create_detailled_report(alert_t *alert,
                             report_infos_t *rinfos, const char *filename) 
{
        FILE *fd;
        
        fd = fopen(filename, "w");
        if ( !fd ) {
                log(LOG_ERR, "couldn't open %s.\n", filename);
                return;
        }

        start_document(fd);
        
        output_plugin_infos(fd, alert);
        fprintf(fd, "<br><br>\n");
        
        output_report_infos(fd, alert, rinfos);
        fprintf(fd, "<br><br>\n");
        
        if ( rinfos->pktdump ) {
                output_pktdump(fd, rinfos->pktdump);
                fprintf(fd, "<br><br>\n");
        }
        
        if ( rinfos->hexdump) {
                output_hexdump(fd, rinfos->hexdump);
                fprintf(fd, "<br><br>\n");
        }
        
        end_document(fd);
        fclose(fd);
}

