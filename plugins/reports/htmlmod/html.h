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
void create_detailled_report(alert_t *alert,
                             report_infos_t *rinfos, const char *filename);

void update_host_index(FILE *fd, alert_t *alert, report_infos_t *rinfos, const char *link, int pages);

void create_host_index(FILE *fd, int pages);
