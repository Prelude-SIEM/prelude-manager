/*****
*
* Copyright (C) 1999 Vandoorselaere Yoann
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
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#include <libprelude/plugin-prelude-log.h>

#include "report-infos.h"


static const char *get_cleartext_alert_kind(rkind_t kind) 
{
        switch(kind) {

        case maybe_faked:
                return "Could be faked";

        case maybe_not_reliable:
                return "May not be reliable";

        case normal:
                return "Should be ok";

        case guess:
                abort();
        }

        return "";
}



void report_infos_get(alert_t *alert, report_infos_t *rinfo) 
{
        rinfo->kind = get_cleartext_alert_kind(alert_kind(alert));
        
        rinfo->date_start = strdup(ctime(&alert_time_start(alert)));
        *(rinfo->date_start + strlen(rinfo->date_start) - 1) = 0;
        
        if ( alert_time_end(alert) ) {
                rinfo->date_end = strdup(ctime(&alert_time_end(alert)));
                *(rinfo->date_end + strlen(rinfo->date_end) - 1) = 0;
        } else
                rinfo->date_end = NULL;

        rinfo->sh = rinfo->dh = NULL;
        rinfo->sp = rinfo->dp = 0;
        rinfo->sensor_data = NULL;
}



void report_infos_free(report_infos_t *rinfo) 
{
        int i;

        free(rinfo->date_start);
        if ( rinfo->date_end )
                free(rinfo->date_end);

        if ( rinfo->sh ) 
                free(rinfo->sh);
                
        if ( rinfo->dh )
                free(rinfo->dh);
}

















