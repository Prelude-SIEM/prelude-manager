/*****
*
* Copyright (C) 2002 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <time.h>
#include <sys/time.h>
#include <inttypes.h>
#include <netinet/in.h> /* for extract.h */

#include <libprelude/list.h>
#include <libprelude/prelude-log.h>
#include <libprelude/extract.h>
#include <libprelude/idmef-tree.h>
#include <libprelude/prelude-ident.h>
#include <libprelude/idmef.h>
#include <libprelude/idmef-tree-wrap.h>

#include "config.h"
#include "idmef-util.h"


static prelude_ident_t *alert_ident;
static prelude_ident_t *heartbeat_ident;


int manager_idmef_ident_init(void) 
{
        alert_ident = prelude_ident_new(PRELUDE_MANAGER_CONFDIR"/alert.ident");
        if ( ! alert_ident ) {
                log(LOG_ERR, "couldn't initialize unique alert ident.\n");
                return -1;
        }

        heartbeat_ident = prelude_ident_new(PRELUDE_MANAGER_CONFDIR"/heartbeat.ident");
        if ( ! heartbeat_ident ) {
                log(LOG_ERR, "couldn't initialize unique heartbeat ident.\n");
                return -1;
        }
        
        return 0;
}


void manager_idmef_ident_exit(void) 
{
        prelude_ident_destroy(alert_ident);
        prelude_ident_destroy(heartbeat_ident);        
}


void manager_idmef_alert_get_ident(idmef_alert_t *alert) 
{
	idmef_alert_set_ident(alert, prelude_ident_inc(alert_ident));
}



void manager_idmef_heartbeat_get_ident(idmef_heartbeat_t *heartbeat) 
{
	idmef_heartbeat_set_ident(heartbeat, prelude_ident_inc(heartbeat_ident));
}
