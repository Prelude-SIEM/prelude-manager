#ifndef _PASSIVE_OS_FINGERPRINT_H
#define _PASSIVE_OS_FINGERPRINT_H

/*****
*
* Copyright (C) 2002, 2003 Laurent Oudot <oudot.laurent@wanadoo.fr>
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


#include <inttypes.h>
#include <sys/types.h>

/* based on ettercap os fingerprint database */
/* WWWW:_MSS:TT:WS:S:N:D:T:F:LN */

#define FINGERPRINT_SIZE	28

typedef struct 
{
	uint16_t win;
	int16_t mss;
        uint8_t	ttl;
	int8_t	wscale;
	uint8_t	sackok;
	uint8_t	nop;
        uint8_t	df;
	uint32_t timestamp;
	uint8_t flags;
	uint16_t len;
} pof_host_data_t;


void passive_os_fingerprint_zero(pof_host_data_t *p);
void passive_os_fingerprint_dump(idmef_alert_t *alert, pof_host_data_t *p);

#endif /* _PASSIVE_OS_FINGERPRINT_H */








