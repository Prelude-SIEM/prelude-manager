/*****
*
* Copyright (C) 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
const char *idmef_additional_data_type_to_string(idmef_additional_data_type_t type);

const char *idmef_classification_origin_to_string(idmef_classification_origin_t origin);

const char *idmef_address_category_to_string(idmef_address_category_t category);

const char *idmef_node_category_to_string(idmef_node_category_t category);

const char *idmef_user_category_to_string(idmef_user_category_t category);

const char *idmef_userid_type_to_string(idmef_userid_type_t type);

const char *idmef_source_spoofed_to_string(idmef_spoofed_t spoofed);

const char *idmef_target_decoy_to_string(idmef_spoofed_t decoy);

int idmef_ident_init(void);

void idmef_ident_exit(void);

void idmef_alert_get_ident(idmef_alert_t *alert);



#define MAX_UTC_DATETIME_SIZE  23   /* YYYY-MM-DDThh:mm:ss.ssZ */
#define MAX_NTP_TIMESTAMP_SIZE 21   /* 0xNNNNNNNN.0xNNNNNNNN   */

void idmef_get_ntp_timestamp(const idmef_time_t *time, char *outptr, size_t size);

void idmef_get_timestamp(const idmef_time_t *time, char *outptr, size_t size);
