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
*****/


#ifndef IDMEF_FUNC_H
#define IDMEF_FUNC_H

/*
 * Functions
 */
idmef_message_t *idmef_alert_new(void);

idmef_message_t *idmef_heartbeat_new(void);

void idmef_message_free(idmef_message_t *msg);

void idmef_additional_data_free(idmef_additional_data_t *data);

idmef_additional_data_t *idmef_additional_data_new(idmef_alert_t *alert);

idmef_source_t *idmef_source_new(idmef_alert_t *alert);

idmef_target_t *idmef_target_new(idmef_alert_t *alert);

idmef_classification_t *idmef_classification_new(idmef_alert_t *alert);

idmef_address_t *idmef_address_new(idmef_node_t *node);

idmef_userid_t *idmef_userid_new(idmef_user_t *user);

const char *idmef_additional_data_type_to_string(idmef_additional_data_type_t type);

const char *idmef_classification_origin_to_string(idmef_classification_origin_t origin);

const char *idmef_address_category_to_string(idmef_address_category_t category);

const char *idmef_node_category_to_string(idmef_node_category_t category);

const char *idmef_user_category_to_string(idmef_user_category_t category);

const char *idmef_userid_type_to_string(idmef_userid_type_t type);

const char *idmef_source_spoofed_to_string(idmef_spoofed_t spoofed);

const char *idmef_target_decoy_to_string(idmef_spoofed_t decoy);

void idmef_get_ntp_timestamp(struct timeval *tv, char *outptr, size_t size);

void idmef_get_timestamp(struct timeval *tv, char *outptr, size_t size);

int idmef_ident_init(void);

void idmef_ident_exit(void);

#endif







