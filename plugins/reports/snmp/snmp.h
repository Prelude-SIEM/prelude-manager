/*****
*
* Copyright (C) 2016-2020 CS GROUP - France. All Rights Reserved.
* Author: François Poirotte <francois.poirotte@c-s.fr>
* Largely inspired from net-snmp's snmptrap command
* written by the Carnegie Mellon University
*
* This file is part of the Prelude-Manager program.
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
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
*****/

#define STRINGIFY_(x)               #x
#define STRINGIFY(x)                STRINGIFY_(x)

#define SUBOID_CSSI                 14132
#define SUBOID_PRELUDE              17

#define PRELUDE_GENERIC_TRAP        6
#define PRELUDE_TRAPS  "1.3.6.1.4.1." STRINGIFY(SUBOID_CSSI) "." STRINGIFY(SUBOID_PRELUDE) ".2.0."

static oid objid_sysuptime[] = { 1, 3, 6, 1, 2, 1, 1, 3, 0 };
static oid objid_snmptrap[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
static oid objid_traps[] = { 1, 3, 6, 1, 4, 1, SUBOID_CSSI, SUBOID_PRELUDE, 2 };


/*
 * Define the identifier and contents of a trap related to an IDMEF alert.
 */
#define PRELUDE_TRAP_ALERT          1

static oid objid_alert_messageid[] = { 1, 3, 6, 1, 4, 1, SUBOID_CSSI, SUBOID_PRELUDE, 3, 1, 1 };
static oid objid_alert_analyzer_analyzerid[] = { 1, 3, 6, 1, 4, 1, SUBOID_CSSI, SUBOID_PRELUDE, 3, 1, 2, 1 };
static oid objid_alert_classification_text[] = { 1, 3, 6, 1, 4, 1, SUBOID_CSSI, SUBOID_PRELUDE, 3, 1, 4, 2 };
static oid objid_alert_createtime[] = { 1, 3, 6, 1, 4, 1, SUBOID_CSSI, SUBOID_PRELUDE, 3, 1, 3 };
static oid objid_alert_source_node_address_address[] = { 1, 3, 6, 1, 4, 1, SUBOID_CSSI, SUBOID_PRELUDE, 3, 1, 7, 4, 5, 5 };
static oid objid_alert_target_node_address_address[] = { 1, 3, 6, 1, 4, 1, SUBOID_CSSI, SUBOID_PRELUDE, 3, 1, 8, 4, 5, 5 };
static oid objid_alert_assessment_impact_severity[] = { 1, 3, 6, 1, 4, 1, SUBOID_CSSI, SUBOID_PRELUDE, 3, 1, 9, 1, 1 };
