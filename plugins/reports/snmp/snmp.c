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

#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-timer.h>
#include <libprelude/idmef-message-print.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include "prelude-manager.h"
#include "snmp.h"

#define SNMP_AGENT_NAME             "prelude-manager"


int snmp_LTX_prelude_plugin_version(void);
int snmp_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *data);
static int snmp_input(int operation, netsnmp_session * session, int reqid, netsnmp_pdu *pdu, void *magic);


typedef struct {
        netsnmp_session session;
#ifdef NETSNMP_SECMOD_USM
        char *auth_key;
        char *priv_key;
#endif
} snmp_plugin_t;

/*
 * The following definitions match their respective counterparts
 * from the netsnmp_session structure defined in net-snmp/types.h.
 */
typedef struct {
        char *label;
        long version;
} snmp_plugin_version_t;

typedef struct {
        char *label;
        int level;
} snmp_plugin_security_level_t;

/*
 * Used for both authentication and privacy protocols.
 */
typedef struct {
        char *label;
        oid *protocol;
        size_t length;
} snmp_plugin_protocol_t;

#ifdef NETSNMP_SECMOD_USM
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(snmp, snmp_plugin_t, auth_key);
PRELUDE_PLUGIN_OPTION_DECLARE_STRING_CB(snmp, snmp_plugin_t, priv_key);
#endif


static int snmp_set_traphost(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        snmp_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);

        plugin->session.peername = strdup(optarg);
        if ( ! plugin->session.peername )
                return prelude_error_from_errno(errno);
        return 0;
}


static int snmp_set_version(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        snmp_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        snmp_plugin_version_t versions[] = {
#ifndef NETSNMP_DISABLE_SNMPV1
                {"v1", SNMP_VERSION_1},
                {"1", SNMP_VERSION_1},
#endif

#ifndef NETSNMP_DISABLE_SNMPV2C
                {"v2c", SNMP_VERSION_2c},
                {"v2", SNMP_VERSION_2c},
                {"2", SNMP_VERSION_2c},
#endif

                {"v3", SNMP_VERSION_3},
                {"3", SNMP_VERSION_3},

                {NULL, 0},
        };
        int i;

        for ( i = 0; versions[i].label != NULL; i++ ) {
                if ( strcasecmp(optarg, versions[i].label) == 0 ) {
                        plugin->session.version = versions[i].version;
                        return 0;
                }
        }

        return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Invalid version specified");
}


static int snmp_set_community(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        snmp_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);

        plugin->session.community = (unsigned char *) strdup(optarg);
        if ( ! plugin->session.community )
                return prelude_error_from_errno(errno);
        return 0;
}


static int snmp_set_security_level(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        snmp_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        snmp_plugin_security_level_t levels[] = {
                {"noAuthNoPriv", SNMP_SEC_LEVEL_NOAUTH},
                {"noauth", SNMP_SEC_LEVEL_NOAUTH},
                {"1", SNMP_SEC_LEVEL_NOAUTH},

                {"authNoPriv", SNMP_SEC_LEVEL_AUTHNOPRIV},
                {"auth", SNMP_SEC_LEVEL_AUTHNOPRIV},
                {"2", SNMP_SEC_LEVEL_AUTHNOPRIV},

                {"authPriv", SNMP_SEC_LEVEL_AUTHPRIV},
                {"priv", SNMP_SEC_LEVEL_AUTHPRIV},
                {"3", SNMP_SEC_LEVEL_AUTHPRIV},

                {NULL, 0},
        };
        int i;

        for ( i = 0; levels[i].label != NULL; i++ ) {
                if ( strcasecmp(optarg, levels[i].label) == 0 ) {
                        plugin->session.securityLevel = levels[i].level;
                        return 0;
                }
        }

        return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Invalid security level specified");
}


static int snmp_set_security_name(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        snmp_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);

        plugin->session.securityName = strdup(optarg);
        if ( ! plugin->session.securityName )
                return prelude_error_from_errno(errno);

        plugin->session.securityNameLen = strlen(optarg);
        return 0;
}


#ifdef NETSNMP_SECMOD_USM
static int snmp_set_auth_proto(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        snmp_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        snmp_plugin_protocol_t protocols[] = {
#ifndef NETSNMP_DISABLE_MD5
                {"MD5", usmHMACMD5AuthProtocol, USM_AUTH_PROTO_MD5_LEN},
#endif
                {"SHA1", usmHMACSHA1AuthProtocol, USM_AUTH_PROTO_SHA_LEN},
                {"SHA", usmHMACSHA1AuthProtocol, USM_AUTH_PROTO_SHA_LEN},
                {NULL, NULL, 0},
        };
        int i;

        for ( i = 0; protocols[i].label != NULL; i++ ) {
                if ( strcasecmp(optarg, protocols[i].label) == 0 ) {
                        plugin->session.securityAuthProto = protocols[i].protocol;
                        plugin->session.securityAuthProtoLen = protocols[i].length;
                        return 0;
                }
        }

        return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Invalid authentication protocol specified");
}


static int snmp_set_priv_proto(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        snmp_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);
        snmp_plugin_protocol_t protocols[] = {
#ifndef NETSNMP_DISABLE_DES
                {"DES", usmDESPrivProtocol, USM_PRIV_PROTO_DES_LEN},
#endif
#ifdef HAVE_AES
                {"AES128", usmAESPrivProtocol, USM_PRIV_PROTO_AES_LEN},
                {"AES", usmAESPrivProtocol, USM_PRIV_PROTO_AES_LEN},
#endif
                {NULL, NULL, 0},
        };
        int i;

        for ( i = 0; protocols[i].label != NULL; i++ ) {
                if ( strcasecmp(optarg, protocols[i].label) == 0 ) {
                        plugin->session.securityPrivProto = protocols[i].protocol;
                        plugin->session.securityPrivProtoLen = protocols[i].length;
                        return 0;
                }
        }

        return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Invalid privacy protocol specified");
}
#endif /* NETSNMP_SECMOD_USM */


static int snmp_set_engineid(prelude_option_t *opt, const char *optarg, prelude_string_t *err, void *context)
{
        unsigned char *buf;
        size_t buf_len = 32, buf_offset = 0;
        snmp_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(context);

        buf = (unsigned char *) malloc(buf_len);
        if ( ! buf )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Could not allocate memory for engine ID");

        if ( plugin->session.securityEngineID ) {
                free(plugin->session.securityEngineID);
                plugin->session.securityEngineID = NULL;
        }

        if ( ! snmp_hex_to_binary(&buf, &buf_len, &buf_offset, 1, optarg) ) {
                free(buf);
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Could not parse engine ID value");
        }

        /*
         * The engine identifier must be 5-32 characters long,
         * as per the definition of SnmpEngineID in RFC 3411.
         */
        if ( buf_offset < 5 || buf_offset > 32 ) {
                free(buf);
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Invalid engine ID value");
        }

        plugin->session.securityEngineID = buf;
        plugin->session.securityEngineIDLen = buf_offset;

        return 0;
}


static int snmp_init_default_version(netsnmp_session *session)
{
        if ( session->version != SNMP_DEFAULT_VERSION ) {
#ifndef NETSNMP_DISABLE_SNMPV1
                if (session->version == NETSNMP_DS_SNMP_VERSION_1)  /* bogus value.  version 1 is actually = 0 */
                    session->version = SNMP_VERSION_1;
#endif

                return 0;
        }

        /*
         * run time default version
         */
        session->version = netsnmp_ds_get_int(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_SNMPVERSION);

        /*
         * compile time default version
         */
        if ( !session->version ) {
                switch ( NETSNMP_DEFAULT_SNMP_VERSION ) {
#ifndef NETSNMP_DISABLE_SNMPV1
                case 1:
                        session->version = SNMP_VERSION_1;
                        break;
#endif

#ifndef NETSNMP_DISABLE_SNMPV2C
                case 2:
                        session->version = SNMP_VERSION_2c;
                        break;
#endif

                case 3:
                        session->version = SNMP_VERSION_3;
                        break;

                default:
                        return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Invalid protocol version");
                }
        }

        return 0;
}


static int snmp_init_default_community(netsnmp_session *session)
{
#if !defined(NETSNMP_DISABLE_SNMPV1) || !defined(NETSNMP_DISABLE_SNMPV2C)
        /*
         * If v1 or v2c, check whether a community has been set.
         * Take it from the default configuration if necessary.
         */

        if ( session->community )
                return 0;

#if defined(NETSNMP_DISABLE_SNMPV1)
        if ( session->version == SNMP_VERSION_2c )
#else
#if defined(NETSNMP_DISABLE_SNMPV2C)
        if ( session->version == SNMP_VERSION_1 )
#else
        if ( session->version == SNMP_VERSION_1 || session->version == SNMP_VERSION_2c )
#endif
#endif
        {
                session->community = (unsigned char *) netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_COMMUNITY);

                if ( ! session->community ) {
                        if ( netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_IGNORE_NO_COMMUNITY) ) {
                                session->community = (unsigned char *) NULL;
                                session->community_len = 0;
                        } else {
                                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: No community name specified");
                        }
                }

                if ( session->community )
                        session->community_len = strlen((char *) session->community);
        }
#endif

        return 0;
}


static int snmp_init(prelude_plugin_instance_t *pi, prelude_string_t *out)
{
        snmp_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);
        netsnmp_session *session = &plugin->session;
        char engineid[SNMP_MAXBUF];
        const oid *def;
        int ret;

        if ( ! session->peername || *session->peername == '\0' )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: No trap recipient specified");

        ret = snmp_init_default_version(session);
        if ( ret != 0 )
                return ret;

#ifdef NETSNMP_SECMOD_USM
        if ( plugin->auth_key ) {
                session->securityAuthKeyLen = USM_AUTH_KU_LEN;
                if ( ! session->securityAuthProto ) {
                        /*
                         * get .conf set default
                         */
                        def = get_default_authtype(&session->securityAuthProtoLen);
                        session->securityAuthProto = snmp_duplicate_objid(def, session->securityAuthProtoLen);
                }

                if ( ! session->securityAuthProto ) {
#ifndef NETSNMP_DISABLE_MD5
                        /*
                         * assume MD5
                         */
                        session->securityAuthProto = snmp_duplicate_objid(usmHMACMD5AuthProtocol, USM_AUTH_PROTO_MD5_LEN);
                        session->securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
#else
                        session->securityAuthProto = snmp_duplicate_objid(usmHMACSHA1AuthProtocol, USM_AUTH_PROTO_SHA_LEN);
                        session->securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
#endif
                }
                if ( generate_Ku(session->securityAuthProto,
                                 session->securityAuthProtoLen,
                                 (u_char *) plugin->auth_key, strlen(plugin->auth_key),
                                 session->securityAuthKey,
                                 &session->securityAuthKeyLen) != SNMPERR_SUCCESS ) {
                        return prelude_error_verbose(PRELUDE_ERROR_GENERIC,
                                "SNMP: Error generating a key from the supplied authentication passphrase");
                }
        }

        if ( plugin->priv_key ) {
                session->securityPrivKeyLen = USM_PRIV_KU_LEN;
                if ( ! session->securityPrivProto ) {
                        /*
                         * get .conf set default
                         */
                        def = get_default_privtype(&session->securityPrivProtoLen);
                        session->securityPrivProto = snmp_duplicate_objid(def, session->securityPrivProtoLen);
                }
                if ( ! session->securityPrivProto ) {
                        /*
                         * assume DES
                         */
#ifndef NETSNMP_DISABLE_DES
                        session->securityPrivProto = snmp_duplicate_objid(usmDESPrivProtocol, USM_PRIV_PROTO_DES_LEN);
                        session->securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
#else
                        session->securityPrivProto = snmp_duplicate_objid(usmAESPrivProtocol, USM_PRIV_PROTO_AES_LEN);
                        session->securityPrivProtoLen = USM_PRIV_PROTO_AES_LEN;
#endif
                }

                if ( generate_Ku(session->securityAuthProto,
                                 session->securityAuthProtoLen,
                                 (u_char *) plugin->priv_key, strlen(plugin->priv_key),
                                 session->securityPrivKey,
                                 &session->securityPrivKeyLen) != SNMPERR_SUCCESS ) {
                        return prelude_error_verbose(PRELUDE_ERROR_GENERIC,
                                "SNMP: Error generating a key from the supplied privacy passphrase");
                }
        }
#endif /* NETSNMP_SECMOD_USM */

        ret = snmp_init_default_community(session);
        if ( ret != 0 )
                return ret;

        if ( ! session->contextEngineIDLen || ! session->contextEngineID )
                session->contextEngineID = snmpv3_generate_engineID(&session->contextEngineIDLen);

        /*
         * Convert the engine IDs to a printable string and log them.
         * This is mainly useful when configuring the trap receiver,
         * to configure the whitelist of allowed engine IDs.
         *
         * When the original value contains a printable string,
         * read_config_save_octet_string() simply adds quotes around it.
         * Otherwise, the string is converted to an hexadecimal representation
         * first, then prefixed with "0x".
         * We need to make sure the buffer can accomodate for the hexadecimal
         * conversion, the additional prefix and the final '\0' byte.
         */
        if ( session->contextEngineIDLen * 2 + 2 < sizeof(engineid) ) {
                read_config_save_octet_string(engineid, session->contextEngineID, session->contextEngineIDLen);
                prelude_log_debug(4, "SNMP: contextEngineID  : %s", engineid);
        }

        if ( session->version == SNMP_VERSION_3 ) {
                if ( ! session->securityEngineIDLen || ! session->securityEngineID )
                        session->securityEngineID = snmpv3_generate_engineID(&session->securityEngineIDLen);

                if ( session->securityEngineIDLen * 2 + 2 < sizeof(engineid) ) {
                        read_config_save_octet_string(engineid, session->securityEngineID, session->securityEngineIDLen);
                        prelude_log_debug(4, "SNMP: securityEngineID : %s", engineid);
                }

                if ( session->engineBoots == 0 )
                        session->engineBoots = 1;

                /*
                 * Strictly speaking, this is incorrect because the agent
                 * may have been launched long after the machine booted up.
                 * It's the best guess we can make though. :-(
                 */
                if ( session->engineTime == 0 )
                        session->engineTime = get_uptime();
        }

        return 0;
}



static int snmp_new(prelude_option_t *opt, const char *arg, prelude_string_t *err, void *context)
{
        snmp_plugin_t *new;

        new = calloc(sizeof(*new), 1);
        if ( ! new )
                return prelude_error_from_errno(errno);

        snmp_sess_init(&new->session);
        init_snmp(SNMP_AGENT_NAME);

        new->session.callback = snmp_input;
        new->session.callback_magic = NULL;

        prelude_plugin_instance_set_plugin_data(context, new);

        return 0;
}


static void burn_token(char *token)
{
        if ( token ) {
                memset(token, 0, strlen(token));
                free(token);
        }
}


static void snmp_destroy(prelude_plugin_instance_t *pi, prelude_string_t *err)
{
        snmp_plugin_t *plugin = prelude_plugin_instance_get_plugin_data(pi);

        prelude_log_debug(4, "SNMP: shutting down SNMP processor");
        snmp_shutdown(SNMP_AGENT_NAME);

#ifdef NETSNMP_SECMOD_USM
        prelude_log_debug(4, "SNMP: burning secret tokens");
        burn_token(plugin->auth_key);
        burn_token(plugin->priv_key);
#endif

        if ( plugin->session.peername )
                free(plugin->session.peername);

        if ( plugin->session.community )
                free(plugin->session.community);

        if ( plugin->session.securityName )
                free(plugin->session.securityName);

        free(plugin);
}



static int snmp_input(int operation, netsnmp_session *session, int reqid, netsnmp_pdu *pdu, void *magic)
{
        /*
         * Reject incoming data: we don't expect any reply to our traps.
         */
        return 1;
}


static int prepare_v1_pdu(netsnmp_session *session, netsnmp_session *active, netsnmp_pdu **trap_pdu)
{
        netsnmp_pdu *pdu;
        in_addr_t *pdu_addr;

        *trap_pdu = pdu = snmp_pdu_create(SNMP_MSG_TRAP);
        if ( ! pdu ) {
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Failed to create trap PDU");
        }

        pdu_addr = (in_addr_t *) pdu->agent_addr;

        /*
         * Copy Prelude's trap OID
         */
        pdu->enterprise = (oid *) malloc(sizeof(objid_traps));
        if ( ! pdu->enterprise ) {
                snmp_free_pdu(pdu);
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Failed to add trap OID");
        }

        memcpy(pdu->enterprise, objid_traps, sizeof(objid_traps));
        pdu->enterprise_length = sizeof(objid_traps) / sizeof(oid);

        /*
         * Agent IP address
         */
        *pdu_addr = get_myaddr();

        pdu->trap_type = PRELUDE_GENERIC_TRAP;
        pdu->specific_type = PRELUDE_TRAP_ALERT;
        pdu->time = get_uptime();

        return 0;
}


static int prepare_v2_pdu(netsnmp_session *session, netsnmp_session *active, netsnmp_pdu **trap_pdu)
{
        int ret;
        char timestamp[20];
        netsnmp_pdu *pdu;

        *trap_pdu = pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
        if ( ! pdu ) {
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Failed to create trap PDU");
        }

        sprintf(timestamp, "%ld", get_uptime());
        ret = snmp_add_var(pdu, objid_sysuptime, sizeof(objid_sysuptime) / sizeof(oid), 't', timestamp);
        if ( ret ) {
                snmp_free_pdu(pdu);
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Failed to add uptime");
        }

        ret = snmp_add_var(pdu, objid_snmptrap, sizeof(objid_snmptrap) / sizeof(oid), 'o', PRELUDE_TRAPS STRINGIFY(PRELUDE_TRAP_ALERT));
        if ( ret ) {
                snmp_free_pdu(pdu);
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Failed to add trap OID");
        }

        return 0;
}


static int send_trap(netsnmp_session *session,
                     const char *analyzerid, const char *messageid,
                     const idmef_time_t *create_time,
                     const char *classification, const char *severity,
                     const char *source, const char *target)
{
        netsnmp_session *ss;
        netsnmp_pdu     *pdu = NULL;
        int             ret;
        char            timestamp[20];

        prelude_log_debug(4, "SNMP: opening active session with %s", session->peername);
        ss = snmp_add(session, netsnmp_transport_open_client("snmptrap", session->peername), NULL, NULL);
        if ( ! ss )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: could not create active session");

#ifndef NETSNMP_DISABLE_SNMPV1
        if ( session->version == SNMP_VERSION_1 ) {
                ret = prepare_v1_pdu(session, ss, &pdu);
        } else
#endif /* NETSNMP_DISABLE_SNMPV1 */
        {
                ret = prepare_v2_pdu(session, ss, &pdu);
        }

        if ( ret ) {
                snmp_close(ss);
                return ret;
        }
        prelude_log_debug(4, "SNMP: active session with %s has been prepared", session->peername);

        ret = snmp_add_var(pdu, objid_alert_analyzer_analyzerid, sizeof(objid_alert_analyzer_analyzerid) / sizeof(oid), 's', analyzerid);
        if ( ret )
                goto cleanup;

        ret = snmp_add_var(pdu, objid_alert_messageid, sizeof(objid_alert_messageid) / sizeof(oid), 's', messageid);
        if ( ret )
                goto cleanup;

        ret = snprintf(timestamp, sizeof(timestamp), "%" PRELUDE_PRIu32, idmef_time_get_sec(create_time));
        if ( ret < 0 || ret >= sizeof(timestamp) ) {
                snmp_free_pdu(pdu);
                snmp_close(ss);
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Could not format IDMEF timestamp");
        }

        ret = snmp_add_var(pdu, objid_alert_createtime, sizeof(objid_alert_createtime) / sizeof(oid), 't', timestamp);
        if ( ret )
                goto cleanup;

        ret = snmp_add_var(pdu, objid_alert_classification_text, sizeof(objid_alert_classification_text) / sizeof(oid), 's', classification);
        if ( ret )
                goto cleanup;

        ret = snmp_add_var(pdu, objid_alert_assessment_impact_severity, sizeof(objid_alert_assessment_impact_severity) / sizeof(oid), 's', severity);
        if ( ret )
                goto cleanup;

        ret = snmp_add_var(pdu, objid_alert_source_node_address_address, sizeof(objid_alert_source_node_address_address) / sizeof(oid), 's', source);
        if ( ret )
                goto cleanup;

        ret = snmp_add_var(pdu, objid_alert_target_node_address_address, sizeof(objid_alert_target_node_address_address) / sizeof(oid), 's', target);
        if ( ret )
                goto cleanup;

        prelude_log_debug(4, "SNMP[%s]: %s - %s [%s] %s -> %s" ,
                          session->peername, timestamp, classification,
                          severity, source, target);

        /*
         * snmp_send() returns 0 on failure.
         */
        ret = !snmp_send(ss, pdu);

    cleanup:

        if ( ret ) {
                snmp_free_pdu(pdu);
        }

        snmp_close(ss);
        return ret;
}



static int snmp_run(prelude_plugin_instance_t *pi, idmef_message_t *idmef)
{
        int                     ret;
        snmp_plugin_t           *plugin = prelude_plugin_instance_get_plugin_data(pi);
        netsnmp_session         *session = &plugin->session;
        idmef_alert_t           *alert = idmef_message_get_alert(idmef);
        idmef_time_t            *create_time;
        idmef_classification_t  *classification;
        idmef_assessment_t      *assessment;
        idmef_path_t            *path;
        idmef_value_t           *value;
        idmef_impact_t          *impact;
        idmef_impact_severity_t *severity = NULL;
        prelude_string_t        *analyzerid = NULL, *messageid;
        prelude_string_t        *source = NULL, *target = NULL, *classif_text = NULL;

        if ( ! alert )
                return 0;

        ret = idmef_path_new_fast(&path, "alert.analyzer(0).analyzerid");
        if ( ret )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Could not create path (alert.analyzer(0).analyzerid)");

        ret = idmef_path_get(path, idmef, &value);
        if ( ret > 0 )
                analyzerid = idmef_value_get_string(value);
        idmef_path_destroy(path);

        messageid = idmef_alert_get_messageid(alert);
        create_time = idmef_alert_get_create_time(alert);

        classification = idmef_alert_get_classification(alert);
        if ( classification ) {
                classif_text = idmef_classification_get_text(classification);
        }

        assessment = idmef_alert_get_assessment(alert);
        if ( assessment ) {
                impact = idmef_assessment_get_impact(assessment);
                if ( impact )
                    severity = idmef_impact_get_severity(impact);
        }

        ret = idmef_path_new_fast(&path, "alert.source(0).node.address(0).address");
        if ( ret )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Could not create path (alert.source(0).node.address(0).address)");

        ret = idmef_path_get(path, idmef, &value);
        if ( ret > 0 )
                source = idmef_value_get_string(value);
        idmef_path_destroy(path);

        ret = idmef_path_new_fast(&path, "alert.target(0).node.address(0).address");
        if ( ret )
                return prelude_error_verbose(PRELUDE_ERROR_GENERIC, "SNMP: Could not create path (alert.target(0).node.address(0).address)");

        ret = idmef_path_get(path, idmef, &value);
        if ( ret > 0 )
                target = idmef_value_get_string(value);
        idmef_path_destroy(path);

        return send_trap(session,
                analyzerid ? prelude_string_get_string(analyzerid) : "",
                prelude_string_get_string(messageid),
                create_time,
                classif_text ? prelude_string_get_string(classif_text) : "",
                severity ? idmef_impact_severity_to_string(*severity) : "",
                source ? prelude_string_get_string(source) : "",
                target ? prelude_string_get_string(target) : "");
}



int snmp_LTX_manager_plugin_init(prelude_plugin_entry_t *pe, void *rootopt)
{
        int ret;
        prelude_option_t *opt;
        static manager_report_plugin_t snmp_plugin;
        int hook = PRELUDE_OPTION_TYPE_CLI|PRELUDE_OPTION_TYPE_CFG|PRELUDE_OPTION_TYPE_WIDE;

        set_persistent_directory(MANAGER_RUN_DIR);
        set_configuration_directory(MANAGER_RUN_DIR);
        setup_engineID(NULL, NULL);

        ret = prelude_option_add(rootopt, &opt, hook, 0, "snmp", "Options for the snmp plugin",
                                 PRELUDE_OPTION_ARGUMENT_OPTIONAL, snmp_new, NULL);
        if ( ret < 0 )
                return ret;

        prelude_plugin_set_activation_option(pe, opt, snmp_init);

        ret = prelude_option_add(opt, NULL, hook, 'h', "traphost", "SNMP trap recipient",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, snmp_set_traphost, NULL);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 0, "version", "SNMP version",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, snmp_set_version, NULL);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 0, "engineid", "SNMP engine identifier",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, snmp_set_engineid, NULL);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 0, "community", "SNMP community",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, snmp_set_community, NULL);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 0, "sec-level", "SNMP security level",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, snmp_set_security_level, NULL);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 0, "sec-name", "SNMP security name",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, snmp_set_security_name, NULL);
        if ( ret < 0 )
                return ret;

#ifdef NETSNMP_SECMOD_USM
       ret = prelude_option_add(opt, NULL, hook, 0, "auth-protocol", "SNMP authentication protocol",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, snmp_set_auth_proto, NULL);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 0, "auth-key", "SNMP authentication key",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, snmp_set_auth_key, NULL);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 0, "priv-protocol", "SNMP privacy protocol",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, snmp_set_priv_proto, NULL);
        if ( ret < 0 )
                return ret;

        ret = prelude_option_add(opt, NULL, hook, 0, "priv-key", "SNMP privacy key",
                                 PRELUDE_OPTION_ARGUMENT_REQUIRED, snmp_set_priv_key, NULL);
        if ( ret < 0 )
                return ret;
#endif /* NETSNMP_SECMOD_USM */

        prelude_plugin_set_name(&snmp_plugin, "SNMP");
        prelude_plugin_set_destroy_func(&snmp_plugin, snmp_destroy);
        manager_report_plugin_set_running_func(&snmp_plugin, snmp_run);

        prelude_plugin_entry_set_plugin(pe, (void *) &snmp_plugin);

        return 0;
}



int snmp_LTX_prelude_plugin_version(void)
{
        return PRELUDE_PLUGIN_API_VERSION;
}
