/*****
*
* Copyright (C) 2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>

#include <libprelude/prelude-log.h>
#include <libprelude/config-engine.h>
#include <libprelude/prelude-client.h>

#include <gcrypt.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "manager-auth.h"


GCRY_THREAD_OPTION_PTHREAD_IMPL;


static int dh_bits = 0;
static gnutls_dh_params dh_params;
static gnutls_certificate_credentials cred;



static int handle_gnutls_error(gnutls_session session, server_generic_client_t *client, int ret)
{
        int last_alert;

        if ( ret == GNUTLS_E_AGAIN ) {
                
                ret = gnutls_record_get_direction(session);
                if ( ret == 1 ) 
                        server_logic_notify_write_enable((server_logic_client_t *) client);
                
                return 0;
        }
        
        if ( ret == GNUTLS_E_WARNING_ALERT_RECEIVED || ret == GNUTLS_E_FATAL_ALERT_RECEIVED ) {
                last_alert = gnutls_alert_get(session);
                server_generic_log_client(client, "TLS alert: %s.\n", gnutls_alert_get_name(last_alert));
        }

        server_generic_log_client(client, "TLS handshake failed: %s.\n", gnutls_strerror(ret));

        return -1;
}



static int verify_certificate(server_generic_client_t *client, gnutls_session session)
{
	int ret;
        time_t now;
        
	ret = gnutls_certificate_verify_peers(session);
	if ( ret < 0 ) {
                server_generic_log_client(client, "TLS certificate error: %s.\n", gnutls_strerror(ret));
                return -1;
        }
        
	if ( ret == GNUTLS_E_NO_CERTIFICATE_FOUND ) {
		server_generic_log_client(client, "TLS authentication error: client did not send any certificate.\n");
                gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_SSL3_NO_CERTIFICATE);
                return -1;
	}

        if ( ret & GNUTLS_CERT_SIGNER_NOT_FOUND) {
		server_generic_log_client(client, "TLS authentication error: client certificate issuer is unknown.\n");
                gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_UNKNOWN_CA);
                return -1;
        }
        
        if ( ret & GNUTLS_CERT_INVALID ) {
                server_generic_log_client(client, "TLS authentication error: client certificate is NOT trusted.\n");
                gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_BAD_CERTIFICATE);
                return -1;
        }

        now = time(NULL);
        
        if ( gnutls_certificate_activation_time_peers(session) > now ) {
                server_generic_log_client(client, "TLS authentication error: client certificate not yet activated.\n");
                gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_BAD_CERTIFICATE);
                return -1;
        }        

        if ( gnutls_certificate_expiration_time_peers(session) < now ) {
                server_generic_log_client(client, "TLS authentication error: client certificate expired.\n");
                gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_CERTIFICATE_EXPIRED);
                return -1;
        }
        
        server_generic_log_client(client, "TLS authentication succeed: client certificate is trusted.\n");

        return 0;
}



int manager_auth_client(server_generic_client_t *client, prelude_io_t *pio)
{
        int ret;
        gnutls_session session;
        int fd = prelude_io_get_fd(pio);
        
        /*
         * check if we already have an TLS descriptor
         * associated with this fd (possible because of non blocking mode).
         */
        session = prelude_io_get_fdptr(pio);
        if ( ! session ) {
                
                gnutls_init(&session, GNUTLS_SERVER);
                gnutls_set_default_priority(session);

                gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
                gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);
                gnutls_dh_set_prime_bits(session, dh_bits);

                gnutls_transport_set_ptr(session, (gnutls_transport_ptr) fd);
                prelude_io_set_tls_io(pio, session);
        }
        
        do {
                ret = gnutls_handshake(session);
        } while ( ret < 0 && ret == GNUTLS_E_INTERRUPTED );
        
        if ( ret < 0 )
                return handle_gnutls_error(session, client, ret);
        
        ret = verify_certificate(client, session);
        if ( ret < 0 )
                return -1;

        return 1;
}




int manager_auth_disable_encryption(server_generic_client_t *client, prelude_io_t *pio)
{
        int ret;
        gnutls_session session;
        
        session = prelude_io_get_fdptr(pio);
        
        do {
                ret = gnutls_bye(session, GNUTLS_SHUT_RDWR);
        } while ( ret < 0 && ret == GNUTLS_E_INTERRUPTED );
        
        if ( ret < 0 )          
                return handle_gnutls_error(session, client, ret);
        
        gnutls_deinit(session);
        prelude_io_set_sys_io(pio, prelude_io_get_fd(pio));

        return 1;
}



int manager_auth_init(prelude_client_t *client)
{
        int line = 0;
        config_t *cfg;
        char keyfile[256], certfile[256], *ptr;

        cfg = config_open(PRELUDE_CONFIG_DIR "/tls/tls.conf");
        if ( ! cfg ) {
                log(LOG_ERR, "couldn't open %s.\n", PRELUDE_CONFIG_DIR "/tls/tls.conf");
                return -1;
        }

        ptr = config_get(cfg, NULL, "generated-key-size", &line);
        if ( ! ptr ) {
                log(LOG_ERR, "couldn't find generated-key-size parameter in cfgfile.\n");
                return -1;
        }

        dh_bits = atoi(ptr);
        config_close(cfg);
        
        gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
        gnutls_global_init();
        
        gnutls_certificate_allocate_credentials(&cred);

        prelude_client_get_tls_key_filename(client, keyfile, sizeof(keyfile));
        prelude_client_get_tls_server_keycert_filename(client, certfile, sizeof(certfile));

        gnutls_certificate_set_x509_key_file(cred, certfile, keyfile, GNUTLS_X509_FMT_PEM);

        prelude_client_get_tls_server_ca_cert_filename(client, certfile, sizeof(certfile));
        gnutls_certificate_set_x509_trust_file(cred, certfile, GNUTLS_X509_FMT_PEM);
                
        gnutls_dh_params_init(&dh_params);
        
        log(LOG_INFO, "- Generating %d bits Diffie-Hellman key for TLS...\n", dh_bits);
        
        gnutls_dh_params_generate2(dh_params, dh_bits);
        gnutls_certificate_set_dh_params(cred, dh_params);
        
	return 0;
}



