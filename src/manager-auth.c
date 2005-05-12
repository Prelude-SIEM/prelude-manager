/*****
*
* Copyright (C) 2001, 2002, 2003, 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
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
* You should have received a copy of the GNU General Public License
* along with this program; see the file COPYING.  If not, write to
* the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
*
*****/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-client.h>
#include <libprelude/prelude-message-id.h>
#include <libprelude/prelude-timer.h>

#include <gcrypt.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "manager-auth.h"


#define DEFAULT_DH_BITS 1024
#define DH_FILENAME MANAGER_RUN_DIR "/tls-parameters.data"


GCRY_THREAD_OPTION_PTHREAD_IMPL;


static int global_dh_lifetime;
static unsigned int global_dh_bits;
static gnutls_certificate_credentials cred;
static gnutls_dh_params cur_dh_params = NULL;
static prelude_timer_t dh_param_regeneration_timer;
static pthread_mutex_t dh_regen_mutex = PTHREAD_MUTEX_INITIALIZER;



static int dh_check_elapsed(void)
{
        int ret;
        struct stat st;
        struct timeval tv;

        if ( ! global_dh_lifetime )
                return 0;
        
        ret = stat(DH_FILENAME, &st);
        if ( ret < 0 ) {

                if ( errno == ENOENT )
                        return -1;
                
                prelude_log(PRELUDE_LOG_ERR, "could not stat %s: %s.\n", DH_FILENAME, strerror(errno));
                return -1;
        }

        gettimeofday(&tv, NULL);
        
        return ((tv.tv_sec - st.st_mtime) < global_dh_lifetime) ? (tv.tv_sec - st.st_mtime) : -1;
}



static int dh_params_load(gnutls_dh_params dh, unsigned int req_bits)
{
        int ret;
        FILE *fd;
        ssize_t size;
        prelude_io_t *pfd;
        unsigned int *bits;
        gnutls_datum prime, generator;
        
        fd = fopen(DH_FILENAME, "r");
        if ( ! fd ) {
                if ( errno != ENOENT )
                        prelude_log(PRELUDE_LOG_ERR, "could not open %s for reading: %s.\n", DH_FILENAME, strerror(errno));

                return -1;
        }

        ret = prelude_io_new(&pfd);
        if ( ret < 0 ) {
                fclose(fd);
                return -1;
        }

        prelude_io_set_file_io(pfd, fd);
        
        size = prelude_io_read_delimited(pfd, (void *) &bits);
        if ( size < 0 || size != sizeof(*bits) ) {
                prelude_perror(size, "error reading dh-prime length");
                goto err;
        }

        if ( *bits != req_bits )
                goto err;
                
        prime.size = size = prelude_io_read_delimited(pfd, &prime.data);
        if ( size < 0 ) {
                prelude_perror(size, "error reading dh-prime");
                goto err;
        }

        generator.size = size = prelude_io_read_delimited(pfd, &generator.data);
        if ( size < 0 ) {
                prelude_perror(size, "error reading dh generator");
                goto err;
        }
        
        ret = gnutls_dh_params_import_raw(dh, &prime, &generator);
        if ( ret < 0 )
                prelude_log(PRELUDE_LOG_WARN, "error importing Diffie-Hellman parameters: %s.\n", gnutls_strerror(ret));

        free(bits);
        free(prime.data);
        free(generator.data);
        prelude_io_close(pfd);
        prelude_io_destroy(pfd);
        
        return ret;
        
 err:
        prelude_io_close(pfd);
        prelude_io_destroy(pfd);

        return -1;
}




static int dh_params_save(gnutls_dh_params dh, unsigned int dh_bits)
{
        int ret, fd;
        prelude_io_t *pfd;
        gnutls_datum prime, generator;
        
        ret = gnutls_dh_params_export_raw(dh, &prime, &generator, NULL);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "error exporting Diffie-Hellman parameters: %s.\n", gnutls_strerror(ret));
                return -1;
        }

        fd = open(DH_FILENAME, O_CREAT|O_TRUNC|O_WRONLY, S_IRUSR|S_IWUSR);
        if ( ! fd ) {
                prelude_log(PRELUDE_LOG_ERR, "error opening %s for writing.\n", DH_FILENAME);
                free(prime.data);
                free(generator.data);
                return -1;
        }

        ret = prelude_io_new(&pfd);
        if ( ret < 0 ) {
                close(fd);
                free(prime.data);
                free(generator.data);
                return -1;
        }

        prelude_io_set_sys_io(pfd, fd);
        prelude_io_write_delimited(pfd, &dh_bits, sizeof(dh_bits));        
        prelude_io_write_delimited(pfd, prime.data, prime.size);        
        prelude_io_write_delimited(pfd, generator.data, generator.size);
        
        prelude_io_close(pfd);
        prelude_io_destroy(pfd);

        free(prime.data);
        free(generator.data);

        return 0;
}




static void dh_params_regenerate(void *data)
{
        int ret;
        gnutls_dh_params new, tmp;
        
        /*
         * generate a new DH key.
         */
        ret = gnutls_dh_params_init(&new);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "error initializing dh parameters object: %s.\n", gnutls_strerror(ret));
                return;
        }

        gnutls_dh_params_generate2(new, global_dh_bits);
        
        pthread_mutex_lock(&dh_regen_mutex);
        tmp = cur_dh_params;
        cur_dh_params = new;
        pthread_mutex_unlock(&dh_regen_mutex);
        
        /*
         * clear the old dh_params.
         */
        gnutls_dh_params_deinit(tmp);

        prelude_log(PRELUDE_LOG_INFO, "- Regenerated %d bits Diffie-Hellman key for TLS.\n", global_dh_bits);

        dh_params_save(cur_dh_params, global_dh_bits);
        prelude_timer_set_expire(&dh_param_regeneration_timer, global_dh_lifetime);
        prelude_timer_reset(&dh_param_regeneration_timer);
}



static int get_params(gnutls_session session, gnutls_params_type type, gnutls_params_st *st)
{
        int ret;
        gnutls_dh_params cpy;
        
        if ( type == GNUTLS_PARAMS_RSA_EXPORT )
                return -1;

        ret = gnutls_dh_params_init(&cpy);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "error creating a new dh parameters object: %s.\n", gnutls_strerror(ret));
                return -1;
        }
        
        pthread_mutex_lock(&dh_regen_mutex);
        
        ret = gnutls_dh_params_cpy(cpy, cur_dh_params);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "could not copy dh params for sessions: %s.\n", gnutls_strerror(ret));
                gnutls_dh_params_deinit(cpy);
                return -1;
        }

        pthread_mutex_unlock(&dh_regen_mutex);
        
        st->deinit = 1;
        st->type = type;
        st->params.dh = cpy;
        
        return 0;
}



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
                server_generic_log_client(client, PRELUDE_LOG_WARN, "TLS alert: %s.\n", gnutls_alert_get_name(last_alert));
        }
        
        server_generic_log_client(client, PRELUDE_LOG_WARN, "TLS error: %s.\n", gnutls_strerror(ret));
        
        return -1;
}



static int verify_certificate(server_generic_client_t *client, gnutls_session session)
{
	int ret;
        time_t now;
        prelude_log_t pri = PRELUDE_LOG_WARN;
        
	ret = gnutls_certificate_verify_peers(session);
	if ( ret < 0 ) {
                server_generic_log_client(client, pri, "TLS certificate error: %s.\n", gnutls_strerror(ret));
                return ret;
        }

	if ( ret == GNUTLS_E_NO_CERTIFICATE_FOUND ) {
		server_generic_log_client(client, pri, "TLS authentication error: client did not send any certificate.\n");
                gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_CERTIFICATE_UNOBTAINABLE);
                return ret;
	}

        if ( ret & GNUTLS_CERT_SIGNER_NOT_FOUND) {
		server_generic_log_client(client, pri, "TLS authentication error: client certificate issuer is unknown.\n");
                gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_UNKNOWN_CA);
                return ret;
        }
        
        if ( ret & GNUTLS_CERT_INVALID ) {
                server_generic_log_client(client, pri, "TLS authentication error: client certificate is NOT trusted.\n");
                gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_CERTIFICATE_UNKNOWN);
                return -1;
        }

        now = time(NULL);
        
        if ( gnutls_certificate_activation_time_peers(session) > now ) {
                server_generic_log_client(client, pri, "TLS authentication error: client certificate not yet activated.\n");
                gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_BAD_CERTIFICATE);
                return -1;
        }        

        if ( gnutls_certificate_expiration_time_peers(session) < now ) {
                server_generic_log_client(client, pri, "TLS authentication error: client certificate expired.\n");
                gnutls_alert_send(session, GNUTLS_AL_FATAL, GNUTLS_A_CERTIFICATE_EXPIRED);
                return -1;
        }
                
        return 0;
}



static int certificate_get_peer_analyzerid(server_generic_client_t *client, gnutls_session session,
                                           uint64_t *analyzerid, prelude_connection_permission_t *permission)
{
        char buf[1024];
        gnutls_x509_crt cert;
        size_t size = sizeof(buf);
        int cert_list_size = 0, ret;
        const gnutls_datum *cert_list;
        
        cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
        if ( ! cert_list || cert_list_size != 1 ) {
                server_generic_log_client(client, PRELUDE_LOG_WARN, "invalid number of peer certificate: %d.\n",
                                          cert_list_size);
                return -1;
        }
        
        ret = gnutls_x509_crt_init(&cert);
        if ( ret < 0 ) {
                server_generic_log_client(client, PRELUDE_LOG_ERR, "error initializing tls certificate: %s.\n",
                                          gnutls_strerror(ret));
                return -1;
        }
        
        ret = gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER);
        if ( ret < 0) {
                server_generic_log_client(client, PRELUDE_LOG_ERR, "error importing certificate: %s.\n",
                                          gnutls_strerror(ret));
                goto err;
        }

        ret = gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_DN_QUALIFIER, 0, 0, buf, &size);
        if ( ret < 0 ) {
                server_generic_log_client(client, PRELUDE_LOG_WARN, "error getting certificate DN: %s.\n",
                                          gnutls_strerror(ret));
                goto err;
        }
        
        ret = sscanf(buf, "%" PRELUDE_PRIu64, analyzerid);
        if ( ret != 1 ) {
                ret = -1;
                server_generic_log_client(client, PRELUDE_LOG_WARN, "error parsing certificate DN.\n");
                goto err;
        }

        ret = gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_COMMON_NAME, 0, 0, buf, &size);
        if ( ret < 0 ) {
                server_generic_log_client(client, PRELUDE_LOG_WARN, "error getting certificate permission: %s.\n",
                                          gnutls_strerror(ret));
                goto err;
        }
        
        ret = sscanf(buf, "%d", (int *) permission);
        if ( ret != 1 ) {
                ret = -1;
                server_generic_log_client(client, PRELUDE_LOG_WARN, "error parsing certificate permission.\n");
                goto err;
        }

 err:
        gnutls_x509_crt_deinit(cert);   
        return ret;
}



int manager_auth_client(server_generic_client_t *client, prelude_io_t *pio)
{
        int ret;
        uint64_t analyzerid;
        gnutls_session session;
        int fd = prelude_io_get_fd(pio);
        prelude_connection_permission_t permission;
        
        /*
         * check if we already have a TLS descriptor
         * associated with this fd (possible because of non blocking mode).
         */
        session = prelude_io_get_fdptr(pio);
        if ( ! session ) {
                const int kx_prio[] = { GNUTLS_KX_DHE_RSA, 0 };
                
                ret = gnutls_init(&session, GNUTLS_SERVER);

                gnutls_set_default_priority(session);
                gnutls_kx_set_priority(session, kx_prio);
                
                gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
                gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);
                
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

        ret = certificate_get_peer_analyzerid(client, session, &analyzerid, &permission);
        if ( ret < 0 )
                return -1;

        ret = server_generic_client_set_permission(client, permission);
        if ( ret < 0 )
                return -1;
        
        server_generic_client_set_analyzerid(client, analyzerid);
        server_generic_log_client(client, PRELUDE_LOG_INFO,
                                  "TLS authentication succeed: client certificate is trusted.\n");
        
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



int manager_auth_init(prelude_client_t *client, int dh_bits, int dh_lifetime)
{
        int ret;
        char keyfile[256], certfile[256];
        prelude_client_profile_t *cp = prelude_client_get_profile(client);

        if ( ! dh_bits )
                dh_bits = DEFAULT_DH_BITS;
        
        global_dh_bits = dh_bits;
        global_dh_lifetime = dh_lifetime;
        
        gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
        gnutls_global_init();
        
        gnutls_certificate_allocate_credentials(&cred);

        prelude_client_profile_get_tls_key_filename(cp, keyfile, sizeof(keyfile));
        prelude_client_profile_get_tls_server_keycert_filename(cp, certfile, sizeof(certfile));

        gnutls_certificate_set_x509_key_file(cred, certfile, keyfile, GNUTLS_X509_FMT_PEM);

        prelude_client_profile_get_tls_server_ca_cert_filename(cp, certfile, sizeof(certfile));
        gnutls_certificate_set_x509_trust_file(cred, certfile, GNUTLS_X509_FMT_PEM);
        
        gnutls_dh_params_init(&cur_dh_params);

        ret = dh_check_elapsed();
                
        if ( ret != -1 && dh_params_load(cur_dh_params, dh_bits) == 0 )
                prelude_timer_set_expire(&dh_param_regeneration_timer, dh_lifetime - ret);
        else {
                prelude_log(PRELUDE_LOG_INFO, "- Generating %d bits Diffie-Hellman key for TLS...\n", dh_bits);

                gnutls_dh_params_generate2(cur_dh_params, dh_bits);
                dh_params_save(cur_dh_params, dh_bits);

                prelude_timer_set_expire(&dh_param_regeneration_timer, dh_lifetime);
        }
        
        gnutls_certificate_set_params_function(cred, get_params);

        if ( dh_lifetime ) {
                prelude_timer_set_callback(&dh_param_regeneration_timer, dh_params_regenerate);
                prelude_timer_init(&dh_param_regeneration_timer);
        }
        
	return 0;
}
