/*****
*
* Copyright (C) 2001-2012 CS-SI. All Rights Reserved.
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
* You should have received a copy of the GNU General Public License along
* with this program; if not, write to the Free Software Foundation, Inc.,
* 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*
*****/

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pathmax.h>
#include <dirent.h>
#include <gnutls/gnutls.h>
#include <errno.h>

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <libprelude/prelude.h>
#include <libprelude/prelude-log.h>
#include <libprelude/prelude-client.h>
#include <libprelude/prelude-message-id.h>
#include <libprelude/prelude-timer.h>

#include <gcrypt.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "glthread/lock.h"
#include "manager-auth.h"


#define DEFAULT_DH_BITS 1024
#define DH_FILENAME MANAGER_RUN_DIR "/tls-parameters.data"


#ifdef HAVE_GNUTLS_STRING_PRIORITY

static gnutls_priority_t tls_priority;

#endif


static int global_dh_lifetime;
static unsigned int global_dh_bits;
static gnutls_certificate_credentials cred;
static gnutls_dh_params cur_dh_params = NULL;
static prelude_timer_t dh_param_regeneration_timer;
static gl_lock_t dh_regen_mutex = gl_lock_initializer;



static int gcry_prelude_mutex_init(void **retval)
{
        int ret;
        gl_lock_t *lock;

        *retval = lock = malloc(sizeof(*lock));
        if ( ! lock )
                return ENOMEM;

        ret = glthread_lock_init(lock);
        if ( ret < 0 )
                free(lock);

        return ret;
}


static int gcry_prelude_mutex_destroy(void **lock)
{
        return glthread_lock_destroy(*lock);
}



static int gcry_prelude_mutex_lock(void **lock)
{
        return glthread_lock_lock((gl_lock_t *) *lock);
}


static int gcry_prelude_mutex_unlock(void **lock)
{
        return glthread_lock_unlock((gl_lock_t *) *lock);
}


static struct gcry_thread_cbs gcry_threads_prelude = {
        GCRY_THREAD_OPTION_USER,
        NULL,
        gcry_prelude_mutex_init,
        gcry_prelude_mutex_destroy,
        gcry_prelude_mutex_lock,
        gcry_prelude_mutex_unlock
};



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
        if ( fd < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "error opening %s for writing: %s.\n", DH_FILENAME, strerror(errno));
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

        gl_lock_lock(dh_regen_mutex);
        tmp = cur_dh_params;
        cur_dh_params = new;
        gl_lock_unlock(dh_regen_mutex);

        /*
         * clear the old dh_params.
         */
        gnutls_dh_params_deinit(tmp);

        prelude_log(PRELUDE_LOG_INFO, "Regenerated %d bits Diffie-Hellman key for TLS.\n", global_dh_bits);

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

        gl_lock_lock(dh_regen_mutex);
        ret = gnutls_dh_params_cpy(cpy, cur_dh_params);
        gl_lock_unlock(dh_regen_mutex);

        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_WARN, "could not copy dh params for sessions: %s.\n", gnutls_strerror(ret));
                gnutls_dh_params_deinit(cpy);
                return -1;
        }

        st->deinit = 1;
        st->type = type;
        st->params.dh = cpy;

        return 0;
}



static int handle_gnutls_error(prelude_io_t *pio, gnutls_session session, server_generic_client_t *client, int ret,
                               gnutls_alert_description *alert_desc)
{
        int level;
        const char *alert;

        if ( ret == GNUTLS_E_AGAIN ) {
                if ( gnutls_record_get_direction(session) == 1 )
                        server_generic_notify_write_enable(client);

                return 0;
        }

        else if ( ret == GNUTLS_E_INTERRUPTED )
                return 1;

        else if ( ret == GNUTLS_E_WARNING_ALERT_RECEIVED ) {
                alert = gnutls_alert_get_name(gnutls_alert_get(session));
                server_generic_log_client(client, PRELUDE_LOG_WARN, "TLS alert from client: %s.\n", alert);
                return 1;
        }

        else if ( ret == GNUTLS_E_FATAL_ALERT_RECEIVED ) {
                alert = gnutls_alert_get_name(gnutls_alert_get(session));
                server_generic_log_client(client, PRELUDE_LOG_WARN, "TLS fatal alert from client: %s.\n", alert);
        }

        else {
                server_generic_log_client(client, PRELUDE_LOG_WARN, "TLS error: %s.\n", gnutls_strerror(ret));
                if ( alert_desc && (ret = gnutls_error_to_alert(ret, &level)) > 0 )
                        *alert_desc = (gnutls_alert_description) ret;
        }

        return -1;
}



static int verify_certificate(server_generic_client_t *client, gnutls_session session, gnutls_alert_description *alert)
{
        int ret;
        time_t now;
        unsigned int status;
        prelude_log_t pri = PRELUDE_LOG_WARN;

        ret = gnutls_certificate_verify_peers2(session, &status);
        if ( ret < 0 ) {
                server_generic_log_client(client, pri, "error verifying certificate: %s.\n", gnutls_strerror(ret));
                return ret;
        }

        if ( status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
                *alert = GNUTLS_A_UNKNOWN_CA;
                server_generic_log_client(client, pri, "TLS authentication error: client certificate issuer is unknown.\n");
                return -1;
        }

        else if ( status & GNUTLS_CERT_REVOKED ) {
                *alert = GNUTLS_A_CERTIFICATE_REVOKED;
                server_generic_log_client(client, pri, "TLS authentication error: client certificate is revoked.\n");
                return -1;
        }

        else if ( status & GNUTLS_CERT_INVALID ) {
                *alert = GNUTLS_A_CERTIFICATE_UNKNOWN;
                server_generic_log_client(client, pri, "TLS authentication error: client certificate is NOT trusted.\n");
                return -1;
        }

#ifdef GNUTLS_CERT_INSECURE_ALGORITHM
        else if ( status & GNUTLS_CERT_INSECURE_ALGORITHM ) {
                *alert = GNUTLS_A_INSUFFICIENT_SECURITY;
                server_generic_log_client(client, pri, "TLS authentication error: client use insecure algorithm");
                return -1;
        }
#endif

        now = time(NULL);

        if ( gnutls_certificate_activation_time_peers(session) > now ) {
                *alert = GNUTLS_A_BAD_CERTIFICATE;
                server_generic_log_client(client, pri, "TLS authentication error: client certificate not yet activated.\n");
                return -1;
        }

        if ( gnutls_certificate_expiration_time_peers(session) < now ) {
                *alert = GNUTLS_A_CERTIFICATE_EXPIRED;
                server_generic_log_client(client, pri, "TLS authentication error: client certificate expired.\n");
                return -1;
        }

        return 0;
}



static int certificate_get_peer_analyzerid(server_generic_client_t *client, gnutls_session session,
                                           uint64_t *analyzerid, prelude_connection_permission_t *permission, char *profile, size_t *profile_size)
{
        int ret;
        char buf[1024];
        gnutls_x509_crt cert;
        size_t size = sizeof(buf);
        const gnutls_datum *cert_list;
        unsigned int cert_list_size = 0;

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

        *profile = '\0';
        ret = gnutls_x509_crt_get_dn_by_oid(cert, GNUTLS_OID_X520_SURNAME, 0, 0, profile, profile_size);
		if (ret == GNUTLS_E_REQUESTED_DATA_NOT_AVAILABLE) {
			// surname is optional
			ret = 0;
		} else if (ret < 0) {
			server_generic_log_client(client, PRELUDE_LOG_WARN, "error getting certificate surName: %s.\n", gnutls_strerror(ret));
			goto err;
		}

 err:
        gnutls_x509_crt_deinit(cert);
        return ret;
}


static void set_default_priority(gnutls_session session)
{
#ifdef HAVE_GNUTLS_STRING_PRIORITY
                gnutls_priority_set(session, tls_priority);
#else
                gnutls_set_default_priority(session);
#endif
}


int manager_auth_client(server_generic_client_t *client, prelude_io_t *pio, gnutls_alert_description *alert)
{
        int ret;
        uint64_t analyzerid;
        gnutls_session session;
        int fd = prelude_io_get_fd(pio);
        prelude_connection_permission_t permission;
        char profile[PATH_MAX];
        size_t profile_size = sizeof(profile);

        /*
         * check if we already have a TLS descriptor
         * associated with this fd (possible because of non blocking mode).
         */
        session = prelude_io_get_fdptr(pio);
        if ( ! session ) {
                union { int fd; void *ptr; } data;

                ret = gnutls_init(&session, GNUTLS_SERVER);
                if ( ret < 0 ) {
                        server_generic_log_client(client, PRELUDE_LOG_WARN, "error initializing TLS session: %s.\n",
                                                  gnutls_strerror(ret));
                        return -1;
                }

                set_default_priority(session);

                gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, cred);
                gnutls_certificate_server_set_request(session, GNUTLS_CERT_REQUEST);

                data.fd = fd;
                gnutls_transport_set_ptr(session, data.ptr);
                prelude_io_set_tls_io(pio, session);
        }

        do {
                ret = gnutls_handshake(session);
                if ( ret == 0 )
                        ret = 1;

        } while ( ret < 0 && (ret = handle_gnutls_error(pio, session, client, ret, alert)) == 1 );

        if ( ret <= 0 )
                return ret;

        ret = verify_certificate(client, session, alert);
        if ( ret < 0 )
                return -1;

        ret = certificate_get_peer_analyzerid(client, session, &analyzerid, &permission, profile, &profile_size);
        if ( ret < 0 ) {
                *alert = GNUTLS_A_BAD_CERTIFICATE;
                return -1;
        }

        if (strcmp(profile, "prelude-manager") == 0) {
        	*alert = GNUTLS_A_ACCESS_DENIED;
        	return -1;
        }

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
                if ( ret == 0 )
                        ret = 1;

        } while ( ret < 0 && (ret = handle_gnutls_error(pio, session, client, ret, NULL)) == 1 );

        if ( ret <= 0 )
                return ret;

        gnutls_deinit(session);
        prelude_io_set_sys_io(pio, prelude_io_get_fd(pio));

        return ret;
}


static int tls_priority_init(const char *tlsopts)
{
#ifdef HAVE_GNUTLS_STRING_PRIORITY
        int ret;
        const char *errptr;

        ret = gnutls_priority_init(&tls_priority, (tlsopts) ? tlsopts : "NORMAL", &errptr);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "TLS priority error: %s: '%s'.\n", gnutls_strerror(ret), errptr);
                return -2;
        }
#else
        if ( tlsopts ) {
                prelude_log(PRELUDE_LOG_ERR, "settings TLS options require GnuTLS 2.2.0 or above.\n");
                return -2;
        }
#endif

        return 0;
}

int manager_auth_init(prelude_client_t *client, const char *tlsopts, int dh_bits, int dh_lifetime)
{
        int ret;
        char keyfile[PATH_MAX], certfile[PATH_MAX], crlfile[PATH_MAX];
        prelude_client_profile_t *cp = prelude_client_get_profile(client);

        if ( ! dh_bits )
                dh_bits = DEFAULT_DH_BITS;

        global_dh_bits = dh_bits;
        global_dh_lifetime = dh_lifetime;

        gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_prelude);
        gnutls_global_init();

        tls_priority_init(tlsopts);
        gnutls_certificate_allocate_credentials(&cred);

        prelude_client_profile_get_tls_key_filename(cp, keyfile, sizeof(keyfile));
        prelude_client_profile_get_tls_server_keycert_filename(cp, certfile, sizeof(certfile));

        ret = access(certfile, R_OK);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "could not open %s for reading.\n", certfile);
                return prelude_error_from_errno(errno);
        }

        ret = access(keyfile, R_OK);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "could not open %s for reading.\n", keyfile);
                return prelude_error_from_errno(errno);
        }

        ret = gnutls_certificate_set_x509_key_file(cred, certfile, keyfile, GNUTLS_X509_FMT_PEM);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "%s: %s\n", keyfile, gnutls_strerror(ret));
                return -1;
        }

        prelude_client_profile_get_tls_server_ca_cert_filename(cp, certfile, sizeof(certfile));

        ret = gnutls_certificate_set_x509_trust_file(cred, certfile, GNUTLS_X509_FMT_PEM);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "%s: %s\n", certfile, gnutls_strerror(ret));
                return -1;
        }

        prelude_client_profile_get_tls_server_crl_filename(cp, crlfile, sizeof(crlfile));
        if ( access(crlfile, R_OK) == 0 ) {
                ret = gnutls_certificate_set_x509_crl_file(cred, crlfile, GNUTLS_X509_FMT_PEM);
                if ( ret < 0 ) {
                        prelude_log(PRELUDE_LOG_ERR, "%s: %s\n", crlfile, gnutls_strerror(ret));
                        return -1;
                }
        }

        gnutls_dh_params_init(&cur_dh_params);

        ret = access(MANAGER_RUN_DIR, R_OK|W_OK);
        if ( ret < 0 ) {
                prelude_log(PRELUDE_LOG_ERR, "could not open %s for reading/writing.\n", MANAGER_RUN_DIR);
                return prelude_error_from_errno(errno);
        }

        ret = dh_check_elapsed();

        if ( ret != -1 && dh_params_load(cur_dh_params, dh_bits) == 0 )
                prelude_timer_set_expire(&dh_param_regeneration_timer, dh_lifetime - ret);
        else {
                prelude_log(PRELUDE_LOG_INFO, "Generating %d bits Diffie-Hellman key for TLS...\n", dh_bits);

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
