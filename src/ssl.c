#include "config.h"

#ifdef HAVE_SSL

/*****
*
* Copyright (C) 2001, 2002 Jeremie Brebec / Toussaint Mathieu
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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>

#include <libprelude/prelude-log.h>
#include <libprelude/config-engine.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-path.h>

#include "ssl.h"


static SSL_CTX *ctx;
static pthread_mutex_t *lock;


/*
 * functions needed for OpenSSL thread safety.
 * I'm not sure this is the right way to do it, we lack
 * good documentation for this.
 */
static unsigned long thread_id_cb(void) 
{
        return (unsigned long) pthread_self();
}



static void thread_lock_cb(int mode, int type, const char *file, int line) 
{
        if ( mode & CRYPTO_LOCK ) 
                pthread_mutex_lock(&lock[type]);
        else 
                pthread_mutex_unlock(&lock[type]);
}



static int setup_openssl_thread(void) 
{
        int i;
        
        lock = malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));
        if ( ! lock ) {
                log(LOG_ERR, "memory exhausted.\n");
                return -1;
        }

        for ( i = 0; i < CRYPTO_num_locks(); i++ )
                pthread_mutex_init(&lock[i], NULL);

        CRYPTO_set_id_callback(thread_id_cb);
        CRYPTO_set_locking_callback(thread_lock_cb);

        return 0;
}




static int do_ssl_accept(SSL *ssl) 
{
        int ret;
        
        ret = SSL_accept(ssl);  
        if ( ret <= 0 ) {
                
                ret = SSL_get_error(ssl, ret);
                if ( ret == SSL_ERROR_WANT_READ )
                        /*
                         * we need more data.
                         */
                        return 0;

                ERR_print_errors_fp(stderr);
                return -1;
        }

        return 1;
}




static int load_certificate_if_needed(void) 
{
        int ret;
        struct stat st;
        static time_t old_mtime = 0;
                        
        ret = stat(SENSORS_CERT, &st);
        if ( ret < 0 && errno != ENOENT ) {
                log(LOG_ERR, "error stating %s.\n", SENSORS_CERT);
                return -1;
        }

        if ( ret == 0 && st.st_mtime != old_mtime ) {
                /*
                 * certificate file has changed, we have to reload it
                 * to take new entry into account.
                 */
                ret = SSL_CTX_load_verify_locations(ctx, SENSORS_CERT, NULL);
                if ( ret != 1 ) {
                        ERR_print_errors_fp(stderr);
                        return -1;
                }

                old_mtime = st.st_mtime;
        }

        return 0;
}





/**
 * ssl_auth_client:
 * @session: Client associated data.
 *
 * Authorize a client...
 *
 * Returns: 0 on sucess, -1 on error.
 */
int ssl_auth_client(prelude_io_t *pio)
{
        int ret;
        SSL *ssl;

        ret = load_certificate_if_needed();
        if ( ret < 0 )
                return -1;
        
        /*
         * check if we already have an SSL descriptor
         * associated with this fd (possible because of non blocking mode).
         */
        ssl = prelude_io_get_fdptr(pio);        
        if ( ! ssl ) {
                ssl = SSL_new(ctx);
                if ( ! ssl ) {
                        ERR_print_errors_fp(stderr);
                        return -1;
                }
                
                ret = SSL_set_fd(ssl, prelude_io_get_fd(pio));
                if ( ret <= 0 ) {
                        ERR_print_errors_fp(stderr);
                        return -1;
                }

                prelude_io_set_ssl_io(pio, ssl);
        }

        return do_ssl_accept(ssl);
}




/**
 * ssl_init_server;
 *
 * Initialize OpenSSL for serving.
 *
 * Returns: 0 on success, -1 on error.
 */
int ssl_init_server(void)
{
        int ret;
        SSL_METHOD *method;

        /*
         * Initialize threading.
         */
        ret = setup_openssl_thread();
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't initialize threaded OpenSSL.\n");
                return -1;
        }
        
	/*
         * Initialize OpenSSL.
         */
	SSL_load_error_strings();
	SSL_library_init();

	method = TLSv1_server_method();
        if ( ! method ) {
                ERR_print_errors_fp(stderr);
                return -1;
        }
        
	ctx = SSL_CTX_new(method);
	if ( ! ctx ) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	SSL_CTX_set_verify_depth(ctx, 1);

        /*
         * No callback, mutual authentication.
         */
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

        ret = SSL_CTX_load_verify_locations(ctx, MANAGER_KEY, NULL);
        if ( ret != 1 ) {
                log(LOG_INFO, "\n\nNo Manager key available. Please run manager-adduser.\n\n");
                return -1;
        }

	ret = SSL_CTX_use_certificate_file(ctx, MANAGER_KEY, SSL_FILETYPE_PEM);
	if ( ret != 1 ) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	ret = SSL_CTX_use_PrivateKey_file(ctx, MANAGER_KEY, SSL_FILETYPE_PEM);
	if ( ret != 1 ) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

        /*
         * check that our private key is consistant with the certificate
         * loaded into ctx.
         */
        ret = SSL_CTX_check_private_key(ctx);
	if ( ret != 1 ) {
                log(LOG_ERR, "Private key does not match certificata.\n");
		return -1;
	}

	return 0;
}

#endif



