#include "config.h"

#ifdef HAVE_SSL

/*****
*
* Copyright (C) 2001 Jeremie Brebec / Toussaint Mathieu
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
#include <inttypes.h>

#include <libprelude/common.h>
#include <libprelude/config-engine.h>
#include <libprelude/prelude-io.h>

#include "ssl.h"


static SSL_CTX *ctx;



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
        int err;
        SSL *ssl;
        
        /*
         * check if we already have an SSL descriptor
         * associated with this fd (possible because of non blocking mode).
         */
        ssl = prelude_io_get_fdptr(pio);        
        if ( ! ssl ) {
                ssl = SSL_new(ctx);
                if (!ssl) {
                        ERR_print_errors_fp(stderr);
                        return -1;
                }
                
                err = SSL_set_fd(ssl, prelude_io_get_fd(pio));
                if (err <= 0) {
                        ERR_print_errors_fp(stderr);
                        return -1;
                }

                prelude_io_set_ssl_io(pio, ssl);
        }

        return do_ssl_accept(ssl);
}



int ssl_close_session(SSL *ssl)
{
        int ret;
        
	ret = SSL_shutdown(ssl);
	SSL_free(ssl);

        return ret;
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
        int n;
	SSL_METHOD *method;
        
	/*
         * Initialize OpenSSL.
         */
	SSL_load_error_strings();
	SSL_library_init();

	method = SSLv3_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_TLSv1);
	SSL_CTX_set_verify_depth(ctx, 1);

        /*
         * No callback, mutual authentication.
         */
	SSL_CTX_set_verify(ctx,
                           SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

	n = SSL_CTX_load_verify_locations(ctx, SENSORS_CERT, NULL);
	if (n <= 0) {
		ERR_print_errors_fp(stderr);
                log(LOG_INFO, "\nNo Sensors certificate available. Please run the "
                    "\"manager-adduser\" program.\n\n");
		return -1;
	}

	n = SSL_CTX_use_certificate_file(ctx, MANAGER_KEY, SSL_FILETYPE_PEM);
	if (n <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	n = SSL_CTX_use_PrivateKey_file(ctx, MANAGER_KEY, SSL_FILETYPE_PEM);
	if (n <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr,
			"Private key does not match the certificate public key\n");
		return -1;
	}

	return 0;
}

#endif



