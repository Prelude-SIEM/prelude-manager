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

#include <libprelude/common.h>
#include <libprelude/config-engine.h>
#include <libprelude/ssl-gencrypto.h>
#include <libprelude/ssl-config.h>

#include "pconfig.h"
#include "ssl.h"


static SSL_CTX *ctx;
static SSL *ssl;


/**
 * ssl_auth_client:
 * @session: Client associated data.
 *
 * Authorize a client...
 *
 * Returns: 0 on sucess, -1 on error.
 */
int ssl_auth_client(int socket)
{
	int err;

	ssl = SSL_new(ctx);
	if (!ssl) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	err = SSL_set_fd(ssl, socket);
	if (err <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}
        
	/*
         * handshake
         */
	err = SSL_accept(ssl);
	if (err <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

        return err == 1 ? 0 : err;
}




ssize_t ssl_read(int fd, void *buf, size_t len)
{
	int n;

	n = SSL_read(ssl , buf, len);        
	if (n == -1)
		ERR_print_errors_fp(stderr);

	return n;
}




ssize_t ssl_write(int fd, const void *buf, size_t len)
{
	int n;

	n = SSL_write(ssl, buf, len);
	if (n == -1)
		ERR_print_errors_fp(stderr);

	return n;
}



void ssl_close_session(void)
{
	SSL_shutdown(ssl);
	SSL_free(ssl);
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
        config_t *cfg;
	SSL_METHOD *method;
        const char *filename;

        cfg = config_open(PRELUDE_REPORT_CONF);
        if ( ! cfg ) {
                log(LOG_ERR, "couldn't open %s.\n", PRELUDE_REPORT_CONF);
                return -1;
                
        ssl_read_config(cfg);

        config_close(cfg);
        
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

        filename = ssl_get_cert_filename(PRELUDE_CERTS);

	n = SSL_CTX_load_verify_locations(ctx, filename, NULL);
	if (n <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	filename = ssl_get_cert_filename(REPORT_KEY);

	n = SSL_CTX_use_certificate_file(ctx, filename, SSL_FILETYPE_PEM);
	if (n <= 0) {
		ERR_print_errors_fp(stderr);
		return -1;
	}

	n = SSL_CTX_use_PrivateKey_file(ctx, filename, SSL_FILETYPE_PEM);
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



extern struct report_config config;

/**
 * ssl_create_certificate:
 *
 * Create the Report server private key,
 * and it's certificate.
 *
 * Returns: 0 on success, -1 on error.
 */
int ssl_create_certificate(config_t *cfg)
{
        X509 *x509ss;
        const char *filename;
        
        ssl_read_config(cfg);

        printf("\nBuilding report private key...\n");

        filename = ssl_get_cert_filename(REPORT_KEY);
        
        x509ss = ssl_gen_crypto(ssl_get_days(), ssl_get_key_length(),
                                filename, config.ssl_key_crypt);
        if ( ! x509ss ) {
                fprintf(stderr, "\nError building report private key\n");
                return -1;
        }

        return 0;
}

#endif



