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

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <stdlib.h>
#include <stdio.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>

#include <libprelude/config-engine.h>
#include <libprelude/ssl-config.h>
#include <libprelude/ssl-gencrypto.h>
#include <libprelude/ssl-registration-msg.h>

#include "ssl.h"
#include "pconfig.h"

#define ACKMSGLEN ACKLENGTH + SHA_DIGEST_LENGTH + HEADLENGTH + PADMAXSIZE


extern struct report_config config;



static int wait_connection(void) 
{
        unsigned int len;
        int sock, ret, on = 1;
        struct sockaddr_in sa_server, sa_client;
        
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		perror("socket");
		return EXIT_FAILURE;
	}

	memset(&sa_server, '\0', sizeof(sa_server));
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr.s_addr = INADDR_ANY;
	sa_server.sin_port = htons(config.port);

        ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
        if ( ret < 0 ) {
                perror("setsockopt");
                return -1;
        }
        
	ret = bind(sock, (struct sockaddr *) &sa_server, sizeof(sa_server));
	if ( ret < 0 ) {
		perror("bind");
		return EXIT_FAILURE;
	}

	ret = listen(sock, 5);
	if ( ret < 0 ) {
		perror("listen");
		return EXIT_FAILURE;
	}

        fprintf(stderr, "waiting for install request from Prelude ...\n");
        
        len = sizeof(struct sockaddr_in);
        ret = accept(sock, (struct sockaddr *) &sa_client, &len);
        close(sock);

        fprintf(stderr, "Connection from %s.\n", inet_ntoa(sa_client.sin_addr));
        
        return ret;
}


static int send_own_certificate(int sock,
                                des_key_schedule *skey1,
                                des_key_schedule *skey2) 
{
        int len;
        X509 *x509ss;
        char buf[BUFMAXSIZE];
                
        x509ss = load_x509(ssl_get_cert_filename(REPORT_KEY));
	if ( !x509ss ) {
		fprintf(stderr, "Error reading own certificate\n");
		return -1;
	}
        
        len = x509_to_msg(x509ss, buf, BUFMAXSIZE, skey1, skey2);
        if (len < 0) {
                fprintf(stderr, "Error reading own certificate\n");
                return -1;
        }

        len = send(sock, buf, len, 0);
        if ( len < 0 ) {
                perror("send");
                return -1;
        }

        return 0;
}



static int wait_certificate(int sd,
                            des_key_schedule *skey1, des_key_schedule *skey2) 
{
        int len, certlen;
        char buf[BUFMAXSIZE];
	char cert[BUFMAXSIZE];
	char ack[ACKMSGLEN];
        const char *filename;
        
        /*
         * receive Prelude certificate
         */
        len = recv(sd, buf, BUFMAXSIZE, 0);
        if (len <= 0) {
                perror("recv");
                goto err;
        }

        certlen = analyse_install_msg(buf, len, cert, BUFMAXSIZE, skey1, skey2);
        if (certlen < 0) {
                fprintf(stderr, "Bad message received\n");
                goto err;
        }
        
        len = send_own_certificate(sd, skey1, skey2);
        if ( len < 0 )
                goto err;
        
        len = recv(sd, buf, ACKMSGLEN, 0);
        if (len < 0) {
                perror("recv");
                goto err;
        }

        len = analyse_install_msg(buf, len, ack, ACKLENGTH, skey1, skey2);
        if (len < 0) {
                fprintf(stderr, "Bad message received\n");
                goto err;
        }
        
        close(sd);
        
        if (strncmp(ACK, ack, ACKLENGTH) != 0) {
                fprintf(stderr, "Bad message received\n");
                goto err;
        }

        filename = ssl_get_cert_filename(PRELUDE_CERTS);
        
        fprintf(stderr, "Writing Prelude certificate to %s\n", filename);
        if (!save_cert(filename, cert, certlen)) {
                fprintf(stderr, "Error writing Prelude certificate\n");
                return -1;
        }

        fprintf(stderr, "Registration completed.\n");
        
        return 0;
        
 err:
        fprintf(stderr, "Registration failed.\n");
        close(sd);

        return -1;
}





int ssl_register_client(void)
{
        int sock;
        des_key_schedule skey1, skey2;
        
	ssl_read_config(PRELUDE_REPORT_CONF);

        if (des_generate_2key(&skey1, &skey2, 1) != 0) {
		fprintf(stderr, "Problem making one shot password\n");
		fprintf(stderr, "\nRegistration failed\n");
		return -1;
	}
        
        sock = wait_connection();
        if ( sock < 0 ) {
                fprintf(stderr, "error waiting client connection (%s).\n", strerror(errno));
                return -1;
        }
        
        return wait_certificate(sock, &skey1, &skey2);
}

#endif
