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

#include <libprelude/ssl.h>
#include <libprelude/common.h>
#include <libprelude/prelude-io.h>
#include <libprelude/config-engine.h>
#include <libprelude/ssl-gencrypto.h>
#include <libprelude/ssl-registration-msg.h>


#define ACKMSGLEN ACKLENGTH + SHA_DIGEST_LENGTH + HEADLENGTH + PADMAXSIZE


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
	sa_server.sin_port = htons(5554);

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



static int recv_ack(prelude_io_t *pio,
                    des_key_schedule *skey1, des_key_schedule *skey2) 
{
        int len;
        char *buf;
        char ack[ACKMSGLEN];
        
        len = prelude_io_read_delimited(pio, (void **) &buf);
        if ( len <= 0 ) {
                log(LOG_ERR, "couldn't read certificate.\n");
                return -1;
        }

        len = analyse_install_msg(buf, len, ack, ACKLENGTH, skey1, skey2);
        if (len < 0) {
                fprintf(stderr, "bad installation message received.\n");
                return -1;
        }
        
        if ( strncmp(ACK, ack, ACKLENGTH) != 0) {
                fprintf(stderr, "bad installation message received\n");
                return -1;
        }

        return 0;
}





static int wait_install_request(prelude_io_t *pio,
                                des_key_schedule *skey1, des_key_schedule *skey2) 
{
        int len, certlen, ret;
	char cert[BUFMAXSIZE];

        certlen = prelude_ssl_recv_cert(pio, cert, BUFMAXSIZE, skey1, skey2);
        if ( certlen < 0 ) {
                log(LOG_ERR, "couldn't receive Manager certificate.\n");
                return -1;
        }

        ret = prelude_ssl_send_cert(pio, MANAGER_KEY, skey1, skey2);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't send Sensor certificate.\n");
                return -1;
        }

        len = recv_ack(pio, skey1, skey2);
        if ( len < 0 ) {
                log(LOG_ERR, "didn't receive Manager acknowledgment.\n");
                return -1;
        }
        
        prelude_io_close(pio);
        
        
        
        fprintf(stderr, "Writing Prelude certificate to %s\n", SENSORS_CERT);

        ret = prelude_ssl_save_cert(SENSORS_CERT, cert, certlen);
        if ( ! ret ) {
                fprintf(stderr, "Error writing Prelude certificate\n");
                return -1;
        }
        
        fprintf(stderr, "Registration completed.\n");
        
        return 0;
        
 err:
        fprintf(stderr, "Registration failed.\n");
        prelude_io_close(pio);

        return -1;
}



static void ask_ssl_settings(int *keysize, int *expire, int *store_crypted)  
{
        int ret;
        char buf[1024];
        
        prelude_ssl_ask_settings(keysize, expire, store_crypted);
        
        if ( *expire )
                snprintf(buf, sizeof(buf), "%d days", *expire);
        else
                snprintf(buf, sizeof(buf), "Never");
        
        fprintf(stderr, "\n\n"
                "Key length        : %d\n"
                "Expire            : %s\n"
                "Store key crypted : %s\n\n",
                *keysize, buf, (*store_crypted) ? "Yes" : "No");

        
        while ( 1 ) {
                fprintf(stderr, "Is this okay [yes/no] : ");

                fgets(buf, sizeof(buf), stdin);
                buf[strlen(buf) - 1] = '\0';
                
                ret = strcmp(buf, "yes");
                if ( ret == 0 )
                        break;
                
                ret = strcmp(buf, "no");
                if ( ret == 0 )
                        ask_ssl_settings(keysize, expire, store_crypted);
        }
}




static int create_manager_key_if_needed(void) 
{
        int ret;
        X509 *x509ss;
        int keysize, expire, store_crypted;

        ret = access(MANAGER_KEY, F_OK);
        if ( ret == 0 )
                return 0;

        fprintf(stderr, "\nNo Manager key exist... Buildling Manager private key...");

        ask_ssl_settings(&keysize, &expire, &store_crypted);
        
        fprintf(stderr, "\n\n");
        
        x509ss = prelude_ssl_gen_crypto(keysize, expire, MANAGER_KEY, store_crypted);
        if ( ! x509ss ) {
                log(LOG_ERR, "error creating SSL key.\n");
                return -1;
        }

        return 0;
}



int ssl_register_client(void)
{
        int sock, ret;
        prelude_io_t *pio;
        des_key_schedule skey1, skey2;

        if ( create_manager_key_if_needed() < 0 )
                return -1;
        
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

        pio = prelude_io_new();
        if (! pio )
                return -1;

        prelude_io_set_socket_io(pio, sock);
        
        return wait_install_request(pio, &skey1, &skey2);
}

#endif

