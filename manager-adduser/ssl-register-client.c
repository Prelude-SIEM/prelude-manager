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

#include <libprelude/prelude-log.h>
#include <libprelude/prelude-io.h>
#include <libprelude/config-engine.h>
#include <libprelude/ssl-settings.h>
#include <libprelude/ssl-gencrypto.h>
#include <libprelude/ssl-registration-msg.h>

#include "ssl.h"
#include "ssl-register-client.h"

#define PRELUDE_PERSISTANT_DATA_DIR "/var/lib/prelude-sensors/ssl"
#define ACKMSGLEN ACKLENGTH + SHA_DIGEST_LENGTH + HEADLENGTH + PADMAXSIZE





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
        
        certlen = prelude_ssl_recv_cert(pio, cert, sizeof(cert), skey1, skey2);
        if ( certlen < 0 ) {
                log(LOG_ERR, "couldn't receive Manager certificate.\n");
                goto err;
        }

        ret = prelude_ssl_send_cert(pio, MANAGER_KEY, skey1, skey2);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't send Sensor certificate.\n");
                goto err;
        }

        len = recv_ack(pio, skey1, skey2);
        if ( len < 0 ) {
                log(LOG_ERR, "didn't receive Manager acknowledgment.\n");
                goto err;
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



static void ask_ssl_settings(int *keysize, int *expire)  
{
        int ret;
        char buf[1024];
        
        prelude_ssl_ask_settings(keysize, expire);
        
        if ( *expire )
                snprintf(buf, sizeof(buf), "%d days", *expire);
        else
                snprintf(buf, sizeof(buf), "Never");
        
        fprintf(stderr, "\n\n"
                "Key length        : %d\n"
                "Expire            : %s\n", *keysize, buf);

        
        while ( 1 ) {
                fprintf(stderr, "Is this okay [yes/no] : ");

                fgets(buf, sizeof(buf), stdin);
                buf[strlen(buf) - 1] = '\0';
                
                ret = strcmp(buf, "yes");
                if ( ret == 0 )
                        break;
                
                ret = strcmp(buf, "no");
                if ( ret == 0 )
                        ask_ssl_settings(keysize, expire);
        }
}




static int create_manager_key_if_needed(void) 
{
        int ret, keysize, expire;
        
        ret = access(MANAGER_KEY, F_OK);
        if ( ret == 0 )
                return 0;

        fprintf(stderr, "\nNo Manager key exist... Building Manager private key...");

        ask_ssl_settings(&keysize, &expire);
        
        fprintf(stderr, "\n\n");

        ret = prelude_ssl_gen_crypto(keysize, expire, MANAGER_KEY, 0);
        if ( ret < 0 ) {
                log(LOG_ERR, "error creating SSL key.\n");
                return -1;
        }

        return 0;
}



int ssl_register_client(prelude_io_t *fd, char *pass, size_t size)
{
        int ret;
        des_cblock pre1, pre2;
	des_key_schedule skey1, skey2;
        
        des_string_to_2keys(pass, &pre1, &pre2);
        memset(pass, 0, size);
        
        ret = des_set_key_checked(&pre1, skey1);
        memset(&pre1, 0, sizeof(des_cblock));
        if ( ret < 0 ) 
		return -1;

	ret = des_set_key_checked(&pre2, skey2);
	memset(&pre2, 0, sizeof(des_cblock));
        if ( ret < 0 )
		return -1;
                
        return wait_install_request(fd, &skey1, &skey2);
}



int ssl_create_manager_key_if_needed(void) 
{
        if ( create_manager_key_if_needed() < 0 )
                return -1;

        return 0;
}



#endif

