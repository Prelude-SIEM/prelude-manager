/*****
*
* Copyright (C) 2001, 2002 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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
#include <unistd.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <libprelude/prelude-log.h>
#include <libprelude/extract.h>
#include <libprelude/prelude-message-id.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-auth.h>

#include "auth.h"
#include "config.h"
#include "ssl-register-client.h"



/*
 * Generate a configuration message containing
 * the kind of connection the Manager support.
 */
static prelude_msg_t *generate_config_message(void)
{
        prelude_msg_t *msg;

        msg = prelude_msg_new(2, 0, PRELUDE_MSG_AUTH, 0);
        if ( ! msg )
                return NULL;
        
#ifdef HAVE_SSL
        prelude_msg_set(msg, PRELUDE_MSG_AUTH_HAVE_SSL, 0, NULL);
#endif
        prelude_msg_set(msg, PRELUDE_MSG_AUTH_HAVE_PLAINTEXT, 0, NULL);
        
        return msg;
}



static int is_already_existing(const char *user, const char *pass) 
{
        int ret;
        char *userp, *passp;

        ret = prelude_auth_read_entry(MANAGER_AUTH_FILE, user, pass, &userp, &passp);
        if ( ret < 0 )
                return ret;
        
        free(userp);
        free(passp);
        
        return ret;
}



static int send_plaintext_creation_result(prelude_io_t *fd, uint8_t tag)
{
        int ret;
        prelude_msg_t *msg;
        
        msg = prelude_msg_new(1, 0, PRELUDE_MSG_AUTH, 0);
        if ( ! msg )
                return -1;
        
        prelude_msg_set(msg, tag, 0, NULL);
        ret = prelude_msg_write(msg, fd);
        prelude_msg_destroy(msg);

        return ret;
}




static int handle_plaintext_account_creation(prelude_io_t *fd, prelude_msg_t *msg)
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t len;
        const char *user = NULL, *pass = NULL;

        while ( (ret = prelude_msg_get(msg, &tag, &len, &buf)) > 0 ) {
                
                switch (tag) {
                        
                case PRELUDE_MSG_AUTH_USERNAME:
                        ret = extract_string_safe(&user, buf, len);
                        if ( ret < 0 )
                                return -1;
                        
                        break;
                        
                case PRELUDE_MSG_AUTH_PASSWORD:
                        ret = extract_string_safe(&pass, buf, len);
                        if ( ret < 0 )
                                return -1;
                        
                        break;
                        
                default:
                        fprintf(stderr, "invalid authentication message.\n");
                        return -1;
                }
        }
        
        if ( ! user || ! pass || ret < 0 ) {
                fprintf(stderr, "invalid authentication message.\n");
                return -1;
        }

        ret = is_already_existing(user, pass);
        if ( ret == -1 ) {
                fprintf(stderr, "generic auth error.\n");
                return -1;
        }
        
        if ( ret == password_does_not_match ) {
                fprintf(stderr, "user %s already exist with a different password: failed.\n", user);
                send_plaintext_creation_result(fd, PRELUDE_MSG_AUTH_EXIST);
                return -1;
        }

        else if ( ret == user_does_not_exist ) {
                ret = prelude_auth_create_account_noprompt(MANAGER_AUTH_FILE, user, pass, 1, 0);
                if ( ret < 0 ) {
                        fprintf(stderr, "error creating new plaintext user account.\n");
                        send_plaintext_creation_result(fd, PRELUDE_MSG_AUTH_FAILED);
                        return -1;
                }

                fprintf(stderr, "successfully created user %s.\n", user);
        }

        else
                fprintf(stderr, "using already existing user: %s.\n", user);
        
        send_plaintext_creation_result(fd, PRELUDE_MSG_AUTH_SUCCEED);

        return 0;
}





static int create_plaintext_account(prelude_io_t *fd, prelude_msg_t *msg, char *oneshot, char *pass) 
{
        int ret;

        ret = strcmp(oneshot, pass);
        if ( ret != 0 ) {
                fprintf(stderr, "Provided password doesn't match one shot password.\n");
                return -1;
        }

        return handle_plaintext_account_creation(fd, msg);
}





/*
 * Either plaintext, either SSL.
 * call the necessary authentication function.
 */
static int handle_authentication_method(prelude_io_t *fd, char *pass)
{
        int ret;
        void *buf;
        uint8_t tag;
        uint32_t dlen;
        prelude_msg_t *msg = NULL;
        prelude_msg_status_t status;

        status = prelude_msg_read(&msg, fd);
        if ( status != prelude_msg_finished )
                return -1;

        
        tag = prelude_msg_get_tag(msg);

        if ( tag != PRELUDE_MSG_AUTH ) {
                fprintf(stderr, "expected authentication tag got (%d).\n", tag);
                return -1;
        }

        ret = prelude_msg_get(msg, &tag, &dlen, &buf);
        if ( ret <= 0 )
                return -1;
        
        switch (tag) {

        case PRELUDE_MSG_AUTH_SSL:
#ifdef HAVE_SSL    
                fprintf(stderr, "sensor choose to use SSL communication method.\n");
                ret = ssl_register_client(fd, pass, strlen(pass));
#else
                fprintf(stderr, "sensor requested to use SSL, but it is unsupported.\n");
                return -1;
#endif
                break;
                
        case PRELUDE_MSG_AUTH_PLAINTEXT:
                fprintf(stderr, "sensor choose to use PLAINTEXT communication method.\n");
                ret = create_plaintext_account(fd, msg, pass, buf);
                break;

        default:
                fprintf(stderr, "invalid authentication tag (%d).\n", tag);
                return -1;
        }


        return ret;
}




static int generate_one_shot_password(char *buf, size_t size) 
{
        char c;
        int num, i;
        struct timeval tv;

        gettimeofday(&tv, NULL);
        
        srand((unsigned int) getpid() * tv.tv_usec);
        
        for ( i = 0; i < (size - 1); i++ ) {
                num = rand();

                c = num % 128;
                if ( c < 33 )
                        c += 33;

                else if ( c > 126 )
                        c = 126;
                                
                buf[i] = c;
                num >>= (sizeof(num) * 8) / (size - 1);
                
        }

        buf[size - 1] = '\0';

        fprintf(stderr, "Generated one-shot password is \"%s\".\n\n"
                "This password will be requested by \"sensor-adduser\" in order to connect.\n"
                "Please remove the first and last quote from this password before using it.\n\n", buf);
        
        return 0;
}





static int wait_connection(void) 
{
        unsigned int len;
        int sock, ret, on = 1;
        struct sockaddr_in sa_server, sa_client;
        
	sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sock < 0) {
		perror("socket");
		return EXIT_FAILURE;
	}

	memset(&sa_server, '\0', sizeof(sa_server));
	sa_server.sin_family = AF_INET;
	sa_server.sin_addr.s_addr = INADDR_ANY;
	sa_server.sin_port = htons(5553);

        ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(int));
        if ( ret < 0 ) {
                perror("setsockopt");
                return -1;
        }
        
	ret = bind(sock, (struct sockaddr *) &sa_server, sizeof(sa_server));
	if ( ret < 0 ) {
		perror("bind");
		return -1;
	}

	ret = listen(sock, 5);
	if ( ret < 0 ) {
		perror("listen");
		return -1;
	}

        fprintf(stderr, "waiting for install request from Prelude sensors...\n");
        
        len = sizeof(struct sockaddr_in);
        ret = accept(sock, (struct sockaddr *) &sa_client, &len);
        close(sock);

        fprintf(stderr, "\nConnection from %s.\n", inet_ntoa(sa_client.sin_addr));
        
        return ret;
}




int main(void) 
{
        char buf[9];
        int sock, ret;
        prelude_io_t *fd;
        prelude_msg_t *config;

#ifdef HAVE_SSL
        ret = ssl_create_manager_key_if_needed();
        if ( ret < 0 )
                return -1;
#endif
        fprintf(stderr, "\n\n");
        
        generate_one_shot_password(buf, sizeof(buf));
        
        sock = wait_connection();
        if ( sock < 0 )
                return -1;

        fd = prelude_io_new();
        if ( ! fd )
                return -1;

        prelude_io_set_sys_io(fd, sock);
        
        config = generate_config_message();
        if ( ! config )
                return -1;

        ret = prelude_msg_write(config, fd);
        if ( ret < 0 )
                return -1;
        
        ret = handle_authentication_method(fd, buf);
        
        exit(ret);
}









