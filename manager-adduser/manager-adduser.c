/*****
*
* Copyright (C) 2001-2004 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <errno.h>

#include <libprelude/prelude-log.h>
#include <libprelude/extract.h>
#include <libprelude/prelude-message-id.h>
#include <libprelude/prelude-io.h>
#include <libprelude/prelude-message.h>
#include <libprelude/prelude-getopt.h>
#include <libprelude/prelude-auth.h>
#include <libprelude/prelude-path.h>

#include "auth.h"
#include "config.h"
#include "ssl-register-client.h"

#define PASSLEN 9


static int keepalive = 0, prompt = 0;


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
                        ret = extract_characters_safe(&user, buf, len);
                        if ( ret < 0 )
                                return -1;
                        
                        break;
                        
                case PRELUDE_MSG_AUTH_PASSWORD:
                        ret = extract_characters_safe(&pass, buf, len);
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
                ret = prelude_auth_create_account_noprompt(MANAGER_AUTH_FILE, user, pass, 1, getuid());
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

        do {
                status = prelude_msg_read(&msg, fd);       
        } while ( status == prelude_msg_unfinished );

        if ( status != prelude_msg_finished ) {
                log(LOG_ERR, "couldn't read authentication method.\n");
                return -1;
        }
        
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


static int ask_one_shot_password(char **buf)
{
	char *pass1, *pass2;
	int ret;
	
	fprintf(stderr, "\n\nPlease enter registration one-shot password.\n"
                "This password will be requested by \"sensor-adduser\" in order to connect.\n\n");
	
	pass1 = getpass("Enter registration one-shot password: ");
	if ( ! pass1 )
		return -1;
	
	pass1 = strdup(pass1);
	if ( ! pass1 )
		return -1;
	
	pass2 = getpass("Confirm registration one-shot password: ");
	if ( ! pass2 )
		return -1;

	ret = strcmp(pass1, pass2);
	memset(pass2, 0, strlen(pass2));
	
	if ( ret == 0 ) {
		*buf = pass1;
		
		return 0;
	}

	memset(pass1, 0, strlen(pass1));
	free(pass1);
	
	return ask_one_shot_password(buf);

}




static int generate_one_shot_password(char **buf) 
{
        int i;
        char c, *mybuf;
        struct timeval tv;
	const char letters[] = "01234567890abcdefghijklmnopqrstuvwxyz";

        gettimeofday(&tv, NULL);
        
        srand((unsigned int) getpid() * tv.tv_usec);
        
	mybuf = malloc(PASSLEN);
	if ( ! mybuf )
		return -1;
	
        for ( i = 0; i < PASSLEN; i++ ) {
		c = letters[rand() % (sizeof(letters) - 1)];
                mybuf[i] = c;
        }

        mybuf[PASSLEN - 1] = '\0';

	*buf = mybuf;

        fprintf(stderr, "Generated one-shot password is \"%s\".\n\n"
                "This password will be requested by \"sensor-adduser\" in order to connect.\n"
                "Please remove the first and last quote from this password before using it.\n\n", mybuf);
        
        return 0;
}




static int handle_client_connection(int sock, char *buf, prelude_msg_t *config) 
{
        int ret;
        prelude_io_t *fd;
        
        fd = prelude_io_new();
        if ( ! fd )
                return -1;
        
        prelude_io_set_sys_io(fd, sock);
                
        ret = prelude_msg_write(config, fd);
        if ( ret < 0 )
                return -1;
        
        /* ignore error and continue looping */
        ret = handle_authentication_method(fd, buf);
        if ( ret >= 0 )
                fprintf(stderr, "\nSensor registered correctly.\n");
        
        ret = prelude_io_close(fd);
        if ( ret < 0 )
                return -1;
        
        prelude_io_destroy(fd);

        return 0;
}




static int wait_connection(int sock, char *buf, prelude_msg_t *config) 
{
        int client, len, ret;
        struct sockaddr_in addr;
        
        fprintf(stderr, "\n\n- Waiting for install request from Prelude sensors...\n");

        do {

                len = sizeof(addr);

                client = accept(sock, (struct sockaddr *) &addr, &len);
                if ( client < 0 ) {
                        fprintf(stderr, "accept returned an error: %s.\n", strerror(errno));
                        return -1;
                }
                
                fprintf(stderr, "- Connection from %s.\n", inet_ntoa(addr.sin_addr));

                ret = handle_client_connection(client, buf, config);
                if ( ret < 0 )
                        return -1;
                
        } while ( keepalive );

        return 0;
}




static int setup_server(void) 
{
        int sock, ret, on = 1;
        struct sockaddr_in sa_server;
        
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

        return sock;
}



static int print_help(void **context, prelude_option_t *opt, const char *optarg)
{
	prelude_option_print(NULL, CLI_HOOK, 20);
	return prelude_option_end;
}



static int set_keepalive(void **context, prelude_option_t *opt, const char *optarg)
{
	keepalive = keepalive ? 0 : 1;
	return prelude_option_success;
}



static int set_prompt(void **context, prelude_option_t *opt, const char *optarg)
{
	prompt = prompt ? 0 : 1;
	return prelude_option_success;
}



static void handle_options(int argc, char **argv)
{
	int ret;

	prelude_option_add(NULL, CLI_HOOK, 'h', "help",
		"Print this help", 
		no_argument, print_help, NULL);

	prelude_option_add(NULL, CLI_HOOK, 'k', "keepalive", 
		"Register sensors in an infinite loop (don't quit after registering)", 
		no_argument, set_keepalive, NULL);
		
	prelude_option_add(NULL, CLI_HOOK, 'p', "prompt",
		"Prompt for one-shot password (rather than generate it)",
		no_argument, set_prompt, NULL);

	ret = prelude_option_parse_arguments(NULL, NULL, NULL, argc, argv);
	if ( ret == prelude_option_end || ret == prelude_option_error )
		exit(ret);		
}


int main(int argc, char **argv) 
{
        char *buf;
        int sock, ret;
        prelude_msg_t *config;

	handle_options(argc, argv);

        /*
         * This will be used for SSL subject
         * generation.
         */
        prelude_set_program_name("prelude-manager");
        
        sock = setup_server();
        if ( sock < 0 )
                return -1;

#ifdef HAVE_SSL
        ret = ssl_create_manager_key_if_needed();
        if ( ret < 0 )
                return -1;
#endif
        fprintf(stderr, "\n\n");
        
	if ( prompt )
		ret = ask_one_shot_password(&buf);
	else
    		ret = generate_one_shot_password(&buf);

	if ( ret < 0 )
		return -1;
        
        config = generate_config_message();
        if ( ! config )
                return -1;
        
        return wait_connection(sock, buf, config);
}









