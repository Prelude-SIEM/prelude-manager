/*****
*
* Copyright (C) 2000 Yoann Vandoorselaere <yoann@mandrakesoft.com>
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

#include <libprelude/common.h>
#include <libprelude/socket-op.h>
#include <libprelude/auth-common.h>

#include "auth.h"


#define AUTH_FILE CONFIG_DIR"/prelude-report.auth"


extern char *crypt(const char *key, const char *salt);



/*
 * Replace \n by \0, as we don't want to take care of them.
 */
static int filter_string(char *string, size_t len) 
{
        int i, ret = -1;
        
        for ( i = 0; i < len; i++ )
                if ( string[i] == '\n' ) {
                        string[i] = 0;
                        ret = 0;
                }

        return ret;
}



/*
 * Separate user and pass from a given string.
 */
static int separate_string(const char *string, size_t slen, char **user, char **pass) 
{
        int len;
        char *p = NULL;
        
        do {
                if ( ! *user && (p = strstr(string, "user ")) ) 
                        *user = strdup(p + 5);
                
                if ( ! *pass && (p = strstr(string, "pass ")) ) 
                        *pass = strdup(p + 5);

                if ( ! *user && ! *pass )
                        return -1;

                len = strlen(string) + 1;
                string += len;
                
        } while ((slen -= len) != 0);

        return 0;
}




/*
 *
 */
static int cmp(const char *given_user, const char *user,
               const char *given_pass, const char *pass) 
{
        int ret;

        ret = strcmp(given_user, user);
        if ( ret != 0 )
                return -1;
        
        if ( strcmp(pass, crypt(given_pass, SALT)) == 0) 
                return 0;
        else {
                log(LOG_INFO, "invalid password for %s.\n", user);
                return -1;
        }

        return -1;
}



/*
 *
 */
static int check_account(const char *given_user, const char *given_pass) 
{
        FILE *fd;
        char *user, *pass;
        int line = 0, ret;
        
        fd = fopen(AUTH_FILE, "r");
        if ( ! fd ) {
                log(LOG_ERR, "couldn't open %s for reading.\n", AUTH_FILE);
                return -1;
        }

        while ( auth_read_entry(fd, &line, &user, &pass) == 0 ) {                
                ret = cmp(given_user, user, given_pass, pass);

                free(user);
                free(pass);
                
                if (ret == 0) {
                        fclose(fd);
                        return 0;
                }
        }
        
        fclose(fd);

        return -1;
}



/*
 *
 */
static int get_account_infos(int sock, char **user, char **pass) 
{
        int tlen, ret, i = 1;       
        char *buf, *u = NULL, *p = NULL;

        do {
                tlen = socket_read_delimited(sock, (void **) &buf, read);                
                if ( tlen <= 0 ) {
                        if ( tlen < 0 )
                                log(LOG_ERR, "error reading socket.\n");
                        goto err;
                }

                ret = filter_string(buf, tlen);
                if ( ret < 0 ) {
                        log(LOG_ERR, "No string delimiter (\\n) found.\n");
                        goto err;
                }
                
                ret = separate_string(buf, tlen, &u, &p);
                if ( ret < 0 ) {
                        log(LOG_ERR, "there was an error parsing the command.\n");
                        goto err;
                }
                
        } while ( (u == NULL || p == NULL) && i-- );

        *user = u;
        *pass = p;
        
        return 0;

 err:
        if ( u ) free(u);
        if ( p ) free(p);

        return -1;
}



/*
 *
 */
int auth_check(int sock) 
{
        int ret;
        char *user = NULL, *pass = NULL;
        
        ret = get_account_infos(sock, &user, &pass);
        if ( ret < 0 ) {
                log(LOG_ERR, "couldn't read remote authentication informations.\n");
                return -1;
        }
        
        ret = check_account(user, pass);
        if ( ret < 0 ) 
                socket_write_delimited(sock, "failed", 6, write);
        else
                socket_write_delimited(sock, "ok", 2, write);
        
        free(user);
        free(pass);
        
        return ret;
}


/*
 *
 */
int auth_init(void) 
{
        return auth_file_exist_or_create(AUTH_FILE, 1);
}





