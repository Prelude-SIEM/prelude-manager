/*****
*
* Copyright (C) 2001, 2002 Yoann Vandoorselaere <yoann@prelude-ids.org>
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
#include <ctype.h>
#include <fcntl.h>
#include <assert.h>

#include <libprelude/prelude-inttypes.h>
#include <libprelude/prelude-log.h>

#include "plugin-util.h"



/*
 * prelude_string_to_hex:
 * @input: Pointer on the input buffer.
 * @len: Length of the data contained in the input buffer.
 *
 * This function will return a formatted hexadecimal dump.
 *
 * Returns: Pointer on an allocated buffer containing the hexadecimal dump,
 * or NULL if an error occured.
 */
char *prelude_string_to_hex(const unsigned char *input, uint32_t  len) 
{
        int i, totlen;
        unsigned char c;
        unsigned int round;
        char *line, *ret, *text;
        const int text_offset = 51;
        const char hextbl[] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
        
        round = (len / 16) + 1;
        totlen = (round * (text_offset + 16 + 1)) + 1;
        
        ret = line = malloc(totlen);
        if ( ! line ) {
                log(LOG_ERR, "memory exhausted.\n");
                return NULL;
        }
        
        text = line + text_offset;
                
        for ( i = 0; i < len; i++ ) {

                c = *input++;
                *line++ = hextbl[c >> 4];
                *line++ = hextbl[c & 0xf];
                *line++ = ' ';
                *text++ = isprint(c) ? c : '.';

                if ( (i + 1) % 16 == 0 ) {
                        *text++ = '\n';                        
                        line = text;
                        
                        if ( i + 1 < len ) 
                                text = text + text_offset;       
                }
                
                else if ( (i + 1) % 4 == 0 ) 
                        *line++ = ' ';
        }
        
        if ( i % 16 != 0 ) {
                /*
                 * fill remaining unwritten data with white space.
                 */
                while ( i++ % 16 != 0 ) {

                        *text++ = ' ';
                        *line++ = ' ';
                        *line++ = ' ';
                        *line++ = ' ';
                        
                        if ( ! (i % 16 == 0) && i % 4 == 0 ) 
                                *line++ = ' ';
                }
                
                *text++ = '\n';
        }
        
        *text++ = '\0';
        
        return ret;
}




