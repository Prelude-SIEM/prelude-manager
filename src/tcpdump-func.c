#include <stdio.h>
#include <string.h>

#include "nethdr.h"
#include "tcpdump-func.h"


const char *etheraddr_string(const unsigned char *ep) 
{
        char *ptr;
        unsigned int i, j;
        const char *hex = "0123456789abcdef";
        static char buf[sizeof("00:00:00:00:00:00")];
        
        ptr = buf;
        if ((j = *ep >> 4) != 0)
                *ptr++ = hex[j];
        *ptr++ = hex[*ep++ & 0xf];
        
        for (i = 5; (int)--i >= 0;) {
                *ptr++ = ':';
                if ((j = *ep >> 4) != 0)
                        *ptr++ = hex[j];
                *ptr++ = hex[*ep++ & 0xf];
        }
        *ptr = '\0';

        return buf;
}        
        
