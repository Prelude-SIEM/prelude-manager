/* Formatted output to strings.
   Copyright (C) 2004 Free Software Foundation, Inc.
   Written by Yoann Vandoorselaere <yoann@prelude-ids.org>

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License along
   with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  */

#ifndef VSNPRINTF_H
#define VSNPRINTF_H

/* Get snprintf declaration, if available.  */
#include <stdio.h>

#if defined HAVE_DECL_VSNPRINTF && !HAVE_DECL_VSNPRINTF
int vsnprintf(char *str, size_t size, const char *format, va_list ap);
#endif

#endif /* VSNPRINTF_H */
