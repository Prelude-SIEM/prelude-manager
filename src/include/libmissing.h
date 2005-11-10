/*****
*
* Copyright (C) 2004, 2005 PreludeIDS Technologies. All Rights Reserved.
* Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
*
* This file is part of the Prelude-Manager program.
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

/*
 * should be in $(top_srcdir)/libmissing, but since the Makefile.am
 * is generated dynamically by gnulib-tool, it can't go there.
 */

#ifndef _PRELUDE_MANAGER_LIBMISSING_H
#define _PRELUDE_MANAGER_LIBMISSING_H

#include "config.h"

#include "getaddrinfo.h"
#include "gettext.h"
#include "inet_ntop.h"

#if HAVE_WCHAR_H && HAVE_WCTYPE_H
# include "mbchar.h"
#endif

#if HAVE_MBRTOWC
# include "mbuiter.h"
#endif

#include "minmax.h"
#include "pathmax.h"
#include "size_max.h"
#include "snprintf.h"
#include "strcase.h"
#include "strdup.h"
#include "strnlen1.h"
#include "time_r.h"
#include "vasnprintf.h"
#include "vsnprintf.h"
#include "xsize.h"
#include <alloca.h>
#include <poll.h>
#include <stdbool.h>
#include <string.h>


#endif /* _PRELUDE_MANAGER_LIBMISSING_H */
