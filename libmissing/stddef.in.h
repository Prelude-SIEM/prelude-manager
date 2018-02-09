/* A substitute for POSIX 2008 <stddef.h>, for platforms that have issues.

   Copyright (C) 2009-2018 Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU Lesser General Public License as published by
   the Free Software Foundation; either version 2.1, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program; if not, see <https://www.gnu.org/licenses/>.  */

/* Written by Eric Blake.  */

/*
 * POSIX 2008 <stddef.h> for platforms that have issues.
 * <http://www.opengroup.org/susv3xbd/stddef.h.html>
 */

#if __GNUC__ >= 3
@PRAGMA_SYSTEM_HEADER@
#endif
@PRAGMA_COLUMNS@

#if defined __need_wchar_t || defined __need_size_t  \
  || defined __need_ptrdiff_t || defined __need_NULL \
  || defined __need_wint_t
/* Special invocation convention inside gcc header files.  In
   particular, gcc provides a version of <stddef.h> that blindly
   redefines NULL even when __need_wint_t was defined, even though
   wint_t is not normally provided by <stddef.h>.  Hence, we must
   remember if special invocation has ever been used to obtain wint_t,
   in which case we need to clean up NULL yet again.  */

# if !(defined _@GUARD_PREFIX@_STDDEF_H && defined _GL_STDDEF_WINT_T)
#  ifdef __need_wint_t
#   define _GL_STDDEF_WINT_T
#  endif
#  @INCLUDE_NEXT@ @NEXT_STDDEF_H@
# endif

#else
/* Normal invocation convention.  */

# ifndef _@GUARD_PREFIX@_STDDEF_H

/* The include_next requires a split double-inclusion guard.  */

#  @INCLUDE_NEXT@ @NEXT_STDDEF_H@

/* On NetBSD 5.0, the definition of NULL lacks proper parentheses.  */
#  if (@REPLACE_NULL@ \
       && (!defined _@GUARD_PREFIX@_STDDEF_H || defined _GL_STDDEF_WINT_T))
#   undef NULL
#   ifdef __cplusplus
   /* ISO C++ says that the macro NULL must expand to an integer constant
      expression, hence '((void *) 0)' is not allowed in C++.  */
#    if __GNUG__ >= 3
    /* GNU C++ has a __null macro that behaves like an integer ('int' or
       'long') but has the same size as a pointer.  Use that, to avoid
       warnings.  */
#     define NULL __null
#    else
#     define NULL 0L
#    endif
#   else
#    define NULL ((void *) 0)
#   endif
#  endif

#  ifndef _@GUARD_PREFIX@_STDDEF_H
#   define _@GUARD_PREFIX@_STDDEF_H

/* Some platforms lack wchar_t.  */
#if !@HAVE_WCHAR_T@
# define wchar_t int
#endif

/* Some platforms lack max_align_t.  The check for _GCC_MAX_ALIGN_T is
   a hack in case the configure-time test was done with g++ even though
   we are currently compiling with gcc.  */
#if ! (@HAVE_MAX_ALIGN_T@ || defined _GCC_MAX_ALIGN_T)
# if !GNULIB_defined_max_align_t
/* On the x86, the maximum storage alignment of double, long, etc. is 4,
   but GCC's C11 ABI for x86 says that max_align_t has an alignment of 8,
   and the C11 standard allows this.  Work around this problem by
   using __alignof__ (which returns 8 for double) rather than _Alignof
   (which returns 4), and align each union member accordingly.  */
#  ifdef __GNUC__
#   define _GL_STDDEF_ALIGNAS(type) \
      __attribute__ ((__aligned__ (__alignof__ (type))))
#  else
#   define _GL_STDDEF_ALIGNAS(type) /* */
#  endif
typedef union
{
  char *__p _GL_STDDEF_ALIGNAS (char *);
  double __d _GL_STDDEF_ALIGNAS (double);
  long double __ld _GL_STDDEF_ALIGNAS (long double);
  long int __i _GL_STDDEF_ALIGNAS (long int);
} rpl_max_align_t;
#  define max_align_t rpl_max_align_t
#  define GNULIB_defined_max_align_t 1
# endif
#endif

#  endif /* _@GUARD_PREFIX@_STDDEF_H */
# endif /* _@GUARD_PREFIX@_STDDEF_H */
#endif /* __need_XXX */
