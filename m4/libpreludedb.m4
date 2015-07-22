dnl Autoconf macros for libpreludedb
dnl $id$

# Modified for LIBPRELUDEDB -- Yoann Vandoorselaere
# Modified for LIBGNUTLS -- nmav
# Configure paths for LIBGCRYPT
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-09

dnl AM_PATH_LIBPRELUDEDB([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]], THREAD_SUPPORT)
dnl Test for libpreludedb, and define LIBPRELUDEDB_CFLAGS, LIBPRELUDEDB_LDFLAGS, and LIBPRELUDEDB_LIBS
dnl
AC_DEFUN([AM_PATH_LIBPRELUDEDB],
[dnl
dnl Get the cflags and libraries from the libpreludedb-config script
dnl
AC_ARG_WITH(libpreludedb-prefix, AC_HELP_STRING(--with-libpreludedb-prefix=PFX, 
		                                Prefix where libpreludedb is installed (optional)),
          libpreludedb_config_prefix="$withval", libpreludedb_config_prefix="")

  if test x$libpreludedb_config_prefix != x ; then
     if test x${LIBPRELUDEDB_CONFIG+set} != xset ; then
        LIBPRELUDEDB_CONFIG=$libpreludedb_config_prefix/bin/libpreludedb-config
     fi
  fi

  AC_PATH_PROG(LIBPRELUDEDB_CONFIG, libpreludedb-config, no)

  if test "$LIBPRELUDEDB_CONFIG" != "no"; then
        if $($LIBPRELUDEDB_CONFIG --thread > /dev/null 2>&1); then
                if test x$4 = xtrue || test x$4 = xyes; then
                        libpreludedb_config_args="--thread"
                fi
        fi
  fi

  min_libpreludedb_version=ifelse([$1], ,0.1.0,$1)
  AC_MSG_CHECKING(for libpreludedb - version >= $min_libpreludedb_version)
  no_libpreludedb=""
  if test "$LIBPRELUDEDB_CONFIG" = "no" ; then
    no_libpreludedb=yes
  else
    LIBPRELUDEDB_CFLAGS=`$LIBPRELUDEDB_CONFIG $libpreludedb_config_args $libpreludedb_config_args --cflags`
    LIBPRELUDEDB_LDFLAGS=`$LIBPRELUDEDB_CONFIG $libpreludedb_config_args $libpreludedb_config_args --ldflags`
    LIBPRELUDEDB_LIBS=`$LIBPRELUDEDB_CONFIG $libpreludedb_config_args $libpreludedb_config_args --libs`
    libpreludedb_config_version=`$LIBPRELUDEDB_CONFIG $libpreludedb_config_args --version`


      ac_save_CFLAGS="$CFLAGS"
      ac_save_LDFLAGS="$LDFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $LIBPRELUDEDB_CFLAGS"
      LDFLAGS="$LDFLAGS $LIBPRELUDEDB_LDFLAGS"
      LIBS="$LIBS $LIBPRELUDEDB_LIBS"
dnl
dnl Now check if the installed libpreludedb is sufficiently new. Also sanity
dnl checks the results of libpreludedb-config to some extent
dnl
      rm -f conf.libpreludedbtest
      AC_TRY_RUN([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libpreludedb/preludedb-version.h>

int
main ()
{
    system ("touch conf.libpreludedbtest");

    if( strcmp( preludedb_check_version(NULL), "$libpreludedb_config_version" ) )
    {
      printf("\n*** 'libpreludedb-config --version' returned %s, but LIBPRELUDEDB (%s)\n",
             "$libpreludedb_config_version", preludedb_check_version(NULL) );
      printf("*** was found! If libpreludedb-config was correct, then it is best\n");
      printf("*** to remove the old version of LIBPRELUDEDB. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If libpreludedb-config was wrong, set the environment variable LIBPRELUDEDB_CONFIG\n");
      printf("*** to point to the correct copy of libpreludedb-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
    else if ( strcmp(preludedb_check_version(NULL), LIBPRELUDEDB_VERSION ) )
    {
      printf("\n*** LIBPRELUDEDB header file (version %s) does not match\n", LIBPRELUDEDB_VERSION);
      printf("*** library (version %s)\n", preludedb_check_version(NULL) );
    }
    else
    {
      if ( preludedb_check_version( "$min_libpreludedb_version" ) )
      {
        return 0;
      }
     else
      {
        printf("no\n*** An old version of LIBPRELUDEDB (%s) was found.\n",
                preludedb_check_version(NULL) );
        printf("*** You need a version of LIBPRELUDEDB newer than %s. The latest version of\n",
               "$min_libpreludedb_version" );
        printf("*** LIBPRELUDEDB is always available from http://www.prelude-siem.org/download/releases.\n");
        printf("*** \n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the libpreludedb-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of LIBPRELUDEDB, but you can also set the LIBPRELUDEDB_CONFIG environment to point to the\n");
        printf("*** correct copy of libpreludedb-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
  return 1;
}
],, no_libpreludedb=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
       LDFLAGS="$ac_save_LDFLAGS"
  fi

  if test "x$no_libpreludedb" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     if test -f conf.libpreludedbtest ; then
        :
     else
        AC_MSG_RESULT(no)
     fi
     if test "$LIBPRELUDEDB_CONFIG" = "no" ; then
       echo "*** The libpreludedb-config script installed by LIBPRELUDEDB could not be found"
       echo "*** If LIBPRELUDEDB was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the LIBPRELUDEDB_CONFIG environment variable to the"
       echo "*** full path to libpreludedb-config."
     else
       if test -f conf.libpreludedbtest ; then
        :
       else
          echo "*** Could not run libpreludedb test program, checking why..."
          CFLAGS="$CFLAGS $LIBPRELUDEDB_CFLAGS"
	  LDFLAGS="$LDFLAGS $LIBPRELUDEDB_LDFLAGS"
          LIBS="$LIBS $LIBPRELUDEDB_LIBS"
          AC_TRY_LINK([
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libpreludedb/preludedb-version.h>
],      [ return !!preludedb_check_version(NULL); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding LIBPRELUDEDB or finding the wrong"
          echo "*** version of LIBPRELUDEDB. If it is not finding LIBPRELUDEDB, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LIBPRELUDEDB was incorrectly installed"
          echo "*** or that you have moved LIBPRELUDEDB since it was installed. In the latter case, you"
          echo "*** may want to edit the libpreludedb-config script: $LIBPRELUDEDB_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
	  LDFLAGS="$ac_save_LDFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     LIBPRELUDEDB_CFLAGS=""
     LIBPRELUDEDB_LDFLAGS=""
     LIBPRELUDEDB_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  rm -f conf.libpreludedbtest
  AC_SUBST(LIBPRELUDEDB_CFLAGS)
  AC_SUBST(LIBPRELUDEDB_LDFLAGS)
  AC_SUBST(LIBPRELUDEDB_LIBS)
])

dnl *-*wedit:notab*-*  Please keep this as the last line.
