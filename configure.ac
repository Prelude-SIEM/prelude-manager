dnl Process this file with autoconf to produce a configure script.

AC_INIT(src)
AM_INIT_AUTOMAKE(prelude-manager, 0.4.1)
AM_CONFIG_HEADER(config.h)
AM_DISABLE_STATIC

AM_MAINTAINER_MODE

AC_LIBTOOL_DLOPEN
AM_PROG_LIBTOOL

dnl Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_C_INLINE
AC_C_BIGENDIAN

AC_SUBST(CFLAGS)
AC_SUBST(CPPFLAGS)
AC_SUBST(LDFLAGS)
COMMON_LIBS=""

if test "x$prefix" = "xNONE"; then
	prefix="/usr/local"
fi

if test "x$localstatedir" = "x\${prefix}/var"; then
	localstatedir="$prefix/var"
fi

if test "x$sysconfdir" = "x\${prefix}/etc"; then
    sysconfdir="$prefix/etc"
fi


dnl **************************************************
dnl * Check for libprelude                           *
dnl **************************************************

AC_PATH_GENERIC(libprelude, 0.4.1, ,
  AC_MSG_ERROR(Cannot find libprelude: Is libprelude-config in the path?) )



dnl **************************************************
dnl * Check for the Posix Thread library             *
dnl **************************************************

AC_CHECK_LIB(pthread, pthread_create, pthrlib="yes")
if test x$pthrlib = xyes; then
	COMMON_LIBS="$COMMON_LIBS -lpthread"
else
	AC_CHECK_LIB(c_r, pthread_create, COMMON_LIBS="$COMMON_LIBS -lc_r")
fi


dnl ***************************************************
dnl * Check for the MySQL library (MySQL plugin       *
dnl ***************************************************

AC_CHECK_PROG(MYSQL_CONFIG, mysql_config, true, false)
AM_CONDITIONAL(HAVE_MYSQL, $MYSQL_CONFIG)
AC_SUBST(HAVE_MYSQL)

if test x$MYSQL_CONFIG = xtrue; then
	MYSQL_LIBS=`mysql_config --libs`
	MYSQL_CFLAGS=`mysql_config --cflags`
fi

AC_SUBST(MYSQL_LIBS)
AC_SUBST(MYSQL_CFLAGS)


dnl ********************************************************
dnl * Check for the PostgreSQL library (PostgreSQL plugin) *
dnl ********************************************************

AC_CHECK_PROG(PGSQL_CONFIG, pg_config, true, false)
AM_CONDITIONAL(HAVE_PGSQL, $PGSQL_CONFIG)
AC_SUBST(HAVE_PGSQL)

if test x$PGSQL_CONFIG = xtrue; then
	PGSQL_LIBDIR=`pg_config --libdir`
	PGSQL_INCLUDEDIR=`pg_config --includedir`
fi

AC_SUBST(PGSQL_LIBDIR)
AC_SUBST(PGSQL_INCLUDEDIR)



dnl **************************************************
dnl * Check for networking function                  *
dnl **************************************************

AC_CHECK_LIB(c, inet_ntoa, libc_inet_ntoa=yes)
if test x$libc_inet_ntoa != xyes; then
	AC_CHECK_LIB(nsl, inet_ntoa, COMMON_LIBS="$COMMON_LIBS -lnsl")
fi

AC_CHECK_LIB(c, socket, libc_socket=yes)
if test x$libc_socket != xyes; then
	AC_CHECK_LIB(socket, socket, COMMON_LIBS="$COMMON_LIBS -lsocket")
fi

AC_CHECK_LIB(c, inet_aton, libc_inet_aton=yes)
if test x$libc_inet_aton != xyes; then
	AC_CHECK_LIB(resolv, inet_aton, COMMON_LIBS="$COMMON_LIBS -lresolv")
fi


dnl **************************************************
dnl * Check for getopt_long                          *
dnl **************************************************

AC_CHECK_HEADER(getopt.h, getopt_long_hdr=yes)
AC_CHECK_LIB(c, getopt_long, getopt_long_func=yes)

if test x$getopt_long_hdr = xyes && test x$getopt_long_func = xyes; then
	AC_DEFINE(HAVE_GETOPT_LONG)
fi



dnl **************************************************
dnl * Check for demand loading of shared lib library *
dnl **************************************************
AC_CHECK_LIB(dl, dlopen, COMMON_LIBS="$COMMON_LIBS -ldl")


dnl **************************************************
dnl * Check for crypt library                        *
dnl **************************************************

AC_CHECK_LIB(crypt, crypt, COMMON_LIBS="$COMMON_LIBS -lcrypt")



dnl **************************************************
dnl * Check for OpenSSL.                             *
dnl **************************************************

AC_CHECK_HEADER(openssl/ssl.h, openssl_header=yes)
AC_ARG_ENABLE(openssl, [  --enable-openssl  Use OpenSSL to communicate with Report Server [default=auto]], \
	      enable_openssl="$enableval", enable_openssl=auto)

if test x$enable_openssl = xauto ; then
	if test x$openssl_header = xyes; then
		COMMON_LIBS="$COMMON_LIBS -lssl -lcrypto"
		AC_DEFINE(HAVE_SSL)
    		enable_openssl=yes
  	else
    		enable_openssl=no
  	fi
fi



dnl **************************************************
dnl * Check for Gtkdoc.                              *
dnl **************************************************

AC_CHECK_PROG(GTKDOC, gtkdoc-mkdb, true, false)
AM_CONDITIONAL(HAVE_GTK_DOC, test -n $GTKDOC)
AC_SUBST(HAVE_GTK_DOC)

AC_ARG_ENABLE(gtk-doc, [  --enable-gtk-doc  Use gtk-doc to build documentation [default=auto]], enable_gtk_doc="$enableval", enable_gtk_doc=auto)
if test x$enable_gtk_doc = xauto ; then
	if test x$GTKDOC = xtrue ; then
    		enable_gtk_doc=yes
  	else
    		enable_gtk_doc=no
  	fi
fi
AM_CONDITIONAL(ENABLE_GTK_DOC, test x$enable_gtk_doc = xyes)




dnl **************************************************
dnl * Html dir ?                                     *
dnl ************************************************** 
if test "x$with_html_dir" = "x" ; then
	HTML_DIR='${datadir}/doc/prelude/html'
else
	HTML_DIR=$with_html_dir
fi
AC_SUBST(HTML_DIR)




dnl **************************************************
dnl * TCP WRAPPER CHECK                              *
dnl **************************************************

AC_MSG_CHECKING(whether to use TCP wrappers)
LIBWRAP_PATH=

for I in $LDFLAGS $LIBS -L/usr/lib -L/usr/local/lib; do
        case "$I" in
        -L*)
        THEFILE="`echo $I | sed -e 's,^-L,,'`"
        if test -f $THEFILE/libwrap.a; then
                LIBWRAP_PATH="$THEFILE"
		LIBWRAP="$THEFILE/libwrap.a"
                echo "Found in $LIBWRAP_PATH" 1>&5
                break
        fi
               esac
done

if test -n "$LIBWRAP"; then
         AC_MSG_RESULT(yes)
else
         AC_MSG_RESULT(no)
fi

dnl END tcp wrapper check

AC_CHECK_LIB(nsl, yp_get_default_domain, LIBNSL="-lnsl")

AC_MSG_CHECKING(whether -lwrap require -lnsl)
     ORIG_LIBS="$LIBS"
     LIBS="$LIBS $LIBWRAP"
 
     AC_TRY_LINK([
     extern int hosts_access;
     int allow_severity, deny_severity;
     ], [return hosts_access;], ,[
 
 	LIBS="$LIBS $LIBWRAP $LIBNSL"
     AC_TRY_LINK([
     extern int hosts_access;
     int allow_severity, deny_severity;
     ], [return hosts_access;], LIBWRAP_LIBS="$LIBWRAP $LIBNSL",
     LIBWRAP_PATH="")
     LIBS="$ORIG_LIBS"
     ])

if test -n "$LIBWRAP_LIBS"; 
 then		
 	AC_MSG_RESULT(yes)
 else	
 	AC_MSG_RESULT(no)
 	LIBWRAP_LIBS="$LIBWRAP"
fi

if test -n "$LIBWRAP_LIBS"; then
	AC_CHECK_HEADERS(tcpd.h)
fi

LIBS="$ORIG_LIBS"



dnl Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_HEADER_TIME

dnl Checks for library functions.
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS(gettimeofday select socket strdup strerror strstr)

configdir=$sysconfdir/prelude
prelude_manager_conf=$configdir/prelude-manager.conf
plugindir=$libdir/prelude
report_plugin_dir=$plugindir/reports/
decode_plugin_dir=$plugindir/decodes/
db_plugin_dir=$plugindir/db/


AC_DEFINE_UNQUOTED(PRELUDE_MANAGER_CONF, "$prelude_manager_conf")

AC_SUBST(defined)
AC_SUBST(configdir)
AC_SUBST(localstatedir)
AC_SUBST(prelude_manager_conf)
AC_SUBST(report_plugin_dir)
AC_SUBST(decode_plugin_dir)
AC_SUBST(db_plugin_dir)
AC_SUBST(LIBWRAP_LIBS)
AC_SUBST(COMMON_LIBS)
AC_SUBST(PRELUDE_LIBS)

CFLAGS="$CFLAGS -Wall -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
-Wbad-function-cast -Wcast-qual -Wcast-align -Wnested-externs"

AC_OUTPUT([

Makefile 
prelude-manager.conf

libmissing/Makefile
manager-adduser/Makefile

src/Makefile 
src/include/Makefile

plugins/Makefile

plugins/db/Makefile
plugins/db/mysql/Makefile
plugins/db/pgsql/Makefile

plugins/decodes/Makefile
plugins/decodes/prelude-nids/Makefile

plugins/reports/Makefile

])

dnl **** TODO add the following lines in above section ****
dnl docs/Makefile
dnl docs/api/Makefile

dnl plugins/execmod/Makefile
dnl plugins/filemod/Makefile
dnl plugins/htmlmod/Makefile
dnl plugins/xmlmod/Makefile


echo
echo "*** Dumping configuration ***"
echo "    - Use OpenSSL   : $enable_openssl"
