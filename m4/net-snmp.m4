dnl Autoconf macros for net-snmp
dnl $id$

# Modified for NET_SNMP -- François Poirotte
# Modified for LIBGNUTLS -- nmav
# Configure paths for LIBGCRYPT
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-09

dnl AM_PATH_NET_SNMP([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]], THREAD_SUPPORT)
dnl Test for net-snmp, and define NET_SNMP_PREFIX, NET_SNMP_CFLAGS,
dnl NET_SNMP_LDFLAGS, and NET_SNMP_LIBS
dnl
AC_DEFUN([AM_PATH_NET_SNMP],
[dnl
dnl Get the cflags and libraries from the net-snmp-config script
dnl
AC_ARG_WITH(net-snmp-prefix,
            AC_HELP_STRING(--with-net-snmp-prefix=PFX, Prefix where net-snmp is installed (optional)),
            net_snmp_config_prefix="$withval", net_snmp_config_prefix="")

  if test x$net_snmp_config_prefix != x ; then
     if test x${NET_SNMP_CONFIG+set} != xset ; then
        NET_SNMP_CONFIG=$net_snmp_config_prefix/bin/net-snmp-config
     fi
  fi

  AC_PATH_PROG(NET_SNMP_CONFIG, net-snmp-config, no)
  min_net_snmp_version=ifelse([$1], ,5.4,[$1])
  AC_MSG_CHECKING(for net-snmp - version >= $min_net_snmp_version)
  no_net_snmp=""
  if test "${NET_SNMP_CONFIG}" = "no"; then
     no_net_snmp=yes
  else
    NET_SNMP_CFLAGS=`$NET_SNMP_CONFIG --cflags`
    NET_SNMP_LDFLAGS=`$NET_SNMP_CONFIG --ldflags`
    NET_SNMP_LIBS=`$NET_SNMP_CONFIG --libs`
    net_snmp_config_major_version=`$NET_SNMP_CONFIG --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\)/\1/'`
    net_snmp_config_minor_version=`$NET_SNMP_CONFIG --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\)/\2/'`

    ac_save_CFLAGS="$CFLAGS"
    ac_save_LDFLAGS="$LDFLAGS"
    ac_save_LIBS="$LIBS"
    CFLAGS="$CFLAGS $NET_SNMP_CFLAGS"
    LDFLAGS="$LDFLAGS $NET_SNMP_LDFLAGS"
    LIBS="$LIBS $NET_SNMP_LIBS"
  fi

  if test "x$no_net_snmp" = x ; then
     AC_MSG_RESULT(yes (version $net_snmp_config_major_version.$net_snmp_config_minor_version))
     ifelse([$2], , :, [$2])
  else
     AC_MSG_RESULT(no)
     if test "$NET_SNMP_CONFIG" = "no" ; then
       echo "*** The net-snmp-config script installed by net-snmp could not be found"
       echo "*** If net-snmp was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the NET_SNMP_CONFIG environment variable to the"
       echo "*** full path to net-snmp-config."
     fi
     ifelse([$3], , :, [$3])
  fi

  AC_SUBST(NET_SNMP_CFLAGS)
  AC_SUBST(NET_SNMP_LDFLAGS)
  AC_SUBST(NET_SNMP_LIBS)
  AC_SUBST(NET_SNMP_PREFIX)
])

dnl *-*wedit:notab*-*  Please keep this as the last line.
