AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @LIBPRELUDE_CFLAGS@ @NET_SNMP_CFLAGS@ -DSNMP_MIB_DIR=\"@MANAGER_DATA_DIR@/snmp/\"
AM_CFLAGS = @GLOBAL_CFLAGS@

snmp_la_LDFLAGS = -module -avoid-version

if HAVE_NET_SNMP

snmp_la_SOURCES = snmp.c snmp.h
snmp_la_LIBADD = @NET_SNMP_LIBS@
snmpdir = $(libdir)/prelude-manager/reports
snmp_LTLIBRARIES = snmp.la

snmpmib_DATA = PRELUDE-SIEM-MIB.mib
snmpmibdir   = $(docdir)/snmp

EXTRA_DIST = $(snmpmib_DATA)

endif

-include $(top_srcdir)/git.mk
