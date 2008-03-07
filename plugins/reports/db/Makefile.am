AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @LIBPRELUDE_CFLAGS@ @LIBPRELUDEDB_CFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@ 

db_la_LDFLAGS = -module -avoid-version

if HAVE_LIBPRELUDEDB

db_la_SOURCES = db.c
db_la_LIBADD = @LIBPRELUDEDB_LIBS@
dbdir = $(libdir)/prelude-manager/reports
db_LTLIBRARIES = db.la

endif
