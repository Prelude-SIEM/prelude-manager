DEFS=-I$(top_srcdir) -I$(top_srcdir)/src/include @defined@ @LIBPRELUDEDB_CFLAGS@

db_la_LDFLAGS = -module -avoid-version

if HAVE_LIBPRELUDEDB

db_la_SOURCES = db.c
db_la_LIBADD = @LIBPRELUDEDB_LIBS@
dbdir = $(libdir)/prelude-manager/reports
db_LTLIBRARIES = db.la

endif
