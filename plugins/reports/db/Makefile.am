DEFS=-I$(top_srcdir) -I$(top_srcdir)/src/include @defined@ @db_cflags@

db_la_LDFLAGS = -module -avoid-version

if HAVE_DB

db_la_SOURCES = db.c
db_la_LIBADD = @db_libs@
dbdir = $(libdir)/prelude-manager/reports
db_LTLIBRARIES = db.la

endif