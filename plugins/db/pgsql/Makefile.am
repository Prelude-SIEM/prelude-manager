DEFS=@defined@

INCLUDES = -I$(top_srcdir)/libmissing -I$(top_srcdir) \
           -I$(top_srcdir)/src/include -I@PGSQL_INCLUDEDIR@

pgsql_la_LDFLAGS = -module -avoid-version

if HAVE_PGSQL

pgsql_la_SOURCES = pgsql.c
pgsql_la_LIBADD = @PGSQL_LIBDIR@ -lpq
pgsqldir = $(libdir)/prelude/db

pgsql_LTLIBRARIES = pgsql.la

endif
