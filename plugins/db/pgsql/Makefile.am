DEFS=-I$(top_srcdir) -I$(top_srcdir)/src/include -I@PGSQL_INCLUDEDIR@ @defined@
pgsql_la_LDFLAGS = -module -avoid-version

if HAVE_PGSQL

pgsql_la_SOURCES = pgsql.c
pgsql_la_LIBADD = -L@PGSQL_LIBDIR@ -lpq
pgsqldir = $(db_plugin_dir)
pgsql_LTLIBRARIES = pgsql.la

sqlscript_DATA = postgres.sql
sqlscriptdir = $(manager_data_dir)/pgsql

EXTRA_DIST = $(sqlscript_DATA)

endif
