DEFS=-I$(top_srcdir) -I$(top_srcdir)/src/include -I@PGSQL_INCLUDEDIR@ @defined@
pgsql_la_LDFLAGS = -module -avoid-version

if HAVE_PGSQL

pgsql_la_SOURCES = pgsql.c
pgsql_la_LIBADD = -L@PGSQL_LIBDIR@ -lpq
pgsqldir = $(db_plugin_dir)
pgsql_LTLIBRARIES = pgsql.la

EXTRA_DIST = postgres.sql

install-data-local:
	$(INSTALL) -d -m 755 $(DESTDIR)/$(manager_data_dir)/pgsql
	$(INSTALL) -m 600 $(srcdir)/postgres.sql $(DESTDIR)/$(manager_data_dir)/pgsql; 
endif
