DEFS=-I$(top_srcdir) -I$(top_srcdir)/src/include @defined@ @MYSQL_CFLAGS@
mysql_la_LDFLAGS = -module -avoid-version

if HAVE_MYSQL

mysql_la_SOURCES = mysql.c
mysql_la_LIBADD = @MYSQL_LIBS@
mysqldir = $(db_plugin_dir)
mysql_LTLIBRARIES = mysql.la

EXTRA_DIST = mysql.sql

install-data-local:
	$(INSTALL) -d -m 755 $(DESTDIR)/$(manager_data_dir)/mysql
	$(INSTALL) -m 600 $(srcdir)/mysql.sql $(DESTDIR)/$(manager_data_dir)/mysql; 
endif