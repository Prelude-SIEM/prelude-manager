DEFS=@defined@ @MYSQL_CFLAGS@

INCLUDES = -I$(top_srcdir)/libmissing -I$(top_srcdir) \
           -I$(top_srcdir)/src/include 

mysql_la_LDFLAGS = -module -avoid-version

if HAVE_MYSQL

mysql_la_SOURCES = mysql.c
mysql_la_LIBADD = @MYSQL_LIBS@
mysqldir = $(libdir)/prelude/db
mysql_LTLIBRARIES = mysql.la

endif