DEFS=@defined@ @MYSQL_CFLAGS@

INCLUDES = -I$(top_srcdir)/libmissing -I$(top_srcdir) \
           -I$(top_srcdir)/src/include 

mysql_la_SOURCES = mysql.c
mysql_la_LIBADD = @MYSQL_LIBS@
mysql_la_LDFLAGS = -module -avoid-version
mysqldir = $(libdir)/prelude/db

mysql_LTLIBRARIES = mysql.la
