DEFS=@defined@ -DPRELUDE_REPORT_CONF=\"@prelude_report_conf@\"

INCLUDES = -I$(top_srcdir)/libmissing -I$(top_srcdir) \
           -I$(top_srcdir)/src/include \
           @LIBPRELUDE_CFLAGS@

mysql_la_SOURCES = mysql.c
mysql_la_LIBADD   = -lmysqlclient
mysql_la_LDFLAGS = -module -avoid-version
mysqldir = $(libdir)/prelude/reports
mysql_LTLIBRARIES = mysql.la
