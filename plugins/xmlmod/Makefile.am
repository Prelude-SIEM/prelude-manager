DEFS += @defined@ -DPRELUDE_REPORT_CONF=\"@prelude_report_conf@\"
INCLUDES = -I$(top_srcdir)/src/prelude-report/include -I$(top_srcdir)/src/libprelude/include \
-I$(top_srcdir)/src/prelude-report/include -I$(top_srcdir)/include 

xmlmod_la_SOURCES = xmlmod.c
xmlmod_la_LDFLAGS = -module -avoid-version
xmlmoddir = $(libdir)/prelude/reports
xmlmod_LTLIBRARIES = xmlmod.la


