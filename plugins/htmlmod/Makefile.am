DEFS += @defined@ -DPRELUDE_REPORT_CONF=\"@prelude_report_conf@\"
INCLUDES = -I$(top_srcdir)/src/prelude-report/include -I$(top_srcdir)/src/libprelude/include \
-I$(top_srcdir)/src/prelude-report/include -I$(top_srcdir)/include 

noinst_HEADERS = html.h

htmlmod_la_SOURCES = htmlmod.c html.c
htmlmod_la_LDFLAGS = -module -avoid-version
htmlmoddir = $(libdir)/prelude/reports
htmlmod_LTLIBRARIES = htmlmod.la
