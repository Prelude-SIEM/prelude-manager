DEFS=@defined@ -DPRELUDE_REPORT_CONF=\"@prelude_report_conf@\"
INCLUDES = -I$(top_srcdir)/src/prelude-report/include -I$(top_srcdir)/src/libprelude/include \
-I$(top_srcdir)/src/prelude-report/include -I$(top_srcdir)/include 

filemod_la_SOURCES = filemod.c
filemod_la_LDFLAGS = -module -avoid-version
filemoddir = $(libdir)/prelude/reports
filemod_LTLIBRARIES = filemod.la
