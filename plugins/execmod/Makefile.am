DEFS=@defined@ -DPRELUDE_REPORT_CONF=\"@prelude_report_conf@\"
INCLUDES = -I$(top_srcdir)/src/prelude-report/include -I$(top_srcdir)/src/libprelude/include \
-I$(top_srcdir)/src/prelude-report/include -I$(top_srcdir)/include 

execmod_la_SOURCES = execmod.c
execmod_la_LDFLAGS = -module -avoid-version
execmoddir = $(libdir)/prelude/reports
execmod_LTLIBRARIES = execmod.la
