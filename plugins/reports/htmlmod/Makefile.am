DEFS += @defined@ -DPRELUDE_REPORT_CONF=\"@prelude_report_conf@\"

INCLUDES = -I$(top_srcdir)/libmissing -I$(top_srcdir) \
           -I$(top_srcdir)/src/include \
           @LIBPRELUDE_CFLAGS@

noinst_HEADERS = html.h

htmlmod_la_SOURCES = htmlmod.c html.c
htmlmod_la_LDFLAGS = -module -avoid-version
htmlmoddir = $(libdir)/prelude/reports
htmlmod_LTLIBRARIES = htmlmod.la
