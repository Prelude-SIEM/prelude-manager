DEFS=@defined@

INCLUDES = -I$(top_srcdir)/libmissing -I$(top_srcdir) \
           -I$(top_srcdir)/src/include \
           @LIBPRELUDE_CFLAGS@

debug_la_SOURCES = debug.c
debug_la_LIBADD   = 
debug_la_LDFLAGS = -module -avoid-version
debugdir = $(libdir)/prelude-manager/reports
debug_LTLIBRARIES = debug.la
