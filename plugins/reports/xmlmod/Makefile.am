DEFS += @defined@

INCLUDES = -I$(top_srcdir)/libmissing -I$(top_srcdir) \
           -I$(top_srcdir)/src/include \
           @LIBPRELUDE_CFLAGS@

xmlmod_la_SOURCES = xmlmod.c
xmlmod_la_LDFLAGS = -module -avoid-version
xmlmoddir = $(libdir)/prelude/reports
xmlmod_LTLIBRARIES = xmlmod.la


