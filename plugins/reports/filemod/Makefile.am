DEFS=@defined@

INCLUDES = -I$(top_srcdir)/libmissing -I$(top_srcdir) \
           -I$(top_srcdir)/src/include \
           @LIBPRELUDE_CFLAGS@

filemod_la_SOURCES = filemod.c
filemod_la_LDFLAGS = -module -avoid-version
filemoddir = $(libdir)/prelude/reports
filemod_LTLIBRARIES = filemod.la
