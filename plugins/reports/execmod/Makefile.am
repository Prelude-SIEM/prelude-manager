DEFS=@defined@

INCLUDES = -I$(top_srcdir)/libmissing -I$(top_srcdir) \
           -I$(top_srcdir)/src/include \
           @LIBPRELUDE_CFLAGS@

execmod_la_SOURCES = execmod.c
execmod_la_LDFLAGS = -module -avoid-version
execmoddir = $(libdir)/prelude/reports
execmod_LTLIBRARIES = execmod.la
