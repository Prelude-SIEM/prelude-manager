DEFS += @defined@

INCLUDES = -I$(top_srcdir)/libmissing -I$(top_srcdir) \
           -I$(top_srcdir)/src/include \
           @LIBPRELUDE_CFLAGS@

fsmod_la_SOURCES = fsmod.c
fsmod_la_LDFLAGS = -module -avoid-version -ldb
fsmoddir = $(libdir)/prelude/reports
fsmod_LTLIBRARIES = fsmod.la
