DEFS=@defined@

INCLUDES = -I$(top_srcdir)/libmissing -I$(top_srcdir) \
           -I$(top_srcdir)/src/include \
           @LIBPRELUDE_CFLAGS@

prelude_nids_la_SOURCES = decode.c
prelude_nids_la_LDFLAGS = -module -avoid-version
prelude_nidsdir = $(libdir)/prelude/decodes
prelude_nids_LTLIBRARIES = prelude-nids.la
