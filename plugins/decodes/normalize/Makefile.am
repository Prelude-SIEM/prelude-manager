AM_CPPFLAGS=-I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @LIBPRELUDE_CFLAGS@ @LIBMAXMINDDB_CFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@ @LIBMAXMINDDB_LIBS@

normalize_la_SOURCES = normalize.c
normalize_la_LDFLAGS = -module -avoid-version
normalizedir = $(libdir)/prelude-manager/decodes
normalize_LTLIBRARIES = normalize.la

-include $(top_srcdir)/git.mk
