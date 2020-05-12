AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @LIBPRELUDE_CFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@

script_la_SOURCES = script.c
script_la_LDFLAGS = -module -avoid-version
scriptdir = $(libdir)/prelude-manager/reports
script_LTLIBRARIES = script.la

-include $(top_srcdir)/git.mk
