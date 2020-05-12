AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @LIBPRELUDE_CFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@

relaying_la_LDFLAGS = -module -avoid-version
relaying_la_SOURCES = relaying.c
relayingdir = $(libdir)/prelude-manager/reports
relaying_LTLIBRARIES = relaying.la


-include $(top_srcdir)/git.mk
