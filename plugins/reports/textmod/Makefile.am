AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @LIBPRELUDE_CFLAGS@ 
AM_CFLAGS = @GLOBAL_CFLAGS@

textmod_la_SOURCES = textmod.c
textmod_la_LDFLAGS = -module -avoid-version
textmoddir = $(libdir)/prelude-manager/reports
textmod_LTLIBRARIES = textmod.la

-include $(top_srcdir)/git.mk
