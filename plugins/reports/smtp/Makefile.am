AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @LIBPRELUDE_CFLAGS@ @LIBPRELUDEDB_CFLAGS@
AM_CFLAGS = @GLOBAL_CFLAGS@

noinst_HEADERS = smtp-io.h

smtp_la_SOURCES = smtp.c smtp-io.c
smtp_la_LDFLAGS = -module -avoid-version
smtp_la_LIBADD = @LIBPRELUDEDB_LIBS@
smtpdir = $(libdir)/prelude-manager/reports
smtp_LTLIBRARIES = smtp.la

smtptemplate_DATA = template.example
smtptemplatedir   = $(docdir)/smtp

EXTRA_DIST = $(smtptemplate_DATA)


-include $(top_srcdir)/git.mk
