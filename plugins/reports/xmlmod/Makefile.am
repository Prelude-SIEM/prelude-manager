AM_CPPFLAGS = -I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing @XML_CPPFLAGS@ @LIBPRELUDE_CFLAGS@ -DIDMEF_DTD=\"@MANAGER_DATA_DIR@/xmlmod/idmef-message.dtd\"
AM_CFLAGS = @GLOBAL_CFLAGS@

xmlmod_la_LDFLAGS = -module -avoid-version

if HAVE_XML2

xmlmod_la_SOURCES = xmlmod.c
xmlmod_la_LIBADD  = @XML_LIBS@
xmlmoddir = $(libdir)/prelude-manager/reports
xmlmod_LTLIBRARIES = xmlmod.la

xmldtd_DATA = idmef-message.dtd
xmldtddir   = $(MANAGER_DATA_DIR)/xmlmod

EXTRA_DIST = $(xmldtd_DATA)

endif

-include $(top_srcdir)/git.mk
