AM_CPPFLAGS=-I$(top_srcdir)/src/include -I$(top_srcdir)/libmissing	\
	@XML_CPPFLAGS@ @defined@ -DIDMEF_DTD=\"@manager_data_dir@/xmlmod/idmef-message.dtd\" 

xmlmod_la_LDFLAGS = -module -avoid-version

if HAVE_XML2

xmlmod_la_SOURCES = xmlmod.c
xmlmod_la_LIBADD  = @XML_LIBS@
xmlmoddir = $(report_plugin_dir)
xmlmod_LTLIBRARIES = xmlmod.la

xmldtd_DATA = idmef-message.dtd
xmldtddir   = $(manager_data_dir)/xmlmod

EXTRA_DIST = $(xmldtd_DATA)

endif
