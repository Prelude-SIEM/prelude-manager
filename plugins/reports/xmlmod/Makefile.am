DEFS=-D_FILE_OFFSET_BITS=64 -I$(top_srcdir) -I$(top_srcdir)/src/include @XML2_CFLAGS@ \
     -DIDMEF_DTD=\"@manager_data_dir@/xmlmod/idmef-message.dtd\" @defined@

xmlmod_la_LDFLAGS = -module -avoid-version

if HAVE_XML2

xmlmod_la_SOURCES = xmlmod.c
xmlmod_la_LIBADD  = @XML2_LIBS@
xmlmoddir = $(report_plugin_dir)
xmlmod_LTLIBRARIES = xmlmod.la

xmldtd_DATA = idmef-message.dtd
xmldtddir   = $(manager_data_dir)/xmlmod

EXTRA_DIST = $(xmldtd_DATA)

endif
