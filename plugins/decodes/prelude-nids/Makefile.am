DEFS=@defined@
INCLUDES = -I$(top_srcdir) -I$(top_srcdir)/src/include

prelude_nids_la_SOURCES = decode.c packet-decode.c optparse.c
prelude_nids_la_LDFLAGS = -module -avoid-version 
prelude_nidsdir = $(decode_plugin_dir)
prelude_nids_LTLIBRARIES = prelude-nids.la

noinst_HEADERS = nethdr.h nids-alert-id.h packet.h optparse.h ethertype.h
