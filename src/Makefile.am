SUBDIRS = include

INCLUDES = -I$(top_srcdir)/ -I$(top_srcdir)/libmissing -I$(srcdir)/include/ @LIBPRELUDE_CFLAGS@ @XML2_CFLAGS@  
DEFS = @defined@ -DCONFIG_DIR=\"@configdir@\"       \
        -DREPORT_PLUGIN_DIR=\"@report_plugin_dir@\" \
	-DDECODE_PLUGIN_DIR=\"@decode_plugin_dir@\" \
	-DLOCALSTATEDIR=\"@localstatedir@\"

bin_PROGRAMS = prelude-manager
prelude_manager_LDADD = @COMMON_LIBS@ @LIBWRAP_LIBS@ @LIBPRELUDE_LIBS@ @XML2_LIBS@
prelude_manager_LDFLAGS = -export-dynamic 

prelude_manager_SOURCES =			\
			pconfig.c		\
			prelude-manager.c	\
			report-plugins.c	\
			server.c		\
			server-logic.c		\
			ssl.c			\
			decode-plugins.c	\
			alert-scheduler.c	\
			idmef-func.c		\
			idmef-message-read.c	\
			api.c


