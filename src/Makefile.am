SUBDIRS = include

INCLUDES = @LIBPRELUDE_CFLAGS@ @LIBPRELUDE_SENSORS_CFLAGS@ \
           -I$(top_srcdir)/ -I$(top_srcdir)/libmissing -I$(srcdir)/include/

DEFS = @defined@ -DCONFIG_DIR=\"@configdir@\"       \
        -DREPORT_PLUGIN_DIR=\"@report_plugin_dir@\" \
	-DDECODE_PLUGIN_DIR=\"@decode_plugin_dir@\" \
	-DLOCALSTATEDIR=\"@localstatedir@\"

bin_PROGRAMS = prelude-manager
prelude_report_LDADD = @COMMON_LIBS@ @LIBWRAP_LIBS@ @LIBPRELUDE_LIBS@ -lpthread
prelude_report_LDFLAGS = -export-dynamic 

prelude_report_SOURCES =			\
			auth.c			\
			pconfig.c		\
			prelude-manager.c	\
			report-plugins.c	\
			server.c		\
			server-logic.c		\
			ssl-register-client.c	\
			ssl.c			\
			decode-plugins.c	\
			alert-fifo.c
