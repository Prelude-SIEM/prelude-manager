SUBDIRS = include

INCLUDES = -I$(top_srcdir)/ -I$(top_srcdir)/libmissing -I$(srcdir)/include/ @LIBPRELUDE_CFLAGS@
DEFS = @defined@ -DCONFIG_DIR=\"@configdir@\"       \
        -DREPORT_PLUGIN_DIR=\"@report_plugin_dir@\" \
	-DDECODE_PLUGIN_DIR=\"@decode_plugin_dir@\" \
	-DDB_PLUGIN_DIR=\"@db_plugin_dir@\"         \
	-DLOCALSTATEDIR=\"@localstatedir@\"

bin_PROGRAMS = prelude-manager
prelude_manager_LDADD = @COMMON_LIBS@ @LIBWRAP_LIBS@ @LIBPRELUDE_LIBS@
prelude_manager_LDFLAGS = -export-dynamic 

prelude_manager_SOURCES =			\
			pconfig.c		\
			prelude-manager.c	\
			db-plugins.c		\
			report-plugins.c	\
			server-logic.c		\
			server-generic.c	\
			sensor-server.c		\
			admin-server.c		\
			ssl.c			\
			decode-plugins.c	\
			alert-scheduler.c	\
			idmef-func.c		\
			idmef-message-read.c	\
			idmef-db-output.c	\
			ntp.c			\
			plugins-util.c	


