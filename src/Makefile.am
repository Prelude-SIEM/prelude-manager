SUBDIRS = include

DEFS = -I$(top_srcdir)/ -I$(srcdir)/include/        \
        @defined@ -DCONFIG_DIR=\"@configdir@\"      \
        -DREPORT_PLUGIN_DIR=\"@report_plugin_dir@\" \
	-DDECODE_PLUGIN_DIR=\"@decode_plugin_dir@\" \
	-DFILTER_PLUGIN_DIR=\"@filter_plugin_dir@\" \
	-DMANAGER_FIFO_DIR=\"@manager_fifo_dir@\"

bin_PROGRAMS = prelude-manager
prelude_manager_LDADD = @LIBWRAP_LIBS@ @LIBPRELUDE_LIBS@
prelude_manager_LDFLAGS = -export-dynamic 

prelude_manager_SOURCES =			\
			pconfig.c		\
			prelude-manager.c	\
			filter-plugins.c	\
			manager-auth.c		\
			pmsg-to-idmef.c         \
			report-plugins.c	\
			server-logic.c		\
			server-generic.c	\
			sensor-server.c		\
			decode-plugins.c	\
			idmef-message-scheduler.c \
			plugins-util.c		\
			reverse-relaying.c


