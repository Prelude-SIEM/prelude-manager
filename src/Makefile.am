INCLUDES = -I$(top_srcdir)/include
DEFS = @defined@ -DCONFIG_DIR=\"@configdir@\" -DPRELUDE_REPORT_CONF=\"@prelude_report_conf@\" -DREPORT_PLUGIN_DIR=\"@report_plugin_dir@\" -DLOCALSTATEDIR=\"@localstatedir@\"

bin_PROGRAMS = prelude_report
prelude_report_LDADD = @COMMON_LIBS@ @LIBWRAP_LIBS@ -lprelude
prelude_report_LDFLAGS = -export-dynamic 

prelude_report_SOURCES =		\
	pconfig.c			\
	cnx.c				\
	prelude-report.c		\
	report-plugins.c		\
	server.c			\
	report-infos.c			\
	optparse.c auth.c		\
	tcpdump-func.c			\
	ssl.c				\
	ssl-register-client.c

