SUBDIRS = include

AM_CPPFLAGS = -I$(srcdir)/include/ -I$(top_srcdir)/libmissing @LIBGNUTLS_CFLAGS@ \
        @defined@ -DCONFIG_DIR=\"@configdir@\" \
        -DREPORT_PLUGIN_DIR=\"@report_plugin_dir@\" \
        -DDECODE_PLUGIN_DIR=\"@decode_plugin_dir@\" \
        -DFILTER_PLUGIN_DIR=\"@filter_plugin_dir@\" \
        -DMANAGER_SCHEDULER_DIR=\"@manager_scheduler_dir@\" \
        -DMANAGER_FAILOVER_DIR=\"@manager_failover_dir@\" \
        -DMANAGER_RUN_DIR=\"@manager_run_dir@\"

bin_PROGRAMS = prelude-manager
prelude_manager_LDADD = @LIBWRAP_LIBS@ @LIBPRELUDE_LIBS@ $(top_builddir)/libmissing/libmissing.la

if HAVE_XML2
 XML_OBJS= -dlopen $(top_builddir)/plugins/reports/xmlmod/xmlmod.la
endif

#
# FIXME: to be done once libtool support dlpreopening with shared library
# (libtool 2). Will break in case of static build otherwise.
#
#if HAVE_LIBPRELUDEDB
# DB_OBJS= -dlopen $(top_builddir)/plugins/reports/db/db.la
#endif

DLOPENED_OBJS=$(XML_OBJS) $(DB_OBJS)

prelude_manager_LDFLAGS = -export-dynamic @LIBPRELUDE_LDFLAGS@ \
        -dlopen $(top_builddir)/plugins/decodes/normalize/normalize.la \
        -dlopen $(top_builddir)/plugins/filters/idmef-criteria/idmef-criteria.la \
        -dlopen $(top_builddir)/plugins/reports/debug/debug.la \
        -dlopen $(top_builddir)/plugins/reports/relaying/relaying.la \
        -dlopen $(top_builddir)/plugins/reports/textmod/textmod.la \
        $(DLOPENED_OBJS)

prelude_manager_SOURCES = \
        manager-options.c \
        prelude-manager.c \
        filter-plugins.c \
        manager-auth.c \
        pmsg-to-idmef.c \
        report-plugins.c \
        server-logic.c \
        server-generic.c \
        sensor-server.c \
        decode-plugins.c \
        idmef-message-scheduler.c \
        reverse-relaying.c
