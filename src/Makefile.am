SUBDIRS = include

AM_CPPFLAGS = -I$(srcdir)/include/ -I$(top_srcdir)/libmissing \
        @defined@ -DCONFIG_DIR=\"@configdir@\" \
        -DREPORT_PLUGIN_DIR=\"@report_plugin_dir@\" \
        -DDECODE_PLUGIN_DIR=\"@decode_plugin_dir@\" \
        -DFILTER_PLUGIN_DIR=\"@filter_plugin_dir@\" \
        -DMANAGER_FIFO_DIR=\"@manager_fifo_dir@\" \
        -DMANAGER_RUN_DIR=\"@manager_run_dir@\"

bin_PROGRAMS = prelude-manager
prelude_manager_LDADD = @LIBWRAP_LIBS@ @LIBPRELUDE_LIBS@ @PTHREAD_CFLAGS@ \
                        @PTHREAD_LIBS@ $(top_builddir)/libmissing/libmissing.la

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

prelude_manager_LDFLAGS = -export-dynamic \
        -dlopen $(top_builddir)/plugins/decodes/prelude-nids/prelude-nids.la \
        -dlopen $(top_builddir)/plugins/filters/filter/filter.la \
        -dlopen $(top_builddir)/plugins/reports/debug2/debug2.la \
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
        plugins-util.c \
        reverse-relaying.c
