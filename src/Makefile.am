SUBDIRS = include

AM_CPPFLAGS = -I$(srcdir)/include/ -I$(top_srcdir)/libmissing -I$(top_srcdir)/libev @LIBPRELUDE_CFLAGS@ @LIBGNUTLS_CFLAGS@
AM_CFLAGS = @PRELUDE_MANAGER_CFLAGS@ @GLOBAL_CFLAGS@

bin_PROGRAMS = prelude-manager
prelude_manager_LDADD = @LIBPRELUDE_LIBS@ @LIBWRAP_LIBS@ $(top_builddir)/libev/libev.la $(top_builddir)/libmissing/libmissing.la @LTLIBMULTITHREAD@

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
        -dlopen $(top_builddir)/plugins/filters/thresholding/thresholding.la \
        -dlopen $(top_builddir)/plugins/reports/debug/debug.la \
        -dlopen $(top_builddir)/plugins/reports/relaying/relaying.la \
        -dlopen $(top_builddir)/plugins/reports/textmod/textmod.la \
        $(DLOPENED_OBJS)

prelude_manager_SOURCES = \
	bufpool.c	  \
        manager-options.c \
        prelude-manager.c \
        filter-plugins.c \
        manager-auth.c \
        pmsg-to-idmef.c \
        report-plugins.c \
        server-generic.c \
        sensor-server.c \
        decode-plugins.c \
        idmef-message-scheduler.c \
        reverse-relaying.c 
