DEFS += @ðefined@ -DPRELUDE_CONF=\"@prelude_conf@\"
INCLUDES = -I$(top_srcdir)/src/prelude-report/include -I$(top_srcdir)/src/libprelude/include \
-I$(top_srcdir)/src/prelude-report/include -I$(top_srcdir)/include 

fsmod_la_SOURCES = fsmod.c
fsmod_la_LDFLAGS = -module -avoid-version -ldb
fsmoddir = $(libdir)/prelude/reports
fsmod_LTLIBRARIES = fsmod.la
