AUTOMAKE_OPTIONS = foreign

VERSION_INFO = 4:0:0

EXTRA_DIST = LICENSE Changes libev.m4 ev_vars.h ev_wrap.h ev_epoll.c ev_select.c ev_poll.c ev_kqueue.c ev_port.c ev_win32.c

libev_la_SOURCES = ev.c
libev_la_LDFLAGS = -version-info $(VERSION_INFO)

noinst_HEADERS = ev.h ev_vars.h ev_wrap.h
noinst_LTLIBRARIES = libev.la

-include $(top_srcdir)/git.mk
