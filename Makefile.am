SUBDIRS = manager-adduser src plugins

preludeconfdir = $(configdir)
preludeconf_DATA = prelude-manager.conf

EXTRA_DIST = $(preludeconf_DATA) config.h \
             AUTHORS COPYING INSTALL NEWS README \
             ChangeLog

install-data-local:
	$(INSTALL) -d -m 700 /var/spool/prelude-manager




