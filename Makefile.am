SUBDIRS = libmissing manager-adduser src plugins

preludeconfdir = $(configdir)
preludeconf_DATA = prelude-manager.conf

EXTRA_DIST = $(preludeconf_DATA) config.h \
             AUTHORS COPYING INSTALL NEWS README \
             ChangeLog

install-data-local:
	$(INSTALL) -d /var/lib/prelude
	$(INSTALL) -d /var/spool/prelude
