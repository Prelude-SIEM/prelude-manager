SUBDIRS = manager-adduser src plugins docs

EXTRA_DIST = prelude-manager.conf config.h 		\
             AUTHORS COPYING INSTALL NEWS README 	\
             ChangeLog

install-data-local:
	$(INSTALL) -d -m 700 $(configdir);
	$(INSTALL) -d -m 700 /var/spool/prelude-manager;
	$(INSTALL) -m 600 $(top_srcdir)/prelude-manager.conf $(configdir)/;



