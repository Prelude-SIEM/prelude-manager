SUBDIRS = manager-adduser src plugins docs

EXTRA_DIST = prelude-manager.conf config.h 		\
             AUTHORS COPYING INSTALL NEWS README 	\
             ChangeLog prelude-create-db.sh

install-data-local:
	$(INSTALL) -d -m 700 $(configdir);
	$(INSTALL) -d -m 700 /var/spool/prelude-manager;
	@if test -f $(top_srcdir)/prelude-manager.conf; then                                                 \
		$(INSTALL) -m 600 $(top_srcdir)/prelude-manager.conf $(configdir)/prelude-manager.conf-dist; \
		echo "********************************************************************************";     \
		echo;											     \
		echo "$(configdir)/prelude-manager.conf already exist...";                                   \
		echo "Installing default configuration in $(configdir)/prelude-manager.conf-dist";           \
		echo;                                                                                        \
		echo "********************************************************************************";     \
	else                                                                                                 \
		$(INSTALL) -m 600 $(top_srcdir)/prelude-manager.conf $(configdir)/;                          \
	fi                                                                                                   


