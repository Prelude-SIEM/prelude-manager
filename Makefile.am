SUBDIRS = manager-adduser src plugins docs

bin_SCRIPTS = prelude-manager-db-create.sh

EXTRA_DIST = prelude-manager.conf config.h 		\
             AUTHORS COPYING INSTALL NEWS README 	\
             ChangeLog prelude-manager-db-create.sh

install-data-local:
	$(INSTALL) -d -m 700 $(DESTDIR)/$(configdir);
	$(INSTALL) -d -m 700 $(DESTDIR)/$(manager_fifo_dir)
	@if test -f $(DESTDIR)/$(configdir)/prelude-manager.conf; then                                                  \
		$(INSTALL) -m 600 $(top_srcdir)/prelude-manager.conf $(DESTDIR)/$(configdir)/prelude-manager.conf-dist; \
		echo "********************************************************************************";     		\
		echo;											     		\
		echo "$(DESTDIR)/$(configdir)/prelude-manager.conf already exist...";                                   \
		echo "Installing default configuration in $(DESTDIR)/$(configdir)/prelude-manager.conf-dist";           \
		echo;                                                                                        		\
		echo "********************************************************************************";     		\
	else                                                                                                 		\
		$(INSTALL) -m 600 $(top_srcdir)/prelude-manager.conf $(DESTDIR)/$(configdir)/;                          \
	fi                                                                                                   


