ACLOCAL_AMFLAGS = -I m4 -I libmissing/m4
SUBDIRS = docs libmissing plugins src

EXTRA_DIST = prelude-manager.conf config.h 				\
             AUTHORS COPYING HACKING.README INSTALL NEWS README 

install-data-local:
	$(INSTALL) -d -m 700 $(DESTDIR)$(configdir);
	$(INSTALL) -d -m 700 $(DESTDIR)$(manager_run_dir);
	$(INSTALL) -d -m 700 $(DESTDIR)$(manager_scheduler_dir);
	$(INSTALL) -d -m 700 $(DESTDIR)$(manager_failover_dir);
	@if test -f $(DESTDIR)$(configdir)/prelude-manager.conf; then                                                  \
		$(INSTALL) -m 600 $(top_srcdir)/prelude-manager.conf $(DESTDIR)$(configdir)/prelude-manager.conf-dist; \
		echo "********************************************************************************";     		\
		echo;											     		\
		echo "$(DESTDIR)$(configdir)/prelude-manager.conf already exist...";                                   \
		echo "Installing default configuration in $(DESTDIR)$(configdir)/prelude-manager.conf-dist";           \
		echo;                                                                                        		\
		echo "********************************************************************************";     		\
	else                                                                                                 		\
		$(INSTALL) -m 600 $(top_srcdir)/prelude-manager.conf $(DESTDIR)$(configdir)/;                          \
	fi                                                                                                   


