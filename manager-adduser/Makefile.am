DEFS = @LIBPRELUDE_CFLAGS@ -DCONFIG_DIR=\"@configdir@\"
INCLUDES = -I$(top_srcdir)/src/include

bin_PROGRAMS = manager-adduser
manager_adduser_LDADD = @LIBPRELUDE_LIBS@
manager_adduser_SOURCES = manager-adduser.c ssl-register-client.c
noinst_HEADERS = ssl-register-client.h


