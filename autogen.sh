aclocal -I m4
autoconf
autoheader
libtoolize -c --force
automake --gnu -a -c
#./configure
