#!/bin/sh

rm -rf autom4te.cache
rm -f configure config.h.in libnfs.pc

IPATHS="-I ./include -I ../include -I ./include -I ./mount -I ./nfs -I ./portmap"

autoheader $IPATHS || exit 1
autoconf $IPATHS || exit 1

rm -rf autom4te.cache

echo "Now run ./configure and then make."
exit 0

