#!/bin/sh
# from output of rcorder, make launchd.conf

rm -f launchd.conf
# remove directory portion

for i in `/sbin/rcorder /etc/rc.d/*`
do
	echo "load /etc/launchd/rc_plist/"`basename $i`".plist" >> launchd.conf
done

