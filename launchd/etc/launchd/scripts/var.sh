#!/bin/sh
#
# Removed dependency from /etc/rc.

# start here
# used to emulate "requires/provide" functionality
pidfile="/var/run/var.pid"
touch $pidfile

_populate_var()
{
	/usr/sbin/mtree -deU -f /etc/mtree/BSD.var.dist -p /var > /dev/null
	case ${sendmail_enable} in
	[Nn][Oo][Nn][Ee])
		;;
	*)
		/usr/sbin/mtree -deU -f /etc/mtree/BSD.sendmail.dist -p / > /dev/null
		;;
	esac
}

# If we do not have a writable /var, create a memory filesystem for /var
# unless told otherwise by rc.conf.  We don't have /usr yet so use mkdir
# instead of touch to test.  We want mount to record its mounts so we
# have to make sure /var/db exists before doing the mount -a.
#
case "${varmfs}" in
[Yy][Ee][Ss])
	mount_md ${varsize} /var "${varmfs_flags}"
	;;
[Nn][Oo])
	;;
*)
	if (/bin/mkdir -p /var/.diskless 2> /dev/null); then
		rmdir /var/.diskless
	else
		mount_md ${varsize} /var "${varmfs_flags}"
	fi
esac

# If we have an empty looking /var, populate it, but only if we have
# /usr available.  Hopefully, we'll eventually find a workaround, but
# in realistic diskless setups, we're probably ok.
case "${populate_var}" in
[Yy][Ee][Ss])
	_populate_var
	;;
[Nn][Oo])
	exit 0
	;;
*)
	if [ -d /var/run -a -d /var/db -a -d /var/empty ] ; then
		true
	elif [ -x /usr/sbin/mtree ] ; then
		_populate_var
	else
		# We need mtree to populate /var so try mounting /usr.
		# If this does not work, we can not boot so it is OK to
		# try to mount out of order.
		mount /usr
		if [ ! -x /usr/sbin/mtree ] ; then
			exit 1
		else
			_populate_var
		fi
	fi
	;;
esac

# Make sure we have /var/log/lastlog and /var/log/wtmp files
if [ ! -f /var/log/lastlog ]; then
	cp /dev/null /var/log/lastlog
	chmod 644 /var/log/lastlog
fi
if [ ! -f /var/log/wtmp ]; then
	cp /dev/null /var/log/wtmp
	chmod 644 /var/log/wtmp
fi
