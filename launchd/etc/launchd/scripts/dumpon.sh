#!/bin/sh
#
# Removed dependency from /etc/rc.

dumpon_try()
{
	if /sbin/dumpon -v "${1}" ; then
		# Make a symlink in devfs for savecore
		ln -fs "${1}" /dev/dumpdev
		return 0
	fi
	return 1
}

dumpon_start()
{
	# Enable dumpdev so that savecore can see it. Enable it
	# early so a crash early in the boot process can be caught.
	#
	case ${dumpdev} in
	[Nn][Oo] | '')
		;;
	[Aa][Uu][Tt][Oo])
		dev=$(/bin/kenv -q dumpdev)
		if [ -n "${dev}" ] ; then
			dumpon_try "${dev}"
			return $?
		fi
		while read dev mp type more ; do
			[ "${type}" = "swap" ] || continue
			[ -c "${dev}" ] || continue
			dumpon_try "${dev}" 2>/dev/null && return 0
		done </etc/fstab
		echo "No suitable dump device was found." 1>&2
		return 1
		;;
	*)
		dumpon_try "${dumpdev}"
		;;
	esac
}

dumpon_stop()
{
	case ${dumpdev} in
	[Nn][Oo] | '')
		;;
	*)
		rm -f /dev/dumpdev
		/sbin/dumpon -v off
		;;
	esac
}

# start here
# used to emulate "requires/provide" functionality
pidfile="/var/run/dumpon.pid"
touch $pidfile

dumpon_start
exit 0
