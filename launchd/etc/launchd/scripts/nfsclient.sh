#!/bin/sh
#
# Removed dependency from /etc/rc.

# Load nfs module if it was not compiled into the kernel
nfsclient_precmd()
{
	if ! sysctl vfs.nfs >/dev/null 2>&1; then
		if ! kldload nfsclient; then
			warn 'Could not load nfs client module'
			return 1
		fi
	fi
	return 0
}

nfsclient_start()
{
	#
	# Set some nfs client related sysctls
	#

	if [ -n "${nfs_access_cache}" ]; then
		echo "NFS access cache time=${nfs_access_cache}"
		sysctl vfs.nfs.access_cache_timeout=${nfs_access_cache} >/dev/null
	fi
	if [ -n "${nfs_bufpackets}" ]; then
		 sysctl vfs.nfs.bufpackets=${nfs_bufpackets} > /dev/null
	fi

	unmount_all
}

unmount_all()
{
	# If /var/db/mounttab exists, some nfs-server has not been
	# successfully notified about a previous client shutdown.
	# If there is no /var/db/mounttab, we do nothing.
	if [ -f /var/db/mounttab ]; then
		rpc.umntall -k
	fi
}

# start here
# used to emulate "requires/provide" functionality
pidfile="/var/run/nfsclient.pid"
touch $pidfile
nfsclient_precmd
nfsclient_start
exit 0
