#!/bin/sh
#
# Removed dependency from /etc/rc.

devfs_start()
{
	if [ -n "$devfs_system_ruleset" -o -n "$devfs_set_rulesets" ]; then
		devfs_init_rulesets
		if [ -n "$devfs_system_ruleset" ]; then
			devfs_set_ruleset $devfs_system_ruleset /dev
			devfs_apply_ruleset $devfs_system_ruleset /dev
		fi
		if [ -n "$devfs_set_rulesets" ]; then
			local _dir_set
			local _dir
			local _set
			for _dir_set in $devfs_set_rulesets; do
				_dir=${_dir_set%=*}
				_set=${_dir_set#*=}
				devfs_set_ruleset $_set $_dir
				devfs_apply_ruleset $_set $_dir
			done
		fi
	fi
	read_devfs_conf
}

read_devfs_conf()
{
	if [ -r /etc/devfs.conf ]; then
		cd /dev
		while read action devicelist parameter; do
			case "${action}" in
			l*)	for device in ${devicelist}; do
					if [ -c ${device} -a ! -e ${parameter} ]; then
						ln -fs ${device} ${parameter}
					fi
				done
				;;
			o*)	for device in ${devicelist}; do
					if [ -c ${device} ]; then
						chown ${parameter} ${device}
					fi
				done
				;;
			p*)	for device in ${devicelist}; do
					if [ -c ${device} ]; then
						chmod ${parameter} ${device}
					fi
				done
				;;
			esac
		done < /etc/devfs.conf
	fi
}

# start here
# used to emulate "requires/provide" functionality
pidfile="/var/run/devfs.pid"
touch $pidfile

devfs_start
exit 0
