INTRODUCTION:

This are some additional binaries to make launchd boot with configuration 
options from pfsense.xml. You need to specify the full path to pfsense.xml in 
the launch_xml.h header file. Those binaries are needed by the launchd scripts
in order to fetch the configuration values from pfsense.xml:

BINARIES:

/bin/netcalc (For calculating netmasks and network ip numbers)
Examples:
	./netcalc -fullmask mask (prints out the mask in full display)
	./netcalc -fullmask 24 (prints out 255.255.255.0)
	./netcalc -network ip mask (prints out the network addr)
	./netcalc -network 192.168.3.1 24 (prints out 192.168.3.0)

/bin/seq (For creading number sequences from shell scripts)
Examples:
	./seq 2 20 (prints out number sequence 2 to 20)

/sbin/launch_xml (For reading informations from /etc/pfsense.xml)
Examples:
	./launch_xml -dom (prints out the whole dom xml tree)
	./launch_xml -get key (prints out the specific key value)
	./launch_xml -get pfsense.version (prints out the version)
	./launch_xml -h (prints out this help)
	./launch_xml -keys (prints out all available keys)
	./launch_xml -num key (prints out how often 'key' is available)

/sbin/nodaemon (For watching daemonized programs using launchd)
Example: 
	./nodaemon /usr/sbin/cron /var/run/cron.pid

launch_xml seq and netcalc are needed by launchd scripts which are located at
/etc/launchd/scripts.  See "launch_xml -h" or "seq -h" for more informations.

HOW TO INSTALL:

make 
make install # As superuser
make clean 

BACKGROUND ON LAUNCHD

launchd's configuration file is located at /etc/launchd.conf. Its loading
all desired plist files.

plist files are located at /etc/launchd/rc_plist/. All services using 
launch_xml should be enabled (see inside the respective plist file):

	<key>RunAtLoad</key>
	<true/>
	<key>Disabled</key>
	<false/>

Launchd jobs kann be started directly or using a launchd script. All services
using launch_xml should using a launchd script. In the plist file the full
path can be set. Here is a full example of using cron with launch_xml (notice
that you should specify the path /etc/launchd/scripts/cron.sh twice!):

<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple Computer//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>cron</string>
	<key>Program</key>
	<string>/etc/launchd/scripts/cron.sh</string>
	<key>ProgramArguments</key>
	<array>
		<string>/etc/launchd/scripts/cron.sh</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>Disabled</key>
	<false/>
</dict>
</plist>

launchd then starts the cron.sh script. cron.sh fetches all values from xml
using launch_xml, set ups /etc/crontab and runs cron using:

exec /sbin/nodaemon /usr/sbin/cron /var/run/cron.pid 

nodaemon is needed, because cron can not run in foreground. nodaemon wraps 
the daemon process, so it can be controlled within launchd. Not all services
need /sbin/nodaemon, e.g. sshd supports the -D flag. launchd can not work with
services which run in background or do forking away or change the euid after
starting.

"launchctl list" gives you the full list of all running and not running 
services. The PID col shows you the PID of the service (Service is currently
running if set) and the Status col shows you the exit status of the service
(e.g. "0" means, job has completed with success and is not running any more. 
Any other status may appear, depends on how the service shuts down after
receiving SIGTERM).

Here a sample output of "launchctl list":

(Notice the dummy job, this one does nothing but sleeping, its there for 
testing stuff, if you dont want it, then just remove it)

PID	Status	Label
-	0	adjkerntz
-	0	save_entropy
-	0	periodic_weekly
-	0	periodic_monthly
-	0	periodic_daily
-	0	newsyslog
-	0	atrun
-	0	bgfsck
144	-	cron
139	-	sshd
137	-	ntpd
-	0	dmesg
134	-	syslogd
-	0	mountcritremote
129	-	devd
-	0	netif
61	-	hostname
-	0	fsck
-	0	early.sh
-	0	dummy
56	-	dhcpd
55	-	snmpd
54	-	lighttpd
-	0	dyndns

"launchctl stop cron" stops cron
"launchctl start cron" starts cron
"launchctl help" shows all available commands

WORKING / TESTED SERVICES:

The following launchd scripts already work with launch_xml on FreeBSD 
6.2-RELEASE. Maybe some few more tests need to be done to be sure to be bug 
free :)

/etc/launchd/scripts/cron.sh
/etc/launchd/scripts/dhcpd.sh
/etc/launchd/scripts/dyndns.sh
/etc/launchd/scripts/hostname.sh
/etc/launchd/scripts/lighttpd.sh
/etc/launchd/scripts/netif.sh
/etc/launchd/scripts/ntpd.sh
/etc/launchd/scripts/snmpd.sh
/etc/launchd/scripts/sshd.sh
/etc/launchd/scripts/syslogd.sh
/etc/launchd/scripts/timezone.sh

MISSING SERVICES / NYI

Not yet implemented services using launch_xml:

pf (to make it work some minor lauch_xml changes needed)
dyndns
vpn

No services using 'installedpackages' keys are used. Because not sure yet
which packages to use at all.

NEEDED ADDITIONAL PACKAGES:

dhcpd (for dhcpd.sh)
lighttpd (for lighttpd.sh)
mpd (for netif.sh)
openntpd (for ntpd.sh)

SO FAR KNOWN XML CONFIGURATION KEYS:

(for making pf work, some minor modification is needed, it must also recognize
empty xml tags, e.g.: <baz><foo><bar/></foo></baz> should be recognized as 
baz.foo=bar)

pfsense.version
pfsense.theme
pfsense.system.optimization
pfsense.system.hostname
pfsense.system.domain
pfsense.system.username
pfsense.system.password
pfsense.system.timezone
pfsense.system.timeservers
pfsense.system.webgui.protocol
pfsense.system.webgui.certificate
pfsense.system.webgui.private-key
pfsense.system.disablenatreflection
pfsense.system.enablesshd
pfsense.system.ssh.port
pfsense.system.disablechecksumoffloading
pfsense.interfaces.lan.if
pfsense.interfaces.lan.ipaddr
pfsense.interfaces.lan.subnet
pfsense.interfaces.lan.bandwidth
pfsense.interfaces.lan.bandwidthtype
pfsense.interfaces.wan.if
pfsense.interfaces.wan.bandwidth
pfsense.interfaces.wan.bandwidthtype
pfsense.interfaces.wan.ipaddr
pfsense.pppoe.username
pfsense.pppoe.password
pfsense.pppoe.provider
pfsense.dyndns.type
pfsense.dhcpd.lan.range.from
pfsense.dhcpd.lan.range.to
pfsense.dhcpd.lan.ddnsdomain
pfsense.snmpd.syslocation
pfsense.snmpd.syscontact
pfsense.snmpd.rocommunity
pfsense.snmpd.pollport
pfsense.filter.rule.type
pfsense.filter.rule.descr
pfsense.filter.rule.interface
pfsense.filter.rule.source.network
pfsense.cron.item.minute
pfsense.cron.item.hour
pfsense.cron.item.mday
pfsense.cron.item.month
pfsense.cron.item.wday
pfsense.cron.item.who
pfsense.cron.item.command
pfsense.cron.item.minute-2
pfsense.cron.item.hour-2
pfsense.cron.item.mday-2
pfsense.cron.item.month-2
pfsense.cron.item.wday-2
pfsense.cron.item.who-2
pfsense.cron.item.command-2
pfsense.cron.item.minute-3
pfsense.cron.item.hour-3
pfsense.cron.item.mday-3
pfsense.cron.item.month-3
pfsense.cron.item.wday-3
pfsense.cron.item.who-3
pfsense.cron.item.command-3
pfsense.cron.item.minute-4
pfsense.cron.item.hour-4
pfsense.cron.item.mday-4
pfsense.cron.item.month-4
pfsense.cron.item.wday-4
pfsense.cron.item.who-4
pfsense.cron.item.command-4
pfsense.cron.item.minute-5
pfsense.cron.item.hour-5
pfsense.cron.item.mday-5
pfsense.cron.item.month-5
pfsense.cron.item.wday-5
pfsense.cron.item.who-5
pfsense.cron.item.command-5
pfsense.cron.item.minute-6
pfsense.cron.item.hour-6
pfsense.cron.item.mday-6
pfsense.cron.item.month-6
pfsense.cron.item.wday-6
pfsense.cron.item.who-6
pfsense.cron.item.command-6
pfsense.cron.item.minute-7
pfsense.cron.item.hour-7
pfsense.cron.item.mday-7
pfsense.cron.item.month-7
pfsense.cron.item.wday-7
pfsense.cron.item.who-7
pfsense.cron.item.command-7
pfsense.cron.item.minute-8
pfsense.cron.item.hour-8
pfsense.cron.item.mday-8
pfsense.cron.item.month-8
pfsense.cron.item.wday-8
pfsense.cron.item.who-8
pfsense.cron.item.command-8
pfsense.installedpackages.package.name
pfsense.installedpackages.package.descr
pfsense.installedpackages.package.website
pfsense.installedpackages.package.category
pfsense.installedpackages.package.version
pfsense.installedpackages.package.status
pfsense.installedpackages.package.required_version
pfsense.installedpackages.package.maintainer
pfsense.installedpackages.package.depends_on_package_base_url
pfsense.installedpackages.package.depends_on_package-2
pfsense.installedpackages.package.depends_on_package-3
pfsense.installedpackages.package.config_file
pfsense.installedpackages.package.configurationfile
pfsense.installedpackages.menu.name
pfsense.installedpackages.menu.tooltiptext
pfsense.installedpackages.menu.section
pfsense.installedpackages.menu.url
pfsense.installedpackages.service.name
pfsense.installedpackages.service.description
pfsense.installedpackages.service.rcfile
pfsense.installedpackages.service.executable
pfsense.installedpackages.squid.config.active_interface
pfsense.installedpackages.squid.config.allow_interface
pfsense.installedpackages.squid.config.transparent_proxy
pfsense.installedpackages.squid.config.log_enabled
pfsense.installedpackages.squid.config.log_dir
pfsense.installedpackages.squid.config.proxy_port
pfsense.installedpackages.squid.config.visible_hostname
pfsense.installedpackages.squid.config.admin_email
pfsense.installedpackages.squid.config.error_language
pfsense.installedpackages.miniupnpd.config.enable
pfsense.installedpackages.miniupnpd.config.iface_array
pfsense.installedpackages.miniupnpd.config.download
pfsense.installedpackages.miniupnpd.config.upload
pfsense.installedpackages.miniupnpd.config.logpackets
pfsense.installedpackages.miniupnpd.config.sysuptime
pfsense.installedpackages.miniupnpd.config.permdefault
pfsense.installedpackages.miniupnpd.config.permuser1
pfsense.revision.description
pfsense.revision.time
