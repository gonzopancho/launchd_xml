#DEBUG=-g3 -ggdb3 
all:
	make -C ./launchd/sbin/launchctl
	make -C ./launchd/sbin/launchd
	make -C ./launch_xml
clean:
	make -C ./launchd/sbin/launchctl clean
	make -C ./launchd/sbin/launchd clean
	make -C ./launch_xml clean
install:
	make -C ./launch_xml install
	make -C ./launchd/sbin/launchctl install
	make -C ./launchd/sbin/launchd install
	if [ ! -d /etc/launchd ]; then \
		cp -R ./launchd/etc/launchd /etc/launchd; \
	fi
	if [ ! -f /etc/launchd.conf ]; then \
		cp ./launchd/etc/launchd.conf /etc/launchd.conf; \
	fi
	
backup: clean
	tar cvjf /tmp/launchd.tar.bz2 /etc/launchd* /root/xml
	scp /tmp/launchd.tar.bz2 buetow@joghurt.wlan:src
	rm /tmp/launchd.tar.bz2
