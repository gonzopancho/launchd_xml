#DEBUG=-g3 -ggdb3 
FLAGS=-Wall -pedantic -std=c99
CC=gcc
all: nodaemon seq netcalc launch_xml 
netcalc:
	$(CC) $(FLAGS) $(DEBUG) netcalc.c -o netcalc
nodaemon:
	$(CC) $(FLAGS) $(DEBUG) nodaemon.c -o nodaemon
seq:
	$(CC) $(FLAGS) $(DEBUG) seq.c -o seq
launch_xml:
	$(CC) $(FLAGS) $(DEBUG) launch_xml.c -o launch_xml -lbsdxml
	@echo Using /etc/pfsense.xml as default. 
	@echo Edit launch_xml.h for changing the dafault!
clean:
	for i in netcalc netcalc.core nodaemon nodaemon.core seq seq.core launch_xml launch_xml.core; do \
		if [ -f $$i ]; \
			then rm $$i; \
		fi \
	done
inst_nodaemon:
	cp -f nodaemon /sbin
inst_launch_xml:
	cp -f launch_xml /sbin
inst_netcalc:
	cp -f netcalc /bin/
inst_seq:
	cp -f seq /bin/
install: inst_nodaemon inst_launch_xml inst_seq inst_netcalc
	cp pfsense.xml /etc/pfsense.xml
deinst_nodaemon:
	if [ -f /sbin/nodaemon ]; then rm -f /sbin/nodaemon; fi
deinst_launch_xml:
	if [ -f /sbin/launch_xml ]; then rm -f /sbin/launch_xml; fi
deinst_seq:
	if [ -f /bin/seq ]; then rm -f /bin/seq; fi
deinst_netcalc:
	if [ -f /bin/netcalc ]; then rm -f /bin/netcalc; fi
deinstall: deinst_nodaemon deinst_launch_xml deinst_seq 
backup: clean
	tar cvjf /tmp/launchd.tar.bz2 /etc/launchd* /root/xml
	scp /tmp/launchd.tar.bz2 buetow@joghurt.wlan:src
	rm /tmp/launchd.tar.bz2
astyle:
	astyle *.c *.h
	rm -f *.orig
stats:
	sh -c 'wc -l *.c *.h'
