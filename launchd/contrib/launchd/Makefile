# Makefile for launchd
# by Joel M. Pareja, IWC

MAKE =make
LAUNCHD_DIR =./launchd
LAUNCHCTL_DIR =./launchctl
LAUNCHDEBUGD_DIR =./launchdebugd
LAUNCHPROXY_DIR =./launchproxy
DESTBINDIR =/sbin

all: launchd launchctl

launchd:
	@echo "Compiling launchd"
	make -f ${LAUNCHD_DIR}/Makefile

launchctl:
	@echo "Compiling launchctl"
	cd $(LAUNCHCTL_DIR) && make

launchdebugd:
	@echo "Compiling launchdebugd"
	cd $(LAUNCHDEBUGD) && make

launchproxy:
	@echo "Compiling launchproxy"
	cd $(LAUNCHPROXY) && make

install:
	@echo "Installing in /sbin"
	cp ${LAUNCHD_DIR}/launchd ${DESTBINDIR}
	cp ${LAUNCHCTL_DIR}/launchctl ${DESTBINDIR}
	@echo "To use launchd as init replacement, edit /boot/loader.conf."
	@echo "Add the line: "
	@echo "\tinit_path=\"\/sbin\/launchd\""
	@echo "\nEnjoy!"

