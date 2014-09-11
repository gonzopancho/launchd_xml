# Makefile for launchctl

PROG=   launchctl
SRCS=   launchctl.c liblaunch.c launch_pliststack.c \
	launch_log.c launch_util.c

#DPADD=  ${LIBUTIL} ${LIBREADLINE} ${LIBPTHREAD} ${LIBBSDXML} ${LIBNCURSES} \
#	${LIBSOLIDB}
#LDADD=  -lutil -lreadline -lpthread -lbsdxml -lncurses -lsolidb

DPADD=  ${LIBREADLINE} ${LIBPTHREAD} ${LIBNCURSES} ${LIBSSL} ${LIBCRYPTO} \
	${LIBUTIL}
LDADD=  -lreadline -lncurses -lpthread -lssl -lcrypto -lutil

CONTRIBDIR=	${.CURDIR}/../../contrib/launchd
CFLAGS= -I${CONTRIBDIR}/includes

CFLAGS+= -D_XML_CONF_
LDADD+= -lbsdxml

# Uncomment below to include SolidBase support
#CFLAGS+= -D_SQL_CONF_
#LDADD+= -lsolidb
#SRCS+= launch_sb_if.c

#DEBUG_FLAGS+= -g

NO_SHARED?=     YES
MAN=	${CONTRIBDIR}/doc/launchctl.1

.PATH: ${CONTRIBDIR}/launchctl ${CONTRIBDIR}/common 
BINDIR=	/sbin

.include <bsd.prog.mk>

