# Makefile for launchd

PROG=   launchd
SRCS=   launchd.c liblaunch.c launchd_core_logic.c launchd_unix_ipc.c \
        init.c launch_pliststack.c launch_log.c launch_util.c

DPADD=  ${LIBBSDXML} ${LIBUTIL} ${LIBSSL} ${LIBCRYPTO}
LDADD=  -lbsdxml -lutil -lssl -lcrypto

CONTRIBDIR=	${.CURDIR}/../../contrib/launchd

CFLAGS= -I${CONTRIBDIR}/includes
CFLAGS+= -D_XML_CONF_
# Uncomment lines to compile with SolidBase support
#CFLAGS+= -D_SQL_CONF_
#SRCS+=	launch_sb_if.c
#DPADD+= ${LIBSOLIDB}
#LDADD+= -lsolidb

#DEBUG_FLAGS+= -g

NO_SHARED?=     YES
MAN=	${CONTRIBDIR}/doc/launchd.8 ${CONTRIBDIR}/doc/launchd.plist.5

.PATH:	${CONTRIBDIR}/launchd ${CONTRIBDIR}/common
BINDIR=	/sbin

.include <bsd.prog.mk>

