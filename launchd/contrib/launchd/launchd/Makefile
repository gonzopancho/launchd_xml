# Makefile for launchd 

PROG=	launchd
SRCS=	launchd.c liblaunch.c launchd_core_logic.c launchd_unix_ipc.c \
	init.c pliststack.c

CFLAGS=	-I../includes -I../../expat/lib
CFLAGS+= -D_XML_CONF_

DPADD=	${LIBBSDXML} ${LIBUTIL}
LDADD=	-lbsdxml -lutil

NO_SHARED?=     YES

.include <bsd.prog.mk>
