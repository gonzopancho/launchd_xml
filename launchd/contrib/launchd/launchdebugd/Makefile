# $FreeBSD$

PROG= launchdebugd
SRCS= launchdebugd.c liblaunch.c
MAN=  launchdebugd.8

LAUNCHD= ${.CURDIR}/../
CFLAGS+= -g -Wall -W -Wshadow -Wpadded -I${LAUNCHD}/includes

.PATH: ${LAUNCHD}

.include <bsd.prog.mk>

