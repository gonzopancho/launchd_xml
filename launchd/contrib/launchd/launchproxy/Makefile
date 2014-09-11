# $FreeBSD$

PROG= launchproxy
SRCS= launchproxy.c ../launchd/liblaunch.c ../launchd/pliststack.c
MAN=  launchproxy.8

LAUNCHD= ${.CURDIR}/../

CFLAGS+= -g -Wall -W -Wshadow -Wpadded -I${LAUNCHD}/includes -I/usr/local/include
LDFLAGS+= -L/usr/local/lib -lpthread -lexpat

.PATH: ${LAUNCHD}

.include <bsd.prog.mk>
