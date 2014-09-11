# Makefile for launchctl
# Formatted in a way that new object files are easy to add

PROG=   launchctl
SRCS=   launchctl.c liblaunch.c pliststack.c

CFLAGS= -I../includes -I../../expat/lib
CFLAGS+= -D_XML_CONF_

DPADD=  ${LIBUTIL} ${LIBREADLINE} ${LIBPTHREAD} ${LIBBSDXML} ${LIBNCURSES}
LDADD=  -lutil -lreadline -lpthread -lbsdxml -lncurses

NO_SHARED?=     YES

.include <bsd.prog.mk>

