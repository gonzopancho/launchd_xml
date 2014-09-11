/* (C) 2014 by Optim Inc., Scott V. Kamp 
   outbackdingo@gmail.com 
 */


/* (C) 2007 by InfoWeapons Inc., Paul Buetow
   pbuetow@infoweapons.com
   launchd@dev.buetow.org
 */ 

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

//#define USELOGGING
#define LOGFILE "/var/log/nodaemon.log"

char *BINARY = NULL;
char *PIDFILE = NULL;

#ifdef USELOGGING
void logging(char *str) {
    FILE *fh = fopen(LOGFILE, "a");
    fprintf(fh, str);
    fclose(fh);
}
#endif

void termproc() {
    FILE *fh = fopen(PIDFILE, "r");
    if (fh == NULL)
        exit(errno);
    char buf[64];
    fgets(buf, 63, fh);
    fclose(fh);

#ifdef USELOGGING
    logging("Recv SIGTERM (");
    logging(BINARY);
    logging(",");
    logging(PIDFILE);
    logging(",pid=");
    logging(buf);
    logging(")\n");
#endif

    int pid = atoi(buf);
    int ret = kill(pid, SIGTERM);

    exit(ret);

}

void usage(char *appname) {
    fprintf(stderr, "%s executable pidfile\n", appname);
    fprintf(stderr, "\tExample: ");
    fprintf(stderr, "%s /usr/sbin/cron /var/run/cron.pid\n", appname);
}

int main(int argc, char** argv) {
    if (argc < 3) {
        fprintf(stderr, "Not enough arguments\n");
        usage(argv[0]);
        exit(1);
    }

    BINARY = argv[1];
    PIDFILE = argv[2];

    int ret = system(BINARY);
    if (ret) exit(ret);

    signal(SIGABRT, termproc);
    signal(SIGHUP, termproc);
    signal(SIGKILL, termproc);
    signal(SIGQUIT, termproc);
    signal(SIGTERM, termproc);

    unsigned int maxseconds = -1; // Unsigned underflow
    for (;;) sleep(maxseconds);

    return 0; // Never reach this point
}
