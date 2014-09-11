/* (C) 2007 by InfoWeapons Inc., Paul Buetow
   pbuetow@infoweapons.com
   launchd@dev.buetow.org
 */ 

#include <ctype.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

void usage(char *appname) {
    fprintf(stderr, "Usage: %s option [args]\n", appname);
    fprintf(stderr, "\tExamples:\n");
    fprintf(stderr, "\t%s -fullmask mask (prints out the mask in full display)\n", appname);
    fprintf(stderr, "\t%s -fullmask 24 (prints out 255.255.255.0)\n", appname);
    fprintf(stderr, "\t%s -network ip mask (prints out the network addr)\n", appname);
    fprintf(stderr, "\t%s -network 192.168.2.1 24 (prints out 192.168.2.0)\n", appname);
}

long _ip2long(char *ip) {
    long l;
    char *next = NULL;

    l = strtoul(ip, &next, 10);
    l <<= 8;

    ip = strchr(ip, '.');
    if (ip == NULL) return 0;
    ++ip;
    l += strtoul(ip, &next, 10);
    l <<= 8;

    ip = strchr(ip, '.');
    if (ip == NULL) return 0;
    ++ip;
    l += strtoul(ip, &next, 10);
    l <<= 8;

    ip = strchr(ip, '.');
    if (ip == NULL) return 0;
    ++ip;
    l += strtoul(ip, &next, 10);

    return l;
}

long _mask2long(char *mask) {
    long l = 0;
    int imask = atoi(mask);

    if (imask > 32)
        imask = 24;

    for (int i = 0; i <= imask; ++i) {
        l += 1;
        l <<= 1;
    }

    for (int i = imask+1; i < 32; ++i)
        l <<= 1;

    return l;
}

void _long2ip(long l, char *str) {
    memset(str, '\0', 1024);

    long oct1 = (l & 0xFF000000) >> 24;
    long oct2 = (l & 0x00FF0000) >> 16;
    long oct3 = (l & 0x0000FF00) >> 8;
    long oct4 = (l & 0x000000FF);

    sprintf(str, "%lu.%lu.%lu.%lu", oct1, oct2, oct3, oct4);
}

void network(char *ip, char *mask) {
    long lip = isdigit(ip[0]) ? _ip2long(ip) : 0;
    long lnm = isdigit(mask[0]) ? _mask2long(mask) : _mask2long("24");

    char network[1024];
    _long2ip(lip & lnm, network);

    printf("%s\n", network);
}

void fullmask(int mask) {
    char temp[1024];

    memset(temp, '\0', 1024);
    sprintf(temp, "%d", mask);

    long lnm = _mask2long(temp);

    memset(temp, '\0', 1024);
    _long2ip(lnm, temp);

    printf("%s\n", temp);
}

int main(int argc, char** argv) {
    int exit = 1;

    if (argc >= 2) {
        if (strncmp(argv[1], "-network", 8) == 0) {
            network(argc < 3 ? "0.0.0.0" : argv[2], argc < 4 ? "24 " : argv[3]);
            exit = 0;

        } else if (strncmp(argv[1], "-fullmask", 9) == 0) {
            int mask = argc < 3 ? 24 : atoi(argv[2]);
            fullmask(mask);
            exit = 0;
        }
    }

    if (exit) {
        fprintf(stderr, "No such option\n");
        usage(argv[0]);
    }

    return exit;
}
