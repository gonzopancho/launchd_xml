/* (C) 2014 by Optim Inc., Scott V. Kamp 
   outbackdingo@gmail.com 
 */


/* (C) 2007 by InfoWeapons Inc., Paul Buetow
   pbuetow@infoweapons.com
   launchd@dev.buetow.org
 */ 

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage(char *appname) {
    fprintf(stderr, "Usage: %s from to\n", appname);
    fprintf(stderr, "\tExamples:\n");
    fprintf(stderr, "\t%s 2 20 (prints out number sequence 2 to 20)\n", appname);
}

int main(int argc, char** argv) {
    int exit = -1;

    if (argc == 2) {
        if (strncmp(argv[1], "-h", 2) == 0) {
            usage(argv[0]);
            exit = 0;
        }

    } else if (argc == 3) {

        if (!isdigit(argv[1][0]) || !isdigit(argv[2][0])) {
            fprintf(stderr, "The arguments need to be (positive) digits!\n");
            usage(argv[0]);
            exit = 1;

        } else {
            int from = atoi(argv[1]);
            int to = atoi(argv[2]);

            for (int i = from; i <= to; ++i)  {
                if (i < 0) {
                    fprintf(stderr, "Range out of sync!\n");
                    return 1;
                }
                if (i < to)
                    printf("%d ", i);
                else
                    printf("%d", i);

                printf("\n");
                exit = 0;
            }
        }
    }

    if (exit == -1) {
        fprintf(stderr, "No such command!\n");
        usage(argv[0]);
        exit = 1;
    }

    return exit;
}
