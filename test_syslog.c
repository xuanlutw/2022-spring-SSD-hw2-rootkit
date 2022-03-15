#include <sys/klog.h> 
#include <stdio.h>
#include "rootkit.h"

int main(void)
{
    char arr[11] = "abcdefghij";
    klogctl(SYSLOG_ACTION_WRITE, arr, 10);
    return 0;
}
