#include <sys/klog.h> 
#include <stdio.h>

int main(void)
{
    char arr[11] = "abcdefghij";
    arr[10] = '\0';
    klogctl(11, arr, 10);
    return 0;
}
