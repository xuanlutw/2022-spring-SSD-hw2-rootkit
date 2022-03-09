obj-m = rootkit.o
PWD := $(shell pwd)
EXTRA_CFLAGS = -Wall -g

all:
	$(MAKE) ARCH=arm64 CROSS_COMPILE=$(CROSS) -C $(KDIR) M=$(PWD) modules
	$(CROSS)gcc -Wall -static test.c -o test

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
