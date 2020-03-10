obj-m += trace_runqlat.o

KERNELDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
all:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

clean:
	rm -rf *.ko *.mod *.mod.c *.o modules.* Module.symvers

install:
	insmod trace_runqlat.ko

remove:
	rmmod trace_runqlat
