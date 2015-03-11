obj-m += test_lsm.o

ccflags-y := -std=gnu99 -Wno-declaration-after-statement

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	-rmmod test_lsm.ko
	insmod test_lsm.ko
	-rm -rf aaa; mkdir aaa; rm -rf aaa;
	#dmesg

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
