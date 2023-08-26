VER := 1
CFLAGS = -DMAKE_VER=$(VER)
obj-m := blockthru$(VER).o
blockthru$(VER)-objs := blockthru_main.o partscan.o persist.o
KDIR := /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

ins:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	if [ -e /dev/bt$(VER)t ]; then echo 1 > /sys/block/bt$(VER)t/blockthru/delete; sleep 1; fi
	if [ -e /sys/module/blockthru$(VER) ]; then rmmod blockthru$(VER).ko; fi
	insmod blockthru$(VER).ko && printf bt$(VER)t > /sys/module/blockthru$(VER)/parameters/create

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean