VER := 3
KBUILD_CFLAGS_MODULE += -D BT_VER=$(VER) -D SALVAGE -I /lib/modules/$(shell uname -r)/build -I /usr/src/linux-source-6.8.0/linux-source-6.8.0
obj-m := blockthru$(VER).o
blockthru$(VER)-objs := blockthru_main.o partscan.o persist.o salvage.o
KDIR := /lib/modules/$(shell uname -r)/build

PWD := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

ins:
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	if [ -e /dev/bt$(VER)t ]; then printf "bt$(VER)t" > /sys/module/blockthru$(VER)/parameters/delete; sleep 1; fi
	if [ -e /sys/module/blockthru$(VER) ]; then rmmod blockthru$(VER).ko; fi
	insmod blockthru$(VER).ko && printf bt$(VER)t > /sys/module/blockthru$(VER)/parameters/create

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
