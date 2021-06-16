obj-m += lisakmod.o

all:
	bash genalladdrs.sh /boot/System.map-$(shell uname -r) && make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	
clean:
	rm symbol_addrs.h && make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean