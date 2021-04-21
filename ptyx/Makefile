#
# ptyx driver module Makefile
#

bindir=/usr/bin


#*****************************************************************************
# KERNELRELEASE is set by the kernel make and will not be set unless this make
#  file calls the kernel make if the kernel version is 2.5 or greater.

ifeq ($(KERNELRELEASE),) 


# This section runs if the kernel is 2.5 or above. The utilities are first built
#  and then the kernel make file is called to set up the environment for the
#  build of a kernel modules.
  DRIVER_MODULE := ptyx.ko
  KDIR	:= /lib/modules/$(shell uname -r)/build
  PWD		:= $(shell pwd)

 all:
	$(MAKE) -C $(KDIR) M=$$PWD
#	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules


# This section will compile the driver module when the kernel is at 2.5 or
#  above and the Kernel make calls this make with KERNELRELEASE variable set 
#  while doing a module build.
else
  obj-m	+= ptyx.o
  ptyx-objs := ptymod.o ptym.o ptys.o ptyc.o
  
endif	#end of KERNELRELEASE.


install:
	mkdir -p $(DESTDIR)/lib/modules/`uname -r`/misc
	install -D -o root -g root -m 644 $(DRIVER_MODULE) $(DESTDIR)/lib/modules/`uname -r`/misc/$(DRIVER_MODULE)

clean:
	rm -f ptymod.o ptym.o ptys.o ptyc.o $(DRIVER_MODULE)

