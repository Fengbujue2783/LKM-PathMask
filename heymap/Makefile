obj-m := heymap.o

KDIR ?= $(HOME)/linux-6.1.90
MDIR := $(realpath $(dir $(lastword $(MAKEFILE_LIST))))

ccflags-y += -std=gnu11 -Wno-unused-function

all:
	make -C $(KDIR) ARCH=x86_64 M=$(MDIR) modules
clean:
	make -C $(KDIR) ARCH=x86_64 M=$(MDIR) clean
