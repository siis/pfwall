INIT_BOTTOM = $(DESTDIR)/usr/share/initramfs-tools/scripts/init-bottom/

CC = gcc
CFLAGS = -g
DIRS = fs_setup daemon interpreter_details
SH = /bin/bash

all: 
	-for d in $(DIRS); do (cd $$d; $(MAKE)); done

install: 
	-for d in $(DIRS); do (cd $$d; $(MAKE)); done
	-for d in $(DIRS); do (cd $$d; $(MAKE) install); done
	
clean:
	-for d in $(DIRS); do (cd $$d; $(MAKE) clean ); done

