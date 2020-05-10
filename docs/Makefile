# Copyright (c) 2012, Intel Corporation
# All rights reserved.

# -*- mode: Makefile; -*-

#
# docs makefile
#

ROOTDIR ?= $(CURDIR)/..

include $(ROOTDIR)/Config.mk
TBOOT_MANPATH ?= $(DISTDIR)/usr/share/man


#
# universal rules
#


build : 


dist : install


install :
	[ -d $(TBOOT_MANPATH)/man8 ] || $(INSTALL_DIR) $(TBOOT_MANPATH)/man8
	$(INSTALL_DATA) -t $(TBOOT_MANPATH)/man8 man/acminfo.8 man/lcp_readpol.8 man/lcp_writepol.8 man/tb_polgen.8 man/txt-stat.8


clean :

mrproper : clean

distclean : clean


#
# dependencies
#


#
# implicit rules
#

