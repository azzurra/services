#************************************************************************
#*   IRC - Internet Relay Chat, Makefile
#*   Copyright (C) 1990, Jarkko Oikarinen
#*
#*   This program is free software; you can redistribute it and/or modify
#*   it under the terms of the GNU General Public License as published by
#*   the Free Software Foundation; either version 1, or (at your option)
#*   any later version.
#*
#*   This program is distributed in the hope that it will be useful,
#*   but WITHOUT ANY WARRANTY; without even the implied warranty of
#*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#*   GNU General Public License for more details.
#*
#*   You should have received a copy of the GNU General Public License
#*   along with this program; if not, write to the Free Software
#*   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#*/
-include Makefile.inc
RM=/bin/rm

# Compile flags
CFLAGS += -pipe -Wall -O0 -g -Wshadow -Wcast-align -Wsign-compare -Wformat -Wformat-signedness -Werror=format
# linker flags.
LDFLAGS=

SHELL=/bin/sh
SUBDIRS=src
MAKE=make 'CFLAGS=${CFLAGS}' 'LDFLAGS=${LDFLAGS}'

all:	build

build: inc/sysconf.h $(SUBDIRS)

inc/sysconf.h:
	@$(SHELL) configure

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	@${RM} -f services
	@cd src; ${RM} -f *.o services; cd ..
	-@if [ -f inc/sysconf.h ] ; then \
	echo "To really restart installation, make distclean" ; \
	fi

distclean:
	@${RM} -f Makefile.inc configure.log services
	@cd inc; ${RM} -f sysconf.h; cd ..
	@cd src; ${RM} -f *.o services; cd ..

.PHONY: all build clean distclean $(SUBDIRS)
