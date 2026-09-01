# SPDX-License-Identifier: ISC
# SPDX-URL: https://spdx.org/licenses/ISC.html
#
# Copyright (C) 2012 William Pitcock <nenolod@dereferenced.org>
# Copyright (C) 2012 Jilles Tjoelker <jilles@stack.nl>
# Copyright (C) 2014 Rylai <gando.depth@gmail.com>
# Copyright (C) 2018-2020 Aaron M. D. Jones <me@aaronmdjones.net>
# Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)

.PHONY: serno.h

include ../extra.mk

DISTCLEAN = instpaths.h serno.h sysconf.h

includesubdir = .

pre-depend: ${DISTCLEAN}

instpaths.h: ../extra.mk instpaths.h.in
	$(info Generate: $@)
	@$(SED)                                     \
		-e 's|@BINDIR[@]|$(bindir)|g'           \
		-e 's|@DATADIR[@]|$(DATADIR)|g'         \
		-e 's|@DOCDIR[@]|$(DOCDIR)|g'           \
		-e 's|@LOCALEDIR[@]|$(LOCALEDIR)|g'     \
		-e 's|@LOGDIR[@]|$(LOGDIR)|g'           \
		-e 's|@MODDIR[@]|$(MODDIR)|g'           \
		-e 's|@PREFIX[@]|$(prefix)|g'           \
		-e 's|@RUNDIR[@]|$(RUNDIR)|g'           \
		-e 's|@SHAREDIR[@]|$(SHAREDIR)|g'       \
		-e 's|@SYSCONFDIR[@]|$(sysconfdir)|g'   \
	< "$@.in" > "$@"

serno.h:
	@sh mkserno.sh

include ../buildsys.mk
