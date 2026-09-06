# SPDX-License-Identifier: ISC
# SPDX-URL: https://spdx.org/licenses/ISC.html
#
# Copyright (C) 2003-2004 E. Will, et al.
# Copyright (C) 2010-2012 William Pitcock <nenolod@atheme.org>
# Copyright (C) 2010 Jilles Tjoelker <jilles@stack.nl>
# Copyright (C) 2011-2012 JD Horelick <jdhore1@gmail.com>
# Copyright (C) 2018-2020 Aaron M. D. Jones <me@aaronmdjones.net>
# Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)

-include extra.mk

SUBDIRS =                   \
    ${SUBMODULE_LIBMOWGLI}  \
    inc                     \
    src                     \
    tools

CLEANDIRS = ${SUBDIRS}
DISTCLEAN = buildsys.mk config.log config.status extra.mk

-include buildsys.mk

buildsys.mk:
	@echo "Fatal Error -- The buildsys.mk file is missing."
	@echo "Please check whether you have run the configure script."
	@exit 1

# Explicit dependencies need to be expressed to ensure parallel builds don't die
src: ${SUBMODULE_LIBMOWGLI} inc
tools: ${SUBMODULE_LIBMOWGLI} inc
