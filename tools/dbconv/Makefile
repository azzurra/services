# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-URL: https://spdx.org/licenses/GPL-2.0-or-later.html
#
# Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)

include ../../extra.mk

PROG = dbconv${PROG_SUFFIX}
SRCS =          \
    chanserv.c  \
    common.c    \
    datafiles.c \
    main.c      \
    memoserv.c  \
    nickserv.c  \
    operdb.c    \
    storage.c

include ../../buildsys.mk

CPPFLAGS += -I../../include

CFLAGS +=                           \
    ${LIBCRYPTO_CFLAGS}             \
    ${LIBGCRYPT_CFLAGS}             \
    ${LIBMBEDCRYPTO_CFLAGS}         \
    ${LIBNETTLE_CFLAGS}             \
    ${LIBQRENCODE_CFLAGS}           \
    ${LIBSODIUM_CFLAGS}

LIBS +=                             \
    ${LIBCRYPTO_LIBS}               \
    ${LIBGCRYPT_LIBS}               \
    ${LIBMBEDCRYPTO_LIBS}           \
    ${LIBNETTLE_LIBS}               \
    ${LIBQRENCODE_LIBS}             \
    ${LIBSODIUM_LIBS}               \
    ${LIBDL_LIBS}                   \
    ${LIBSOCKET_LIBS}

build: all
