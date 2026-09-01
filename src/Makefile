# SPDX-License-Identifier: GPL-2.0-or-later
# SPDX-URL: https://spdx.org/licenses/GPL-2.0-or-later.html
#
# Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)

include ../extra.mk

LANG_SRCS = ../lang/English.lang ../lang/French.lang ../lang/Italian.lang ../lang/Spanish.lang

HELP_LINGUAS = es fr it us

PROG = ${PACKAGE_TARNAME}${PROG_SUFFIX}
SRCS =               \
    access.c         \
    akill.c          \
    blacklist.c      \
    channels.c       \
    chanserv.c       \
    cidr.c           \
    compat.c         \
    conf.c           \
    crypt_shs1.c     \
    crypt_userhost.c \
    datafiles.c      \
    debugserv.c      \
    helpserv.c       \
    ignore.c         \
    jupe.c           \
    lang.c           \
    logging.c        \
    main.c           \
    memory.c         \
    memoserv.c       \
    messages.c       \
    misc.c           \
    nickserv.c       \
    oper.c           \
    operserv.c       \
    process.c        \
    regions.c        \
    reserved.c       \
    rootserv.c       \
    seenserv.c       \
    send.c           \
    servers.c        \
    signals.c        \
    sockutil.c       \
    spam.c           \
    statserv.c       \
    storage.c        \
    strings.c        \
    sxline.c         \
    tagline.c        \
    timeout.c        \
    trigger.c        \
    users.c          \
    version.c

include ../buildsys.mk

CPPFLAGS += -I../inc

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

.PHONY: clng

build: depend all clng

# This sucks, gettext will make it suck slightly less...
clng: ../lang/langcomp.py ${LANG_SRCS}
	(cd ../lang; python3 langcomp.py --out-dir=. --no-header)

install-extra: clng
	-${INSTALL} -m 755 -d ${DESTDIR}${prefix}
	-${INSTALL} -m 755 -d ${DESTDIR}${bindir}
	-${INSTALL} -m 755 -d ${DESTDIR}${sysconfdir}
	-${INSTALL} -m 755 -d ${DESTDIR}${localstatedir}
	-${INSTALL} -m 755 -d ${DESTDIR}${DOCDIR}
	-${INSTALL} -m 755 -d ${DESTDIR}${LOGDIR}
	-${INSTALL} -m 755 -d ${DESTDIR}${RUNDIR}
	-${INSTALL} -m 755 -d ${DESTDIR}${DATADIR}
	-${INSTALL} -m 755 -d ${DESTDIR}${DATADIR}/lang
	-${INSTALL} -m 755 -d ${DESTDIR}${SHAREDIR}/helpfiles
	-${INSTALL} -m 755 -d ${DESTDIR}${SHAREDIR}/ohelpfiles
	${INSTALL} -m 644 -c ../doc/lang.conf.example ${DESTDIR}${sysconfdir}
	${INSTALL} -m 644 -c ../doc/services.motd.example ${DESTDIR}${sysconfdir}
	${INSTALL} -m 600 -c ../doc/crypt.key.example ${DESTDIR}${sysconfdir}
	${INSTALL} -m 600 -c ../doc/services.conf.example ${DESTDIR}${sysconfdir}
	[ -r ${DESTDIR}${sysconfdir}/services.motd ] || ${INSTALL} -m 644 -c ../doc/services.motd.example ${DESTDIR}${sysconfdir}/services.motd || :
	(cd ../lang; for i in *.clng; do \
		[ -f $$i ] && ${INSTALL} -m 644 -c $$i ${DESTDIR}${DATADIR}/lang; \
	done)
	(for lingua in ${HELP_LINGUAS}; do \
		${INSTALL} -m 755 -d ${DESTDIR}${SHAREDIR}/helpfiles/$$lingua; \
		(cd ../run/data/helpfiles/$$lingua; for i in *; do \
			[ -f $$i ] && ${INSTALL} -m 644 -c $$i ${DESTDIR}${SHAREDIR}/helpfiles/$$lingua; \
			if [ -d $$i ]; then \
				cd $$i; \
				${INSTALL} -m 755 -d ${DESTDIR}${SHAREDIR}/helpfiles/$$lingua/$$i; \
				for j in *; do \
					[ -f $$j ] && ${INSTALL} -m 644 -c $$j ${DESTDIR}${SHAREDIR}/helpfiles/$$lingua/$$i; \
					if [ -d $$j ]; then \
						cd $$j; \
						${INSTALL} -m 755 -d ${DESTDIR}${SHAREDIR}/helpfiles/$$lingua/$$i/$$j; \
						for k in *; do \
							[ -f $$k ] && ${INSTALL} -m 644 -c $$k ${DESTDIR}${SHAREDIR}/helpfiles/$$lingua/$$i/$$j; \
						done; \
						cd ..; \
					fi; \
				done; \
				cd ..; \
			fi; \
		done); \
	done)
	(for lingua in ${HELP_LINGUAS}; do \
		${INSTALL} -m 755 -d ${DESTDIR}${SHAREDIR}/ohelpfiles/$$lingua; \
		(cd ../run/data/ohelpfiles/$$lingua; for i in *; do \
			[ -f $$i ] && ${INSTALL} -m 644 -c $$i ${DESTDIR}${SHAREDIR}/ohelpfiles/$$lingua; \
			if [ -d $$i ]; then \
				cd $$i; \
				${INSTALL} -m 755 -d ${DESTDIR}${SHAREDIR}/ohelpfiles/$$lingua/$$i; \
				for j in *; do \
					[ -f $$j ] && ${INSTALL} -m 644 -c $$j ${DESTDIR}${SHAREDIR}/ohelpfiles/$$lingua/$$i; \
					if [ -d $$j ]; then \
						cd $$j; \
						${INSTALL} -m 755 -d ${DESTDIR}${SHAREDIR}/ohelpfiles/$$lingua/$$i/$$j; \
						for k in *; do \
							[ -f $$k ] && ${INSTALL} -m 644 -c $$k ${DESTDIR}${SHAREDIR}/ohelpfiles/$$lingua/$$i/$$j; \
						done; \
						cd ..; \
					fi; \
				done; \
				cd ..; \
			fi; \
		done); \
	done)
	@echo " "
	@echo "----------------------------------------------------------------------"
	@echo ">>> Remember to cd to ${DESTDIR}${prefix} and edit your config file.";
	@echo "----------------------------------------------------------------------"
	@echo " "
