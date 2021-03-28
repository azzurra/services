# Makefile for Services

include ../Makefile.inc

OBJS =	access.o akill.o blacklist.o channels.o chanserv.o compat.o conf.o cidr.o crypt_shs1.o crypt_userhost.o \
	datafiles.o debugserv.o helpserv.o ignore.o jupe.o lang.o logging.o main.o memory.o memoserv.o messages.o misc.o \
	mtab.o nickserv.o oper.o operserv.o process.o regions.o reserved.o rootserv.o seenserv.o send.o servers.o signals.o \
	sockutil.o spam.o statserv.o storage.o strings.o sxline.o tagline.o timeout.o trie.o trigger.o users.o version.o

SRCS =	access.c akill.c blacklist.c channels.c chanserv.c compat.c conf.c cidr.c crypt_shs1.c crypt_userhost.c \
	datafiles.c debugserv.c helpserv.c ignore.c jupe.c lang.c logging.c main.c memory.c memoserv.c messages.c misc.c \
	mtab.c nickserv.c oper.c operserv.c process.c regions.c reserved.c rootserv.c seenserv.c send.c servers.c signals.c \
	sockutil.c spam.c statserv.c storage.c strings.c sxline.c tagline.c timeout.c trie.c trigger.c users.c version.c

build: services


########


services: ../inc/version.h $(OBJS)
	$(CC) $(LFLAGS) $(LIBS) $(OBJS) -o $@

.c.o:
	$(CC) $(CFLAGS) -c $<

access.o:			access.c 
akill.o:			akill.c
blacklist.o:			blacklist.c			../inc/blacklist.h
channels.o:			channels.c
chanserv.o:			chanserv.c			../inc/lang.h ../inc/lang_msg.h ../inc/timeout.h ../inc/options.h
compat.o:			compat.c
cidr.o:				cidr.c				../inc/cidr.h
conf.o:				conf.c
crypt_shs1.o:			crypt_shs1.c 			../inc/crypt_shs1.h
crypt_userhost.o:		crypt_userhost.c		../inc/crypt_shs1.h
datafiles.o:			datafiles.c
debugserv.o: 			debugserv.c 			../inc/lang.h ../inc/options.h
helpserv.o:			helpserv.c			../inc/lang.h
ignore.o:			ignore.c			../inc/ignore.h
jupe.o:				jupe.c				../inc/jupe.h
lang.o:				lang.c 				../inc/lang.h ../inc/lang_msg.h
logging.o:			logging.c 			../inc/lang.h
main.o:				main.c				../inc/lang.h ../inc/timeout.h ../inc/options.h
memory.o:			memory.c			../inc/options.h
memoserv.o:			memoserv.c			 ../inc/lang.h ../inc/lang_msg.h ../inc/options.h
messages.o:			messages.c			../inc/lang.h ../inc/lang_msg.h
misc.o:				misc.c
mtab.o:				mtab.c				../inc/mtab.h
nickserv.o:			nickserv.c			../inc/lang.h ../inc/lang_msg.h ../inc/timeout.h ../inc/options.h
oper.o:				oper.c
operserv.o:			operserv.c			../inc/lang.h ../inc/lang_msg.h ../inc/options.h
process.o:			process.c			../inc/version.h
regions.o:			regions.c			../inc/regions.h
reserved.o:			reserved.c			../inc/reserved.h
rootserv.o:			rootserv.c  			../inc/lang.h ../inc/lang_msg.h ../inc/options.h
seenserv.o:			seenserv.c			../inc/options.h
send.o:				send.c				../inc/lang.h ../inc/lang_msg.h
servers.o:			servers.c
signals.o:			signals.c
sockutil.o:			sockutil.c			../inc/options.h
spam.o:				spam.c				../inc/spam.h ../inc/common.h ../inc/send.h
statserv.o:			statserv.c			../inc/options.h
storage.o:			storage.c			../inc/storage.h
strings.o:			strings.c
sxline.o:			sxline.c			../inc/sxline.h
tagline.o:			tagline.c			../inc/tagline.h
timeout.o:			timeout.c			../inc/timeout.h
trie.o:				trie.c				../inc/mtab.h ../inc/trie.h
trigger.o:			trigger.c			../inc/trigger.h
users.o:			users.c				../inc/lang.h ../inc/lang_msg.h
version.o:			version.c 			../inc/version.h ../inc/branch.h


config.h: ../inc/sysconf.h
	touch $@

version.h: Makefile $(SRCS)
