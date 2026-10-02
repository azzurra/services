/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* common.h - Standard header inclusion
* 
*/


#ifndef SRV_COMMON_H
#define SRV_COMMON_H

#include <services/sysconf.h>

/* C headers */
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>
#include <grp.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <sys/socket.h> 
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <ctype.h>
#include <fcntl.h>
#include <inttypes.h>
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif

/* Libmowgli */
#include <mowgli.h>

/* Services headers */
#include <services/attributes.h>
#include <services/xrefs.h>
#include <services/sysconf.h>
#include <services/options.h>
#include <services/config.h>
#include <services/macros.h>
#include <services/instpaths.h>

/* Causes a warning if value is not of type (or compatible), returning value. */
#define ENSURE_TYPE(value, type) (true ? (value) : (type)0)

#endif /* SRV_COMMON_H */
