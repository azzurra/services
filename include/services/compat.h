/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* compat.h - compatibility routines
* 
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
*
*/


#ifndef SRV_COMPAT_H
#define SRV_COMPAT_H


/*********************************************************
 * Public code                                           *
 *********************************************************/

#ifndef HAVE_SNPRINTF

#define vsnprintf my_vsnprintf
#define snprintf my_snprintf

extern int vsnprintf(char *buf, size_t size, CSTR fmt, va_list args);
extern int snprintf(char *buf, size_t size, CSTR fmt, ...);
#endif

#ifndef HAVE_STRERROR
extern char *strerror(int errnum);
#endif

#ifndef HAVE_STRSIGNAL
char *strsignal(int signum);
#endif



#endif /* SRV_COMPAT_H */
