/*
*
* Azzurra IRC Services
* 
* compat.c - compatibility routines
* 
* Basato su:
*   SirvNET Services is copyright (c) 1998-2001 Trevor Klingbeil. (E-mail: <priority1@dal.net>)
*   Originally based on EsperNet Services(c) by Andy Church.
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/compat.h"


/*********************************************************/

#ifndef HAVE_STRERROR

#if HAVE_SYS_ERRLIST
extern char *sys_errlist[];
#endif

char *strerror(int errnum) {

#if HAVE_SYS_ERRLIST
	return sys_errlist[errnum];
#else
	static char buf[32];
	sprintf(buf, "Error %d", errnum);
	return buf;
#endif
}

#endif

/*********************************************************/

#ifndef HAVE_STRSIGNAL
char *strsignal(int signum) {

	static char buf[32];
	switch (signum) {

		case SIGHUP:
			strcpy(buf, "Hangup");
			break;

		case SIGINT:
			strcpy(buf, "Interrupt");
			break;

		case SIGQUIT:
			strcpy(buf, "Quit");
			break;
#ifdef SIGILL
		case SIGILL:
			strcpy(buf, "Illegal instruction");
			break;
#endif
#ifdef SIGABRT
		case SIGABRT:
			strcpy(buf, "Abort");
			break;
#endif
#if defined(SIGIOT) && (!defined(SIGABRT) || SIGIOT != SIGABRT)
		case SIGIOT:
			strcpy(buf, "IOT trap");
			break;
#endif

#ifdef SIGBUS
		case SIGBUS:
			strcpy(buf, "Bus error");
			break;
#endif
		case SIGFPE:
			strcpy(buf, "Floating point exception");
			break;

		case SIGKILL:
			strcpy(buf, "Killed");
			break;

		case SIGUSR1:
			strcpy(buf, "User signal 1");
			break;

		case SIGSEGV:
			strcpy(buf, "Segmentation fault");
			break;

		case SIGUSR2:
			strcpy(buf, "User signal 2");
			break;

		case SIGPIPE:
			strcpy(buf, "Broken pipe");
			break;

		case SIGALRM:
			strcpy(buf, "Alarm clock");
			break;

		case SIGTERM:
			strcpy(buf, "Terminated");
			break;

		case SIGSTOP:
			strcpy(buf, "Suspended (signal)");
			break;

		case SIGTSTP:
			strcpy(buf, "Suspended");
			break;

		case SIGIO:
			strcpy(buf, "I/O error");
			break;

		default:
			sprintf(buf, "Signal %d\n", signum);
			break;
	}
	return buf;
}
#endif
