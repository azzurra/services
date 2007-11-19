/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* cybcop.h - Socks Monitor include file
* 
* Originally based on Epona (c) 2000-2001, 2004 PegSoft (epona@pegsoft.net)
*
*/

#ifndef SRV_CYBCOP_H
#define SRV_CYBCOP_H

/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/access.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct floodcache_ FloodCache;

struct floodcache_ {

	FloodCache *prev, *next;

	char *host;			/* The hostname */
	time_t last_hit;
	int hits;
	LANG_ID lang;
};


/* Proxy stuff */
typedef struct hostcache_ HostCache;

struct hostcache_ {

	HostCache *prev, *next;

	char *nick;			/* The user's nickname */	
	char *host;			/* The hostname */
	char *req;			/* Nick of whoever requested the scan, if any */

	unsigned long ip;	/* The IP address */
	time_t used;		/* When was this entry last used? */
	LANG_ID lang;

	short status;		/* HC_* below */
};


/* Struct handled by the main threaded scan loop. */
typedef struct scanentry_ ScanEntry;

struct scanentry_ {

	HostCache *hc;
	ScanEntry *next;
};


/* Ports to scan and scanning methods. */
typedef struct scan_ Scan;
struct scan_ {

	Scan *next;

	unsigned short int port;		/* Port to scan. */
	unsigned short int method;		/* Method to use (socks/proxy/wingate/etc.). */
	unsigned long int counter;		/* Usage counter. */
};


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define HC_EXEMPT		-4				/* Exempted from socks scan */
#define HC_SKIPPED		-3				/* Skipped (IPv6, etc) */
#define HC_QUEUED		-2				/* Waiting to be scanned */
#define HC_PROGRESS		-1				/* Currently being scanned */

#define HC_NORMAL		 0				/* No proxy found on this host */

#define HC_WINGATE		 1				/* Wingate found */
#define HC_SOCKS4		 2				/* Socks4 found */
#define HC_SOCKS5		 3				/* Socks5 found */
#define HC_HTTP1		 4				/* HTTP proxy on port 3128 found */
#define HC_HTTP2		 5				/* HTTP proxy on port 8080 found */
#define HC_HTTP3		 6				/* HTTP proxy on port 80 found */
#define HC_HTTP4		 7				/* HTTP proxy on port 6588 found */

#define HC_PROXY_TYPE_FIRST		HC_WINGATE
#define HC_PROXY_TYPE_LAST		HC_HTTP4
#define HC_PROXY_TYPE_COUNT		(HC_PROXY_TYPE_LAST - HC_PROXY_TYPE_FIRST + 1)

#define SCAN_METHOD_SOCKS4	1
#define SCAN_METHOD_SOCKS5	2
#define SCAN_METHOD_PROXY	3
#define SCAN_METHOD_HTTP	4
#define SCAN_METHOD_WINGATE	5


/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern Access *APMList;


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void monitor_init(void);
extern void monitor(CSTR source, User *callerUser, char *buf);

/* Database stuff */
extern void load_apm_dbase(void);
extern void save_apm_dbase(void);
extern void load_monitor_db(void);
extern void save_monitor_db(void);

/* Proxy scan stuff */
extern void proxy_expire(const time_t now);
extern int proxy_check(CSTR nick, CSTR host, const unsigned long int ip, CSTR source, LANG_ID lang);
extern void clear_from_cache(CSTR host);

/* APM stuff */
extern void remove_apm(CSTR apmnick, char status);
extern void free_apm_list(void);

/* Flooders stuff. */
extern BOOL check_flooder(CSTR nick, CSTR username, CSTR host, const unsigned long int ip, CSTR realname, const LANG_ID lang);
extern BOOL check_ngi_lamer(CSTR nick, CSTR username, CSTR host, CSTR realname, const unsigned long int ip);
extern void monitor_handle_SJOIN(CSTR source, const int ac, char **av);

extern void monitor_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int monitor_mem_report(CSTR sourceNick, const User *callerUser);

#endif /* SRV_CYBCOP_H */
