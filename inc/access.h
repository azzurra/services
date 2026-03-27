/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* access.h - For eggdrop-like access structures
* 
*/

#ifndef SRV_ACCESS_H
#define SRV_ACCESS_H

/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "config.h"


/*********************************************************
 * Version stuff                                         *
 *********************************************************/

#define	ACCESS_DB_CURRENT_VERSION		10
#define ACCESS_DB_SUPPORTED_VERSION		"10"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _access_V10 Access_V10;

struct _access_V10 {

	Access_V10	*next;

	STR			nick;
	STR			user;
	STR			user2;
	STR			user3;
	STR			host;
	STR			host2;
	STR			host3;
	STR			server;
	STR			server2;
	STR			server3;

	long		flags;		/* AC_* defined below. */

	long		modes_on;	/* Modes added on connect. */
	long		modes_off;	/* Modes removed on connect. */

	Creator		creator;

	time_t		lastUpdate;
};


#define Access Access_V10

#ifdef OS_64BIT
typedef struct _access_V10_32 Access_V10_32;

struct _access_V10_32 {
	int32_t next;

	int32_t nick;
	int32_t user;
	int32_t user2;
	int32_t user3;
	int32_t host;
	int32_t host2;
	int32_t host3;
	int32_t server;
	int32_t server2;
	int32_t server3;

	int32_t flags; /* AC_* defined below. */

	int32_t modes_on; /* Modes added on connect. */
	int32_t modes_off; /* Modes removed on connect. */

	Creator32 creator;

	int32_t lastUpdate;
};


typedef Access_V10_32 Access32;
#endif


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define AC_FLAG_ENABLED		0x00000001
#define AC_FLAG_ONLINE		0x00000002


#define AC_RESULT_NOTFOUND	0
#define AC_RESULT_GRANTED	1
#define AC_RESULT_DENIED	2


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void send_access_list(Access *accessList, CSTR sourceNick, const User *target);
extern BOOL send_access_info(Access *accessList, CSTR nick, CSTR sourceNick, const User *target);

extern int access_remove(Access **accessList, CSTR nick, char *removed);
extern Access *access_add(Access **accessList, CSTR nick, CSTR creator);
extern int match_access(Access *anAccess, CSTR user, CSTR host, CSTR server);
extern int check_access(Access *accessList, CSTR nick, CSTR user, CSTR host, CSTR server, time_t signon, Access **userAccess);
extern Access *find_access(Access *accessList, CSTR nick);
extern void free_access_list(Access *accessList, int *ListLoadComplete);
extern BOOL access_db_save(Access *accessList, CSTR database, int ListLoadComplete);
extern BOOL access_db_load(Access **accessList, CSTR database, int *ListLoadComplete);

extern void access_ds_dump(Access *accessList, CSTR sourceNick, const User *callerUser, BOOL listOnly);
extern void access_send_dump(Access *anAccess, CSTR sourceNick, const User *callerUser);
extern unsigned long int access_mem_report(Access *accessList, int *count);

#endif /* SRV_ACCESS_H */
