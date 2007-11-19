/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* blacklist.h - Blacklisted E-Mail addresses
* 
*/


#ifndef SRV_BLACKLIST_H
#define SRV_BLACKLIST_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/strings.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _blacklist_V10		BlackList_V10;
struct _blacklist_V10 {

	BlackList_V10	*prev, *next;

	char			*address;

	CreationInfo	info;
	time_t			lastUsed;

	tiny_flags_t	flags;
	short			pad;
};


// Current struct version
typedef	BlackList_V10		BlackList;


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define	BLACKLIST_DB_CURRENT_VERSION		10
#define BLACKLIST_DB_SUPPORTED_VERSION		"10"

#define BLACKLIST_FLAG_NOTIFY	0x0001
#define BLACKLIST_FLAG_DENY		0x0002


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern BOOL blacklist_db_load(void);
extern BOOL blacklist_db_save(void);
extern void handle_blacklist(CSTR source, User *callerUser, ServiceCommandData *data);
extern BOOL blacklist_match(const User *user, CSTR address, const char type);
extern void blacklist_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int blacklist_mem_report(CSTR sourceNick, const User *callerUser);


#endif /* SRV_BLACKLIST_H */
