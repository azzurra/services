/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* ignore.h - Services ignores
* 
*/


#ifndef SRV_IGNORE_H
#define SRV_IGNORE_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/strings.h"
#include "../inc/cidr.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _ignore_V10		Ignore_V10;
struct _ignore_V10 {

	Ignore_V10 *prev, *next;

	char *nick;
	char *username;
	char *host;

	CIDR_IP cidr;

	CreationInfo info;

	time_t expireTime;
	time_t lastUsed;

	tiny_flags_t flags;
};

// Current struct version
typedef	Ignore_V10		Ignore;


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define	IGNORE_DB_CURRENT_VERSION		10
#define IGNORE_DB_SUPPORTED_VERSION		"10"

#define	IGNORE_FLAG_MANUAL		0x0001
#define IGNORE_FLAG_TEMPORARY	0x0002
#define IGNORE_FLAG_PERMANENT	0x0004
#define IGNORE_FLAG_WITHCIDR	0x0008


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern BOOL ignore_db_load(void);
extern BOOL ignore_db_save(void);
extern void ignore_create_record(CSTR source, STR nick, STR username, STR host, CSTR reason, BOOL manual, const time_t expire_t, BOOL have_CIDR, CIDR_IP cidr);
extern BOOL ignore_match(const User *user);
extern BOOL is_already_ignored(CSTR nick, CSTR username, CSTR host, const time_t expire_t, const User *callerUser);
extern void ignore_expire(void);
extern void handle_ignore(CSTR source, User *callerUser, ServiceCommandData *data);
extern void ignore_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int ignore_mem_report(CSTR sourceNick, const User *callerUser);

#endif /* SRV_IGNORE_H */
