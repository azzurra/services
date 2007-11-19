/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* trigger.h - Clone triggers
* 
*/


#ifndef SRV_TRIGGER_H
#define SRV_TRIGGER_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/strings.h"
#include "../inc/cidr.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _trigger_V10		Trigger_V10;
struct _trigger_V10 {

	Trigger_V10		*prev, *next;

	char			*username;
	char			*host;
	CIDR_IP			cidr;

	unsigned char	pad;			/* Not used. */
	unsigned char	value;
	tiny_flags_t	flags;

	CreationInfo	info;

	time_t			lastUsed;
	time_t			expireTime;
};

// Current struct version
typedef	Trigger_V10		Trigger;

enum _TRIGGER_RESULT { triggerFound = 0, triggerNotFound, triggerExempt, triggerInvalidData};
typedef enum _TRIGGER_RESULT	TRIGGER_RESULT;


typedef struct _exempt_V10		Exempt_V10;
struct _exempt_V10 {

	Exempt_V10		*prev, *next;

	char			*realname;

	CreationInfo	info;

	time_t			lastUsed;
	time_t			expireTime;
};

// Current struct version
typedef	Exempt_V10		Exempt;

/*********************************************************
 * Constants                                             *
 *********************************************************/

#define	TRIGGER_DB_CURRENT_VERSION		10
#define TRIGGER_DB_SUPPORTED_VERSION	"10"

#define TRIGGER_FLAG_CIDR		0x0001
#define TRIGGER_FLAG_HOST		0x0002
#define TRIGGER_FLAG_REALNAME	0x0004


#define	EXEMPT_DB_CURRENT_VERSION		10
#define EXEMPT_DB_SUPPORTED_VERSION		"10"


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void handle_trigger(CSTR source, User *callerUser, ServiceCommandData *data);

extern BOOL trigger_db_load(void);
extern BOOL trigger_db_save(void);
extern TRIGGER_RESULT trigger_match(CSTR username, CSTR host, const unsigned long int ip, const int cloneCount, char **reason, int *position);

extern BOOL exempt_db_load(void);
extern BOOL exempt_db_save(void);
extern BOOL exempt_match(CSTR realname, int *position);

extern void trigger_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int trigger_mem_report(CSTR sourceNick, const User *callerUser);

#endif /* SRV_TRIGGER_H */
