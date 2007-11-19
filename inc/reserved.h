/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* reserved.h - Reserved names
* 
*/


#ifndef SRV_RESERVED_H
#define SRV_RESERVED_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/strings.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _reservedName_V10	reservedName_V10;
struct _reservedName_V10 {

	reservedName_V10	*next;

	char				*name;

	CreationInfo		info;

	flags_t				flags;		/* RESERVED_* */
	time_t				lastUpdate;
};

// Current structs version
typedef	reservedName_V10			reservedName;

enum _RESERVED_RESULT { reservedValid = 0, reservedBlock, reservedKill, reservedAutoKill};
typedef enum _RESERVED_RESULT	RESERVED_RESULT;


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define	RESERVED_DB_CURRENT_VERSION		10
#define RESERVED_DB_SUPPORTED_VERSION	"10"

#define RESERVED_NOUSE	0x00000010	/* Impedire l'uso del nome */
#define RESERVED_NOREG	0x00000020	/* Impedire la registrazione del nome */
#define RESERVED_ALERT	0x00000100	/* Ad un tentativo di utilizzo, mandare un avviso agli operatori */
#define RESERVED_KILL	0x00000200	/* Killare l'utente */
#define RESERVED_AKILL	0x00000400	/* Akillare l'utente */
#define RESERVED_LOG	0x00000800	/* Logging attivo */
#define RESERVED_ACTIVE	0x00001000	/* Nome riservato attivo */

#define RESERVED_NICK		0x00000001
#define RESERVED_CHAN		0x00000002


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern BOOL reserved_db_load(void);
extern BOOL reserved_db_save(void);
extern void reserved_terminate(void);
extern RESERVED_RESULT reserved_match(CSTR value, const long int type, const BOOL isReg, CSTR service, CSTR nick, CSTR ident, CSTR host, const unsigned long int ip, const BOOL isExempt, const LANG_ID lang);
extern void handle_reserved(CSTR source, User *callerUser, ServiceCommandData *data);
extern void reserved_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int reserved_mem_report(CSTR sourceNick, const User *callerUser);

#endif /* SRV_RESERVED_H */
