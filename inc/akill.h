/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* akill.h - Header gestione AutoKill
* 
*/


#ifndef SRV_AKILL_H
#define SRV_AKILL_H

/*********************************************************
 * Version stuff                                         *
 *********************************************************/

#define	AKILL_DB_CURRENT_VERSION	10
#define AKILL_DB_SUPPORTED_VERSION	"10"


/*********************************************************
 * Data types                                            *
 **********************************************************/

typedef struct _AutoKill_V10		AutoKill_V10;
struct _AutoKill_V10 {

	AutoKill_V10 *prev, *next;

	char *username;			/* User part of the AKILL */
	char *host;				/* Host part of the AKILL */
	char *reason;			/* Why they got akilled */
	char *desc;				/* Description available to opers on LIST */

	CIDR_IP cidr;			/* CIDR data, if available (flagged WITHCIDR) */

	Creator creator;		/* Who created it, and when */

	time_t expireTime;		/* When it expires */
	time_t lastUsed;

	unsigned long id;		/* Autokill unique ID number */
	flags_t type;			/* AKILL_TYPE_* defined below */
};


// Current structs version
typedef	AutoKill_V10		AutoKill;


/*********************************************************
 * Constants                                             *
 *********************************************************/

// AutoKill.flags
#define AKILL_TYPE_NONE			0x00000000
#define AKILL_TYPE_TEMPORARY		0x00000001
#define AKILL_TYPE_PERMANENT		0x00000002
#define AKILL_TYPE_BY_APM		0x00000004
#define AKILL_TYPE_MANUAL		0x00000008
#define AKILL_TYPE_FLOODER		0x00000010
#define AKILL_TYPE_SOCKS		0x00000020
#define AKILL_TYPE_PROXY		0x00000040
#define AKILL_TYPE_WINGATE		0x00000080
#define AKILL_TYPE_CLONES		0x00000100
#define AKILL_TYPE_IDENT		0x00000200
#define AKILL_TYPE_BOTTLER		0x00000400
#define AKILL_TYPE_TROJAN		0x00000800
#define AKILL_TYPE_MIRCWORM		0x00001000
#define AKILL_TYPE_PROXY80		0x00002000
#define AKILL_TYPE_PROXY8080		0x00004000
#define AKILL_TYPE_PROXY3128		0x00008000
#define AKILL_TYPE_PROXY6588		0x00010000
#define AKILL_TYPE_SOCKS4		0x00020000
#define AKILL_TYPE_SOCKS5		0x00040000
#define AKILL_TYPE_RESERVED		0x00080000
#define AKILL_TYPE_WITHCIDR		0x00100000
#define AKILL_TYPE_BY_DNSBL		0x00200000

#define AKILL_TYPE_DISABLED		0x80000000


/*********************************************************
 * Public code                                           *
 *********************************************************/

// Handlers
extern void handle_akill(CSTR source, User *callerUser, ServiceCommandData *data);

// Database stuff
extern BOOL akill_db_load(void);
extern BOOL akill_db_save(void);

// Misc functions
extern void akill_expire(void);
extern BOOL is_already_akilled(CSTR username, CSTR host, const time_t expiry, CSTR agent, const User *callerUser);
extern BOOL akill_match(CSTR nick, CSTR username, CSTR host, unsigned long int ip);
extern void akill_add(CSTR source, CSTR username, CSTR host, CSTR reason, const BOOL manual, const BOOL withCIDR,
	CIDR_IP *cidr, const unsigned int type, const unsigned int expireTime, const unsigned long int akillID, const LANG_ID lang);

extern void akill_remove(CSTR username, CSTR host);
extern void akill_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int akill_mem_report(CSTR sourceNick, const User *callerUser);

#endif /* SRV_AKILL_H */
