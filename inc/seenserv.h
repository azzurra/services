/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* seebserv.h - SeenServ service
* 
*/


#ifndef SRV_SEENSERV_H
#define SRV_SEENSERV_H

#ifdef USE_STATS

/*********************************************************
 * Version stuff                                         *
 *********************************************************/

#define	SEENSERV_DB_CURRENT_VERSION		10
#define SEENSERV_DB_SUPPORTED_VERSION	"7 10"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _SeenInfo_V10	SeenInfo_V10;
struct _SeenInfo_V10 {

	SeenInfo_V10	*next, *prev;

	#ifdef FIX_USE_MPOOL
	MEMORYBLOCK_ID	mblock_id;
	#endif

	char			*nick;			/* user's nickname */
	char			*username;		/* user's username (ident) */
	char			*host;			/* user's hostname */
	char			*realname;

	unsigned long	ip;
	short int		mode;			/* User's last usermodes */
	unsigned char   type;			/* SEEN_TYPE_* defined below */
	char			*tempnick;		/* Nick the user changed to (or from, depending on type),
									   or oper who killed it */
	char			*quitmsg;		/* User's quit message */
	time_t			last_seen;
	unsigned char   pad;
};

// Current structs version
typedef SeenInfo_V10	SeenInfo;


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define SEEN_TYPE_NICK		1
#define SEEN_TYPE_QUIT		2	/* User has quit. */
#define SEEN_TYPE_NCTO		3	/* User changed nick. */
#define SEEN_TYPE_NCFR		4	/* New nick after a nick change. */
#define SEEN_TYPE_KILL		5	/* User has been killed. */
#define SEEN_TYPE_SPLIT		6	/* User has split. */
#define SEEN_TYPE_NOSEEN	7	/* Services went down and user quit before they were restarted. */
#define SEEN_TYPE_AKILL		8	/* User has been Autokilled. */
#define SEEN_TYPE_KLINE		9	/* User has been K-Lined. */


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void seenserv_init(const time_t now);
extern void seenserv_terminate(void);

// Handlers
extern void seenserv(CSTR source, User *callerUser, char *buf);

// Database stuff
extern BOOL seenserv_db_load(void);
extern BOOL seenserv_db_save(void) ;

extern void seenserv_expire_records();
extern void seenserv_weekly_expire();

extern SeenInfo *seenserv_create_record(const User *user);

extern SeenInfo *hash_seeninfo_find(CSTR value);

extern BOOL is_seen_exempt(CSTR nick, CSTR username, CSTR host, const unsigned long int ip);

extern void seenserv_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int seenserv_mem_report(CSTR sourceNick, const User *callerUser);


#endif /* USE_STATS */

#endif /* SRV_SEENSERV_H */
