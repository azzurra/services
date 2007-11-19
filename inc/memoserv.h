/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* memoserv.h - MemoServ service
* 
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
*
*/


#ifndef SRV_MEMOSERV_H
#define SRV_MEMOSERV_H

#ifdef USE_SERVICES

/*********************************************************
 * Version stuff                                         *
 *********************************************************/

#define	MEMOSERV_DB_CURRENT_VERSION		7
#define MEMOSERV_DB_SUPPORTED_VERSION	"7"


/*********************************************************
 * Data types                                            *
 *********************************************************/

// a single memo
typedef struct _Memo_V7		Memo_V7;
struct _Memo_V7 {

    char		sender[NICKMAX];
    long		unused;	/* Was index number */
    time_t		time;	/* When it was sent */
    char		*text;
    char		*chan;
    short		flags;	/* MF_* */
    short		level;	/* If it is a channel memo, this is CS_ACCESS_*, 0 otherwise. */
    long		reserved[3];   /* For future expansion -- set to 0 */
};

typedef struct _Memo_V10	Memo_V10;
struct _Memo_V10 {

	Memo_V10	*next, *prev;

	char			*sender;
    char			*text;
    char			*chan;
    time_t			time;

	unsigned short	flags:11;
	unsigned short	level:5;
};

// Current structs version
typedef	Memo_V7		Memo;



// Ignore-list
typedef struct _MemoIgnore_V7	MemoIgnore_V7;
struct _MemoIgnore_V7 {

	time_t			creationTime;
	STR				ignoredNick;
	MemoIgnore_V7	*next, *prev;
};

typedef struct _MemoIgnore_V10	MemoIgnore_V10;
struct _MemoIgnore_V10 {

	MemoIgnore_V10	*next, *prev;

	STR				ignoredNick;
	time_t			creationTime;
};

// Current structs version
typedef	MemoIgnore_V7	MemoIgnore;



// a nickname memo-list
typedef struct _MemoList_V7		MemoList_V7;
struct _MemoList_V7 {

    MemoList_V7			*next, *prev;
    char				nick[NICKMAX];				/* Owner of the memos */
    long				n_memos;					/* Number of memos */
    Memo_V7				*memos;					/* The memos themselves */

	long				n_ignores;					/* Number of ignores */
	MemoIgnore_V7		*ignores;			/* Ignore-list */

	long reserved[2];				/* For future expansion - set to 0 */
};


typedef struct _MemoList_V10	MemoList_V10;
struct _MemoList_V10 {


    MemoList_V10		*next, *prev;
    
	char				*nick;

	unsigned char		n_memos;
    Memo_V10			*memos;

    unsigned char		n_ignores;
    MemoIgnore_V10		*ignores;
};

// Current structs version
typedef	MemoList_V7		MemoList;



/*********************************************************
 * Constants                                             *
 *********************************************************/

// Memo.flags (max 11 bit)
#define MF_UNREAD	0x001	/* Memo_V7 has not yet been read */
#define MF_DEL      0x002	/* Memo_V7 marked as deleted */


#define MEMO_TYPE_CHANNEL	1
#define MEMO_TYPE_DIRECT	2
#define MEMO_TYPE_NEW		3


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void memoserv_init(void);
extern void memoserv_terminate(void);

// Handlers
extern void memoserv(CSTR source, User *callerUser, char *buf);

// Database stuff
extern void load_ms_dbase(void);
extern void save_ms_dbase(void);
extern void expire_memos(void);

extern void check_memos(const User *callerUser, NickInfo *ni);
extern void clear_memos(CSTR nick);
extern void memoserv_delete_flagged_memos(CSTR nick, BOOL noMessage);
extern void send_memo_internal(NickInfo *ni, CSTR message);

extern void memoserv_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long memoserv_mem_report(CSTR sourceNick, const User *callerUser);

#endif /* USE_SERVICES */

#endif /* SRV_MEMOSERV_H */
