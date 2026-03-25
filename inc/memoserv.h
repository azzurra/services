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

// Current structs version
typedef	Memo_V7		Memo;



// Ignore-list
typedef struct _MemoIgnore_V7	MemoIgnore_V7;
struct _MemoIgnore_V7 {

	time_t			creationTime;
	STR				ignoredNick;
	MemoIgnore_V7	*next, *prev;
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


// Current structs version
typedef	MemoList_V7		MemoList;
#ifdef OS_64BIT
// a single memo
typedef struct _Memo_V7_32		Memo_V7_32;
struct _Memo_V7_32 {

	char		sender[NICKMAX];
	uint32_t	unused;	/* Was index number */
	uint32_t	time;	/* When it was sent */
	uint32_t	text;
	uint32_t	chan;
	short		flags;	/* MF_* */
	short		level;	/* If it is a channel memo, this is CS_ACCESS_*, 0 otherwise. */
	uint32_t	reserved[3];   /* For future expansion -- set to 0 */
};

// Current structs version
typedef	Memo_V7_32		Memo32;



// Ignore-list
typedef struct _MemoIgnore_V7_32	MemoIgnore_V7_32;
struct _MemoIgnore_V7_32 {

	uint32_t			creationTime;
	uint32_t			ignoredNick;
	uint32_t			next, prev;
};

// Current structs version
typedef	MemoIgnore_V7_32	MemoIgnore32;


// a nickname memo-list
typedef struct _MemoList_V7_32		MemoList_V7_32;
struct _MemoList_V7_32 {

	uint32_t			next, prev;
	char				nick[NICKMAX];		/* Owner of the memos */
	uint32_t			n_memos;			/* Number of memos */
	uint32_t			memos;				/* The memos themselves */

	uint32_t			n_ignores;			/* Number of ignores */
	uint32_t			ignores;			/* Ignore-list */

	uint32_t reserved[2];					/* For future expansion - set to 0 */
};
typedef	MemoList_V7_32		MemoList32;
#endif


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

#endif /* SRV_MEMOSERV_H */
