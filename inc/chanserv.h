/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* chanserv.h - ChanServ service
* 
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
*
*/


#ifndef SRV_CHANSERV_H
#define SRV_CHANSERV_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "lang.h"


/*********************************************************
 * Version stuff                                         *
 *********************************************************/

#define	CHANSERV_DB_CURRENT_VERSION		8
#define CHANSERV_DB_SUPPORTED_VERSION	"7, 8"


/*********************************************************
 * Data types                                            *
 *********************************************************/

// Access levels for users

typedef struct {

    short	level;
	short	status:4; /* See ACCESS_ENTRY_* below */

	short   flags:12;

	char	*name;
	char	*creator;

	time_t	creationTime;

} ChanAccess_V7;

#ifdef OS_64BIT
typedef struct _ChanAccess_V7_32 {
		short	level;
		short	status:4; /* See ACCESS_ENTRY_* below */

		short   flags:12;

		uint32_t	name;
		uint32_t	creator;

		uint32_t	creationTime;

} ChanAccess_V7_32;
typedef ChanAccess_V7_32 ChanAccess32;
#endif
// Current structs version
typedef	ChanAccess_V7	ChanAccess;



// AutoKick data.

typedef struct _AutoKick_V7		AutoKick_V7;
struct _AutoKick_V7 {

    unsigned short	isNick:1;
    short			flags:15;

    short			banType;

    char			*name;
    char			*reason;
	char			*creator;

	time_t			creationTime;
};

#ifdef OS_64BIT
typedef struct _AutoKick_V7_32		AutoKick_V7_32;
struct _AutoKick_V7_32 {
	unsigned short	isNick:1;
	short			flags:15;

	short			banType;

	uint32_t			name;
	uint32_t			reason;
	uint32_t			creator;

	uint32_t			creationTime;
};
typedef	AutoKick_V7_32		AutoKick32;
#endif

// Current structs version
typedef	AutoKick_V7		AutoKick;



// a registered channel
typedef struct _ChannelInfo_V8		ChannelInfo_V8;
struct _ChannelInfo_V8 {

    ChannelInfo_V8	*next, *prev;
    char			name[CHANMAX];
    char			founder[NICKMAX];				/* Always a reg'd nick */
    char			founderpass[PASSMAX];
    char			*desc;
    time_t			time_registered;
    time_t			last_used;
    long			accesscount;
    ChanAccess_V7	*access;					/* List of authorized users */
    long			akickcount;
    AutoKick_V7		*akick;
    flags_t			mlock_on, mlock_off;			/* See channel modes below */
    long			mlock_limit;					/* 0 if no limit */
    char			*mlock_key;					/* NULL if no key */
    char			*last_topic;					/* Last topic on the channel */
    char			last_topic_setter[NICKMAX];	/* Who set the last topic */
    time_t			last_topic_time;				/* When the last topic was set */
    flags_t			flags;							/* CI_* */
    char			*successor;					
    char			*url;
    char			*email;
    char			*welcome;
    char			*hold;       /*  }                                         */
    char			*mark;       /*  }   --   Identities (what admin did it?)  */
    char			*freeze;     /*  }   --                                    */
    char			*forbid;     /*  }                                         */
    int				topic_allow;					/* Who's allowed to change topic */
    unsigned long	auth;
    long			settings;
    char			*real_founder;
	time_t			last_drop_request;
	NICK_LANG_ID	langID;
    unsigned char	banType;					/* For future expansion -- decrease! */
    unsigned char	reserved[2];					/* For future expansion -- decrease! */

};

// Current structs version
typedef	ChannelInfo_V8	ChannelInfo;

#ifdef OS_64BIT
typedef struct _ChannelInfo_V8_32		ChannelInfo_V8_32;
struct _ChannelInfo_V8_32 {

	uint32_t		next, prev;
	char			name[CHANMAX];
	char			founder[NICKMAX];				/* Always a reg'd nick */
	char			founderpass[PASSMAX];
	uint32_t		desc;
	int32_t			time_registered;
	int32_t			last_used;
	int32_t			accesscount;
	int32_t			access;					/* List of authorized users */
	int32_t			akickcount;
	int32_t			akick;
	uint32_t		mlock_on, mlock_off;			/* See channel modes below */
	int32_t			mlock_limit;					/* 0 if no limit */
	uint32_t		mlock_key;					/* NULL if no key */
	uint32_t		last_topic;					/* Last topic on the channel */
	char			last_topic_setter[NICKMAX];	/* Who set the last topic */
	int32_t			last_topic_time;				/* When the last topic was set */
	uint32_t		flags;							/* CI_* */
	int32_t 		successor;
	int32_t 		url;
	int32_t 		email;
	int32_t 		welcome;
	int32_t 		hold;       /*  }                                         */
	int32_t 		mark;       /*  }   --   Identities (what admin did it?)  */
	int32_t 		freeze;     /*  }   --                                    */
	int32_t 		forbid;     /*  }                                         */
	int				topic_allow;					/* Who's allowed to change topic */
	uint32_t	auth;
	int32_t			settings;
	int32_t			real_founder;
	int32_t			last_drop_request;
	NICK_LANG_ID	langID;
	unsigned char	banType;					/* For future expansion -- decrease! */
	unsigned char	reserved[2];					/* For future expansion -- decrease! */

};

// Current structs version
typedef	ChannelInfo_V8_32	ChannelInfo32;
#endif



// ChanServ timeout data
typedef struct channel_timeout_data {

	int	type;	/* CTOD_* */

	union _info {
		char			*name;
		ChannelInfo		*record;
	} info;
} ChannelTimeoutData;


/*********************************************************
 * Constants                                             *
 *********************************************************/

// ChanAccess.status
#define ACCESS_ENTRY_FREE		0
#define ACCESS_ENTRY_NICK		1
#define ACCESS_ENTRY_MASK		2
#define ACCESS_ENTRY_EXPIRED	3

#define ACCESS_FLAG_LOCKED		1


#define AKICK_FLAG_LOCKED		1

// ChannelInfo.flags

#define CI_KEEPTOPIC	0x00000001
#define CI_OPGUARD		0x00000002
#define CI_AUTOVOICE	0x00000004
#define CI_TOPICLOCK	0x00000008
#define CI_RESTRICTED	0x00000010
#define CI_LEAVEOPS		0x00000020
#define CI_IDENT		0x00000040
#define CI_FORBIDDEN	0x00000080
#define CI_AUTOHALFOP	0x00000100
#define CI_HELDCHAN     0x00000200
#define CI_MARKCHAN     0x00000400
#define CI_MEMO_HOP     0x00000800
#define CI_SOPONLY      0x00001000
#define CI_SAONLY       0x00002000
#define CI_SRAONLY      0x00004000
#define CI_CODERONLY    0x00008000
#define CI_AUTOOP		0x00010000
#define CI_FROZEN		0x00020000
#define CI_MEMO_VOP     0x00040000
#define CI_MEMO_AOP     0x00080000
#define CI_MEMO_SOP     0x00100000
#define CI_MEMO_CF      0x00200000
#define CI_MEMO_FR      0x00400000
#define CI_MEMO_NONE    0x00800000
#define CI_SUSPENDED    0x01000000
#define CI_REMIND       0x02000000
#define CI_PROTECTED    0x04000000
#define CI_CLOSED       0x08000000
#define CI_NEVEROP		0x10000000
#define CI_NOENTRY		0x20000000
#define CI_TIMEOUT		0x40000000
#define CI_NOMKICK		0x80000000

/* bit 32+: flags_t is unsigned long, 64-bit on LP64 — bits above 0x80000000
   are only meaningful on 64-bit services and must NEVER be persisted to a
   32-bit ChannelInfo_V8_32 migration record. */
#define CI_PASSRESET	0x100000000ULL		/* Channel requested a password reset. */

/* Shaka 13/05/01

  Alcuni valori restituiti da get_access()

  15 Founder
  13 Co-Founder
  10 SOP
   5 AOP
   3 VOP
   ? AKICK

*/
#define CS_ACCESS_FOUNDER		15
#define CS_ACCESS_COFOUNDER		13
#define CS_ACCESS_SOP			10
#define CS_ACCESS_AOP			5
#define CS_ACCESS_HOP			4
#define CS_ACCESS_VOP			3
#define CS_ACCESS_NONE			0
#define CS_ACCESS_AKICK			20	/* valore impostato arbitrariamente */

#define CS_STATUS_IDCHAN		4
#define CS_STATUS_IDNICK		3
#define CS_STATUS_ACCLIST		2
#define CS_STATUS_MASK			1
#define CS_STATUS_NONE			0


/* Flag di lock per ci.settings */
#define CI_ACCCESS_NO_LOCK				0x00000000
#define CI_ACCCESS_CFOUNDER_LOCK		0x00000001
#define CI_ACCCESS_SOP_LOCK				0x00000002
#define CI_ACCCESS_AOP_LOCK				0x00000004
#define CI_ACCCESS_VOP_LOCK				0x00000008
#define CI_ACCCESS_AKICK_LOCK			0x00000010
#define CI_ACCCESS_HOP_LOCK				0x00000020


/* Flag per il livello di verbose (ci.settings) */
#define CI_NOTICE_VERBOSE_NONE			0x0000000 // 000 00000000 00000000 00000000
#define CI_NOTICE_VERBOSE_CLEAR			0x0000100 // 000 00000000 00000001 00000000
#define CI_NOTICE_VERBOSE_ACCESS		0x0000200 // 000 00000000 00000010 00000000
#define CI_NOTICE_VERBOSE_SET			0x0000300 // 000 00000000 00000011 00000000

#define CI_NOTICE_VERBOSE_MASK      	0x0000300 // 000 00000000 00000011 00000000
#define CI_NOTICE_VERBOSE_RESETMASK 	0x000FCFF // 000 00000000 11111100 11111111


/* ChannelTimeoutData.type */
#define	CTOD_CHAN_NAME		1
#define CTOD_CHAN_RECORD	2


/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern unsigned long cs_regCount;


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void chanserv_init(void);
extern void chanserv_terminate(void);


// Handlers
extern void chanserv(CSTR source, User *callerUser, char *buf);

// Database stuff
extern void load_cs_dbase(void);
extern void save_cs_dbase(void);
extern void load_suspend_db(void);
extern void save_suspend_db(void);
extern void expire_chans(void);
extern void chanserv_daily_expire(void);
extern void cs_remove_nick(CSTR nick);

extern void chanserv_dispose_timeout_data(void *data);
extern void check_modelock(Channel *chan, User *changedBy);
extern void check_welcome(const User *user, ChannelInfo *ci);
extern BOOL check_should_op(const User *user, ChannelInfo *ci);
extern BOOL check_should_halfop(const User *user, ChannelInfo *ci);
extern BOOL check_should_voice(const User *user, ChannelInfo *ci);
extern BOOL check_valid_op(const User *user, ChannelInfo *ci, int newchan);
extern void record_topic(Channel *chan);
extern void restore_topic(Channel *chan);
extern BOOL check_topiclock(const User *user, Channel *chan);
extern ChannelInfo *cs_findchan(CSTR chan);
extern int get_access(const User *user, const ChannelInfo *ci, char *accessName, int *accessMatch, int *accessStatus);
extern BOOL chanserv_check_user_join(const User *user, Channel *chan);
extern void chanserv_listchans(const User *callerUser, CSTR nick, const BOOL isSelf);

#define CSMatchVerbose(settings, level)		( ((settings) & CI_NOTICE_VERBOSE_MASK) >= (level) )

extern void chanserv_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int chanserv_mem_report(CSTR sourceNick, const User *callerUser);


#endif /* SRV_CHANSERV_H */
