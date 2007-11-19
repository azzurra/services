/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* nickserv.h - NickServ service
* 
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
*
*/


#ifndef SRV_NICKSERV_H
#define SRV_NICKSERV_H

#ifdef USE_SERVICES

/*********************************************************
 * Version stuff                                         *
 *********************************************************/

#define	NICKSERV_DB_CURRENT_VERSION		7
#define NICKSERV_DB_SUPPORTED_VERSION	"7"


/*********************************************************
 * Data types                                            *
 *********************************************************/


// a registered nickname
typedef struct _NickInfo_V7		NickInfo_V7;
struct _NickInfo_V7 {

    NickInfo_V7			*next, *prev;
    char				nick[NICKMAX];
    char				pass[PASSMAX];
    char				*last_usermask;
    char				*last_realname;
    time_t				time_registered;
    time_t				last_seen;
    long				accesscount;			/* # of entries */
    char				**access;				/* Array of strings */
    long				flags;					/* NI_* */
	time_t				last_drop_request;		/* Was id_timestamp */
    unsigned short int	memomax;
    short				channelcount;			/* Number of channels nick has access to */
    char				*url;
    char				*email;
    char				*forward;
    char				*hold;       /*  }                                       */
    char				*mark;       /*  }   --   Identities (what svsadmin did it?)  */
    char				*forbid;     /*  }                                       */
    int					news;
    char				*regemail;				/* Original e-mail */
	time_t				last_email_request;		/* Was ICQ number */
    unsigned long int	auth;
    char				*freeze;
    NICK_LANG_ID		langID;

	unsigned char		reserved[3];		/* For future expansion -- decrease! */
};

typedef struct _NickInfo_V10		NickInfo_V10;
struct _NickInfo_V10 {

    NickInfo_V10		*next, *prev;

	char				*nick;
    char				*pass;
    char				*last_usermask;
    char				*last_realname;

    char				*url;
    char				*email;
    char				*regemail;
    char				*forward;

    time_t				time_registered;
    time_t				last_seen;
    time_t				last_email_request;
    time_t				last_drop_request;

    unsigned char		accesscount;
    char				**access;

    flags_t				flags;
    unsigned char		channelcount;

    NICK_LANG_ID		langID;
	SettingsInfo		*info;

    unsigned long int	auth;
};

// Current structs version
typedef NickInfo_V7		NickInfo;


// NickServ timeout data
typedef struct nick_timeout_data {

	NickInfo	*ni;
	int			step;
	BOOL		user_online;

} NickTimeoutData;



/*********************************************************
 * Constants                                             *
 *********************************************************/

// NickInfo.flags
#define NI_KILL_SLOW		0x00000001  /* "Guest" if not identified in 60s */
#define NI_SECURE			0x00000002  /* Don't recognize unless identified */
#define NI_FORBIDDEN		0x00000004  /* Nick may not be registered or used */
#define NI_ENCRYPTEDPW		0x00000008  /* Nickname password is encrypted */
#define NI_MEMO_SIGNON		0x00000010  /* Notify of memos at signon and identify */
#define NI_MEMO_RECEIVE		0x00000020  /* Notify of new memos when sent */
#define NI_REVERSEIGN		0x00000040  /* Was NI_PRIVATE */
#define NI_HIDE_EMAIL		0x00000080
#define NI_MARK				0x00000100
#define NI_HOLD				0x00000200
#define NI_EMAILMEMOS		0x00000400
#define NI_NOOP				0x00000800
#define NI_NOMEMO			0x00001000
#define NI_NOMAIL			0x00002000	/* Nick may not request a mail change */
#define NI_READNEWS			0x00004000	/* Was NI_SENDLOGS */
#define NI_NEVEROP			0x00008000
#define NI_REMIND			0x00010000
#define NI_AUTH				0x00020000
#define NI_FROZEN			0x00040000
#define NI_TIMEOUT			0x00080000
#define NI_ENFORCE			0x00100000  /* Nick must be enforced at nickchange */
#define NI_MAILCHANGE		0x00200000	/* Nick requested a mail change */
#define NI_DROP				0x00400000	/* Nick requested a drop */
#define NI_KILL_NORMAL		0x00800000  /* "Guest" if not identified in 20s */
#define NI_KILL_FAST		0x01000000  /* "Guest" if not identified in 5s */
#define NI_NOCHANMEMO		0x02000000  /* No memos sent to channels will be received. */
#define NI_ENFORCED			0x20000000  /* Nick is being held after a kill */
#define NI_NOWELCOME		0x40000000  /* Was NI_RECOGNIZED */
#define NI_IDENTIFIED		0x80000000  /* This is free */


/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern unsigned long ns_regCount;


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void nickserv_init(void);
extern void nickserv_terminate(void);

// Handlers
extern void nickserv(const char *source, User *callerUser, char *buf);

// Database stuff
extern void load_ns_dbase(void);
extern void save_ns_dbase(void);
extern void expire_nicks(void);
extern void nickserv_daily_expire(void);


extern void validate_user(const User *user);
extern NickInfo *findnick(const char *nick);
extern NickInfo *retnick(int i);
extern void nickserv_update_news(const LANG_ID lang_id);
extern void check_enforce(NickInfo *ni);
extern BOOL is_on_access(const User *user, const NickInfo *ni);
extern void nickserv_dispose_timeout_data(void *data);
extern void nickserv_guest_reserve(unsigned int guestNumber);
extern void nickserv_guest_free(unsigned int guestNumber);

extern void nickserv_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int nickserv_mem_report(CSTR sourceNick, const User *callerUser);

#endif /* USE_SERVICES */

#endif /* SRV_NICKSERV_H */
