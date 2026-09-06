/* SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-URL: https://spdx.org/licenses/GPL-2.0-or-later.html
 *
 * Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)
 *
 * nickserv.h - datafile definitions for nickserv
 */

#ifndef DBCONV_NICKSERV_H
#define DBCONV_NICKSERV_H 1

/*********************************************************
 * Version stuff                                         *
 *********************************************************/

#define NICKSERV_DB_CURRENT_VERSION     7
#define NICKSERV_DB_SUPPORTED_VERSION   "7"


/*********************************************************
 * Data types                                            *
 *********************************************************/


// a registered nickname
typedef struct _NickInfo_V7     NickInfo_V7;
struct _NickInfo_V7 {

    NickInfo_V7         *next, *prev;
    char                nick[NICKMAX];
    char                pass[PASSMAX];
    char                *last_usermask;
    char                *last_realname;
    time_t              time_registered;
    time_t              last_seen;
    long                accesscount;            /* # of entries */
    char                **access;               /* Array of strings */
    long                flags;                  /* NI_* */
    time_t              last_drop_request;      /* Was id_timestamp */
    unsigned short int  memomax;
    short               channelcount;           /* Number of channels nick has access to */
    char                *url;
    char                *email;
    char                *forward;
    char                *hold;       /*  }                                       */
    char                *mark;       /*  }   --   Identities (what svsadmin did it?)  */
    char                *forbid;     /*  }                                       */
    int                 news;
    char                *regemail;              /* Original e-mail */
    time_t              last_email_request;     /* Was ICQ number */
    unsigned long int   auth;
    char                *freeze;
    NICK_LANG_ID        langID;

    unsigned char       reserved[3];        /* For future expansion -- decrease! */
};

struct _NickInfo_V7_32 {

    int                 next, prev; //we read it has 32bit pointers
    char                nick[NICKMAX];
    char                pass[PASSMAX];
    int32_t             last_usermask;
    int32_t             last_realname;
    int32_t             time_registered;
    int32_t             last_seen;
    int32_t             accesscount;            /* # of entries */
    int32_t             access;             /* Array of strings */
    int32_t             flags;                  /* NI_* */
    int32_t             last_drop_request;      /* Was id_timestamp */
    uint16_t            memomax;
    int16_t             channelcount;           /* Number of channels nick has access to */
    int32_t             url;
    int32_t             email;
    int32_t             forward;
    int32_t             hold;       /*  }                                       */
    int32_t             mark;       /*  }   --   Identities (what svsadmin did it?)  */
    int32_t             forbid;     /*  }                                       */
    int                 news;
    int32_t             regemail;               /* Original e-mail */
    int32_t             last_email_request;     /* Was ICQ number */
    uint32_t            auth;
    int32_t             freeze;
    NICK_LANG_ID        langID;

    unsigned char       reserved[3];        /* For future expansion -- decrease! */
};

// Current structs version
typedef NickInfo_V7     NickInfo;
typedef struct _NickInfo_V7_32      NickInfo32;

/*********************************************************
 * Constants                                             *
 *********************************************************/

// NickInfo.flags
#define NI_KILL_SLOW        0x00000001  /* "Guest" if not identified in 60s */
#define NI_SECURE           0x00000002  /* Don't recognize unless identified */
#define NI_FORBIDDEN        0x00000004  /* Nick may not be registered or used */
#define NI_ENCRYPTEDPW      0x00000008  /* Nickname password is encrypted */
#define NI_MEMO_SIGNON      0x00000010  /* Notify of memos at signon and identify */
#define NI_MEMO_RECEIVE     0x00000020  /* Notify of new memos when sent */
#define NI_REVERSEIGN       0x00000040  /* Was NI_PRIVATE */
#define NI_HIDE_EMAIL       0x00000080
#define NI_MARK             0x00000100
#define NI_HOLD             0x00000200
#define NI_EMAILMEMOS       0x00000400
#define NI_NOOP             0x00000800
#define NI_NOMEMO           0x00001000
#define NI_NOMAIL           0x00002000  /* Nick may not request a mail change */
#define NI_READNEWS         0x00004000  /* Was NI_SENDLOGS */
#define NI_NEVEROP          0x00008000
#define NI_REMIND           0x00010000
#define NI_AUTH             0x00020000
#define NI_FROZEN           0x00040000
#define NI_TIMEOUT          0x00080000
#define NI_ENFORCE          0x00100000  /* Nick must be enforced at nickchange */
#define NI_MAILCHANGE       0x00200000  /* Nick requested a mail change */
#define NI_DROP             0x00400000  /* Nick requested a drop */
#define NI_KILL_NORMAL      0x00800000  /* "Guest" if not identified in 20s */
#define NI_KILL_FAST        0x01000000  /* "Guest" if not identified in 5s */
#define NI_NOCHANMEMO       0x02000000  /* No memos sent to channels will be received. */
#define NI_PASSRESET        0x04000000  /* Nick requested a password reset. */
#define NI_ENFORCED         0x20000000  /* Nick is being held after a kill */
#define NI_NOWELCOME        0x40000000  /* Was NI_RECOGNIZED */
#define NI_IDENTIFIED       0x80000000  /* This is free */

/*********************************************************
 * Public API                                            *
 *********************************************************/
extern void nickserv_init(void);
extern void nickserv_terminate(void);

extern void load_ns_dbase(void);
extern void dump_ns_dbase(void); /* TODO: replace with actual writing routines*/

#endif /* DBCONV_NICKSERV_H */
