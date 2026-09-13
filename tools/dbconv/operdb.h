/* SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-URL: https://spdx.org/licenses/GPL-2.0-or-later.html
 *
 * Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)
 *
 * operdb.c - combined OperServ/RootServ database structures
 */

#ifndef DBCONV_OPERDB_H
#define DBCONV_OPERDB_H 1

/*********************************************************
 * Version stuff                                         *
 *********************************************************/

#define ACCESS_DB_CURRENT_VERSION       10
#define ACCESS_DB_SUPPORTED_VERSION     "10"
#define DYNCONF_DB_CURRENT_VERSION      10
#define DYNCONF_DB_SUPPORTED_VERSION    "10"
#define SPAM_DB_CURRENT_VERSION         10
#define SPAM_DB_SUPPORTED_VERSION       "10"
#define TRIGGER_DB_CURRENT_VERSION      10
#define TRIGGER_DB_SUPPORTED_VERSION    "10"
#define IGNORE_DB_CURRENT_VERSION       10
#define IGNORE_DB_SUPPORTED_VERSION     "10"
#define SXLINE_DB_CURRENT_VERSION       10
#define SXLINE_DB_SUPPORTED_VERSION     "10"
#define RESERVED_DB_CURRENT_VERSION     10
#define RESERVED_DB_SUPPORTED_VERSION   "10"
#define BLACKLIST_DB_CURRENT_VERSION    10
#define BLACKLIST_DB_SUPPORTED_VERSION  "10"
#define TAGLINE_DB_CURRENT_VERSION      10
#define TAGLINE_DB_SUPPORTED_VERSION    "10"
#define AKILL_DB_CURRENT_VERSION        10
#define AKILL_DB_SUPPORTED_VERSION      "10"
#define REGIONS_DB_CURRENT_VERSION      10
#define REGIONS_DB_SUPPORTED_VERSION    "7 10"
#define OPER_DB_CURRENT_VERSION         11
#define OPER_DB_SUPPORTED_VERSION       "11"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef uint32_t REGION_ID;
typedef uint32_t REGION_TYPE;

struct _CIDR_IP {
    uint32_t ip;
    uint32_t mask;
};

typedef struct _CIDR_IP CIDR_IP;

typedef struct _Creator {

    char        *name;
    time_t      time;

} Creator;

typedef struct _Creator_32 {
    uint32_t    name;
    uint32_t    time;
} Creator32;

typedef struct _CreationInfo {

    Creator     creator;
    char        *reason;

} CreationInfo;

typedef struct _CreationInfo_32 {
    Creator32   creator;
    uint32_t    reason;
} CreationInfo32;

typedef struct  _SettingsInfo   SettingsInfo;
struct _SettingsInfo {

    SettingsInfo        *next;

    CreationInfo        creation;
    unsigned long int   type;
};


typedef struct _access_V10 Access_V10;

struct _access_V10 {

    Access_V10  *next;

    char        *nick;
    char        *user;
    char        *user2;
    char        *user3;
    char        *host;
    char        *host2;
    char        *host3;
    char        *server;
    char        *server2;
    char        *server3;

    long        flags;      /* AC_* defined below. */

    long        modes_on;   /* Modes added on connect. */
    long        modes_off;  /* Modes removed on connect. */

    Creator     creator;

    time_t      lastUpdate;
};


#define Access Access_V10

typedef struct _access_V10_32 Access_V10_32;

struct _access_V10_32 {
    int32_t next;

    int32_t nick;
    int32_t user;
    int32_t user2;
    int32_t user3;
    int32_t host;
    int32_t host2;
    int32_t host3;
    int32_t server;
    int32_t server2;
    int32_t server3;

    int32_t flags; /* AC_* defined below. */

    int32_t modes_on; /* Modes added on connect. */
    int32_t modes_off; /* Modes removed on connect. */

    Creator32 creator;

    int32_t lastUpdate;
};


typedef Access_V10_32 Access32;

typedef struct _dynConfig dynConfig;

struct _dynConfig {
   // limiti nelle registrazioni di nick e chan
   unsigned long    ns_regLimit;
   unsigned long    cs_regLimit;

   // notice on-connect
   char             *welcomeNotice;
};

typedef struct _dynConfig32 dynConfig32;
struct __attribute__((packed)) _dynConfig32 {
    // limiti nelle registrazioni di nick e chan
    uint32_t    ns_regLimit;
    uint32_t    cs_regLimit;

    // notice on-connect
    int32_t          welcomeNotice;
};

typedef struct _SpamItem SpamItem;

struct _SpamItem {
    SpamItem        *next;

    char            *text;
    flags_t         flags;  // SPF_*
    unsigned char   type;

    Creator         creator;
    char            *reason;

    unsigned char   pad;
};

typedef struct _SpamItem_32 SpamItem32;
#pragma pack(push, 4)
struct _SpamItem_32 {
    uint32_t        next;

    uint32_t        text;
    uint32_t        flags;  // SPF_*
    uint8_t         type;

    Creator32       creator;
    uint32_t        reason;

    unsigned char   pad;
};
#pragma pack(pop)

typedef struct _trigger_V10     Trigger_V10;
struct _trigger_V10 {

    Trigger_V10     *prev, *next;

    char            *username;
    char            *host;
    CIDR_IP         cidr;

    unsigned char   pad;            /* Not used. */
    unsigned char   value;
    tiny_flags_t    flags;

    CreationInfo    info;

    time_t          lastUsed;
    time_t          expireTime;
};

// Current struct version
typedef Trigger_V10     Trigger;

typedef struct _trigger_V10_32      Trigger_V10_32;
struct _trigger_V10_32 {

    uint32_t        prev, next;

    uint32_t        username;
    uint32_t        host;
    CIDR_IP         cidr;

    unsigned char   pad;            /* Not used. */
    unsigned char   value;
    tiny_flags_t    flags;

    CreationInfo32  info;

    int32_t         lastUsed;
    int32_t         expireTime;
};

// Current struct version
typedef Trigger_V10_32      Trigger32;

typedef struct _ignore_V10      Ignore_V10;
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
typedef Ignore_V10 Ignore;

typedef struct _ignore_V10_32 Ignore_V10_32;
struct _ignore_V10_32 {

    int32_t     prev, next;

    int32_t     nick;
    int32_t     username;
    int32_t     host;

    CIDR_IP cidr;

    CreationInfo32 info;

    int32_t expireTime;
    int32_t lastUsed;

    tiny_flags_t flags;
};

// Current struct version
typedef Ignore_V10_32 Ignore32;

typedef struct _SXLine_V10 SXLine_V10;
struct _SXLine_V10 {

    SXLine_V10      *prev, *next;

    char            *name;      /* Realname if it's a G:Line, nick/channel if it's a Q:Line. */

    CreationInfo    info;

    time_t          lastUsed;
};

// Current struct version
typedef SXLine_V10  SXLine;

typedef struct _SXLine_V10_32       SXLine_V10_32;
struct _SXLine_V10_32 {
    int32_t         prev, next;
    uint32_t        name;
    CreationInfo32  info;
    int32_t         lastUsed;
};
typedef SXLine_V10_32   SXLine32;

typedef struct _reservedName_V10    reservedName_V10;
struct _reservedName_V10 {

    reservedName_V10    *next;

    char                *name;

    CreationInfo        info;

    flags_t             flags;      /* RESERVED_* */
    time_t              lastUpdate;
};

// Current structs version
typedef reservedName_V10            reservedName;

typedef struct _reservedName_V10_32 reservedName_V10_32;
struct _reservedName_V10_32 {

    int32_t             next;

    int32_t             name;

    CreationInfo32      info;

    uint32_t            flags;      /* RESERVED_* */
    int32_t             lastUpdate;
};

// Current structs version
typedef reservedName_V10_32         reservedName32;

typedef struct _blacklist_V10       BlackList_V10;
struct _blacklist_V10 {

    BlackList_V10   *prev, *next;

    char            *address;

    CreationInfo    info;
    time_t          lastUsed;

    tiny_flags_t    flags;
    short           pad;
};

// Current struct version
typedef BlackList_V10       BlackList;

typedef struct _BlackList_V10_32        BlackList_V10_32;
struct _BlackList_V10_32 {
    int32_t         prev, next;

    int32_t         address;

    CreationInfo32  info;
    int32_t         lastUsed;

    tiny_flags_t    flags;
    uint16_t        pad;
};
typedef BlackList_V10_32        BlackList32;

typedef struct _tagline_V10     Tagline_V10;
struct _tagline_V10 {

    Tagline_V10 *prev, *next;

    char        *text;
    Creator     creator;
};

// Current struct version
typedef Tagline_V10     Tagline;

typedef struct _tagline_V10_32      Tagline_V10_32;
struct _tagline_V10_32 {

    int32_t     prev, next;

    int32_t     text;
    Creator32   creator;
};

// Current struct version
typedef Tagline_V10_32      Tagline32;

typedef struct _AutoKill_V10        AutoKill_V10;
struct _AutoKill_V10 {

    AutoKill_V10 *prev, *next;

    char *username;         /* User part of the AKILL */
    char *host;             /* Host part of the AKILL */
    char *reason;           /* Why they got akilled */
    char *desc;             /* Description available to opers on LIST */

    CIDR_IP cidr;           /* CIDR data, if available (flagged WITHCIDR) */

    Creator creator;        /* Who created it, and when */

    time_t expireTime;      /* When it expires */
    time_t lastUsed;

    unsigned long id;       /* Autokill unique ID number */
    flags_t type;           /* AKILL_TYPE_* defined below */
};


// Current structs version
typedef AutoKill_V10        AutoKill;

typedef struct _AutoKill_V10_32     AutoKill_V10_32;
struct __attribute__((packed)) _AutoKill_V10_32 {

    int32_t                     prev, next;

    int32_t username;           /* User part of the AKILL */
    int32_t host;               /* Host part of the AKILL */
    int32_t reason;         /* Why they got akilled */
    int32_t desc;               /* Description available to opers on LIST */

    CIDR_IP cidr;           /* CIDR data, if available (flagged WITHCIDR) */

    Creator32 creator;      /* Who created it, and when */

    int32_t expireTime;     /* When it expires */
    int32_t lastUsed;

    uint32_t id;            /* Autokill unique ID number */
    uint32_t type;          /* AKILL_TYPE_* defined below */
};


// Current structs version
typedef AutoKill_V10_32     AutoKill32;

typedef struct _Region  Region;
struct _Region {

    REGION_ID       id;
    unsigned long   flags;  /* RF_* */
    unsigned long   hits;

    CIDR_IP         cidr;
    char            *host_mask;

    Creator         creator;
    char            *reason;

    Region          *next, *prev;
};

typedef struct _Region_32   Region32;
struct __attribute__((packed)) _Region_32 {

    REGION_ID       id;
    uint32_t        flags;  /* RF_* */
    uint32_t        hits;

    CIDR_IP         cidr;
    uint32_t        host_mask;

    Creator32       creator;
    uint32_t        reason;

    uint32_t        next, prev;
};

typedef struct _Oper_V11    Oper_V11;
struct _Oper_V11 {

    Oper_V11        *prev, *next;

    char            *nick;

    Creator         creator;
    time_t          lastUpdate;

    flags_t         flags;                  /* OPER_* defined below. */
    int             level;                  /* Oper's access level to services (ULEVEL_*) */
};

typedef struct _Oper_V11_32 Oper_V11_32;
struct _Oper_V11_32 {

    int32_t             prev, next;

    int32_t             nick;

    Creator32           creator;
    int32_t             lastUpdate;

    uint32_t            flags;                  /* OPER_* defined below. */
    int32_t             level;                  /* Oper's access level to services (ULEVEL_*) */
};
typedef Oper_V11_32 Oper32;

// Current structs version
#define Oper    Oper_V11

/*********************************************************
 * Constants                                             *
 *********************************************************/

#define AC_FLAG_ENABLED     0x00000001
#define AC_FLAG_ONLINE      0x00000002

#define AC_RESULT_NOTFOUND  0
#define AC_RESULT_GRANTED   1
#define AC_RESULT_DENIED    2

#define SPF_ENABLED 0x00000001
#define SPAM_REASON_MAXLEN 200

#define TRIGGER_FLAG_CIDR       0x0001
#define TRIGGER_FLAG_HOST       0x0002
#define TRIGGER_FLAG_REALNAME   0x0004

#define IGNORE_FLAG_MANUAL      0x0001
#define IGNORE_FLAG_TEMPORARY   0x0002
#define IGNORE_FLAG_PERMANENT   0x0004
#define IGNORE_FLAG_WITHCIDR    0x0008

#define SXLINE_TYPE_GLINE   1
#define SXLINE_TYPE_QLINE   2

#define RESERVED_NOUSE  0x00000010  /* Impedire l'uso del nome */
#define RESERVED_NOREG  0x00000020  /* Impedire la registrazione del nome */
#define RESERVED_ALERT  0x00000100  /* Ad un tentativo di utilizzo, mandare un avviso agli operatori */
#define RESERVED_KILL   0x00000200  /* Killare l'utente */
#define RESERVED_AKILL  0x00000400  /* Akillare l'utente */
#define RESERVED_LOG    0x00000800  /* Logging attivo */
#define RESERVED_ACTIVE 0x00001000  /* Nome riservato attivo */

#define RESERVED_NICK       0x00000001
#define RESERVED_CHAN       0x00000002

#define BLACKLIST_FLAG_NOTIFY   0x0001
#define BLACKLIST_FLAG_DENY     0x0002

#define AKILL_TYPE_NONE         0x00000000
#define AKILL_TYPE_TEMPORARY    0x00000001
#define AKILL_TYPE_PERMANENT    0x00000002
#define AKILL_TYPE_BY_APM       0x00000004
#define AKILL_TYPE_MANUAL       0x00000008
#define AKILL_TYPE_FLOODER      0x00000010
#define AKILL_TYPE_SOCKS        0x00000020
#define AKILL_TYPE_PROXY        0x00000040
#define AKILL_TYPE_WINGATE      0x00000080
#define AKILL_TYPE_CLONES       0x00000100
#define AKILL_TYPE_IDENT        0x00000200
#define AKILL_TYPE_BOTTLER      0x00000400
#define AKILL_TYPE_TROJAN       0x00000800
#define AKILL_TYPE_MIRCWORM     0x00001000
#define AKILL_TYPE_PROXY80      0x00002000
#define AKILL_TYPE_PROXY8080    0x00004000
#define AKILL_TYPE_PROXY3128    0x00008000
#define AKILL_TYPE_PROXY6588    0x00010000
#define AKILL_TYPE_SOCKS4       0x00020000
#define AKILL_TYPE_SOCKS5       0x00040000
#define AKILL_TYPE_RESERVED     0x00080000
#define AKILL_TYPE_WITHCIDR     0x00100000
#define AKILL_TYPE_BY_DNSBL     0x00200000

#define AKILL_TYPE_DISABLED     0x80000000

#define REGION_IT       (REGION_ID) 0
#define REGION_US       (REGION_ID) 1
#define REGION_FR       (REGION_ID) 2
#define REGION_DE       (REGION_ID) 3
#define REGION_ES       (REGION_ID) 4
#define REGION_JP       (REGION_ID) 5

#define REGION_INVALID  (REGION_ID) (-1)

#define REGION_FIRST    REGION_IT
#define REGION_LAST     REGION_JP
#define REGION_COUNT    6

#define REGIONTYPE_IP   (REGION_TYPE) 0x00000001
#define REGIONTYPE_HOST (REGION_TYPE) 0x00000002
// only for region_match()
#define REGIONTYPE_BOTH REGIONTYPE_IP | REGIONTYPE_HOST

// Oper.flags
#define OPER_FLAG_ENABLED   0x00000001

// Livelli di accesso ai comandi
#define CMDLEVEL_USER               0x00000001
#define CMDLEVEL_OPER               0x00000002
#define CMDLEVEL_AGENT              0x00000004
#define CMDLEVEL_HOP                0x00000008
#define CMDLEVEL_SOP                0x00000020
#define CMDLEVEL_SA                 0x00000040
#define CMDLEVEL_SRA                0x00000080
#define CMDLEVEL_CODER              0x00000100
#define CMDLEVEL_MASTER             0x00000200

#define CMDLEVEL_DISABLED           0x10000000
#define CMDLEVEL_CANT_BE_DISABLED   0x08000000

// Livelli utenti standard
#define ULEVEL_NOACCESS         0x00000000
#define ULEVEL_USER             CMDLEVEL_USER
#define ULEVEL_OPER             (ULEVEL_USER  | CMDLEVEL_OPER)
#define ULEVEL_AGENT            (ULEVEL_USER  | CMDLEVEL_AGENT)
#define ULEVEL_HOP              (ULEVEL_USER  | CMDLEVEL_HOP)
#define ULEVEL_SOP              (ULEVEL_AGENT | CMDLEVEL_HOP | CMDLEVEL_OPER | CMDLEVEL_SOP)
#define ULEVEL_SA               (ULEVEL_SOP   | CMDLEVEL_SA)
#define ULEVEL_SRA              (ULEVEL_SA    | CMDLEVEL_SRA)
#define ULEVEL_CODER            (ULEVEL_SRA   | CMDLEVEL_CODER)
#define ULEVEL_MASTER           (ULEVEL_CODER | CMDLEVEL_MASTER)

/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void operdb_init(void);
extern void operdb_terminate(void);

extern void operdb_load(void);

extern mowgli_list_t *serverBotList;
extern mowgli_list_t *spam_list;
extern mowgli_list_t *trigger_list;
extern mowgli_list_t *ignore_list;
extern mowgli_list_t *sqline_list;
extern mowgli_list_t *sgline_list;
extern mowgli_list_t *reserved_list;
extern mowgli_list_t *blacklist_list;
extern mowgli_list_t *tagline_list;
extern mowgli_list_t *akill_list;
extern mowgli_list_t *regions_list;

extern mowgli_patricia_t *opers_tree;

extern dynConfig dynConf;

#endif /* DBCONV_OPERDB_H */
