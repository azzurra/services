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

/*********************************************************
 * Data types                                            *
 *********************************************************/

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

extern dynConfig dynConf;

#endif /* DBCONV_OPERDB_H */
