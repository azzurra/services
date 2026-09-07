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

#define	ACCESS_DB_CURRENT_VERSION		10
#define ACCESS_DB_SUPPORTED_VERSION		"10"
#define	DYNCONF_DB_CURRENT_VERSION		10
#define DYNCONF_DB_SUPPORTED_VERSION	"10"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _Creator {

	char		*name;
	time_t		time;

} Creator;

typedef struct _Creator_32 {
	uint32_t	name;
	uint32_t	time;
} Creator32;

typedef struct _CreationInfo {

	Creator		creator;
	char		*reason;

} CreationInfo;

typedef struct _CreationInfo_32 {
	Creator32	creator;
	uint32_t	reason;
} CreationInfo32;

typedef struct	_SettingsInfo	SettingsInfo;
struct _SettingsInfo {

	SettingsInfo		*next;

	CreationInfo		creation;
	unsigned long int	type;
};


typedef struct _access_V10 Access_V10;

struct _access_V10 {

	Access_V10	*next;

	char		*nick;
	char		*user;
	char		*user2;
	char		*user3;
	char		*host;
	char		*host2;
	char		*host3;
	char		*server;
	char		*server2;
	char		*server3;

	long		flags;		/* AC_* defined below. */

	long		modes_on;	/* Modes added on connect. */
	long		modes_off;	/* Modes removed on connect. */

	Creator		creator;

	time_t		lastUpdate;
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

/*********************************************************
 * Constants                                             *
 *********************************************************/

#define AC_FLAG_ENABLED		0x00000001
#define AC_FLAG_ONLINE		0x00000002

#define AC_RESULT_NOTFOUND	0
#define AC_RESULT_GRANTED	1
#define AC_RESULT_DENIED	2


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void operdb_init(void);
extern void operdb_terminate(void);

extern void operdb_load(void);

extern mowgli_list_t *serverBotList;
extern dynConfig dynConf;

#endif /* DBCONV_OPERDB_H */
