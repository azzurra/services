/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* config.h - Services configuration header
* 
*/

#ifndef SRV_CONFIG_H
#define SRV_CONFIG_H


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef	int	agentid_t;


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define CRYPT_NETNAME		"Azzurra"
#define CRYPT_NETNAME_LEN	7			/* strlen(CRYPT_NETNAME) */

#define AGENTID_UNKNOWN		(agentid_t) 0
#define AGENTID_NICKSERV	(agentid_t) 1
#define AGENTID_CHANSERV	(agentid_t) 2
#define AGENTID_MEMOSERV	(agentid_t) 3
#define AGENTID_HELPSERV	(agentid_t) 4
#define AGENTID_DEBUGSERV	(agentid_t) 5
#define AGENTID_OPERSERV	(agentid_t) 6
#define AGENTID_ROOTSERV	(agentid_t) 7
#define AGENTID_STATSERV	(agentid_t) 8
#define AGENTID_SEENSERV	(agentid_t) 9
#define AGENTID_CYBCOP		(agentid_t) 10
#define AGENTID_GNOTICER	(agentid_t) 11

#define AGENTID_FIRST		AGENTID_NICKSERV
#define AGENTID_LAST		AGENTID_GNOTICER


/******* General configuration *******/

#define CONFIG_FILE 	"../services.conf"
#define MOTD_FILENAME   "../services.motd"
#define PID_FILE	"../services.pid"

/******* End of runtime-configurable options. *******/

#define HELPSERV_DIR		"helpfiles"
#define HELPSERV_OPER_DIR	"ohelpfiles"

/* Database filenames */

#define OPERACCESS_DB		"operacc.db"
#define OPER_DB			"oper.db"

#define NICKSERV_DB		"nick.db"
#define CHANSERV_DB		"chan.db"
#define MEMOSERV_DB		"memo.db"
#define IGNORE_DB		"ignore.db"
#define QLINE_DB		"qline.db"
#define GLINE_DB		"gline.db"
#define TAGLINE_DB		"tagline.db"
#define TRIGGER_DB		"trigger.db"
#define BLACKLIST_DB		"blacklist.db"
#define SERVERBOT_DB		"serverbot.db"
#define RESERVED_DB		"reserved.db"
#define DYNCONF_DB		"dynconf.db"
#define LANGMATCH_DB		"langmatch.db"
#define SUSPEND_DB		"suspend.db"
#define EXEMPT_DB		"exempt.db"
#define STATSERV_DB		"statserv.db"
#define SERVSTATS_DB	"servstats.db"
#define SEENSERV_DB		"seenserv.db"
#define AKILL_DB		"akill.db"

/******* OperServ configuration *******/

/* How big a hostname list do we keep for clone detection?  On large nets
 * (over 500 simultaneous users or so), you may want to increase this. */
#define CLONE_DETECT_SIZE 60

/******* Miscellaneous - it should be safe to leave these untouched *******/

#define CHANMAX			64
#define CHANSIZE		CHANMAX + 1
#define NICKMAX			32
#define NICKSIZE		NICKMAX + 1
#define PASSMAX			32
#define PASSSIZE		PASSMAX + 1
#define UINMAX			11
#define UINSIZE			UINMAX + 1
#define URLMAX			100
#define URLSIZE			URLMAX + 1
#define KEYMAX			23
#define KEYSIZE			KEYMAX + 1
#define MAILMAX			100
#define MAILSIZE		MAILMAX + 1
#define USERMAX			10
#define USERSIZE		USERMAX + 1
#define HOSTMAX			63
#define HOSTSIZE		HOSTMAX + 1
#define MASKMAX			NICKMAX + USERMAX + HOSTMAX + 2
#define MASKSIZE		MASKMAX + 1
#define TOPICMAX		307
#define TOPICSIZE		TOPICMAX + 1
#define IPSIZE			16
#define REALMAX			50

#define SERVER_DESC_MAX	50
#define MAX_IGNORES		16

/* Size of input buffer */
#define IRCBUFSIZE		512
#define BUFSIZE			1024

/* Maximum file path length */
#define MAX_PATH		255

/* IRCd-specific define */
#define USER_MAX_MODES		6
#define SERVER_MAX_MODES	11		/* Don't set to 12, bahamut bug */
#define IRCD_MAX_PARAMS		16		/* DON'T CHANGE! Must be >= MAXPARA from bahamut. */
#define IRCD_MAX_BANS		100

/* E-Mail defines */
#define MAIL_KLINE 		"kline@azzurra.org"
#define MAIL_ABUSE		"abuse@azzurra.org"

/* For SeenServ */
#define WILDSEEN		5

// buttare
#define FILE_VERSION_MAX        8

#define SERVICES_IP_HOST_ORDER		3221554673UL	/* 192.5.5.241 -> f.root-servers.net */
#define SERVICES_IP_NETWORK_ORDER	4043638208UL	/* The above reversed -> 241.5.5.192 */

#endif	/* SRV_CONFIG_H */
