/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* conf.h - Configuration routines
* 
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
*
*/


#ifndef SRV_CONF_H
#define SRV_CONF_H

#ifdef USE_SOCKSMONITOR
#include <arpa/inet.h>
#endif


/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern BOOL conf_monitor_inputbuffer;


/*********************************************************
 * Common configuration variables                        *
 *********************************************************/

extern char *CONF_REMOTE_SERVER;
extern unsigned short int CONF_REMOTE_PORT;
extern char *CONF_REMOTE_PASSWORD;

extern char *CONF_SERVICES_NAME;
extern char *CONF_SERVICES_DESC;
extern char *CONF_SERVICES_USERNAME;
extern char *CONF_SERVICES_HOST;

extern char s_DebugServ[NICKSIZE];
extern char s_DS[3];

extern char *CONF_NETWORK_NAME;
extern time_t CONF_DATABASE_UPDATE_FREQUENCY;
extern BOOL CONF_DISPLAY_UPDATES;
extern char *CONF_SNOOP_CHAN;
extern char *CONF_DEBUG_CHAN;
extern int CONF_DATABASE_BACKUP_FREQUENCY;
extern BOOL CONF_SET_DEBUG;
extern BOOL CONF_SET_READONLY;
extern BOOL CONF_SET_SNOOP;
extern BOOL CONF_SET_NOEXPIRE;
extern BOOL CONF_SET_EXTRASNOOP;
extern BOOL CONF_SET_FLOOD;
extern int CONF_FLOOD_MAX_MESSAGES;
extern time_t CONF_FLOOD_MESSAGE_RESET;
extern time_t CONF_FLOOD_LEVEL_RESET;
extern char *CONF_SERVICES_MASTER;

#ifndef USE_SERVICES
extern char *CONF_SERVICES_MASTER_PASS;
#endif

#ifdef USE_SERVICES

extern char s_NickServ[NICKSIZE];
extern char s_ChanServ[NICKSIZE];
extern char s_MemoServ[NICKSIZE];
extern char s_HelpServ[NICKSIZE];
extern char s_OperServ[NICKSIZE];
extern char s_RootServ[NICKSIZE];
extern char s_GlobalNoticer[NICKSIZE];
extern char s_NS[3];
char s_CS[3];
char s_MS[3];
char s_HS[3];
char s_OS[3];
char s_RS[3];

extern time_t CONF_TIMEOUT_CHECK;
#ifndef NEW_SOCK
extern time_t CONF_TIMEOUT_STARTUP_DELTA;
#endif
extern int CONF_INVALID_PASSWORD_MAX_ATTEMPTS;
extern time_t CONF_INVALID_PASSWORD_RESET;
extern int CONF_INVALID_PASSWORD_FIRST_IGNORE;
extern int CONF_INVALID_PASSWORD_SECOND_IGNORE;
extern int CONF_CHANNEL_EXPIRE;
extern int CONF_NICK_EXPIRE;
extern int CONF_MEMO_EXPIRE;
extern int CONF_SEND_REMINDER;
extern int CONF_CHAN_ACCESS_MAX;
extern int CONF_AKICK_MAX;
extern int CONF_USER_ACCESS_MAX;
extern int CONF_USER_CHAN_ACCESS_MAX;
extern time_t CONF_REGISTER_DELAY;
extern time_t CONF_MEMO_SEND_DELAY;
extern time_t CONF_RELEASE_TIMEOUT;
extern time_t CONF_CHANNEL_INHABIT;
extern int CONF_DEF_MAX_MEMOS;
extern time_t CONF_DEFAULT_IGNORE_EXPIRY;
extern BOOL CONF_SET_CLONE;
extern int CONF_CLONE_MIN_USERS;
extern time_t CONF_CLONE_WARNING_DELAY;
extern int CONF_AKILL_CLONES;
extern int CONF_CLONE_SCAN_V6;
extern time_t CONF_DEFAULT_CLONEKILL_EXPIRY;
extern BOOL CONF_USE_EMAIL;
extern char *CONF_RETURN_EMAIL;
extern char *CONF_SENDMAIL_PATH;
extern long int CONF_DEF_MLOCKON;
extern long int CONF_DEF_MLOCKOFF;
extern BOOL CONF_FORCE_AUTH;
extern int CONF_AUTHDEL_DAYS;
extern BOOL CONF_SHOW_TAGLINES;
#endif

#ifdef USE_SOCKSMONITOR

extern char s_SocksMonitor[NICKSIZE];
extern char s_SM[3];

extern char *CONF_MONITOR_TEST_IP;
extern unsigned short int CONF_MONITOR_TEST_PORT;
extern char *CONF_MONITOR_LOCAL_HOST;
extern unsigned short int CONF_MONITOR_LOCAL_PORT;
extern struct sockaddr_in MONITOR_LOCAL_ADDRESS;

extern char SOCKS4_BUFFER[9];
extern char SOCKS5_BUFFER[10];
extern char PROXY_BUFFER[IRCBUFSIZE];
extern ssize_t PROXY_BUFFER_LEN;

extern char *CONF_PROXY_CHAN;

extern int CONF_MONITOR_MAXTHREADS;

extern time_t CONF_SOCKET_TIMEOUT;
extern time_t CONF_PROXY_EXPIRE;
extern time_t CONF_HOST_CACHE_EXPIRE;
extern time_t CONF_FLOOD_CACHE_EXPIRE;
extern int CONF_MAX_FLOOD_HITS;

extern BOOL CONF_SCAN_SOCKS4;
extern BOOL CONF_SCAN_SOCKS5;
extern BOOL CONF_SCAN_WINGATE;
extern BOOL CONF_SCAN_80;
extern BOOL CONF_SCAN_3128;
extern BOOL CONF_SCAN_6588;
extern BOOL CONF_SCAN_8080;

extern BOOL CONF_WARMACHINE_DETECT;
extern BOOL CONF_PROMIRC_DETECT;
extern BOOL CONF_VENOM_DETECT;
extern BOOL CONF_UNKNOWN_CLONER_DETECT;
extern BOOL CONF_UNUTNET_WORM_DETECT;
extern BOOL CONF_WARSATAN_DETECT;
extern BOOL CONF_CLONESX_DETECT;
extern BOOL CONF_SABAN_DETECT;
extern BOOL CONF_PROXER_DETECT;
extern BOOL CONF_MUHSTIK_DETECT;
extern BOOL CONF_DTHN_DETECT;
extern BOOL CONF_GUEST_DETECT;
extern BOOL CONF_FIZZER_DETECT;
extern BOOL CONF_MAIL_DETECT;
extern BOOL CONF_OPTIXPRO_DETECT;
extern BOOL CONF_BOTTLER_DETECT;
extern BOOL CONF_TENERONE_DETECT;
extern BOOL CONF_NGILAMER_DETECT;
#endif

#ifdef USE_STATS
extern char s_StatServ[NICKSIZE];
extern char s_SeenServ[NICKSIZE];
extern char s_ST[3];
extern char s_SS[3];

extern int CONF_STATS_EXPIRE;
extern int CONF_SEEN_EXPIRE;
extern int CONF_MAX_WILD_SEEN;
#endif

#if defined(USE_SERVICES) || defined(USE_SOCKSMONITOR)
extern float CONF_AKILL_PERCENT;
extern time_t CONF_DEFAULT_AKILL_EXPIRY;
#endif


#ifdef USE_SERVICES
	#define s_Snooper		s_OperServ
	#define s_SN			s_OS
	#define s_RootSnooper	s_RootServ
	#define s_RSN			s_RS
#elif defined(USE_STATS)
	#define s_Snooper		s_StatServ
	#define s_SN			s_ST
	#define s_RootSnooper	s_StatServ
	#define s_RSN			s_ST
#else
	#define s_Snooper		s_SocksMonitor
	#define s_SN			s_SM
	#define s_RootSnooper	s_SocksMonitor
	#define s_RSN			s_SM
#endif


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void init_conf(BOOL rehash);
extern void conf_rehash();
extern void handle_rehash(CSTR source, User *callerUser, ServiceCommandData *data);
extern void handle_set(CSTR source, User *callerUser, ServiceCommandData *data);
extern void conf_ds_dump(CSTR sourceNick, const User *callerUser, STR request);

#endif /* SRV_CONF_H */
