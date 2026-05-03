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

extern char s_NickServ[NICKSIZE];
extern char s_ChanServ[NICKSIZE];
extern char s_MemoServ[NICKSIZE];
extern char s_HelpServ[NICKSIZE];
extern char s_OperServ[NICKSIZE];
extern char s_RootServ[NICKSIZE];
extern char s_GlobalNoticer[NICKSIZE];
extern char s_NS[3];
extern char s_CS[3];
extern char s_MS[3];
extern char s_HS[3];
extern char s_OS[3];
extern char s_RS[3];

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

extern float CONF_AKILL_PERCENT;
extern time_t CONF_DEFAULT_AKILL_EXPIRY;


#define s_Snooper	s_OperServ
#define s_SN		s_OS
#define s_RootSnooper	s_RootServ
#define s_RSN		s_RS


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void init_conf(BOOL rehash);
extern void conf_rehash();
extern void handle_rehash(CSTR source, User *callerUser, ServiceCommandData *data);
extern void handle_set(CSTR source, User *callerUser, ServiceCommandData *data);
extern void conf_ds_dump(CSTR sourceNick, const User *callerUser, STR request);

#endif /* SRV_CONF_H */
