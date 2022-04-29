/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* conf.c - configuration routines
*
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/memory.h"
#include "../inc/logging.h"
#include "../inc/lang.h"
#include "../inc/send.h"
#include "../inc/main.h"
#include "../inc/misc.h"
#include "../inc/users.h"
#include "../inc/crypt_userhost.h"
#include "../inc/nickserv.h"
#include "../inc/conf.h"


/*********************************************************
 * Debug configuration variables                         *
 *********************************************************/

BOOL conf_monitor_inputbuffer = FALSE;


/*********************************************************
 * Common configuration variables                        *
 *********************************************************/

/* Info on the server we're going to connect to. */
char *CONF_REMOTE_SERVER = NULL;
unsigned short CONF_REMOTE_PORT = 0;
char *CONF_REMOTE_PASSWORD = NULL;

/* Services' name, description, username and host. */
char *CONF_SERVICES_NAME = NULL;
char *CONF_SERVICES_DESC = NULL;
char *CONF_SERVICES_USERNAME = NULL;
char *CONF_SERVICES_HOST = NULL;

char s_DebugServ[NICKSIZE] = "";
char s_DS[3] = "DS";

/* Our network's name. */
char *CONF_NETWORK_NAME = NULL;

/* Frequency of database updates, in seconds. */
time_t CONF_DATABASE_UPDATE_FREQUENCY = 1800;		/* Defaults to 30 minutes. */

/* Send a globop when saving databases? */
BOOL CONF_DISPLAY_UPDATES = TRUE;

/* Channel to send snoop messages in. */
char *CONF_SNOOP_CHAN = NULL;

/* Channel to send debug messages in. */
char *CONF_DEBUG_CHAN = NULL;

/* Frequency of database backups. */
int CONF_DATABASE_BACKUP_FREQUENCY = 10;		/* Defaults to one backup every 10 saves. */

/* Are we in debug mode? */
BOOL CONF_SET_DEBUG = FALSE;

/* Are we in read-only mode? */
BOOL CONF_SET_READONLY = FALSE;

/* Should we send snoop messages? */
BOOL CONF_SET_SNOOP = FALSE;

/* Disable channel/nickname/memo expiration? */
BOOL CONF_SET_NOEXPIRE = FALSE;

/* Enable snooping of extra messages? */
BOOL CONF_SET_EXTRASNOOP = FALSE;

/* Enable flood protection? */
BOOL CONF_SET_FLOOD = TRUE;

/* Number of messages to trigger protection. */
int CONF_FLOOD_MAX_MESSAGES = 10;

/* Number of seconds to wait to go down one level. */
time_t CONF_FLOOD_MESSAGE_RESET = 15;

/* Time to wait for a full reset. */
time_t CONF_FLOOD_LEVEL_RESET = ONE_HOUR;

/* Nick of our services master. */
char *CONF_SERVICES_MASTER = NULL;

char s_NickServ[NICKSIZE] = "";
char s_ChanServ[NICKSIZE] = "";
char s_MemoServ[NICKSIZE] = "";
char s_HelpServ[NICKSIZE] = "";
char s_OperServ[NICKSIZE] = "";
char s_RootServ[NICKSIZE] = "";
char s_StatServ[NICKSIZE] = "";
char s_SeenServ[NICKSIZE] = "";
char s_GlobalNoticer[NICKSIZE] = "";
char s_NS[3] = "NS";
char s_CS[3] = "CS";
char s_MS[3] = "MS";
char s_HS[3] = "HS";
char s_OS[3] = "OS";
char s_RS[3] = "RS";
char s_ST[3] = "ST";
char s_SS[3] = "SS";


/* Number of seconds to wait for the next timeout check. */
time_t CONF_TIMEOUT_CHECK = 2;

#ifndef NEW_SOCK
/* Number of seconds to wait before starting timeout checks (old method only). */
time_t CONF_TIMEOUT_STARTUP_DELTA = 180;		/* Defaults to 3 minutes. */
#endif

/* Password hack related variables. */
int CONF_INVALID_PASSWORD_MAX_ATTEMPTS = 5;				/* Number of failed attempts allowed. */
time_t CONF_INVALID_PASSWORD_RESET = 10 * ONE_MINUTE;	/* Time to wait for reset. */
int CONF_INVALID_PASSWORD_FIRST_IGNORE = 5;				/* Number of minutes to ignore the first time. */
int CONF_INVALID_PASSWORD_SECOND_IGNORE = 30;			/* Number of minutes to ignore the second time. */

/* Expiration variables. */
int CONF_CHANNEL_EXPIRE = 30;		/* Channel expiration time, in days. */
int CONF_NICK_EXPIRE = 30;			/* Nickname expiration time, in days. */
int CONF_MEMO_EXPIRE = 30;			/* Memo expiration time, in days. */
int CONF_STATS_EXPIRE = 30;			/* Channel stats expiration time, in days. */
int CONF_SEEN_EXPIRE = 30;			/* Seen expiration time, in days. */

/* Send an E-Mail reminder when nicknames or channels are about to expire? */
int CONF_SEND_REMINDER = 0;		/* Defaults to 0 days (off). */

/* Maximum number of VOPs/AOPs/SOPs/CFs for a single channel. */
int CONF_CHAN_ACCESS_MAX = 300;

/* Maximum number of AutoKicks for a single channel. */
int CONF_AKICK_MAX = 100;

/* Maximum number of Access List entries for a single nick. */
int CONF_USER_ACCESS_MAX = 5;

/* Maximum number of channels a nick can be added to. */
int CONF_USER_CHAN_ACCESS_MAX = 25;

/* Time to wait between registrations, in seconds. */
time_t CONF_REGISTER_DELAY = 30;

/* Time to wait between memo sends, in seconds. */
time_t CONF_MEMO_SEND_DELAY = 5;

/* Time to keep a nick enforced, in seconds. */
time_t CONF_RELEASE_TIMEOUT = 180;

/* Time to keep a channel closed, in seconds. */
time_t CONF_CHANNEL_INHABIT = ONE_MINUTE;

/* Default maximum number of memos a nick can hold. */
int CONF_DEF_MAX_MEMOS = 50;

/* Default time to ignore an user. */
time_t CONF_DEFAULT_IGNORE_EXPIRY = ONE_HOUR;

/* Enable clone detection? */
BOOL CONF_SET_CLONE = TRUE;

/* Number of clones to send a globop on. */
int CONF_CLONE_MIN_USERS = 5;

/* Time to wait between globops for the same host, in seconds. */
time_t CONF_CLONE_WARNING_DELAY = 10;

/* AutoKill clones when they reach the limit? */
int CONF_AKILL_CLONES = 5;		/* Default to AutoKill upon fifth clone connection. */

/* Scan for V6 clones? If so, how many fields to match? */
int CONF_CLONE_SCAN_V6 = 5;

/* Default clones AutoKill time, in seconds. */
time_t CONF_DEFAULT_CLONEKILL_EXPIRY = 600;		/* Defaults to 10 minutes. */

/* Use E-Mails (for nick registrations, drops, etc)? */
BOOL CONF_USE_EMAIL = TRUE;

/* E-Mail address to send mails from. */
char *CONF_RETURN_EMAIL = NULL;

/* sendmail path on the box. */
char *CONF_SENDMAIL_PATH = NULL;

/* Default channel modelock. */
long int CONF_DEF_MLOCKON = 0;
long int CONF_DEF_MLOCKOFF = 0;

/* Force users to authorize their nicks? */
BOOL CONF_FORCE_AUTH = TRUE;

/* Time to wait for nickname authorization, in days. */
int CONF_AUTHDEL_DAYS = 1;

/* Show taglines when saving databases? */
BOOL CONF_SHOW_TAGLINES = FALSE;

/* Maximum percentage of users allowed to be AutoKilled. */
float CONF_AKILL_PERCENT = 50.0;

/* Default AutoKill duration, in seconds. */
time_t CONF_DEFAULT_AKILL_EXPIRY = 3 * ONE_HOUR;


static void conf_break(int ac, char **av, BOOL rehash) {

	char *err;
	long int value;


	TRACE_FCLT(FACILITY_CONF);

	if (av[0][0] == '#')
		return;

	if (str_len(av[0]) > 1) {

		if (ac != 2) {

			if (rehash)
				send_globops(NULL, "Error in option %s", av[0]);
			else
				fatal_error(FACILITY_CONF, __LINE__, "Error in option %s", av[0]);
		}
		else if (str_equals_nocase(av[0], "UPDATE")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 300) || (value > ONE_DAY)) {

				if (rehash)
					send_globops(NULL, "Value %s for UPDATE is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for UPDATE is not valid", av[1]);
			}
			else
				CONF_DATABASE_UPDATE_FREQUENCY = value;
		}
		else if (str_equals_nocase(av[0], "DISPLAY_UPDATES")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || ((value != FALSE) && (value != TRUE))) {

				if (rehash)
					send_globops(NULL, "Value %s for DISPLAY_UPDATES is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for DISPLAY_UPDATES is not valid", av[1]);
			}
			else
				CONF_DISPLAY_UPDATES = value;
		}
		else if (str_equals_nocase(av[0], "BACKUP")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value <= 0) || (value > 1000)) {

				if (rehash)
					send_globops(NULL, "Value %s for BACKUP is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for BACKUP is not valid", av[1]);
			}
			else
				CONF_DATABASE_BACKUP_FREQUENCY = value;
		}
		else if (str_equals_nocase(av[0], "SNOOPCHAN")) {

			if ((av[1][0] != '#') || (str_len(av[1]) > CHANMAX) || !validate_channel(av[1])) {

				if (rehash)
					send_globops(NULL, "Value %s for SNOOPCHAN is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for SNOOPCHAN is not valid", av[1]);
			}
			else {

				if (CONF_SNOOP_CHAN)
					mem_free(CONF_SNOOP_CHAN);
				CONF_SNOOP_CHAN = str_duplicate(av[1]);
			}
		}
		else if (str_equals_nocase(av[0], "DEBUGCHAN")) {

			if ((av[1][0] != '#') || (str_len(av[1]) > CHANMAX) || !validate_channel(av[1])) {

				if (rehash)
					send_globops(NULL, "Value %s for DEBUGCHAN is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for DEBUGCHAN is not valid", av[1]);
			}
			else {

				if (CONF_DEBUG_CHAN)
					mem_free(CONF_DEBUG_CHAN);
				CONF_DEBUG_CHAN = str_duplicate(av[1]);
			}
		}
		else if (str_equals_nocase(av[0], "SNOOP")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || ((value != FALSE) && (value != TRUE))) {

				if (rehash)
					send_globops(NULL, "Value %s for SNOOP is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for SNOOP is not valid", av[1]);
			}
			else
				CONF_SET_SNOOP = value;
		}
		else if (str_equals_nocase(av[0], "DEBUG")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || ((value != FALSE) && (value != TRUE))) {

				if (rehash)
					send_globops(NULL, "Value %s for DEBUG is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for DEBUG is not valid", av[1]);
			}
			else
				CONF_SET_DEBUG = value;
		}
		else if (str_equals_nocase(av[0], "NOEXPIRE")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || ((value != FALSE) && (value != TRUE))) {

				if (rehash)
					send_globops(NULL, "Value %s for NOEXPIRE is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for NOEXPIRE is not valid", av[1]);
			}
			else
				CONF_SET_NOEXPIRE = value;
		}
		else if (str_equals_nocase(av[0], "EXTRA_SNOOP")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || ((value != FALSE) && (value != TRUE))) {

				if (rehash)
					send_globops(NULL, "Value %s for EXTRASNOOP is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for EXTRASNOOP is not valid", av[1]);
			}
			else
				CONF_SET_EXTRASNOOP = value;
		}
		else if (str_equals_nocase(av[0], "FLOOD")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || ((value != FALSE) && (value != TRUE))) {

				if (rehash)
					send_globops(NULL, "Value %s for FLOOD is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for FLOOD is not valid", av[1]);
			}
			else
				CONF_SET_FLOOD = value;
		}
		else if (str_equals_nocase(av[0], "DEBUGSERV") || str_equals_nocase(av[0], "DS")) {

			if (str_len(av[1]) > NICKMAX || !validate_nick(av[1], FALSE)) {

				if (rehash)
					send_globops(NULL, "Value %s for DEBUGSERV is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for DEBUGSERV is not valid", av[1]);
			}
			else
				str_copy_checked(av[1], s_DebugServ, sizeof(s_DebugServ));
		}

		else if (str_equals_nocase(av[0], "TIMEOUT")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 0) || (value > 30)) {

				if (rehash)
					send_globops(NULL, "Value %s for TIMEOUT is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for TIMEOUT is not valid", av[1]);
			}
			else
				CONF_TIMEOUT_CHECK = value;
		}

		#ifndef NEW_SOCK
		else if (str_equals_nocase(av[0], "TIMEOUT_STARTUP_DELTA")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 0) || (value > 300)) {

				if (rehash)
					send_globops(NULL, "Value %s for TIMEOUT_STARTUP_DELTA is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for TIMEOUT_STARTUP_DELTA is not valid", av[1]);
			}
			else
				CONF_TIMEOUT_STARTUP_DELTA = value;
		}
		#endif
		else if (str_equals_nocase(av[0], "TAGLINES")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || ((value != FALSE) && (value != TRUE))) {

				if (rehash)
					send_globops(NULL, "Value %s for TAG is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for TAG is not valid", av[1]);
			}
			else
				CONF_SHOW_TAGLINES = value;
		}
		else if (str_equals_nocase(av[0], "NICKSERV") || str_equals_nocase(av[0], "NS")) {

			if (str_len(av[1]) > NICKMAX || !validate_nick(av[1], FALSE)) {

				if (rehash)
					send_globops(NULL, "Value %s for NICKSERV is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for NICKSERV is not valid", av[1]);
			}
			else
				str_copy_checked(av[1], s_NickServ, NICKSIZE);
		}
		else if (str_equals_nocase(av[0], "CHANSERV") || str_equals_nocase(av[0], "CS")) {

			if (str_len(av[1]) > NICKMAX || !validate_nick(av[1], FALSE)) {

				if (rehash)
					send_globops(NULL, "Value %s for CHANSERV is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for CHANSERV is not valid", av[1]);
			}
			else
				str_copy_checked(av[1], s_ChanServ, sizeof(s_ChanServ));
		}
		else if (str_equals_nocase(av[0], "MEMOSERV") || str_equals_nocase(av[0], "MS")) {

			if (str_len(av[1]) > NICKMAX || !validate_nick(av[1], FALSE)) {

				if (rehash)
					send_globops(NULL, "Value %s for MEMOSERV is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for MEMOSERV is not valid", av[1]);
			}
			else
				str_copy_checked(av[1], s_MemoServ, sizeof(s_MemoServ));
		}
		else if (str_equals_nocase(av[0], "HELPSERV") || str_equals_nocase(av[0], "HS")) {

			if (str_len(av[1]) > NICKMAX || !validate_nick(av[1], FALSE)) {

				if (rehash)
					send_globops(NULL, "Value %s for HELPSERV is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for HELPSERV is not valid", av[1]);
			}
			else
				str_copy_checked(av[1], s_HelpServ, sizeof(s_HelpServ));
		}
		else if (str_equals_nocase(av[0], "OPERSERV") || str_equals_nocase(av[0], "OS")) {

			if (str_len(av[1]) > NICKMAX || !validate_nick(av[1], FALSE)) {

				if (rehash)
					send_globops(NULL, "Value %s for OPERSERV is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for OPERSERV is not valid", av[1]);
			}
			else
				str_copy_checked(av[1], s_OperServ, sizeof(s_OperServ));
		}
		else if (str_equals_nocase(av[0], "ROOTSERV") || str_equals_nocase(av[0], "RS")) {

			if (str_len(av[1]) > NICKMAX || !validate_nick(av[1], FALSE)) {

				if (rehash)
					send_globops(NULL, "Value %s for ROOTSERV is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for ROOTSERV is not valid", av[1]);
			}
			else
				str_copy_checked(av[1], s_RootServ, sizeof(s_RootServ));
		}
		else if (str_equals_nocase(av[0], "STATSERV") || str_equals_nocase(av[0], "ST")) {

			if (str_len(av[1]) > NICKMAX || !validate_nick(av[1], FALSE)) {

				if (rehash)
					send_globops(NULL, "Value %s for STATSERV is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for STATSERV is not valid", av[1]);
			}
			else
				str_copy_checked(av[1], s_StatServ, sizeof(s_StatServ));
		}
		else if (str_equals_nocase(av[0], "SEENSERV") || str_equals_nocase(av[0], "SS")) {

			if (str_len(av[1]) > NICKMAX || !validate_nick(av[1], FALSE)) {

				if (rehash)
					send_globops(NULL, "Value %s for SEENSERV is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for SEENSERV is not valid", av[1]);
			}
			else
				str_copy_checked(av[1], s_SeenServ, sizeof(s_SeenServ));
		}
		else if (str_equals_nocase(av[0], "GLOBAL")) {

			if (str_len(av[1]) > NICKMAX || !validate_nick(av[1], FALSE)) {

				if (rehash)
					send_globops(NULL, "Value %s for GLOBAL is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for GLOBAL is not valid", av[1]);
			}
			else
				str_copy_checked(av[1], s_GlobalNoticer, sizeof(s_GlobalNoticer));
		}
		else if (str_equals_nocase(av[0], "USERACC")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value <= 0) || (value > 100)) {

				if (rehash)
					send_globops(NULL, "Value %s for USERACC is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for USERACC is not valid", av[1]);
			}
			else
				CONF_USER_CHAN_ACCESS_MAX = value;
		}
		else if (str_equals_nocase(av[0], "CHANEXP")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value <= 0) || (value > 3650)) {

				if (rehash)
					send_globops(NULL, "Value %s for CHANEXP is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for CHANEXP is not valid", av[1]);
			}
			else
				CONF_CHANNEL_EXPIRE = value;
		}
		else if (str_equals_nocase(av[0], "AKICK")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 0) || (value > 300)) {

				if (rehash)
					send_globops(NULL, "Value %s for AKICK is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for AKICK is not valid", av[1]);
			}
			else
				CONF_AKICK_MAX = value;
		}
		else if (str_equals_nocase(av[0], "REGDELAY")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 0) || (value > 300)) {

				if (rehash)
					send_globops(NULL, "Value %s for REGDELAY is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for REGDELAY is not valid", av[1]);
			}
			else
				CONF_REGISTER_DELAY = value;
		}
		else if (str_equals_nocase(av[0], "NICKEXP")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value <= 0) || (value > 3650)) {

				if (rehash)
					send_globops(NULL, "Value %s for NICKEXP is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for NICKEXP is not valid", av[1]);
			}
			else
				CONF_NICK_EXPIRE = value;
		}
		else if (str_equals_nocase(av[0], "RELEASE")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value <= 0) || (value > 600)) {

				if (rehash)
					send_globops(NULL, "Value %s for RELEASE is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for RELEASE is not valid", av[1]);
			}
			else
				CONF_RELEASE_TIMEOUT = value;
		}
		else if (str_equals_nocase(av[0], "MEMOMAX")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value <= 0) || (value > 250)) {

				if (rehash)
					send_globops(NULL, "Value %s for MEMOMAX is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for MEMOMAX is not valid", av[1]);
			}
			else
				CONF_DEF_MAX_MEMOS = value;
		}
		else if (str_equals_nocase(av[0], "MEMO_DELAY")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 0) || (value > 600)) {

				if (rehash)
					send_globops(NULL, "Value %s for MEMO_WAIT is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for MEMO_WAIT is not valid", av[1]);
			}
			else
				CONF_MEMO_SEND_DELAY = value;
		}
		else if (str_equals_nocase(av[0], "MEMOEXP")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value <= 0) || (value > 120)) {

				if (rehash)
					send_globops(NULL, "Value %s for MEMOEXP is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for MEMOEXP is not valid", av[1]);
			}
			else
				CONF_MEMO_EXPIRE = value;
		}
		else if (str_equals_nocase(av[0], "IGNEXP")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value <= 0) || (value > ONE_DAY)) {

				if (rehash)
					send_globops(NULL, "Value %s for IGNEXP is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for IGNEXP is not valid", av[1]);
			}
			else
				CONF_DEFAULT_IGNORE_EXPIRY = value;
		}
		else if (str_equals_nocase(av[0], "MAX_CLONES")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value <= 0) || (value > 30)) {

				if (rehash)
					send_globops(NULL, "Value %s for MAX_CLONES is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for MAX_CLONES is not valid", av[1]);
			}
			else
				CONF_CLONE_MIN_USERS = value;
		}
		else if (str_equals_nocase(av[0], "CLONE_WARN")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 5) || (value > 300)) {

				if (rehash)
					send_globops(NULL, "Value %s for CLONE_WARN is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for CLONE_WARN is not valid", av[1]);
			}
			else
				CONF_CLONE_WARNING_DELAY = value;
		}
		else if (str_equals_nocase(av[0], "CHAN_ACC_MAX")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 0) || (value > 500)) {

				if (rehash)
					send_globops(NULL, "Value %s for C_ACC_MAX is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for C_ACC_MAX is not valid", av[1]);
			}
			else
				CONF_CHAN_ACCESS_MAX = value;
		}
		else if (str_equals_nocase(av[0], "U_ACC_MAX")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 0) || (value > 16)) {

				if (rehash)
					send_globops(NULL, "Value %s for U_ACC_MAX is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for U_ACC_MAX is not valid", av[1]);
			}
			else
				CONF_USER_ACCESS_MAX = value;
		}
		else if (str_equals_nocase(av[0], "EMAIL")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || ((value != FALSE) && (value != TRUE))) {

				if (rehash)
					send_globops(NULL, "Value %s for EMAIL is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for EMAIL is not valid", av[1]);
			}
			else
				CONF_USE_EMAIL = value;
		}
		else if (str_equals_nocase(av[0], "READONLY")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || ((value != FALSE) && (value != TRUE))) {

				if (rehash)
					send_globops(NULL, "Value %s for READONLY is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for READONLY is not valid", av[1]);
			}
			else
				CONF_SET_READONLY = value;
		}
		else if (str_equals_nocase(av[0], "CLONES")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || ((value != FALSE) && (value != TRUE))) {

				if (rehash)
					send_globops(NULL, "Value %s for CLONES is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for CLONES is not valid", av[1]);
			}
			else
				CONF_SET_CLONE = value;
		}
		else if (str_equals_nocase(av[0], "CHANNEL_INHABIT")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value <= 0) || (value > 600)) {

				if (rehash)
					send_globops(NULL, "Value %s for CHANNEL_INHABIT is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for CHANNEL_INHABIT is not valid", av[1]);
			}
			else
				CONF_CHANNEL_INHABIT = value;
		}
		else if (str_equals_nocase(av[0], "MLOCK")) {

			char modebuf[32];
			int add = 1;
			char *modes = av[1];

			memset(modebuf, 0, sizeof(modebuf));

			CONF_DEF_MLOCKON = 0;
			CONF_DEF_MLOCKOFF = 0;

			while (*modes) {

				switch(*modes++) {

					case '+':
						add = 1;
						break;

					case '-':
						add = 0;
						break;

					case 'c':
						add ? AddFlag(CONF_DEF_MLOCKON, CMODE_c) : AddFlag(CONF_DEF_MLOCKOFF, CMODE_c);
						break;

					case 'C':
						add ? AddFlag(CONF_DEF_MLOCKON, CMODE_C) : AddFlag(CONF_DEF_MLOCKOFF, CMODE_C);
						break;

					case 'd':
						break;

					case 'i':
						add ? AddFlag(CONF_DEF_MLOCKON, CMODE_i) : AddFlag(CONF_DEF_MLOCKOFF, CMODE_i);
						break;

					case 'm':
						add ? AddFlag(CONF_DEF_MLOCKON, CMODE_m) : AddFlag(CONF_DEF_MLOCKOFF, CMODE_m);
						break;

					case 'M':
						add ? AddFlag(CONF_DEF_MLOCKON, CMODE_M) : AddFlag(CONF_DEF_MLOCKOFF, CMODE_M);
						break;

					case 'n':
						add ? AddFlag(CONF_DEF_MLOCKON, CMODE_n) : AddFlag(CONF_DEF_MLOCKOFF, CMODE_n);
						break;

					case 'p':
						add ? AddFlag(CONF_DEF_MLOCKON, CMODE_p) : AddFlag(CONF_DEF_MLOCKOFF, CMODE_p);
						break;

					case 'R':
						add ? AddFlag(CONF_DEF_MLOCKON, CMODE_R) : AddFlag(CONF_DEF_MLOCKOFF, CMODE_R);
						break;

					case 's':
						add ? AddFlag(CONF_DEF_MLOCKON, CMODE_s) : AddFlag(CONF_DEF_MLOCKOFF, CMODE_s);
						break;

					case 't':
						add ? AddFlag(CONF_DEF_MLOCKON, CMODE_t) : AddFlag(CONF_DEF_MLOCKOFF, CMODE_t);
						break;

					case 'u':
						add ? AddFlag(CONF_DEF_MLOCKON, CMODE_u) : AddFlag(CONF_DEF_MLOCKOFF, CMODE_u);
						break;
					
					case 'U':
						add ? AddFlag(CONF_DEF_MLOCKON, CMODE_U) : AddFlag(CONF_DEF_MLOCKOFF, CMODE_U);
						break;
				}
			}
		}
		else if (str_equals_nocase(av[0], "REMIND")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 0) || (value > 120)) {

				if (rehash)
					send_globops(NULL, "Value %s for REMIND is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for REMIND is not valid", av[1]);
			}
			else
				CONF_SEND_REMINDER = value;
		}
		else if (str_equals_nocase(av[0], "RETURN")) {

			if (str_len(av[1]) > MAILMAX || !validate_email(av[1], FALSE)) {

				if (rehash)
					send_globops(NULL, "Value %s for RETURN is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for RETURN is not valid", av[1]);
			}
			else {

				if (CONF_RETURN_EMAIL)
					mem_free(CONF_RETURN_EMAIL);
				CONF_RETURN_EMAIL = str_duplicate(av[1]);
			}
		}
		else if (str_equals_nocase(av[0], "SENDMAIL")) {

			if (CONF_SENDMAIL_PATH)
				mem_free(CONF_SENDMAIL_PATH);
			CONF_SENDMAIL_PATH = str_duplicate(av[1]);
		}
		else if (str_equals_nocase(av[0], "FORCE_AUTH")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || ((value != FALSE) && (value != TRUE))) {

				if (rehash)
					send_globops(NULL, "Value %s for FORCE_AUTH is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for FORCE_AUTH is not valid", av[1]);
			}
			else
				CONF_FORCE_AUTH = value;
		}
		else if (str_equals_nocase(av[0], "CLONEKILL")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || ((value != 0) && (value < CONF_CLONE_MIN_USERS)) || (value > 50)) {

				if (rehash)
					send_globops(NULL, "Value %s for CLONEKILL is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for CLONEKILL is not valid", av[1]);
			}
			else
				CONF_AKILL_CLONES = value;
		}
		else if (str_equals_nocase(av[0], "CLONETIME")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value <= 0) || (value > ONE_HOUR)) {

				if (rehash)
					send_globops(NULL, "Value %s for CLONETIME is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for CLONETIME is not valid", av[1]);
			}
			else
				CONF_DEFAULT_CLONEKILL_EXPIRY = value;
		}
		else if (str_equals_nocase(av[0], "AUTODEL")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 0) || (value > 30)) {

				if (rehash)
					send_globops(NULL, "Value %s for AUTODEL is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for AUTODEL is not valid", av[1]);
			}
			else
				CONF_AUTHDEL_DAYS = value;
		}
		else if (str_equals_nocase(av[0], "SCANV6")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 3) || (value > 7)) {

				if (rehash)
					send_globops(NULL, "Value %s for SCANV6 is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for SCANV6 is not valid", av[1]);
			}
			else
				CONF_CLONE_SCAN_V6 = value;
		}
		else if (str_equals_nocase(av[0], "STATEXP")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value <= 0) || (value > 120)) {

				if (rehash)
					send_globops(NULL, "Value %s for STATEXP is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for STATEXP is not valid", av[1]);
			}
			else
				CONF_STATS_EXPIRE = value;
		}
		else if (str_equals_nocase(av[0], "SEENEXP")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value <= 0) || (value > 120)) {

				if (rehash)
					send_globops(NULL, "Value %s for SEENEXP is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for SEENEXPSEENEXP is not valid", av[1]);
			}
			else
				CONF_SEEN_EXPIRE = value;
		}
		else if (str_equals_nocase(av[0], "PERCENT")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 0) || (value > 100)) {

				if (rehash)
					send_globops(NULL, "Value %s for PERCENT is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for PERCENT is not valid", av[1]);
			}
			else {

				CONF_AKILL_PERCENT = atof(av[1]);
				CONF_AKILL_PERCENT += .0;
			}
		}
		else if (str_equals_nocase(av[0], "AKILLEXP")) {

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 0) || (value > ONE_DAY)) {

				if (rehash)
					send_globops(NULL, "Value %s for AKILLEXP is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for AKILLEXP is not valid", av[1]);
			}
			else
				CONF_DEFAULT_AKILL_EXPIRY = value;
		}
		else {

			if (rehash)
				send_globops(NULL, "Unknown option: %s", av[0]);
			else
				fatal_error(FACILITY_CONF, __LINE__, "Unknown option: %s", av[0]);
		}

		return;
	}

	switch (av[0][0]) {

		case 'C':
			/* This cannot be changed at runtime. */
			if (rehash)
				return;

			if (ac != 5)
				fatal_error(FACILITY_CONF, __LINE__, "Invalid number of params for C: line");

			if ((str_len(av[1]) > HOSTMAX) || !validate_host(av[1], FALSE, FALSE, FALSE))
				fatal_error(FACILITY_CONF, __LINE__, "Value %s for server name in C: line is not valid", av[1]);

			else {

				if (CONF_SERVICES_NAME)
					mem_free(CONF_SERVICES_NAME);
				CONF_SERVICES_NAME = str_duplicate(av[1]);
			}

			if (str_len(av[2]) > PASSMAX)
				fatal_error(FACILITY_CONF, __LINE__, "Value %s for password in C: line is not valid", av[2]);

			else {

				if (CONF_REMOTE_PASSWORD)
					mem_free(CONF_REMOTE_PASSWORD);
				CONF_REMOTE_PASSWORD = str_duplicate(av[2]);
			}

			if ((str_len(av[3]) > HOSTMAX) || !validate_host(av[3], FALSE, FALSE, FALSE))
				fatal_error(FACILITY_CONF, __LINE__, "Value %s for remote server in C: line is not valid", av[3]);

			else {

				if (CONF_REMOTE_SERVER)
					mem_free(CONF_REMOTE_SERVER);
				CONF_REMOTE_SERVER = str_duplicate(av[3]);
			}

			value = strtol(av[4], &err, 10);

			if ((*err != '\0') || (value <= 0) || (value > 65535))
				fatal_error(FACILITY_CONF, __LINE__, "Value %s for remote port in C: line is not valid", av[4]);
			else
				CONF_REMOTE_PORT = value;

			return;


		case 'D': {

			char *desc;

			/* This cannot be changed at runtime. */
			if (rehash)
				return;

			if (ac == 0)
				fatal_error(FACILITY_CONF, __LINE__, "Invalid number of params for D: line");

			--ac;
			++av;

			desc = merge_args(ac, av);

			if (IS_NULL(desc) || (str_len(desc) > SERVER_DESC_MAX))
				fatal_error(FACILITY_CONF, __LINE__, "Invalid D: line");

			else {

				if (CONF_SERVICES_DESC)
					mem_free(CONF_SERVICES_DESC);
				CONF_SERVICES_DESC = str_duplicate(desc);
			}

			return;
		}

		case 'F': {

			if (ac != 4) {

				if (rehash)
					send_globops(NULL, "Invalid number of params for F: line");
				else
					fatal_error(FACILITY_CONF, __LINE__, "Invalid number of params for F: line");
			}

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 3) || (value > 50)) {

				if (rehash)
					send_globops(NULL, "Value %s for Max Messages in F: line is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for Max Messages in F: line is not valid", av[1]);
			}
			else
				CONF_FLOOD_MAX_MESSAGES = value;

			value = strtol(av[2], &err, 10);

			if ((*err != '\0') || (value < 5) || (value > 300)) {

				if (rehash)
					send_globops(NULL, "Value %s for Messages Reset in F: line is not valid", av[2]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for Messages Reset in F: line is not valid", av[2]);
			}
			else
				CONF_FLOOD_MESSAGE_RESET = value;

			value = strtol(av[3], &err, 10);

			if ((*err != '\0') || (value < ONE_MINUTE) || (value > ONE_HOUR)) {

				if (rehash)
					send_globops(NULL, "Value %s for Level Reset in F: line is not valid", av[3]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for Level Reset in F: line is not valid", av[3]);
			}
			else
				CONF_FLOOD_LEVEL_RESET = value;

			return;
		}

		case 'P': {

			if (ac != 5) {

				if (rehash)
					send_globops(NULL, "Invalid number of params for P: line");
				else
					fatal_error(FACILITY_CONF, __LINE__, "Invalid number of params for P: line");
			}

			value = strtol(av[1], &err, 10);

			if ((*err != '\0') || (value < 1) || (value > 50)) {

				if (rehash)
					send_globops(NULL, "Value %s for Max Attempts in P: line is not valid", av[1]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for Max Attempts in P: line is not valid", av[1]);
			}
			else
				CONF_INVALID_PASSWORD_MAX_ATTEMPTS = value;

			value = strtol(av[2], &err, 10);

			if ((*err != '\0') || (value < 1) || (value > 300)) {

				if (rehash)
					send_globops(NULL, "Value %s for Password Reset in P: line is not valid", av[2]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for Password Reset in P: line is not valid", av[2]);
			}
			else
				CONF_INVALID_PASSWORD_RESET = value;

			value = strtol(av[3], &err, 10);

			if ((*err != '\0') || (value < 1) || (value > 60)) {

				if (rehash)
					send_globops(NULL, "Value %s for First Ignore Time in P: line is not valid", av[3]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for First Ignore in P: line is not valid", av[3]);
			}
			else
				CONF_INVALID_PASSWORD_FIRST_IGNORE = value;

			value = strtol(av[4], &err, 10);

			if ((*err != '\0') || (value < 1) || (value > 180)) {

				if (rehash)
					send_globops(NULL, "Value %s for Second Ignore Time in P: line is not valid", av[3]);
				else
					fatal_error(FACILITY_CONF, __LINE__, "Value %s for Second Ignore in P: line is not valid", av[3]);
			}
			else
				CONF_INVALID_PASSWORD_SECOND_IGNORE = value;

			return;
		}

		case 'U':
			/* This cannot be changed at runtime. */
			if (rehash)
				return;

			if (ac != 3)
				fatal_error(FACILITY_CONF, __LINE__, "Invalid number of params for U: line");

			if ((str_len(av[1]) > USERMAX) || !validate_username(av[1], FALSE))
				fatal_error(FACILITY_CONF, __LINE__, "Value %s for services username in U: line is not valid", av[1]);

			else {

				if (CONF_SERVICES_USERNAME)
					mem_free(CONF_SERVICES_USERNAME);
				CONF_SERVICES_USERNAME = str_duplicate(av[1]);
			}

			if ((str_len(av[2]) > HOSTMAX) || !validate_host(av[2], FALSE, FALSE, FALSE))
				fatal_error(FACILITY_CONF, __LINE__, "Value %s for services host in U: line is not valid", av[2]);

			else {

				if (CONF_SERVICES_HOST)
					mem_free(CONF_SERVICES_HOST);
				CONF_SERVICES_HOST = str_duplicate(av[2]);
			}

			return;

		case 'A':
			/* This cannot be changed at runtime. */
			if (rehash)
				return;

			if (ac != 2)
				fatal_error(FACILITY_CONF, __LINE__, "Invalid number of params for A: line");

			if ((str_len(av[1]) > 32))
				fatal_error(FACILITY_CONF, __LINE__, "Value %s for network name in A: line is not valid", av[1]);

			else {

				if (CONF_NETWORK_NAME)
					mem_free(CONF_NETWORK_NAME);
				CONF_NETWORK_NAME = str_duplicate(av[1]);
			}

			return;

		case 'M':
			/* This cannot be changed at runtime. */
			if (rehash)
				return;

			if (ac < 2)
				fatal_error(FACILITY_CONF, __LINE__, "Invalid number of params for M: line");

			if ((str_len(av[1]) > NICKMAX) || !validate_nick(av[1], FALSE))
				fatal_error(FACILITY_CONF, __LINE__, "Value %s for services master in M: line is not valid", av[1]);

			else {

				if (CONF_SERVICES_MASTER)
					mem_free(CONF_SERVICES_MASTER);
				CONF_SERVICES_MASTER = str_duplicate(av[1]);
			}

			return;

		default:
			if (rehash)
				send_globops(NULL, "Unknown field in conf file: %c", av[0][0]);
			else
				fatal_error(FACILITY_CONF, __LINE__, "Unknown field in conf file: %c", av[0][0]);
	}
}


void init_conf(BOOL rehash) {

	FILE *conf_file;
	char linebuf[BUFSIZE];
	char *param, *av[100];
	int ac;
	
	/* Caricamento key di criptazione */
	if (!crypt_load_key())
		fatal_error(FACILITY_CONF, __LINE__, "Errors loading host encryption key file!");

	/* Lettura opzioni */
	if (IS_NULL(conf_file = fopen(CONFIG_FILE, "r"))) {

		if (rehash) {

			send_globops(NULL, "Error opening configuration file %s", CONFIG_FILE);
			return;
		}
		else
			fatal_error(FACILITY_CONF, __LINE__, "Error opening configuration file %s", CONFIG_FILE);
	}

	while (fgets(linebuf, sizeof(linebuf), conf_file)) {

		if (IS_NOT_NULL(param = strtok(linebuf, ": \n\r,"))) {

			ac = 0;
			av[ac++] = param;

			while (IS_NOT_NULL(param = strtok(NULL, ": \n\r,"))) {

				av[ac++] = param;

				if (ac >= 100)
					break;
			}

			conf_break(ac, av, rehash);
		}
	}

	fclose(conf_file);

	AddFlag(CONF_DEF_MLOCKON, CMODE_r);

	if (!rehash) {

		if (IS_NULL(CONF_REMOTE_SERVER) || !CONF_REMOTE_PORT ||
			IS_NULL(CONF_REMOTE_PASSWORD) || IS_NULL(CONF_SERVICES_NAME))
			fatal_error(FACILITY_CONF, __LINE__, "ERROR: Missing C: line");

		else if (IS_NULL(CONF_SERVICES_DESC))
			fatal_error(FACILITY_CONF, __LINE__, "ERROR: Missing D: line");

		else if (IS_NULL(CONF_SERVICES_USERNAME) || IS_NULL(CONF_SERVICES_HOST))
			fatal_error(FACILITY_CONF, __LINE__, "ERROR: Missing U: line");

		else if (IS_NULL(CONF_NETWORK_NAME))
			fatal_error(FACILITY_CONF, __LINE__, "ERROR: Missing A: line");

		else if (IS_NULL(CONF_SERVICES_MASTER))
			fatal_error(FACILITY_CONF, __LINE__, "ERROR: Missing M: line");

		else if (!CONF_USE_EMAIL && CONF_FORCE_AUTH)
			fatal_error(FACILITY_CONF, __LINE__, "ERROR: Must have EMAIL enabled to use FORCE_AUTH");

		else if (!CONF_USE_EMAIL && CONF_AUTHDEL_DAYS)
			fatal_error(FACILITY_CONF, __LINE__, "ERROR: Must have EMAIL enabled to use AUTODEL");

		/* If it's not a rehash, initialize these variables. Done this way so we have all
		   of them duplicated in case of a rehash, where we can free and reallocate them. */

		if (IS_NULL(CONF_SNOOP_CHAN))
			CONF_SNOOP_CHAN = str_duplicate("#snoop");

		if (IS_NULL(CONF_DEBUG_CHAN))
			CONF_DEBUG_CHAN = str_duplicate("#debug");

		if (IS_NULL(CONF_RETURN_EMAIL))
			CONF_RETURN_EMAIL = str_duplicate("nickserv@azzurra.org");

		if (IS_NULL(CONF_SENDMAIL_PATH))
			CONF_SENDMAIL_PATH = str_duplicate("/usr/sbin/sendmail");

		if (s_DebugServ[0] == c_NULL)
			str_copy_checked("DebugServ", s_DebugServ, sizeof(s_DebugServ));

		if (s_NickServ[0] == c_NULL)
			str_copy_checked("NickServ", s_NickServ, sizeof(s_NickServ));

		if (s_OperServ[0] == c_NULL)
			str_copy_checked("OperServ", s_OperServ, sizeof(s_OperServ));

		if (s_ChanServ[0] == c_NULL)
			str_copy_checked("ChanServ", s_ChanServ, sizeof(s_ChanServ));

		if (s_MemoServ[0] == c_NULL)
			str_copy_checked("MemoServ", s_MemoServ, sizeof(s_MemoServ));

		if (s_RootServ[0] == c_NULL)
			str_copy_checked("RootServ", s_RootServ, sizeof(s_RootServ));

		if (s_StatServ[0] == c_NULL)
			str_copy_checked("StatServ", s_StatServ, sizeof(s_StatServ));

		if (s_SeenServ[0] == c_NULL)
			str_copy_checked("SeenServ", s_SeenServ, sizeof(s_SeenServ));

		if (s_HelpServ[0] == c_NULL)
			str_copy_checked("HelpServ", s_HelpServ, sizeof(s_HelpServ));

		if (s_GlobalNoticer[0] == c_NULL)
			str_copy_checked(CONF_NETWORK_NAME, s_GlobalNoticer, sizeof(s_GlobalNoticer));
	}
}

void conf_rehash() {

	LOG_DEBUG("Re-loading conf file");
	init_conf(TRUE);

	LOG_DEBUG("Re-loading news information");
	rehash_news();

	LOG_DEBUG("Rehash process complete.");
}

/*********************************************************/

void handle_rehash(const char *source, User *callerUser, ServiceCommandData *data) {

	if (data->operMatch) {

		LOG_SNOOP(data->agent->nick, "%s RH -- by %s (%s@%s)", data->agent->shortNick, source, callerUser->username, callerUser->host);
		log_services(data->agent->logID, "RH -- by %s (%s@%s)", source, callerUser->username, callerUser->host);

		send_globops(NULL, "\2%s\2 rehashed config files", source);
	}
	else {

		LOG_SNOOP(data->agent->nick, "%s RH -- by %s (%s@%s) through %s", data->agent->shortNick, source, callerUser->username, callerUser->host, data->operName);
		log_services(data->agent->logID, "RH -- by %s (%s@%s) through %s", source, callerUser->username, callerUser->host, data->operName);

		send_globops(NULL, "\2%s\2 (through \2%s\2) rehashed config files", source, data->operName);
	}

	send_notice_to_user(data->agent->nick, callerUser, "Configuration files have been reloaded.");
	conf_rehash();
}

/*********************************************************/

void handle_set(const char *source, User *callerUser, ServiceCommandData *data) {

	char *option = strtok(NULL, " ");
	char *setting = strtok(NULL, " ");
	int *var = NULL;
	char *desc = NULL;

	if (IS_NULL(option) || IS_NULL(setting)) {

		send_notice_to_user(data->agent->nick, callerUser, "\2SET\2 option [ON|OFF]");
		return;
	}

	str_toupper(option);

	if (str_equals(option, "NOEXPIRE")) {

		var = &CONF_SET_NOEXPIRE;
		desc = "No-Expire";
	}
	else if (str_equals(option, "READONLY")) {

		var = &CONF_SET_READONLY;
		desc = "Read-Only";
	}
	else if (str_equals(option, "SNOOP")) {

		var = &CONF_SET_SNOOP;
		desc = "Snoop";
	}
	else if (str_equals(option, "EXTRASNOOP")) {

		var = &CONF_SET_EXTRASNOOP;
		desc = "Extra Snoop";
	}
	else if (str_equals(option, "FLOOD")) {

		var = &CONF_SET_FLOOD;
		desc = "Flood Detection";
	}
	else if (str_equals(option, "CLONES")) {

		var = &CONF_SET_CLONE;
		desc = "Clone Detection";
	}
	else if (str_equals(option, "SCANV6")) {

		long int value;
		char *err;


		value = strtol(setting, &err, 10);

		if ((*err != '\0') || (value < 3) || (value > 7)) {

			if (data->operMatch)
				LOG_SNOOP(data->agent->nick, "%s +SET* SCANV6 -- by %s (%s@%s) [Invalid value: %s]", data->agent->shortNick, callerUser->nick, callerUser->username, callerUser->host, setting);
			else
				LOG_SNOOP(data->agent->nick, "%s +SET* SCANV6 -- by %s (%s@%s) through %s [Invalid value: %s]", data->agent->shortNick, callerUser->nick, callerUser->username, callerUser->host, data->operName, setting);

			send_notice_to_user(data->agent->nick, callerUser, "Setting for SCANV6 must be an integer between 1 and 8.");
		}
		else if (value == CONF_CLONE_SCAN_V6) {

			TRACE_MAIN();
			if (data->operMatch)
				LOG_SNOOP(data->agent->nick, "%s +SET* SCANV6 -- by %s (%s@%s) [Already set to %d]", data->agent->shortNick, callerUser->nick, callerUser->username, callerUser->host, value);
			else
				LOG_SNOOP(data->agent->nick, "%s +SET* SCANV6 -- by %s (%s@%s) through %s [Already set to %d]", data->agent->shortNick, callerUser->nick, callerUser->username, callerUser->host, data->operName, value);

			send_notice_to_user(data->agent->nick, callerUser, "SCANV6 is already set to \2%d\2.", value);
		}
		else {

			if (data->operMatch) {

				LOG_SNOOP(data->agent->nick, "%s +SET SCANV6 -- by %s (%s@%s) [%d -> %d]", data->agent->shortNick, callerUser->nick, callerUser->username, callerUser->host, CONF_CLONE_SCAN_V6, value);
				log_services(data->agent->logID, "+SET SCANV6 -- by %s (%s@%s) [%d -> %d]", callerUser->nick, callerUser->username, callerUser->host, CONF_CLONE_SCAN_V6, value);

				send_globops(data->agent->nick, "\2%s\2 enabled V6 Clone Detection at field \2%d\2", source, value);
			}
			else {

				LOG_SNOOP(data->agent->nick, "%s +SET SCANV6 -- by %s (%s@%s) through %s [%d -> %d]", data->agent->shortNick, callerUser->nick, callerUser->username, callerUser->host, data->operName, CONF_CLONE_SCAN_V6, value);
				log_services(data->agent->logID, "+SET SCANV6 -- by %s (%s@%s) through %s [%d -> %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, CONF_CLONE_SCAN_V6, value);

				send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) enabled V6 Clone Detection at field \2%d\2", source, data->operName, value);
			}

			send_notice_to_user(data->agent->nick, callerUser, "Services is now V6 Clone Detecting at field \2%d\2.", value);

			CONF_CLONE_SCAN_V6 = value;
		}

		return;
	}

	if (IS_NULL(var) || IS_NULL(desc)) {

		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2SET\2 option ON|OFF");
		return;
	}

	if (str_equals_nocase(setting, "ON")) {

		if (*var == TRUE) {

			if (data->operMatch) {

				LOG_SNOOP(data->agent->nick, "%s +S* %s -- by %s (%s@%s) [Already Enabled]", data->agent->shortNick, option, source, callerUser->username, callerUser->host);
				log_services(data->agent->logID, "+S* %s -- by %s (%s@%s) [Already Enabled]", option, source, callerUser->username, callerUser->host);
			}
			else {

				LOG_SNOOP(data->agent->nick, "%s +S* %s -- by %s (%s@%s) through %s [Already Enabled]", data->agent->shortNick, option, source, callerUser->username, callerUser->host, data->operName);
				log_services(data->agent->logID, "+S* %s -- by %s (%s@%s) through %s [Already Enabled]", option, source, callerUser->username, callerUser->host, data->operName);
			}

			send_notice_to_user(data->agent->nick, callerUser, "%s is already enabled.", desc);
			return;
		}

		*var = TRUE;

		if (data->operMatch) {

			LOG_SNOOP(data->agent->nick, "%s +S %s -- by %s (%s@%s)", data->agent->shortNick, option, source, callerUser->username, callerUser->host);
			log_services(data->agent->logID, "+S %s -- by %s (%s@%s)", option, source, callerUser->username, callerUser->host);
		}
		else {

			LOG_SNOOP(data->agent->nick, "%s +S %s -- by %s (%s@%s) through %s", data->agent->shortNick, option, source, callerUser->username, callerUser->host, data->operName);
			log_services(data->agent->logID, "+S %s -- by %s (%s@%s) through %s", option, source, callerUser->username, callerUser->host, data->operName);
		}

		send_globops(data->agent->nick, "\2%s\2 enabled %s", source, desc);

		send_notice_to_user(data->agent->nick, callerUser, "%s option enabled.", desc);
	}
	else if (str_equals_nocase(setting, "OFF")) {

		if (*var == FALSE) {

			if (data->operMatch) {

				LOG_SNOOP(data->agent->nick, "%s -S* %s -- by %s (%s@%s) [Already Disabled]", data->agent->shortNick, option, source, callerUser->username, callerUser->host);
				log_services(data->agent->logID, "-S* %s -- by %s (%s@%s) [Already Disabled]", option, source, callerUser->username, callerUser->host);
			}
			else {

				LOG_SNOOP(data->agent->nick, "%s -S* %s -- by %s (%s@%s) through %s [Already Disabled]", data->agent->shortNick, option, source, callerUser->username, callerUser->host, data->operName);
				log_services(data->agent->logID, "-S* %s -- by %s (%s@%s) through %s [Already Disabled]", option, source, callerUser->username, callerUser->host, data->operName);
			}

			send_notice_to_user(data->agent->nick, callerUser, "%s is already disabled.", desc);
			return;
		}

		*var = FALSE;

		if (data->operMatch) {

			LOG_SNOOP(data->agent->nick, "%s -S %s -- by %s (%s@%s)", data->agent->shortNick, option, source, callerUser->username, callerUser->host);
			log_services(data->agent->logID, "-S %s -- by %s (%s@%s)", option, source, callerUser->username, callerUser->host);
		}
		else {

			LOG_SNOOP(data->agent->nick, "%s -S %s -- by %s (%s@%s) through %s", data->agent->shortNick, option, source, callerUser->username, callerUser->host, data->operName);
			log_services(data->agent->logID, "-S %s -- by %s (%s@%s) through %s", option, source, callerUser->username, callerUser->host, data->operName);
		}

		send_globops(data->agent->nick, "\2%s\2 disabled %s", source, desc);

		send_notice_to_user(data->agent->nick, callerUser, "%s option disabled.", desc);
	}
	else
		send_notice_to_user(data->agent->nick, callerUser, "Setting for %s must be \2ON\2 or \2OFF\2.", option);
}

/*********************************************************/

void conf_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	FILE *conf_file;
	char linebuf[BUFSIZE], *text;
	int line = 0;

	/* Lettura opzioni */
	if (IS_NULL(conf_file = fopen(CONFIG_FILE, "r"))) {

		send_notice_to_user(sourceNick, callerUser, "DUMP: Config file \2%s\2 not found.", CONFIG_FILE);
		return;
	}

	while (fgets(linebuf, sizeof(linebuf), conf_file)) {

		++line;

		text = strtok(linebuf, "\r\n");

		if (IS_NULL(text))
			continue;

		if ((text[0] == '\0') || (text[0] == '#'))
			continue;

		send_notice_to_user(sourceNick, callerUser, "Line %d: \2%s\2", line, text);
	}

	fclose(conf_file);

	LOG_DEBUG_SNOOP("Command: DUMP CONF -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
}
