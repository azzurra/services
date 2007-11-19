/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* cybcop.c - Socks Monitor Services
* 
* Originally based on Epona (c) 2000-2001, 2004 PegSoft (epona@pegsoft.net)
*
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"

#ifdef USE_SOCKSMONITOR

#include <pthread.h>
#include <fcntl.h>
#include <sys/select.h>

#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/logging.h"
#include "../inc/cybcop.h"
#include "../inc/memory.h"
#include "../inc/datafiles.h"
#include "../inc/conf.h"
#include "../inc/main.h"
#include "../inc/send.h"
#include "../inc/servers.h"
#include "../inc/helpserv.h"
#include "../inc/misc.h"
#include "../inc/timeout.h"
#include "../inc/crypt_userhost.h"
#include "../inc/lang.h"
#include "../inc/regions.h"
#include "../inc/version.h"
#include "../inc/akill.h"
#include "../inc/list.h"

/*********************************************************/

/* Stuff to pass to the command handler. */
static Agent a_SocksMonitor;

/* List of hosts to be scanned. */
static ScanEntry *ScanHead;
static ScanEntry *ScanTail;

/* List of APMs. */
Access *APMList;
BOOL APMListLoadComplete;

/* Hashed list of HostCache and FloodCache; threads must not use them! */
static HostCache *hcache[256];		/* One for each initial character */
static FloodCache *fcache[256]; 	/* One for each initial character */

/* Proxy queue; access controlled by queuemut. */
pthread_mutex_t queuemut = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queuecond = PTHREAD_COND_INITIALIZER;

#if !defined(HAVE_GETHOSTBYNAME_R6) && !defined(HAVE_GETHOSTBYNAME_R5) && !defined(HAVE_GETHOSTBYNAME_R3)
pthread_mutex_t resmut = PTHREAD_MUTEX_INITIALIZER;
#endif

/* Proxy statistics variables. */
static unsigned long int iAkills, iCacheAkills, iExempt, iSkipped, iQueued;
static unsigned long int iChecked, iResolve, iProgress, iNormal, iBottler, iResolveCalls;
static unsigned long int iSocks4, iSocks5, iProxy1, iProxy2, iProxy3, iProxy4;
static unsigned long int iProxy5, iProxy6, iProxy7, iProxy8, iWingate;

/*********************************************************/

static void alpha_insert_cache(HostCache *hc);
static void delcache(HostCache *hc, BOOL removeAkill);

static void alpha_insert_flood_cache(FloodCache *fc);
static void delfloodcache(FloodCache *fc, BOOL removeAkill);
static FloodCache *findfloodcache(const char *host);
static void flood_hit(CSTR host, LANG_ID lang);

static void proxy_queue_lock(void);
static void proxy_queue_signal(void);
static void proxy_queue_unlock(void);
static void *proxy_thread_main(void *arg);

/*********************************************************/

static void do_apm(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_apm_akill(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_bottler(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_cache(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_check(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_exception(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_flood(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_login(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_settings(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_stats(CSTR source, User *callerUser, ServiceCommandData *data);

/*********************************************************/

static unsigned int nexceptions = 0;
static unsigned int exceptions_size = 0;

static struct Exception {

	char *host;			/* Hosts to which this exception applies */
	char *who;			/* Nick of person who added the exception */
	char *reason;		/* Reason for exception's addition */
	time_t time;		/* When this exception was added */
	time_t lastUsed;
} *exceptions = NULL;


static unsigned int nbottlers = 0;
static unsigned int bottlers_size = 0;

static struct Bottler {

	char *channel;		/* Channel we're monitoring for bottlers */
	char *who;			/* Nick of person who added the channel */
	time_t time;		/* When this channel was added */
	time_t lastUsed;
} *bottlers = NULL;


/*********************************************************/

// 'A' (65 / 0)
static ServiceCommand	socksmonitor_commands_A[] = {
	{ "AKILL",		ULEVEL_OPER,			0, handle_akill },	/* Opers only get to LIST. */
	{ "APMPRXAK",	ULEVEL_USER,			0, do_apm_akill },
	{ "APM",		ULEVEL_SA,				0, do_apm },
	{ NULL,			0,						0, NULL }
};
// 'B' (66 / 1)
static ServiceCommand	socksmonitor_commands_B[] = {
	{ "BOTTLER",	ULEVEL_OPER,			0, do_bottler },	/* Opers only get to LIST. */
	{ NULL,			0,						0, NULL }
};
// 'C' (67 / 2)
static ServiceCommand	socksmonitor_commands_C[] = {
	{ "CHECK",		ULEVEL_OPER,			0, do_check },
	{ "CACHE",		ULEVEL_OPER,			0, do_cache },		/* Opers only get to LIST. */
	{ "COUNT",		ULEVEL_SA,				0, handle_count },
	{ "CRYPTKEY",	ULEVEL_SRA,				0, handle_cryptkey },
	{ NULL,			0,						0, NULL }
};
// 'D' (68 / 3)
// 'E' (69 / 4)
static ServiceCommand	socksmonitor_commands_E[] = {
	{ "EXCEPTION",	ULEVEL_OPER,			0, do_exception },	/* Opers only get to LIST. */
	{ NULL,			0,						0, NULL }
};
// 'F' (70 / 5)
static ServiceCommand	socksmonitor_commands_F[] = {
	{ "FLOOD",		ULEVEL_SOP,				0, do_flood },		/* Opers only get to LIST. */
	{ NULL,			0,						0, NULL }
};
// 'G' (71 / 6)
// 'H' (72 / 7)
static ServiceCommand	socksmonitor_commands_H[] = {
	{ "HELP",		ULEVEL_OPER,			0, handle_help },
	{ NULL,			0,						0, NULL }
};
// 'I' (73 / 8)
// 'J' (74 / 9)
// 'K' (75 / 10)
// 'L' (76 / 11)
static ServiceCommand	socksmonitor_commands_L[] = {
	{ "LOGIN",		ULEVEL_OPER,			0, do_login },
	{ "LANG",		ULEVEL_SRA,				0, handle_lang },
	{ NULL,			0,						0, NULL }
};
// 'M' (77 / 12)
// 'N' (78 / 13)
static ServiceCommand	socksmonitor_commands_N[] = {
	{ "NOOP",		ULEVEL_SRA,				0, handle_noop },
	{ NULL,			0,						0, NULL }
};
// 'O' (79 / 14)
static ServiceCommand	socksmonitor_commands_O[] = {
	{ "OHELP",		ULEVEL_OPER,			0, handle_help },
	{ "OPER",		ULEVEL_OPER,			0, handle_oper },	/* Opers only get to LIST. */
	{ NULL,			0,						0, NULL }
};
// 'P' (80 / 15)
// 'Q' (81 / 16)
static ServiceCommand	socksmonitor_commands_Q[] = {
	{ "QUIT",		ULEVEL_SRA,				0, handle_quit },
	{ NULL,			0,						0, NULL }
};
// 'R' (82 / 17)
static ServiceCommand	socksmonitor_commands_R[] = {
	{ "REHASH",		ULEVEL_SA,				0, handle_rehash },
	{ "RESTART",	ULEVEL_SRA,				0, handle_restart },
	{ "REGIONS",	ULEVEL_SRA,				0, handle_regions },
	{ NULL,			0,						0, NULL }
};
// 'S' (83 / 18)
static ServiceCommand	socksmonitor_commands_S[] = {
	{ "SET",		ULEVEL_SA,				0, handle_set },
	{ "SETTINGS",	ULEVEL_SA,				0, do_settings },
	{ "STATS",		ULEVEL_OPER,			0, do_stats },
	{ "SHUTDOWN",	ULEVEL_SRA,				0, handle_shutdown },
	{ "SEARCH",		ULEVEL_SRA,				0, handle_search },
	{ NULL,			0,						0, NULL }
};
// 'T' (84 / 19)
// 'U' (85 / 20)
static ServiceCommand	socksmonitor_commands_U[] = {
	{ "UPTIME",		ULEVEL_OPER,			0, handle_uptime },
	{ "UPDATE",		ULEVEL_SA,				0, handle_update },
	{ "UINFO",		ULEVEL_OPER,			0, handle_uinfo },
	{ NULL,			0,						0, NULL }
};
// 'V' (86 / 21)
static ServiceCommand	socksmonitor_commands_V[] = {
	{ "VERSION",	ULEVEL_OPER,			0, handle_version },
	{ NULL,			0,						0, NULL }
};
// 'W' (87 / 22)
// 'X' (88 / 23)
// 'Y' (89 / 24)
// 'Z' (90 / 25)

ServiceCommand	*socksmonitor_commands[26] = {
	socksmonitor_commands_A,	socksmonitor_commands_B,
	socksmonitor_commands_C,	NULL,
	socksmonitor_commands_E,	socksmonitor_commands_F,
	NULL,						socksmonitor_commands_H,
	NULL,						NULL,
	NULL,						socksmonitor_commands_L,
	NULL,						socksmonitor_commands_N,
	socksmonitor_commands_O,	NULL,
	socksmonitor_commands_Q,	socksmonitor_commands_R,
	socksmonitor_commands_S,	NULL,
	socksmonitor_commands_U,	socksmonitor_commands_V,
	NULL,						NULL,
	NULL,						NULL
};

/*********************************************************/

/* Main Socks Monitor routine. */
void monitor(CSTR source, User *callerUser, char *buf) {

	char *cmd = strtok(buf, " ");

	TRACE_FCLT(FACILITY_SOCKSMONITOR);

	if (IS_NULL(cmd))
		return;

	else if (cmd[0] == '\001') {

		++cmd;

		if (IS_EMPTY_STR(cmd))
			LOG_SNOOP(s_SocksMonitor, "Invalid CTCP from \2%s\2", source);

		else {

			char *reply;

			reply = strtok(NULL, "");

			if (reply) {

				size_t len = str_len(reply);
				BOOL isEmpty = ((len == 1) && (reply[0] == '\001'));

				if (reply[len - 1] == '\001')
					reply[len - 1] = '\0';

				if (CONF_BOTTLER_DETECT) {

					/* Ignore if it's going to be killed because of another CTCP reply. */
					if (FlagSet(callerUser->flags, USER_FLAG_ISBOTTLER))
						return;

					/* Also ignore if the user is registered. */
					if (FlagSet(callerUser->mode, UMODE_r))
						return;

					if (str_equals_nocase(cmd, "VERSION")) {

						if (str_match_wild_nocase("*Bottler*", reply) ||
							str_match_wild_nocase("*IRC*Ork*", reply) ||
							str_match_wild_nocase("*XDCC*CATCHER*", reply)) {

							if (!is_already_akilled("*", callerUser->host, ONE_DAY, NULL, NULL))
								akill_add(s_SocksMonitor, "*", callerUser->host, NULL, FALSE, FALSE, NULL, AKILL_TYPE_BOTTLER, ONE_DAY, 0, callerUser->current_lang);

							++iBottler;
							AddFlag(callerUser->flags, USER_FLAG_ISBOTTLER);
						}
					}
					else if (str_equals_nocase(cmd, "USERINFO")) {

						char buffer[IRCBUFSIZE];
						char *ptr;

						if (isEmpty) {

							if (FlagSet(callerUser->flags, USER_FLAG_EMPTYFINGER)) {

								// Both the FINGER and USERINFO reply are empty. It's a Bottler.

								log_proxy(s_SocksMonitor, "Bottler found on \2%s\2 [USERINFO/FINGER both empty]", callerUser->nick);

								if (!is_already_akilled("*", callerUser->host, ONE_DAY, NULL, NULL))
									akill_add(s_SocksMonitor, "*", callerUser->host, NULL, FALSE, FALSE, NULL, AKILL_TYPE_BOTTLER, ONE_DAY, 0, callerUser->current_lang);


								AddFlag(callerUser->flags, USER_FLAG_ISBOTTLER);
								++iBottler;
							}
							else
								AddFlag(callerUser->flags, USER_FLAG_EMPTYUSERINFO);

							return;
						}

						/* We want to check whether the reply matches the following pattern:
						   "nick (nick) Idle 234 seconds"
						   Where nick is callerUser->nick, and 234 is any number. */

						memset(buffer, 0, sizeof(buffer));

						ptr = str_tokenize(reply, buffer, sizeof(buffer), c_SPACE);

						/* Note: bottler users with spaces in the nick will return negative. */
						if (IS_NULL(ptr) || IS_EMPTY_STR(buffer) || str_not_equals(buffer, callerUser->nick))
							return;

						ptr = str_tokenize(ptr, buffer, sizeof(buffer), ')');

						if (IS_NULL(ptr) || IS_EMPTY_STR(buffer) || buffer[0] != '(')
							return;

						if (str_not_equals(buffer + 1, callerUser->nick)) {

							char pattern[64];

							/* Get rid of Blotter pre 3.0.5d */

							snprintf(pattern, sizeof(pattern), "%s@hotmail.com", callerUser->nick);

							if (str_not_equals(buffer + 1, pattern) && !strchr(buffer + 1, c_SPACE))
								return;
						}

						/* +1 because the last str_tokenize() left a trailing space. */
						ptr = str_tokenize(ptr + 1, buffer, sizeof(buffer), c_SPACE);

						if (IS_NULL(ptr) || IS_EMPTY_STR(buffer) || str_not_equals(buffer, "Idle"))
							return;

						ptr = str_tokenize(ptr, buffer, sizeof(buffer), c_SPACE);

						if (IS_NULL(ptr) || IS_EMPTY_STR(buffer) || !str_spn(buffer, "0123456789"))
							return;

						ptr = str_tokenize(ptr, buffer, sizeof(buffer), c_NULL);

						if (IS_NULL(ptr) || IS_EMPTY_STR(buffer) || str_not_equals(buffer, "seconds"))
							return;

						log_services(LOG_SERVICES_SOCKSMONITOR, "Bottler found on \2%s\2 [USERINFO: %s]", callerUser->nick, reply);

						if (!is_already_akilled("*", callerUser->host, ONE_DAY, NULL, NULL))
							akill_add(s_SocksMonitor, "*", callerUser->host, NULL, FALSE, FALSE, NULL, AKILL_TYPE_BOTTLER, ONE_DAY, 0, callerUser->current_lang);

						AddFlag(callerUser->flags, USER_FLAG_ISBOTTLER);
						++iBottler;
					}
					else if (str_equals_nocase(cmd, "FINGER")) {

						char buffer[IRCBUFSIZE];
						char *ptr;
						BOOL falsePositive = FALSE;

						if (isEmpty) {

							if (FlagSet(callerUser->flags, USER_FLAG_EMPTYUSERINFO)) {

								// Both the FINGER and USERINFO reply are empty. It's a Bottler.

								log_proxy(s_SocksMonitor, "Bottler found on \2%s\2 [FINGER/USERINFO both empty]", callerUser->nick);

								if (!is_already_akilled("*", callerUser->host, ONE_DAY, NULL, NULL))
									akill_add(s_SocksMonitor, "*", callerUser->host, NULL, FALSE, FALSE, NULL, AKILL_TYPE_BOTTLER, ONE_DAY, 0, callerUser->current_lang);

								AddFlag(callerUser->flags, USER_FLAG_ISBOTTLER);
								++iBottler;
							}
							else
								AddFlag(callerUser->flags, USER_FLAG_EMPTYFINGER);

							return;
						}

						/* We want to check whether the reply matches the following pattern:
						   "nick (whatever@whatever.com) Idle N seconds"
						   Where nick is callerUser->nick, and N is any number. */

						memset(buffer, 0, sizeof(buffer));

						ptr = str_tokenize(reply, buffer, sizeof(buffer), c_SPACE);

						/* buf holds "nick" here. */
						if (IS_NULL(ptr) || IS_EMPTY_STR(buffer) || str_not_equals(buffer, callerUser->nick))
							return;

						if (str_equals(buffer, callerUser->realname) && !str_match_wild("*UNIX", callerUser->username))
							falsePositive = TRUE;

						ptr = str_tokenize(ptr, buffer, sizeof(buffer), ')');

						/* buf holds "(some@isp.com" here. */
						if (IS_NULL(ptr) || IS_EMPTY_STR(buffer) || buffer[0] != '(')
							return;

						/* Stupid script got the finger response wrong. */
						if (str_match_wild_nocase("*sysreset*", buffer))
							return;

						if (falsePositive == TRUE) {

							if (str_equals(buffer + 1, callerUser->nick) || str_match_wild("*@hotmail.com", buffer + 1))
								falsePositive = FALSE;
						}

						/* +1 because the last str_tokenize() left a trailing space. */
						ptr = str_tokenize(ptr + 1, buffer, sizeof(buffer), c_SPACE);

						if (IS_NULL(ptr) || IS_EMPTY_STR(buffer) || str_not_equals(buffer, "Idle"))
							return;

						ptr = str_tokenize(ptr, buffer, sizeof(buffer), c_SPACE);

						if (IS_NULL(ptr) || IS_EMPTY_STR(buffer) || !str_spn(buffer, "0123456789"))
							return;

						ptr = str_tokenize(ptr, buffer, sizeof(buffer), c_NULL);

						if (IS_NULL(ptr) || IS_EMPTY_STR(buffer) || str_not_equals(buffer, "seconds"))
							return;

						if (falsePositive)
							LOG_PROXY(s_SocksMonitor, "Possible Blotter found on \2%s\2 [FINGER: %s]", callerUser->nick, reply);

						else {

							log_services(LOG_SERVICES_SOCKSMONITOR, "Bottler found on \2%s\2 [FINGER: %s]", callerUser->nick, reply);

							if (!is_already_akilled("*", callerUser->host, ONE_DAY, NULL, NULL))
								akill_add(s_SocksMonitor, "*", callerUser->host, NULL, FALSE, FALSE, NULL, AKILL_TYPE_BOTTLER, ONE_DAY, 0, callerUser->current_lang);

							AddFlag(callerUser->flags, USER_FLAG_ISBOTTLER);
							++iBottler;
						}
					}
				}
				else
					LOG_SNOOP(s_SocksMonitor, "CTCP: %s %s from \2%s\2", cmd, reply, source);
			}
			else {

				if (cmd[str_len(cmd) - 1] == '\001')
					cmd[str_len(cmd) - 1] = '\0';

				LOG_SNOOP(s_SocksMonitor, "CTCP: %s from \2%s\2", cmd, source);
			}
		}
	}
	else {

		if (user_is_ircop(callerUser) || FlagSet(callerUser->flags, USER_FLAG_IS_APM))
			oper_invoke_agent_command(cmd, socksmonitor_commands, callerUser, &a_SocksMonitor);
	}
}

/*********************************************************/

/* Load Socks Monitor host cache. */

static void load_hostcache_db(void) {

	FILE *f;
	int i, ver;
	HostCache *hc;


	TRACE_FCLT(FACILITY_SOCKSMONITOR_HOSTCACHE_DB_LOAD);

	if (!(f = open_db_read(s_SocksMonitor, HOSTCACHE_DB)))
		return;

	switch (ver = get_file_version(f, HOSTCACHE_DB)) {

		case 7:

			for (i = FIRST_VALID_HOST_CHAR; i <= LAST_VALID_HOST_CHAR; ++i) {

				while (fgetc(f) == 1) {

					hc = mem_calloc(1, sizeof(HostCache));				

					if (fread(hc, sizeof(HostCache), 1, f) != 1)
						fatal_error(FACILITY_SOCKSMONITOR_HOSTCACHE_DB_LOAD, __LINE__, "Read error on %s", HOSTCACHE_DB);

					hc->host = read_string(f, HOSTCACHE_DB);
					alpha_insert_cache(hc);

					hc->nick = read_string(f, HOSTCACHE_DB);

					if (hc->req)
						hc->req = read_string(f, HOSTCACHE_DB);
				}
			}
			break;

		default:
			fatal_error(FACILITY_SOCKSMONITOR_HOSTCACHE_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", ver, HOSTCACHE_DB);
	}

	close_db(f, HOSTCACHE_DB);
}

/*********************************************************/

static void save_hostcache_db(void) {

	int i;
	FILE *f;
	HostCache *hc;


	TRACE_FCLT(FACILITY_SOCKSMONITOR_HOSTCACHE_DB_SAVE);

	if (!(f = open_db_write(s_SocksMonitor, HOSTCACHE_DB)))
		return;

	TRACE();

	for (i = FIRST_VALID_HOST_CHAR; i <= LAST_VALID_HOST_CHAR; ++i) {

		TRACE();

		for (hc = hcache[i]; hc; hc = hc->next) {

			TRACE();

			/* Don't save in-progress scans */
			if ((hc->status < HC_NORMAL) && (hc->status > HC_SKIPPED))
				continue;

			fputc(1, f);

			if (fwrite(hc, sizeof(HostCache), 1, f) != 1)
				fatal_error(FACILITY_SOCKSMONITOR_HOSTCACHE_DB_SAVE, __LINE__, "Write error on %s", HOSTCACHE_DB);

			TRACE();
			write_string(hc->host, f, HOSTCACHE_DB);

			TRACE();
			write_string(hc->nick, f, HOSTCACHE_DB);

			TRACE();
			if (hc->req)
				write_string(hc->req, f, HOSTCACHE_DB);
		}

		TRACE();
		fputc(0, f);
	}

	TRACE();
	close_db(f, HOSTCACHE_DB);
}

/*********************************************************/

static void load_exceptions_db(void) {

	FILE *f;
	unsigned int i;
	int ver;


	TRACE_FCLT(FACILITY_SOCKSMONITOR_EXCEPTIONS_DB_LOAD);

	if (!(f = open_db_read(s_SocksMonitor, EXCEPTION_DB)))
		return;

	switch (ver = get_file_version(f, EXCEPTION_DB)) {

		case 7:
			nexceptions = fgetc(f) * 256 + fgetc(f);

			TRACE();
			if (nexceptions < 8)
				exceptions_size = 16;
			else
				exceptions_size = 2*nexceptions;

			TRACE();
			exceptions = mem_malloc(sizeof(struct Exception) * exceptions_size);

			if (!nexceptions) {

				close_db(f, EXCEPTION_DB);
				return;
			}

			TRACE();
			if (fread(exceptions, sizeof(struct Exception), nexceptions, f) != nexceptions)
				fatal_error(FACILITY_SOCKSMONITOR_EXCEPTIONS_DB_LOAD, __LINE__, "Read error on %s", EXCEPTION_DB);

			TRACE();
			for (i = 0; i < nexceptions; ++i) {

				exceptions[i].host = read_string(f, EXCEPTION_DB);
				exceptions[i].who = read_string(f, EXCEPTION_DB);
				exceptions[i].reason = read_string(f, EXCEPTION_DB);
			}

			break;

		default:
			fatal_error(FACILITY_SOCKSMONITOR_EXCEPTIONS_DB_LOAD, __LINE__, "Unsupported version (%d) on %s", ver, EXCEPTION_DB);
	}

	close_db(f, EXCEPTION_DB);
}

/*********************************************************/

static void save_exceptions_db(void) {

	FILE *f;
	unsigned int i;


	TRACE_FCLT(FACILITY_SOCKSMONITOR_EXCEPTIONS_DB_SAVE);

	if (!(f = open_db_write(s_SocksMonitor, EXCEPTION_DB)))
		return;

	TRACE();
	fputc(nexceptions / 256, f);
	fputc(nexceptions & 255, f);

	if (fwrite(exceptions, sizeof(struct Exception), nexceptions, f) != nexceptions)
		fatal_error(FACILITY_SOCKSMONITOR_EXCEPTIONS_DB_SAVE, __LINE__, "Write error on %s", EXCEPTION_DB);

	TRACE();
	for (i = 0; i < nexceptions; ++i) {

		write_string(exceptions[i].host, f, EXCEPTION_DB);
		write_string(exceptions[i].who, f, EXCEPTION_DB);
		write_string(exceptions[i].reason, f, EXCEPTION_DB);
	}

	TRACE();
	close_db(f, EXCEPTION_DB);
}

/*********************************************************/

static void load_bottlers_db(void) {

	FILE *f;
	unsigned int i;
	int ver;


	TRACE_FCLT(FACILITY_SOCKSMONITOR_BOTTLERS_DB_LOAD);

	if (!(f = open_db_read(s_SocksMonitor, BOTTLERS_DB)))
		return;

	switch (ver = get_file_version(f, BOTTLERS_DB)) {

		case 7:
			nbottlers = fgetc(f) * 256 + fgetc(f);

			TRACE();
			if (nbottlers < 8)
				bottlers_size = 16;
			else
				bottlers_size = 2*nbottlers;

			TRACE();
			bottlers = mem_malloc(sizeof(struct Bottler) * bottlers_size);

			if (!nbottlers) {

				close_db(f, BOTTLERS_DB);
				return;
			}

			TRACE();
			if (nbottlers != fread(bottlers, sizeof(struct Bottler), nbottlers, f))
				fatal_error(FACILITY_SOCKSMONITOR_BOTTLERS_DB_LOAD, __LINE__, "Read error on %s", BOTTLERS_DB);

			TRACE();
			for (i = 0; i < nbottlers; ++i) {

				bottlers[i].channel = read_string(f, BOTTLERS_DB);
				bottlers[i].who = read_string(f, BOTTLERS_DB);
			}

			break;

		default:
			fatal_error(FACILITY_SOCKSMONITOR_BOTTLERS_DB_LOAD, __LINE__, "Unsupported version (%d) on %s", ver, BOTTLERS_DB);
	}

	close_db(f, BOTTLERS_DB);
}

/*********************************************************/

static void save_bottlers_db(void) {

	FILE *f;
	unsigned int i;


	TRACE_FCLT(FACILITY_SOCKSMONITOR_BOTTLERS_DB_SAVE);

	if (!(f = open_db_write(s_SocksMonitor, BOTTLERS_DB)))
		return;

	TRACE();
	fputc(nbottlers / 256, f);
	fputc(nbottlers & 255, f);

	if (fwrite(bottlers, sizeof(struct Bottler), nbottlers, f) != nbottlers)
		fatal_error(FACILITY_SOCKSMONITOR_BOTTLERS_DB_SAVE, __LINE__, "Write error on %s", BOTTLERS_DB);

	TRACE();
	for (i = 0; i < nbottlers; ++i) {

		write_string(bottlers[i].channel, f, BOTTLERS_DB);
		write_string(bottlers[i].who, f, BOTTLERS_DB);
	}

	TRACE();
	close_db(f, BOTTLERS_DB);
}

/*********************************************************/

void load_monitor_db(void) {

	load_hostcache_db();
	load_exceptions_db();
	load_bottlers_db();
}

void save_monitor_db(void) {

	save_hostcache_db();
	save_exceptions_db();
	save_bottlers_db();
}


/*********************************************************
 * Socks Monitor private routines.                       *
 *********************************************************/

static void alpha_insert_cache(HostCache *hc) {

	HostCache	*branch_head;
	int			branch_name;

	branch_name = str_char_tolower(hc->host[0]);

	branch_head = hcache[branch_name];
	hcache[branch_name] = hc;

	hc->next = branch_head;
	hc->prev = NULL;

	if (IS_NOT_NULL(branch_head))
		branch_head->prev = hc;
}

/*********************************************************/

static HostCache *makecache(const char *host) {

	HostCache *hc;

	hc = mem_calloc(1, sizeof(HostCache));
	hc->host = str_duplicate(host);
	hc->used = NOW;
	alpha_insert_cache(hc);
	return hc;
}

/*********************************************************/

static void delcache(HostCache *hc, BOOL removeAkill) {
	
	/* Just to be sure */
	if (hc->status == HC_QUEUED || hc->status == HC_PROGRESS)
		return;

	if ((removeAkill == TRUE) && (hc->status > HC_NORMAL))
		akill_remove("*", hc->host);

	if (hc->next)
		hc->next->prev = hc->prev;

	if (hc->prev)
		hc->prev->next = hc->next;
	else
		hcache[str_char_tolower(*(hc->host))] = hc->next;

	TRACE();
	mem_free(hc->host);
	TRACE();
	mem_free(hc->nick);

	TRACE();
	if (hc->req)
		mem_free(hc->req);

	mem_free(hc);
}

/*********************************************************/

static HostCache *findcache(const char *host) {

	HostCache *hc;
	
	if (IS_NOT_NULL(host) && IS_NOT_EMPTY_STR(host)) {

		for (hc = hcache[str_char_tolower(*host)]; hc; hc = hc->next) {

			if (str_equals_nocase(hc->host, host))
				return hc;
		}
	}

	return NULL;
}

/*********************************************************/

void clear_from_cache(CSTR host) {

	HostCache *hc;
	FloodCache *fc;

	if (IS_NOT_NULL(hc = findcache(host)))
		delcache(hc, FALSE);

	if (IS_NOT_NULL(fc = findfloodcache(host)))
		delfloodcache(fc, FALSE);
}

/*********************************************************/

static char *get_scan_type(unsigned short type) {

	switch (type) {

		case HC_WINGATE:
			return "Wingate";

		case HC_SOCKS4:
			return "Socks 4";

		case HC_SOCKS5:
			return "Socks 5";

		case HC_HTTP1:
			return "Proxy (3128)";

		case HC_HTTP2:
			return "Proxy (8080)";

		case HC_HTTP3:
			return "Proxy (80)";

		case HC_HTTP4:
			return "Proxy (6588)";
	}

	return "Error";
}

/*********************************************************/

static char *get_akill_type_from_cache(int status, flags_t *type) {

	switch (status) {

		case HC_WINGATE:
			*type = AKILL_TYPE_WINGATE;
			return NULL;

		case HC_SOCKS4:
			*type = AKILL_TYPE_SOCKS4;
			return NULL;

		case HC_SOCKS5:
			*type = AKILL_TYPE_SOCKS5;
			return NULL;

		case HC_HTTP1:
			*type = AKILL_TYPE_PROXY;
			return "3128";

		case HC_HTTP2:
			*type = AKILL_TYPE_PROXY;
			return "8080";

		case HC_HTTP3:
			*type = AKILL_TYPE_PROXY;
			return "80";

		case HC_HTTP4:
			*type = AKILL_TYPE_PROXY;
			return "6588";
	}

	log_error(FACILITY_SOCKSMONITOR, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_PROPAGATED, 
		"get_akill_type_from_cache(): unknown status supplied: %d", status);

	*type = AKILL_TYPE_NONE;
	return NULL;
}

/*********************************************************/

/* Find the first exception this host matches and return it. */
static BOOL host_is_exempt(CSTR host, const unsigned long ip) {

	unsigned int i;

	if (ip == SERVICES_IP_HOST_ORDER ||		/* Services' clients and enforcers. */
		ip == 4213038297UL)					/* golia.caltanet.it */
		return TRUE;

	for (i = 0; i < nexceptions; ++i) {

		if (str_match_wild_nocase(exceptions[i].host, host)) {

			exceptions[i].lastUsed = NOW;
			return TRUE;
		}
	}

	return FALSE;
}

/*********************************************************/

/* Find the first exception this host matches and return it. */
static BOOL channel_has_bottlers(const char *channel) {

	unsigned int i;

	for (i = 0; i < nbottlers; ++i) {

		if (str_match_wild_nocase(bottlers[i].channel, channel)) {

			bottlers[i].lastUsed = NOW;
			return TRUE;
		}
	}

	return FALSE;
}

/*********************************************************/

static BOOL is_bottler_exempt(const User *user) {

	if (FlagSet(user->flags, USER_FLAG_HAS_IPV6))
		return TRUE;

	if (FlagSet(user->flags, USER_FLAG_BOTTLER))
		return TRUE;

	if (region_match(user->ip, user->host, REGIONTYPE_BOTH) == REGION_IT)
		return TRUE;

	return FALSE;
}

/*********************************************************/

static BOOL channel_has_tenerone(const char *channel) {

	if (str_equals_nocase(channel, "#roma") ||
		str_equals_nocase(channel, "#erotica") ||
		str_equals_nocase(channel, "#napoletani") ||
		str_equals_nocase(channel, "#sesso") ||
		str_equals_nocase(channel, "#java") ||
		str_equals_nocase(channel, "#lacapitale") ||
		str_equals_nocase(channel, "#ragazze") ||
		str_equals_nocase(channel, "#irchelp") ||
		str_equals_nocase(channel, "#quizzer") ||
		str_equals_nocase(channel, "#napoli") ||
		str_equals_nocase(channel, "#palermo") ||
		str_equals_nocase(channel, "#sessosfrenato") ||
		str_equals_nocase(channel, "#sentimenti") ||
		str_equals_nocase(channel, "#italiaquiz") ||
		str_equals_nocase(channel, "#ircitalia") ||
		str_equals_nocase(channel, "#solosesso"))
		return TRUE;

	return FALSE;
}

/*********************************************************/

static BOOL user_matches_tenerone(const User *user) {

	if (str_equals_nocase(user->nick, "[Marte]") ||
		str_equals_nocase(user->nick, "larax") ||
		str_equals_nocase(user->nick, "ShackaN") ||
		str_equals_nocase(user->nick, "tyrant88") ||
		str_match_wild_nocase(user->nick, "*sillaba*") ||
		str_match_wild_nocase(user->nick, "*xab*"))
		return FALSE;

	if (str_match_wild_nocase("host*-204.pool80117.interbusiness.it", user->host) ||
		str_match_wild_nocase("host*-135.pool8249.interbusiness.it", user->host) ||
		str_match_wild_nocase("host*-136.pool8249.interbusiness.it", user->host) ||
		str_match_wild_nocase("host*-128.pool8249.interbusiness.it", user->host) ||
		str_match_wild_nocase("host*-139.pool8249.interbusiness.it", user->host) ||
		str_match_wild_nocase("host*-140.pool8249.interbusiness.it", user->host) ||
		str_match_wild_nocase("82.49.140.*", user->host) ||
		str_match_wild_nocase("82.49.135.*", user->host) ||
		str_match_wild_nocase("82.49.136.*", user->host) ||
		str_match_wild_nocase("82.49.128.*", user->host) ||
		str_match_wild_nocase("82.49.139.*", user->host))
		return TRUE;

	return FALSE;
}

/*********************************************************/

void monitor_handle_SJOIN(CSTR source, const int ac, char **av) {

	User		*user;
	int			param = 0, action;
	char		*chan_name;

	TRACE_MAIN_FCLT(FACILITY_CHANNELS_HANDLE_SJOIN);

#ifdef ENABLE_CAPAB_SSJOIN
	if (FlagSet(uplink_capab, CAPAB_SSJOIN)) {

		if (!strchr(source, '.')) {

			/* This is a single client joining a (hopefully) existent channel. */

			chan_name = av[1];

			/* Are we monitoring this channel for bottlers? */
			if (channel_has_bottlers(chan_name))
				action = 1;
			else if (channel_has_tenerone(chan_name))
				action = 2;
			else
				return;

			user = hash_onlineuser_find(source);

			if (IS_NULL(user)) {

				log_error(FACILITY_CHANNELS_HANDLE_SJOIN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
					"handle_SJOIN(): SJOIN for %s from nonexistent user %s", av[1], source);

				return;
			}

			switch (action) {

				case 2:
					if (user_matches_tenerone(user))
						send_globops(s_SocksMonitor, "\2\3%02dWARNING\3\2: Possible tenerone detected on \2%s\2 (%s@%s) [Joined: %s]", 7, user->nick, user->username, user->host, chan_name);
					break;


				default:
				case 1:
					if (!CONF_BOTTLER_DETECT)
						return;

					if (IS_NOT_NULL(user->server) && FlagSet(user->server->flags, SERVER_FLAG_SCANEXEMPT))
						return;

					if (FlagSet(user->mode, UMODE_r))
						return;

					if (user_is_services_agent(user) || is_bottler_exempt(user))
						return;

					send_CTCP(user->nick, "VERSION");
					send_CTCP(user->nick, "USERINFO");
					send_CTCP(user->nick, "FINGER");
					AddFlag(user->flags, USER_FLAG_BOTTLER);
					break;
			}

			return;
		}
		else {

			/* This is a SJOIN during sync. */
			param = 1;
		}
	}
#endif

	/* Old-style SJOIN handling begins here. */
	{
		char	*nick, *nick_token_ptr, nick_token[NICKSIZE + 2]; /* "@+" */

		/* Variable initializations, sanity checks. */
		chan_name = av[2 - param];

		/* Are we monitoring this channel for bottlers? */
		if (channel_has_bottlers(chan_name))
			action = 1;
		else if (channel_has_tenerone(chan_name))
			action = 2;
		else
			return;

		nick_token_ptr = av[ac - 1];

		if (IS_NULL(nick_token_ptr) || IS_EMPTY_STR(nick_token_ptr)) {

			/* Nobody joined? wtf? */

			log_error(FACILITY_CHANNELS_HANDLE_SJOIN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
				"handle_SJOIN(): Empty SJOIN received for %s (%s)", chan_name, merge_args(ac, av));

			return;
		}

		TRACE_MAIN();

		memset(nick_token, 0, sizeof(nick_token));
		nick_token_ptr = str_tokenize(nick_token_ptr, nick_token, sizeof(nick_token), c_SPACE);

		while (IS_NOT_NULL(nick_token_ptr)) {

			nick = nick_token;

			TRACE_MAIN();

			/* Skip channel ops. */
			if (nick[0] == c_AT) {

				nick_token_ptr = str_tokenize(nick_token_ptr, nick_token, sizeof(nick_token), c_SPACE);
				continue;
			}

			/* Skip leading +, if any. */
			if (nick[0] == c_PLUS)
				++nick;

			if (IS_NULL(user = hash_onlineuser_find(nick))) {

				/* User not found. Process the next one.*/

				log_error(FACILITY_CHANNELS_HANDLE_SJOIN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
					"handle_SJOIN(): SJOIN for %s from nonexistent user %s", chan_name, nick);

				nick_token_ptr = str_tokenize(nick_token_ptr, nick_token, sizeof(nick_token), c_SPACE);
				continue;
			}

			switch (action) {

				case 2:

					if (user_matches_tenerone(user))
						send_globops(s_SocksMonitor, "\2\3%02dWARNING\3\2: Possible tenerone detected on \2%s\2 (%s@%s) [Joined: %s]", 7, user->nick, user->username, user->host, chan_name);
					break;


				default:
				case 1:
					if (!CONF_BOTTLER_DETECT)
						break;

					/* Skip if it's on a server exempt from socks/proxy scan (i.e. v6, Services). */
					if (IS_NOT_NULL(user->server) && FlagSet(user->server->flags, SERVER_FLAG_SCANEXEMPT))
						break;

					/* Skip if it's registered, or exempt. */
					if (FlagSet(user->mode, UMODE_r) || is_bottler_exempt(user))
						break;

					send_CTCP(user->nick, "VERSION");
					send_CTCP(user->nick, "USERINFO");
					send_CTCP(user->nick, "FINGER");

					AddFlag(user->flags, USER_FLAG_BOTTLER);
					break;
			}

			/* Process the next user.*/
			nick_token_ptr = str_tokenize(nick_token_ptr, nick_token, sizeof(nick_token), c_SPACE);
		}
	}
}


/*********************************************************
 * Socks Monitor command functions.                      *
 *********************************************************/

static void do_login(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *nick, *pass;

	TRACE_MAIN_FCLT(FACILITY_SOCKSMONITOR_HANDLE_LOGIN);

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2LOGIN\2 [nick] password)");
		send_notice_to_user(s_SocksMonitor, callerUser, "Type \2/msg %s HELP LOGIN\2 for more information.", s_SocksMonitor);
		return;
	}

	if (IS_NOT_NULL(pass = strtok(NULL, " "))) {

		if (str_len(nick) > NICKMAX) {

			send_notice_to_user(s_SocksMonitor, callerUser, "Nicknames may not be longer than \2%d\2 characters.", NICKMAX);
			return;
		}
		else if (str_len(pass) > PASSMAX) {

			send_notice_to_user(s_SocksMonitor, callerUser, "Passwords may not be longer than \2%d\2 characters.", PASSMAX);
			return;
		}
	}
	else {

		if (str_len(nick) > PASSMAX) {

			send_notice_to_user(s_SocksMonitor, callerUser, "Passwords may not be longer than \2%d\2 characters.", PASSMAX);
			return;
		}

		pass = nick;
		nick = (char *)source;
	}

	TRACE_MAIN();

	/* This takes care of replying as well. */
	check_oper(callerUser, nick, pass);
}

/*********************************************************/

/* STATS command. */

static void do_stats(CSTR source, User *callerUser, ServiceCommandData *data) {

	send_notice_to_user(s_SocksMonitor, callerUser, "\2%s\2 statistics:", s_SocksMonitor);
	send_notice_to_user(s_SocksMonitor, callerUser, s_SPACE);
	send_notice_to_user(s_SocksMonitor, callerUser, "Hosts Scanned: \2%lu\2", iChecked);
	send_notice_to_user(s_SocksMonitor, callerUser, "Hosts in Progress: \2%lu\2", iProgress);
	send_notice_to_user(s_SocksMonitor, callerUser, "Hosts Queued: \2%lu\2", iQueued);
	send_notice_to_user(s_SocksMonitor, callerUser, s_SPACE);
	send_notice_to_user(s_SocksMonitor, callerUser, "Hosts Skipped: \2%lu\2", iSkipped);
	send_notice_to_user(s_SocksMonitor, callerUser, "Hosts Exempt: \2%lu\2", iExempt);
	send_notice_to_user(s_SocksMonitor, callerUser, "Hosts Unresolved: \2%lu\2", iResolve);
	send_notice_to_user(s_SocksMonitor, callerUser, "Open Proxies: \2%lu\2 (3128: \2%lu\2, 8080: \2%lu\2, 80: \2%lu\2, 8000: \2%lu\2)", (iProxy1 + iProxy2 + iProxy3 + iProxy4), iProxy1, iProxy2, iProxy3, iProxy4);
	send_notice_to_user(s_SocksMonitor, callerUser, "Open Socks: \2%lu\2 (Socks 4: \2%lu\2, Socks 5: \2%lu\2)", (iSocks4 + iSocks5), iSocks4, iSocks5);
	send_notice_to_user(s_SocksMonitor, callerUser, "Open Wingates: \2%lu\2", iWingate);
	send_notice_to_user(s_SocksMonitor, callerUser, "Bottlers: \2%lu\2", iBottler);
	send_notice_to_user(s_SocksMonitor, callerUser, "Hosts Autokilled: \2%lu\2 (\2%lu\2 in cache)", iAkills, iCacheAkills);
	send_notice_to_user(s_SocksMonitor, callerUser, "Hosts Clean: \2%lu\2", iNormal);
	send_notice_to_user(s_SocksMonitor, callerUser, "Resolve calls: \2%lu\2", iResolveCalls);
	send_notice_to_user(s_SocksMonitor, callerUser, s_SPACE);
	send_notice_to_user(s_SocksMonitor, callerUser, "*** \2End of Stats\2 ***");
}

/*********************************************************/

static void do_settings(CSTR source, User *callerUser, ServiceCommandData *data) {

	char	buffer[IRCBUFSIZE];
	size_t	len = 0;

	send_notice_to_user(s_SocksMonitor, callerUser, "\2%s\2 statistics:", s_SocksMonitor);
	send_notice_to_user(s_SocksMonitor, callerUser, s_SPACE);

	send_notice_to_user(s_SocksMonitor, callerUser, "Default AKILL expiry time: %s", (CONF_DEFAULT_AKILL_EXPIRY > 0) ? convert_time(buffer, sizeof(buffer), CONF_DEFAULT_AKILL_EXPIRY, LANG_DEFAULT) : "None");

	send_notice_to_user(s_SocksMonitor, callerUser, "Current Threads: \2%d\2, Proxy Timeout: \2%d\2", CONF_MONITOR_MAXTHREADS, CONF_SOCKET_TIMEOUT);

	/* Send options. */
	APPEND_BUFFER(CONF_SCAN_WINGATE, "23")
	APPEND_BUFFER(CONF_SCAN_80, "80")
	APPEND_BUFFER(CONF_SCAN_SOCKS4, "1080")
	APPEND_BUFFER(CONF_SCAN_3128, "3128")
	APPEND_BUFFER(CONF_SCAN_6588, "6588")
	APPEND_BUFFER(CONF_SCAN_8080, "8080")

	send_notice_to_user(s_SocksMonitor, callerUser, "Scanning: %s", (len > 0) ? buffer : "Nothing");

	send_notice_to_user(s_SocksMonitor, callerUser, "Proxy Expire: \2%d\2, Cache Expire: \2%d\2", CONF_PROXY_EXPIRE, CONF_HOST_CACHE_EXPIRE);

	len = 0;

	/* Send flood protections. */
	APPEND_BUFFER(CONF_WARMACHINE_DETECT, "\2War Machine\2")
	APPEND_BUFFER(CONF_PROMIRC_DETECT, "\2Promirc\2")
	APPEND_BUFFER(CONF_UNKNOWN_CLONER_DETECT, "\2Unknown Cloner\2")
	APPEND_BUFFER(CONF_UNUTNET_WORM_DETECT, "\2Unut.net Worm\2")
	APPEND_BUFFER(CONF_VENOM_DETECT, "\2Venom\2")
	APPEND_BUFFER(CONF_WARSATAN_DETECT, "\2WarSatan\2")
	APPEND_BUFFER(CONF_CLONESX_DETECT, "\2ClonesX\2")
	APPEND_BUFFER(CONF_SABAN_DETECT, "\2Saban Power\2")
	APPEND_BUFFER(CONF_PROXER_DETECT, "\2Unknown Proxer\2")
	APPEND_BUFFER(CONF_MUHSTIK_DETECT, "\2Muhstik\2")
	APPEND_BUFFER(CONF_BOTTLER_DETECT, "\2Bottler\2")
	APPEND_BUFFER(CONF_DTHN_DETECT, "\2DTHN trojan\2")
	APPEND_BUFFER(CONF_GUEST_DETECT, "\2Guest mIRC worm\2")
	APPEND_BUFFER(CONF_FIZZER_DETECT, "\2Fizzer trojan\2")
	APPEND_BUFFER(CONF_MAIL_DETECT, "\2Mail Cloner\2")
	APPEND_BUFFER(CONF_OPTIXPRO_DETECT, "\2Optix Pro trojan\2")

	send_notice_to_user(s_SocksMonitor, callerUser, "Flood protections: %s", (len > 0) ? buffer : "None");

	send_notice_to_user(s_SocksMonitor, callerUser, "Flood Cache Expire: \2%d\2, Max Flood Hits: \2%d\2", CONF_FLOOD_CACHE_EXPIRE, CONF_MAX_FLOOD_HITS);

	send_notice_to_user(s_SocksMonitor, callerUser, s_SPACE);
	send_notice_to_user(s_SocksMonitor, callerUser, "*** \2End of Stats\2 ***");
}

/*********************************************************/

static void do_check(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *host;

	if (IS_NOT_NULL(host = strtok(NULL, " "))) {

		if (!validate_host(host, FALSE, FALSE, FALSE)) {

			send_notice_to_user(s_SocksMonitor, callerUser, "Invalid host.");
			return;
		}

		send_notice_to_user(s_SocksMonitor, callerUser, "Performing requested check on host \2%s\2", host);
		proxy_check("!", host, 0, source, LANG_DEFAULT);
	}
	else
		send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2CHECK\2 host");
}

/*********************************************************/

static void do_exception(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *cmd = strtok(NULL, " ");
	unsigned int i;

	TRACE();

	if (IS_NULL(cmd))
		send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2EXCEPTION\2 [ADD|DEL|LIST|MOVE] [time] host [reason]");

	else if (str_equals_nocase(cmd, "LIST")) {

		char *mask = strtok(NULL, " ");
		char timebuf[64];
		struct tm tm;
		int count = 0;

		send_notice_to_user(s_SocksMonitor, callerUser, "Proxy Scan Exception list:");

		for (i = 0; i < nexceptions; ++i) {

			if (mask ? str_match_wild_nocase(mask, exceptions[i].host) : 1) {

				tm = *localtime(&(exceptions[i].time));
				strftime(timebuf, sizeof(timebuf), "%d %b %Y", &tm);

				send_notice_to_user(s_SocksMonitor, callerUser, "%d) \2%s\2 [Reason: %s]", ++count, exceptions[i].host, exceptions[i].reason);
				send_notice_to_user(s_SocksMonitor, callerUser, "Set by \2%s\2 on %s", exceptions[i].who, timebuf);
			}
		}

		send_notice_to_user(s_SocksMonitor, callerUser, "*** \2End of List\2 ***");
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SOP))
		send_notice_to_user(s_SocksMonitor, callerUser, "Access denied.");

	else if (str_equals_nocase(cmd, "ADD")) {

		char *host = strtok(NULL, " ");
		char *reason = strtok(NULL, "");

		if (IS_NULL(reason)) {

			send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2EXCEPTION ADD\2 host reason");
			return;
		}

		if (strchr(host, '!') || strchr(host, '@')) {

			send_notice_to_user(s_SocksMonitor, callerUser, "Invalid hostmask.");

			if (data->operMatch) {

				LOG_SNOOP(s_SocksMonitor, "SM +E* %s -- by %s (%s@%s) [Invalid Hostmask]", host, source, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_SOCKSMONITOR, "+E* %s -- by %s (%s@%s) [Invalid Hostmask]", host, source, callerUser->username, callerUser->host);
			}
			else {

				LOG_SNOOP(s_SocksMonitor, "SM +E* %s -- by %s (%s@%s) through %s [Invalid Hostmask]", host, source, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_SOCKSMONITOR, "+E* %s -- by %s (%s@%s) through %s [Invalid Hostmask]", host, source, callerUser->username, callerUser->host, data->operName);
			}

			return;
		}

		/* Check if an exception already exists for this mask */
		for (i = 0; i < nexceptions; ++i) {

			if (str_equals_nocase(host, exceptions[i].host)) {

				send_notice_to_user(s_SocksMonitor, callerUser, "Exception already present: %s", host);
				return;
			}
		}

		if (data->operMatch) {

			LOG_SNOOP(s_SocksMonitor, "SM +E %s -- by %s (%s@%s) [Reason: %s]", host, source, callerUser->username, callerUser->host, reason);
			log_services(LOG_SERVICES_SOCKSMONITOR, "+E %s -- by %s (%s@%s) [Reason: %s]", host, source, callerUser->username, callerUser->host, reason);

			send_globops(s_SocksMonitor, "\2%s\2 added an exception for \2%s\2 [Reason: %s]", source, host, reason);
		}
		else {

			LOG_SNOOP(s_SocksMonitor, "SM +E %s -- by %s (%s@%s) through %s [Reason: %s]", host, source, callerUser->username, callerUser->host, data->operName, reason);
			log_services(LOG_SERVICES_SOCKSMONITOR, "+E %s -- by %s (%s@%s) through %s [Reason: %s]", host, source, callerUser->username, callerUser->host, data->operName, reason);

			send_globops(s_SocksMonitor, "\2%s\2 (through \2%s\2) added an exception for \2%s\2 [Reason: %s]", source, data->operName, host, reason);
		}

		send_notice_to_user(s_SocksMonitor, callerUser, "Added exception: %s", host);

		if (nexceptions >= exceptions_size) {

			if (exceptions_size < 8)
				exceptions_size = 8;
			else
				exceptions_size *= 2;

			TRACE();
			exceptions = mem_realloc(exceptions, sizeof(struct Exception) * exceptions_size);
		}

		exceptions[nexceptions].host = str_duplicate(host);
		exceptions[nexceptions].reason = str_duplicate(reason);
		exceptions[nexceptions].time = NOW;
		exceptions[nexceptions].who = str_duplicate(data->operName);

		++nexceptions;
	}
	else if (str_equals_nocase(cmd, "DEL")) {

		char *host, *err;
		unsigned long int idx;


		if (IS_NULL(host = strtok(NULL, " "))) {

			send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2EXCEPTION DEL\2 host|number");
			return;
		}

		idx = strtoul(host, &err, 10);

		if ((idx > 0) && (*err == '\0')) {
				
			if (idx > nexceptions) {

				send_notice_to_user(s_SocksMonitor, callerUser, "Entry \2%s\2 not found on Exception list.", host);

				if (data->operMatch) {

					LOG_SNOOP(s_SocksMonitor, "SM -E* %s -- by %s (%s@%s) [Not Found]", host, source, callerUser->username, callerUser->host);
					log_services(LOG_SERVICES_SOCKSMONITOR, "-E* %s -- by %s (%s@%s) [Not Found]", host, source, callerUser->username, callerUser->host);
				}
				else {

					LOG_SNOOP(s_SocksMonitor, "SM -E* %s -- by %s (%s@%s) through %s [Not Found]", host, source, callerUser->username, callerUser->host, data->operName);
					log_services(LOG_SERVICES_SOCKSMONITOR, "-E* %s -- by %s (%s@%s) through %s [Not Found]", host, source, callerUser->username, callerUser->host, data->operName);
				}

				return;
			}
			else
				--idx;
		}
		else {

			for (idx = 0; idx < nexceptions; ++idx) {

				if (str_equals_nocase(exceptions[idx].host, host))
					break;
			}

			if (idx == nexceptions) {

				send_notice_to_user(s_SocksMonitor, callerUser, "Host \2%s\2 not found on Exception list.", host);

				if (data->operMatch) {

					LOG_SNOOP(s_SocksMonitor, "SM -E* %s -- by %s (%s@%s) [Not Found]", host, source, callerUser->username, callerUser->host);
					log_services(LOG_SERVICES_SOCKSMONITOR, "-E* %s -- by %s (%s@%s) [Not Found]", host, source, callerUser->username, callerUser->host);
				}
				else {

					LOG_SNOOP(s_SocksMonitor, "SM -E* %s -- by %s (%s@%s) through %s [Not Found]", host, source, callerUser->username, callerUser->host, data->operName);
					log_services(LOG_SERVICES_SOCKSMONITOR, "-E* %s -- by %s (%s@%s) through %s [Not Found]", host, source, callerUser->username, callerUser->host, data->operName);
				}

				return;
			}
		}

		if (data->operMatch) {

			LOG_SNOOP(s_SocksMonitor, "SM -E %s -- by %s (%s@%s)", exceptions[idx].host, source, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_SOCKSMONITOR, "-E %s -- by %s (%s@%s)", exceptions[idx].host, source, callerUser->username, callerUser->host);

			send_globops(s_SocksMonitor, "\2%s\2 removed \2%s\2 from the exception list", source, exceptions[idx].host);
		}
		else {

			LOG_SNOOP(s_SocksMonitor, "SM -E %s -- by %s (%s@%s) through %s", exceptions[idx].host, source, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_SOCKSMONITOR, "-E %s -- by %s (%s@%s) through %s", exceptions[idx].host, source, callerUser->username, callerUser->host, data->operName);

			send_globops(s_SocksMonitor, "\2%s\2 (through \2%s\2) removed \2%s\2 from the exception list", source, data->operName, exceptions[idx].host);
		}

		send_notice_to_user(s_SocksMonitor, callerUser, "\2%s\2 deleted from exception list.", exceptions[idx].host);

		mem_free(exceptions[idx].host);
		mem_free(exceptions[idx].reason);
		mem_free(exceptions[idx].who);
		--nexceptions;

		if (idx < nexceptions)
			memmove(exceptions + idx, exceptions + idx + 1, sizeof(struct Exception) * (nexceptions - idx));
	}
	else
		send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2EXCEPTION\2 [ADD|DEL|LIST|MOVE] [time] host [reason]");
}

/*********************************************************/

static void do_bottler(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *cmd = strtok(NULL, " ");
	unsigned int i;

	TRACE();

	if (IS_NULL(cmd))
		send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2BOTTLER\2 [ADD|DEL|LIST] #channel");

	else if (str_equals_nocase(cmd, "LIST")) {

		char *mask = strtok(NULL, " ");
		char timebuf[64];
		struct tm tm;
		int count = 0;

		send_notice_to_user(s_SocksMonitor, callerUser, "Channel scanned for bottlers:");

		for (i = 0; i < nbottlers; ++i) {

			if (mask ? str_match_wild_nocase(mask, bottlers[i].channel) : 1) {

				tm = *localtime(&(bottlers[i].time));
				strftime(timebuf, sizeof(timebuf), "%d %b %Y", &tm);

				send_notice_to_user(s_SocksMonitor, callerUser, "%d) \2%s\2 [Set by \2%s\2 on %s]", ++count, bottlers[i].channel, bottlers[i].who, timebuf);
			}
		}

		send_notice_to_user(s_SocksMonitor, callerUser, "*** \2End of List\2 ***");
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SA))
		send_notice_to_user(s_SocksMonitor, callerUser, "Access denied.");

	else if (str_equals_nocase(cmd, "ADD")) {

		char *channel = strtok(NULL, " ");

		if (IS_NULL(channel)) {

			send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2BOTTLER ADD\2 #channel");
			return;
		}

		if (channel[0] != '#') {

			send_notice_to_user(s_SocksMonitor, callerUser, "Invalid channel.");

			if (data->operMatch) {

				LOG_SNOOP(s_SocksMonitor, "SM +B* %s -- by %s (%s@%s) [Invalid Channel]", channel, source, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_SOCKSMONITOR, "+B* %s -- by %s (%s@%s) [Invalid Channel]", channel, source, callerUser->username, callerUser->host);
			}
			else {

				LOG_SNOOP(s_SocksMonitor, "SM +B* %s -- by %s (%s@%s) through %s [Invalid Channel]", channel, source, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_SOCKSMONITOR, "+B* %s -- by %s (%s@%s) through %s [Invalid Channel]", channel, source, callerUser->username, callerUser->host, data->operName);
			}

			return;
		}

		/* Check if this channel is already being monitored. */
		for (i = 0; i < nbottlers; ++i) {

			if (str_equals_nocase(channel, bottlers[i].channel)) {

				send_notice_to_user(s_SocksMonitor, callerUser, "Channel \2%s\2 is already being monitored for bottlers.", channel);
				return;
			}
		}

		if (data->operMatch) {

			LOG_SNOOP(s_SocksMonitor, "SM +B %s -- by %s (%s@%s)", channel, source, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_SOCKSMONITOR, "+B %s -- by %s (%s@%s)", channel, source, callerUser->username, callerUser->host);

			send_globops(s_SocksMonitor, "\2%s\2 added \2%s\2 to the bottlers scan list", source, channel);
		}
		else {

			LOG_SNOOP(s_SocksMonitor, "SM +B %s -- by %s (%s@%s) through %s", channel, source, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_SOCKSMONITOR, "+B %s -- by %s (%s@%s) through %s", channel, source, callerUser->username, callerUser->host, data->operName);

			send_globops(s_SocksMonitor, "\2%s\2 (through \2%s\2) added \2%s\2 to the bottlers scan list", source, data->operName, channel);
		}

		send_notice_to_user(s_SocksMonitor, callerUser, "Channel \2%s\2 is now being monitored for bottlers.", channel);

		if (nbottlers >= bottlers_size) {

			if (bottlers_size < 8)
				bottlers_size = 8;
			else
				bottlers_size *= 2;

			TRACE();
			bottlers = mem_realloc(bottlers, sizeof(struct Bottler) * bottlers_size);
		}

		bottlers[nbottlers].channel = str_duplicate(channel);
		bottlers[nbottlers].who = str_duplicate(data->operName);
		bottlers[nbottlers].time = NOW;

		++nbottlers;
	}
	else if (str_equals_nocase(cmd, "DEL")) {

		char *channel, *err;
		unsigned long int idx;


		if (IS_NULL(channel = strtok(NULL, " "))) {

			send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2BOTTLER DEL\2 #channel");
			return;
		}

		idx = strtoul(channel, &err, 10);

		if ((idx > 0) && (*err == '\0')) {

			if (idx > nbottlers) {

				send_notice_to_user(s_SocksMonitor, callerUser, "Entry \2%s\2 not found on the bottlers scan list.", channel);

				if (data->operMatch) {

					LOG_SNOOP(s_SocksMonitor, "SM -B* %s -- by %s (%s@%s) [Not Found]", channel, source, callerUser->username, callerUser->host);
					log_services(LOG_SERVICES_SOCKSMONITOR, "-B* %s -- by %s (%s@%s) [Not Found]", channel, source, callerUser->username, callerUser->host);
				}
				else {

					LOG_SNOOP(s_SocksMonitor, "SM -B* %s -- by %s (%s@%s) through %s [Not Found]", channel, source, callerUser->username, callerUser->host, data->operName);
					log_services(LOG_SERVICES_SOCKSMONITOR, "-B* %s -- by %s (%s@%s) through %s [Not Found]", channel, source, callerUser->username, callerUser->host, data->operName);
				}

				return;
			}
			else
				--idx;
		}
		else {

			for (idx = 0; idx < nbottlers; ++idx) {

				if (str_equals_nocase(bottlers[idx].channel, channel))
					break;
			}

			if (idx == nbottlers) {

				send_notice_to_user(s_SocksMonitor, callerUser, "Channel \2%s\2 not found on the bottlers scan list.", channel);

				if (data->operMatch) {

					LOG_SNOOP(s_SocksMonitor, "SM -B* %s -- by %s (%s@%s) [Not Found]", channel, source, callerUser->username, callerUser->host);
					log_services(LOG_SERVICES_SOCKSMONITOR, "-B* %s -- by %s (%s@%s) [Not Found]", channel, source, callerUser->username, callerUser->host);
				}
				else {

					LOG_SNOOP(s_SocksMonitor, "SM -B* %s -- by %s (%s@%s) through %s [Not Found]", channel, source, callerUser->username, callerUser->host, data->operName);
					log_services(LOG_SERVICES_SOCKSMONITOR, "-B* %s -- by %s (%s@%s) through %s [Not Found]", channel, source, callerUser->username, callerUser->host, data->operName);
				}

				return;
			}
		}

		if (data->operMatch) {

			LOG_SNOOP(s_SocksMonitor, "SM -B %s -- by %s (%s@%s)", bottlers[idx].channel, source, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_SOCKSMONITOR, "-B %s -- by %s (%s@%s)", bottlers[idx].channel, source, callerUser->username, callerUser->host);

			send_globops(s_SocksMonitor, "\2%s\2 removed \2%s\2 from the bottlers scan list", source, bottlers[idx].channel);
		}
		else {

			LOG_SNOOP(s_SocksMonitor, "SM -B %s -- by %s (%s@%s) through %s", bottlers[idx].channel, source, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_SOCKSMONITOR, "-B %s -- by %s (%s@%s) through %s", bottlers[idx].channel, source, callerUser->username, callerUser->host, data->operName);

			send_globops(s_SocksMonitor, "\2%s\2 (through \2%s\2) removed \2%s\2 from the bottlers scan list", source, data->operName, bottlers[idx].channel);
		}

		send_notice_to_user(s_SocksMonitor, callerUser, "\2%s\2 deleted from the bottlers scan list.", bottlers[idx].channel);

		mem_free(bottlers[idx].channel);
		mem_free(bottlers[idx].who);
		--nbottlers;

		if (idx < nbottlers)
			memmove(bottlers + idx, bottlers + idx + 1, sizeof(struct Bottler) * (nbottlers - idx));
	}
	else
		send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2BOTTLER\2 [ADD|DEL|LIST] #channel");
}


/*********************************************************
 * Internal Proxy Functions.                             *
 *********************************************************/

void monitor_init(void) {

	int i, result;
	pthread_t th;


	TRACE_FCLT(FACILITY_SOCKSMONITOR_INIT);

	if (CONF_MONITOR_LOCAL_HOST) {

		/* Set up our vhost. */

		struct hostent *hp;

		memset(&MONITOR_LOCAL_ADDRESS, 0, sizeof(MONITOR_LOCAL_ADDRESS));

		if (IS_NOT_NULL(hp = gethostbyname(CONF_MONITOR_LOCAL_HOST))) {

			memcpy((char *)&MONITOR_LOCAL_ADDRESS.sin_addr, hp->h_addr, hp->h_length);
			MONITOR_LOCAL_ADDRESS.sin_family = hp->h_addrtype;

			if (CONF_MONITOR_LOCAL_PORT) {

				MONITOR_LOCAL_ADDRESS.sin_port = htons(CONF_MONITOR_LOCAL_PORT);
				fprintf(stderr, "\nUsing virtual host %s[%s] on port %d\n\n", CONF_MONITOR_LOCAL_HOST, get_ip(MONITOR_LOCAL_ADDRESS.sin_addr.s_addr), CONF_MONITOR_LOCAL_PORT);
			}
			else
				fprintf(stderr, "\nUsing virtual host %s[%s]\n\n", CONF_MONITOR_LOCAL_HOST, get_ip(MONITOR_LOCAL_ADDRESS.sin_addr.s_addr));
		}
		else
			fatal_error(FACILITY_SOCKSMONITOR_INIT, __LINE__, "Unable to resolve virtual host %s", CONF_MONITOR_LOCAL_HOST);
	}

	ScanHead = NULL;
	ScanTail = NULL;

	LOG_DEBUG("Scanner: Creating %d proxy threads...", CONF_MONITOR_MAXTHREADS);

	for (i = 0; i < CONF_MONITOR_MAXTHREADS; ++i) {

		if ((result = pthread_create(&th, NULL, proxy_thread_main, NULL)))
			fatal_error(FACILITY_SOCKSMONITOR_INIT, __LINE__, "Unable to create thread %d of %d (error code: %d)", i + 1, CONF_MONITOR_MAXTHREADS, result);

		if ((result = pthread_detach(th)))
			fatal_error(FACILITY_SOCKSMONITOR_INIT, __LINE__, "Unable to detach thread %d of %d (error code: %d)", i + 1, CONF_MONITOR_MAXTHREADS, result);

		LOG_DEBUG("Creating proxy thread %ld (%d of %d)", (long) th, i + 1, CONF_MONITOR_MAXTHREADS);
	}

	iAkills = iCacheAkills = iExempt = iSkipped = iQueued = 0;
	iChecked = iResolve = iProgress = iNormal = iBottler = iResolveCalls = 0;
	iSocks4 = iSocks5 = iProxy1 = iProxy2 = iProxy3 = iProxy4 = 0;
	iProxy5 = iProxy6 = iProxy7 = iProxy8 = iWingate = 0;

	/* Initialize this struct. */
	a_SocksMonitor.nick = s_SocksMonitor;
	a_SocksMonitor.shortNick = s_SM;
	a_SocksMonitor.agentID = AGENTID_CYBCOP;
	a_SocksMonitor.logID = logid_from_agentid(AGENTID_CYBCOP);

	LOG_DEBUG("Proxy detector initialized");
}


/*********************************************************
 * proxy_check()                                         *
 *                                                       *
 * Checks whether the specified host is in the cache.    *
 * If so:                                                *
 *   * if it's a proxy, take the appropriate actions,    *
 *     including killing nick                            *
 *   * if it's not a proxy, do nothing                   *
 *                                                       *
 * If not:                                               *
 *   * add the host to the cache                         *
 *   * add the host to the queue                         *
 *   * send a signal to a waiting thread (if any)        *
 *                                                       *
 * Returns 1 if killed or clean, 0 else.                 *
 *********************************************************/

int proxy_check(CSTR nick, CSTR host, const unsigned long ip, CSTR source, LANG_ID lang) {

	HostCache *hc;

	TRACE_FCLT(FACILITY_SOCKSMONITOR);

	if ((str_len(host) == 0) || (str_len(nick) == 0)) {

		TRACE();
		log_services(LOG_PROXY_SCAN, "Skipping %s [%s]", nick, host);
		++iSkipped;
		return 0;
	}

	TRACE();
	if (host_is_exempt(host, ip)) {

		TRACE();
		log_services(LOG_PROXY_SCAN, "Host %s is exempt, skipping", host);

		TRACE();
		if (str_not_equals_nocase(source, "!"))
			send_notice_to_nick(s_SocksMonitor, source, "Requested host \2%s\2 is exempt.", host);

		TRACE();
		++iExempt;
		return 0;
	}

	TRACE();
	if ((hc = findcache(host))) {

		TRACE();
		if (str_not_equals_nocase(source, "!")) {

			switch (hc->status) {

				case HC_EXEMPT:
					send_notice_to_nick(s_SocksMonitor, source, "Requested host \2%s\2 is cached. Status: Exempt.", host);
					break;

				case HC_SKIPPED:
					send_notice_to_nick(s_SocksMonitor, source, "Requested host \2%s\2 is cached. Status: Skipped.", host);
					break;

				case HC_QUEUED:
					send_notice_to_nick(s_SocksMonitor, source, "Requested host \2%s\2 is cached. Status: Queued.", host);
					break;

				case HC_PROGRESS:
					send_notice_to_nick(s_SocksMonitor, source, "Requested host \2%s\2 is cached. Status: In Progress.", host);
					break;

				case HC_NORMAL:
					send_notice_to_nick(s_SocksMonitor, source, "Requested host \2%s\2 is cached. Status: Clean.", host);
					break;

				case HC_WINGATE:
					send_notice_to_nick(s_SocksMonitor, source, "Requested host \2%s\2 is cached. Status: Wingate.", host);
					break;

				case HC_SOCKS4:
					send_notice_to_nick(s_SocksMonitor, source, "Requested host \2%s\2 is cached. Status: Socks4.", host);
					break;

				case HC_SOCKS5:
					send_notice_to_nick(s_SocksMonitor, source, "Requested host \2%s\2 is cached. Status: Socks5.", host);
					break;

				case HC_HTTP1:
					send_notice_to_nick(s_SocksMonitor, source, "Requested host \2%s\2 is cached. Status: Proxy (3128).", host);
					break;

				case HC_HTTP2:
					send_notice_to_nick(s_SocksMonitor, source, "Requested host \2%s\2 is cached. Status: Proxy (8080).", host);
					break;

				case HC_HTTP3:
					send_notice_to_nick(s_SocksMonitor, source, "Requested host \2%s\2 is cached. Status: Proxy (80).", host);
					break;

				case HC_HTTP4:
					send_notice_to_nick(s_SocksMonitor, source, "Requested host \2%s\2 is cached. Status: Proxy (6588).", host);
					break;

				default:
					break;
			}
			return 0;
		}

		TRACE();
		if (IS_NULL(hc->nick) || str_not_equals_nocase(hc->nick, nick)) {

			if (hc->nick)
				mem_free(hc->nick);
			hc->nick = str_duplicate(nick);
		}

		TRACE();
		hc->used = NOW;

		TRACE();
		if (hc->status <= HC_NORMAL)
			return 0;	

		else {

			time_t expiry = ((hc->lang == LANG_IT) ? ((CONF_PROXY_EXPIRE < 600) ? CONF_PROXY_EXPIRE : 600) : CONF_PROXY_EXPIRE);

			TRACE();
			LOG_DEBUG("Proxy in cache, akilling \2%s\2 [%s]", hc->nick, host);
			++iCacheAkills;
			++iAkills;

			if (!is_already_akilled("*", host, expiry, NULL, NULL)) {

				char *port;
				flags_t type;

				port = get_akill_type_from_cache(hc->status, &type);

				akill_add(s_SocksMonitor, "*", host, port, FALSE, FALSE, NULL, type, expiry, 0, hc->lang);
			}

			return FALSE;
		}
	}

	++iQueued;

	if (iQueued == 200)
		LOG_DEBUG_SNOOP("\2WARNING:\2 More than 200 hosts queued for scanning, possible crash");

	TRACE();
	if ((hc = makecache(host))) {

		ScanEntry *scan;

		TRACE();
		hc->nick = str_duplicate(nick);

		hc->ip = ip;
		hc->lang = lang;

		TRACE();
		if (str_not_equals_nocase(source, "!"))
			hc->req = str_duplicate(source);

		TRACE();
		hc->status = HC_QUEUED;

		TRACE();
		proxy_queue_lock();

		TRACE();
		scan = (ScanEntry *)mem_calloc(1, sizeof(ScanEntry));
		scan->hc = hc;

		if (ScanTail)
			ScanTail->next = scan;
		else
			ScanHead = scan;

		ScanTail = scan;

		TRACE();
		LOG_DEBUG("Added %s to proxy queue", hc->host);

		TRACE();
		proxy_queue_signal();

		TRACE();
		proxy_queue_unlock();

		TRACE();
		return 0;
	}
	else
		return 1;
}

/*********************************************************/

/* Initiates a non-blocking connection */

static int proxy_connect(unsigned long ip, unsigned short port, unsigned short type) {

	struct sockaddr_in sockin;
	struct timeval tv;
	fd_set fds;
	int s, error;
	socklen_t errlen;
	char ipbuf[IPSIZE];

	if ((s = socket(PF_INET, SOCK_STREAM, 0)) == -1) {

		LOG_SNOOP(s_SocksMonitor, "Warning: out of sockets!");
		return -1;
	}		

	get_ip_r(ipbuf, IPSIZE, ip);

	if (fcntl(s, F_SETFL, O_NONBLOCK) == -1) {

		log_services(LOG_PROXY_SCAN, "Socket %d [%s] %s error: blocking connection", s, ipbuf, get_scan_type(type));
		close(s);
		return -1;
	}

	memset(&sockin, 0, sizeof(struct sockaddr_in));

	sockin.sin_family = AF_INET;
	sockin.sin_addr.s_addr = ip;
	sockin.sin_port = htons(port);

	if ((CONF_MONITOR_LOCAL_HOST) && bind(s, (struct sockaddr *)&MONITOR_LOCAL_ADDRESS, sizeof(MONITOR_LOCAL_ADDRESS)) < 0) {

		log_services(LOG_PROXY_SCAN, "Socket %d [%s] %s error: Could not bind local host to socket", s, ipbuf, get_scan_type(type));
		close(s);
		return -1;
	}

	if (connect(s, (struct sockaddr *)&sockin, sizeof(struct sockaddr_in)) == -1 && errno != EINPROGRESS) {

		log_services(LOG_PROXY_SCAN, "Socket %d [%s] %s error: could not connect", s, ipbuf, get_scan_type(type));
		close(s);
		return -1;
	}

	FD_ZERO(&fds);
	FD_SET(s, &fds);

	tv.tv_sec = CONF_SOCKET_TIMEOUT;
	tv.tv_usec = 0;

	if (select(s+1, NULL, &fds, NULL, &tv) <= 0) {

		log_services(LOG_PROXY_SCAN, "Socket %d [%s] %s error: failed select, closing", s, ipbuf, get_scan_type(type));
		close(s);
		return -1;	
	}

	errlen = sizeof(int);

	if (getsockopt(s, SOL_SOCKET, SO_ERROR, &error, &errlen) == -1 || error != 0) {

		switch (error) {

			case 111:
				log_services(LOG_PROXY_SCAN, "Socket %d [%s] %s error: Connection refused", s, ipbuf, get_scan_type(type));
				break;

			case 113:
				log_services(LOG_PROXY_SCAN, "Socket %d [%s] %s error: No route to host", s, ipbuf, get_scan_type(type));
				break;

			default:
				log_services(LOG_PROXY_SCAN, "Socket %d [%s] %s error %d, closing", s, ipbuf, get_scan_type(type), error);
				break;
		}

		close(s);
		return -1;
	}

	return s; 
}

/*********************************************************/

/* Deletes expired cache entries */

void proxy_expire(const time_t now) {

	int i, hctotal = 0, nexp = 0, pexp = 0;
	int fctotal = 0, fexp = 0;
	FloodCache *fc, *next_fc;
	HostCache *hc, *next;

	TRACE_FCLT(FACILITY_SOCKSMONITOR);

	for (i = FIRST_VALID_HOST_CHAR; i <= LAST_VALID_HOST_CHAR; ++i) {

		TRACE();

		for (hc = hcache[i]; hc; hc = next) {

			TRACE();
			++hctotal;
			next = hc->next;
			
			TRACE();

			/* Don't expire not scanned yet entries */
			if ((hc->status == HC_QUEUED) || (hc->status == HC_PROGRESS))
				continue;
				
			TRACE();

			if ((hc->status >= HC_NORMAL) && ((now - hc->used) >= CONF_HOST_CACHE_EXPIRE)) {

				TRACE();
				if (hc->status == HC_NORMAL)
					++nexp;
				else
					++pexp;

				delcache(hc, TRUE);
				TRACE();
			}
		}
	}

	TRACE();

	for (i = FIRST_VALID_HOST_CHAR; i <= LAST_VALID_HOST_CHAR; ++i) {

		for (fc = fcache[i]; fc; fc = next_fc) {

			++fctotal;
			next_fc = fc->next;

			if ((now - fc->last_hit) >= CONF_FLOOD_CACHE_EXPIRE) {

				TRACE();
				++fexp;
				delfloodcache(fc, TRUE);
				TRACE();
			}
		}
	}

	TRACE();
}

/*********************************************************/

static void proxy_queue_cleanup_unlock(void *arg) {

	proxy_queue_unlock();		
}

/*********************************************************/

static void proxy_queue_lock(void) {

	LOG_DEBUG("Thread %ld: Locking proxy queue mutex", (long) pthread_self());
	pthread_mutex_lock(&queuemut);	
}

/*********************************************************/

static void proxy_queue_signal(void) {

	LOG_DEBUG("Thread %ld: Signaling proxy queue condition", (long) pthread_self());
	pthread_cond_signal(&queuecond);
}

/*********************************************************/

static void proxy_queue_unlock(void) {

	LOG_DEBUG("Thread %ld: Unlocking proxy queue mutex", (long) pthread_self());	
	pthread_mutex_unlock(&queuemut);
}

/*********************************************************/

static void proxy_queue_wait(void) {

	LOG_DEBUG("Thread %ld: waiting proxy queue condition", (long) pthread_self());	
	pthread_cond_wait(&queuecond, &queuemut);
	LOG_DEBUG("Thread %ld: passed proxy queue condition", (long) pthread_self());	
}

/*********************************************************/

/* Reads from the socket, in a non-blocking manner */
static int proxy_read(int s, char *buf, size_t buflen, unsigned long ip, unsigned short type) {

	struct timeval tv;
	fd_set fds;

	FD_ZERO(&fds);
	FD_SET(s, &fds);

	tv.tv_sec = CONF_SOCKET_TIMEOUT;
	tv.tv_usec = 0;

	if (select(s+1, &fds, NULL, NULL, &tv) <= 0) {

		char ipbuf[IPSIZE];

		get_ip_r(ipbuf, IPSIZE, ip);

		log_services(LOG_PROXY_SCAN, "Socket %d [%s] %s error: Failed proxy_read() select", s, ipbuf, get_scan_type(type));
		return -1;
	}

	return recv(s, buf, buflen, 0);
} 

/*********************************************************/

/* Resolves hostnames in a thread safe manner */
static unsigned long proxy_resolve(char *host) {

	struct hostent *hentp = NULL;
	unsigned long ip = INADDR_NONE;

#if defined(HAVE_GETHOSTBYNAME_R6)	
	struct hostent hent;
	char hbuf[8192];
	int herrno;

	if (gethostbyname_r(host, &hent, hbuf, sizeof(hbuf), &hentp, &herrno) < 0)
		hentp = NULL;

#elif defined(HAVE_GETHOSTBYNAME_R5)
	struct hostent hent
	char hbuf[8192];
	int herrno;
	hentp = gethostbyname_r(host, &hent, hbuf, sizeof(hbuf), &herrno);

#elif defined(HAVE_GETHOSTBYNAME_R3)
	struct hostent hent;
	struct hostent_data data;
	hentp = gethostbyname_r(host, &hent, &data);

#else
	/* Make it safe that way */

	pthread_mutex_lock(&resmut);
	hentp = gethostbyname(host);
#endif

	if (hentp) {

		char ipbuf[IPSIZE];

		memcpy(&ip, hentp->h_addr, sizeof(hentp->h_length));

		get_ip_r(ipbuf, IPSIZE, ip);

		if (FlagSet(uplink_capab, CAPAB_NICKIP))
			LOG_DEBUG_SNOOP("Thread %ld: resolved %s to %s", (long)pthread_self(), host, ipbuf);

		LOG_DEBUG("Thread %ld: resolved %s to %s", (long)pthread_self(), host, ipbuf);
	}
	else {

		if (FlagSet(uplink_capab, CAPAB_NICKIP))
			LOG_DEBUG_SNOOP("Unable to resolve host \2%s\2", host);

		LOG_DEBUG("Unable to resolve host \2%s\2", host);
	}

#if !defined(HAVE_GETHOSTBYNAME_R6) && !defined(HAVE_GETHOSTBYNAME_R5) && !defined(HAVE_GETHOSTBYNAME_R3)
	pthread_mutex_unlock(&resmut);
#endif

	++iResolveCalls;

	return ip;
}

/*********************************************************/

/* Scans the given host for proxy */

static int monitor_last_proxy_type_found = HC_SOCKS4;

static int proxy_scan(HostCache *hc) {

	unsigned long ip = hc->ip;
	int	i, s, current_check_type;
	char buf[BUFSIZE], ipbuf[IPSIZE];

	++iChecked;

	memset(buf, 0, sizeof(buf));

	get_ip_r(ipbuf, IPSIZE, ip);

	current_check_type = monitor_last_proxy_type_found - 1;

	for (i = 0; i < HC_PROXY_TYPE_COUNT; ++i) {

		switch (current_check_type + 1) {

			case HC_SOCKS4:
				/* Scan for SOCKS 4 */

				if (!CONF_SCAN_SOCKS4)
					break;

				if ((s = proxy_connect(ip, 1080, HC_SOCKS4)) == -1)
					break;

				if (send(s, SOCKS4_BUFFER, 9, 0) != 9) {

					close(s);
					break;
				}

				if (proxy_read(s, buf, 2, ip, HC_SOCKS4) != 2) {

					close(s);
					break;
				}

				if (buf[1] == 90) {

					close(s);
					++iSocks4;
					return monitor_last_proxy_type_found = HC_SOCKS4;
				}

				close(s);
				break;


			case HC_SOCKS5:
				/* Scan for SOCKS 5 */

				if (!CONF_SCAN_SOCKS5)
					break;

				if ((s = proxy_connect(ip, 1080, HC_SOCKS5)) == -1)
					break;

				if (send(s, "\5\1\0", 3, 0) != 3) {

					close(s);
					break;
				}

				if (proxy_read(s, buf, 2, ip, HC_SOCKS5) != 2) {

					close(s);
					break;
				}

				if ((buf[0] != 5) || (buf[1] != 0)) {

					close(s);
					break;
				}

				if (send(s, SOCKS5_BUFFER, 10, 0) != 10) {

					close(s);
					break;
				}

				if (proxy_read(s, buf, 2, ip, HC_SOCKS5) != 2) {

					close(s);
					break;
				}

				if ((buf[0] == 5) && (buf[1] == 0)) {

					close(s);
					++iSocks5;
					return monitor_last_proxy_type_found = HC_SOCKS5;
				}

				close(s);
				break;


			case HC_HTTP1:
			case HC_HTTP2:
			case HC_HTTP4: {

				BOOL	condition;
				unsigned short port;
				unsigned long int *counter;

				switch (current_check_type + 1) {

					default:
					case HC_HTTP1: {

						port = 3128;
						counter = &iProxy1;
						condition = CONF_SCAN_3128;
						break;
					}

					case HC_HTTP2: {

						port = 8080;
						counter = &iProxy2;
						condition = CONF_SCAN_8080;
						break;
					}

					case HC_HTTP4: {

						port = 6588;
						counter = &iProxy8;
						condition = CONF_SCAN_6588;
						break;
					}
				}

				if (condition && ((s = proxy_connect(ip, port, current_check_type + 1)) != -1)) {

					log_services(LOG_PROXY_SCAN, "Socket %d [%s] Proxy (%u): Sending %s", s, ipbuf, port, PROXY_BUFFER);

					if (send(s, PROXY_BUFFER, PROXY_BUFFER_LEN, 0) == PROXY_BUFFER_LEN) {

						log_services(LOG_PROXY_SCAN, "Socket %d [%s] Proxy (%d): send() successful", s, ipbuf, port);

						if (proxy_read(s, buf, sizeof(buf), ip, current_check_type + 1) > 0) {

							log_services(LOG_PROXY_SCAN, "Socket %d [%s] Proxy (%d): Read: %s", s, ipbuf, port, buf);

							if (str_match_wild_nocase("HTTP/?.? 200*", buf)) {

								close(s);
								++*counter;
								return monitor_last_proxy_type_found = current_check_type + 1;
							}
						}
					}

					close(s);
				}

				break;
			}


			case HC_HTTP3:

				if (!CONF_SCAN_80)
					break;

				if ((s = proxy_connect(ip, 80, HC_HTTP3)) != -1) {

					log_services(LOG_PROXY_SCAN, "Socket %d [%s] Proxy (80): Sending %s", s, ipbuf, PROXY_BUFFER);

					if (send(s, PROXY_BUFFER, PROXY_BUFFER_LEN, 0) == PROXY_BUFFER_LEN) {

						int len;

						log_services(LOG_PROXY_SCAN, "Socket %d [%s] Proxy (80): send() successful", s, ipbuf);

						if ((len = proxy_read(s, buf, sizeof(buf), ip, HC_HTTP3)) > 0) {

							log_services(LOG_PROXY_SCAN, "Socket %d [%s] Proxy (80): Read: %s", s, ipbuf, buf);

							if (str_match_wild_nocase("HTTP/?.? 200*", buf)
								&& !str_match_wild_nocase("*Server*Apache*", buf)
								&& !str_match_wild_nocase("*Server*Microsoft*IIS*", buf)
								&& !str_match_wild_nocase("*Access*Denied*", buf)
								&& !str_match_wild_nocase("*image*gif*GIF89a*", buf)
								&& !str_match_wild_nocase("*Server*Jana*Server*", buf)
								&& !str_match_wild_nocase("*proxy*disabled*", buf)
								&& !str_match_wild_nocase("*Server*WebMail*", buf)
								&& !str_match_wild_nocase("*Server*CERN*", buf)
								&& !str_match_wild_nocase("*Server*eMule*", buf)) {

								close(s);
								++iProxy3;
								return monitor_last_proxy_type_found = HC_HTTP3;
							}
						}
					}

					close(s);
				}

				break;


			case HC_WINGATE: {

				/* Scan for Wingate */

				if (CONF_SCAN_WINGATE && (s = proxy_connect(ip, 23, HC_WINGATE)) != -1) {

					log_services(LOG_PROXY_SCAN, "Socket %d [%s] Wingate check", s, ipbuf);

					if (proxy_read(s, buf, 8, ip, HC_WINGATE) == 8) {

						buf[8] = '\0';

						if (str_equals_nocase(buf, "Wingate>") || str_equals_nocase(buf, "Too many")) {

							log_services(LOG_PROXY_SCAN, "Socket %d [%s] Wingate check: Read: %s", s, ipbuf, buf);

							close(s);
							++iWingate;
							return monitor_last_proxy_type_found = HC_WINGATE;
						}
					}
					close(s);
				}

				break;
			}
		}

		current_check_type = RANGE_INC(current_check_type, 1, HC_PROXY_TYPE_COUNT);
	}

	++iNormal;
	return HC_NORMAL;
}

/*********************************************************/

/* Proxy detector threads entry point */
static void *proxy_thread_main(void *arg) {	

	while (1) {

		pthread_cleanup_push(&proxy_queue_cleanup_unlock, NULL);
		proxy_queue_lock();
		proxy_queue_wait();
		pthread_cleanup_pop(1);

		/* We loop until there are no more hosts to check in the list */
		while (1) {

			HostCache *hc = NULL;
			int status;

			pthread_cleanup_push(&proxy_queue_cleanup_unlock, NULL);
			proxy_queue_lock();

			if (IS_NOT_NULL(ScanHead)) {

				TRACE();
				hc = ScanHead->hc;
				hc->status = HC_PROGRESS;
				--iQueued;
				++iProgress;

				/* Are we removing the only element present? */
				if (ScanHead == ScanTail) {

					mem_free(ScanHead);
					ScanHead = NULL;
					ScanTail = NULL;
				}
				else {

					ScanEntry *next;

					next = ScanHead->next;
					mem_free(ScanHead);
					ScanHead = next;
				}
			}

			pthread_cleanup_pop(1); 

			if (IS_NULL(hc))
				break;

			/* Test if it's an IP, and if not try to resolve the hostname */
			if (hc->ip == 0) {

				if ((hc->ip = aton(hc->host)) == INADDR_NONE)
					hc->ip = proxy_resolve(hc->host);
			}

			if (hc->ip == INADDR_NONE) {

				if (CONF_SET_DEBUG)
					log_services(LOG_PROXY_SCAN, "Unable to resolve %s, skipped", hc->host);

				if (IS_NOT_NULL(hc->req)) {

					LOG_PROXY(s_SocksMonitor, "Unable to resolve \2%s\2 [Requested by \2%s\2]", hc->host, hc->req);
					send_notice_to_nick(s_SocksMonitor, hc->req, "Unble to resolve requested host \2%s\2", hc->host);
				}

				++iChecked;
				++iResolve;

				hc->status = HC_NORMAL;
				--iProgress;
				continue;
			}
			else {

				if (CONF_SET_DEBUG) {

					char ipbuf[IPSIZE];

					get_ip_r(ipbuf, IPSIZE, hc->ip);

					log_services(LOG_PROXY_SCAN, "Scanning host %s [%s] for proxy", hc->host, ipbuf);

					status = proxy_scan(hc);

					log_services(LOG_PROXY_SCAN, "Scan for %s [%s] complete, result: %d", hc->host, ipbuf, status);
				}
				else
					status = proxy_scan(hc);
			}

			if (status > HC_NORMAL) {

				int expiry = ((hc->lang == LANG_IT) ? ((CONF_PROXY_EXPIRE < 600) ? CONF_PROXY_EXPIRE : 600) : CONF_PROXY_EXPIRE);

				++iAkills;

				if (!is_already_akilled("*", hc->host, expiry, NULL, NULL)) {

					char *port;
					flags_t type;

					port = get_akill_type_from_cache(status, &type);

					akill_add(s_SocksMonitor, "*", hc->host, port, FALSE, FALSE, NULL, type, expiry, 0, hc->lang);
				}

				if (IS_NULL(hc->req)) {

					switch (status) {

						case HC_WINGATE:
							LOG_PROXY(s_SocksMonitor, "Open Wingate found on \2%s\2 [%s]", hc->nick, hc->host);
							log_services(LOG_PROXY_GENERAL, "Open Wingate found on %s", hc->host);
							break;

						case HC_SOCKS4:
							LOG_PROXY(s_SocksMonitor, "Socks 4 found on \2%s\2 [%s]", hc->nick, hc->host);
							log_services(LOG_PROXY_GENERAL, "Socks 4 found on %s", hc->host);
							break;

						case HC_SOCKS5:
							LOG_PROXY(s_SocksMonitor, "Socks 5 found on \2%s\2 [%s]", hc->nick, hc->host);
							log_services(LOG_PROXY_GENERAL, "Socks 5 found on %s", hc->host);
							break;

						case HC_HTTP1:
							LOG_PROXY(s_SocksMonitor, "Open proxy on port 3128 found on \2%s\2 [%s]", hc->nick, hc->host);
							log_services(LOG_PROXY_GENERAL, "Open proxy on port 3128 found on %s", hc->host);
							break;

						case HC_HTTP2:
							LOG_PROXY(s_SocksMonitor, "Open proxy on port 8080 found on \2%s\2 [%s]", hc->nick, hc->host);
							log_services(LOG_PROXY_GENERAL, "Open proxy on port 8080 found on %s", hc->host);
							break;

						case HC_HTTP3:
							LOG_PROXY(s_SocksMonitor, "Open proxy on port 80 found on \2%s\2 [%s]", hc->nick, hc->host);
							log_services(LOG_PROXY_GENERAL, "Open proxy on port 80 found on %s", hc->host);
							break;

						case HC_HTTP4:
							LOG_PROXY(s_SocksMonitor, "Open proxy on port 6588 found on \2%s\2 [%s]", hc->nick, hc->host);
							log_services(LOG_PROXY_GENERAL, "Open proxy on port 6588 found on %s", hc->host);
							break;

						default:
							LOG_DEBUG_SNOOP(s_SocksMonitor, "Ack! Return value error!");
							break;
					}
				}
				else {

					switch (status) {

						case HC_WINGATE:
							LOG_PROXY(s_SocksMonitor, "Open Wingate found on \2%s\2 [Requested by \2%s\2]", hc->host, hc->req);
							log_services(LOG_PROXY_GENERAL, "Open Wingate found on %s [Requested by %s]", hc->host, hc->req);
							send_notice_to_nick(s_SocksMonitor, hc->req, "Open Wingate found on requested host \2%s\2", hc->host);
							break;

						case HC_SOCKS4:
							LOG_PROXY(s_SocksMonitor, "Socks 4 found on \2%s\2 [Requested by \2%s\2]", hc->host, hc->req);
							log_services(LOG_PROXY_GENERAL, "Socks 4 found on %s [Requested by %s]", hc->host, hc->req);
							send_notice_to_nick(s_SocksMonitor, hc->req, "Socks 4 found on requested host \2%s\2", hc->host);
							break;

						case HC_SOCKS5:
							LOG_PROXY(s_SocksMonitor, "Socks 5 found on \2%s\2 [Requested by \2%s\2]", hc->host, hc->req);
							log_services(LOG_PROXY_GENERAL, "Socks 5 found on %s [Requested by %s]", hc->host, hc->req);
							send_notice_to_nick(s_SocksMonitor, hc->req, "Socks 5 found on requested host \2%s\2", hc->host);
							break;

						case HC_HTTP1:
							LOG_PROXY(s_SocksMonitor, "Open proxy on port 3128 found on \2%s\2 [Requested by \2%s\2]", hc->host, hc->req);
							log_services(LOG_PROXY_GENERAL, "Open proxy on port 3128 found on %s [Requested by %s]", hc->host, hc->req);
							send_notice_to_nick(s_SocksMonitor, hc->req, "Open proxy on port 3128 found on requested host \2%s\2", hc->host);
							break;

						case HC_HTTP2:
							LOG_PROXY(s_SocksMonitor, "Open proxy on port 8080 found on \2%s\2 [Requested by \2%s\2]", hc->host, hc->req);
							log_services(LOG_PROXY_GENERAL, "Open proxy on port 8080 found on %s [Requested by %s]", hc->host, hc->req);
							send_notice_to_nick(s_SocksMonitor, hc->req, "Open proxy on port 8080 found on requested host \2%s\2", hc->host);
							break;

						case HC_HTTP3:
							LOG_PROXY(s_SocksMonitor, "Open proxy on port 80 found on \2%s\2 [Requested by \2%s\2]", hc->host, hc->req);
							log_services(LOG_PROXY_GENERAL, "Open proxy on port 80 found on %s [Requested by %s]", hc->host, hc->req);
							send_notice_to_nick(s_SocksMonitor, hc->req, "Open proxy on port 80 found on requested host \2%s\2", hc->host);
							break;

						case HC_HTTP4:
							LOG_PROXY(s_SocksMonitor, "Open proxy on port 6588 found on \2%s\2 [Requested by \2%s\2]", hc->host, hc->req);
							log_services(LOG_PROXY_GENERAL, "Open proxy on port 6588 found on %s [Requested by %s]", hc->host, hc->req);
							send_notice_to_nick(s_SocksMonitor, hc->req, "Open proxy on port 6588 found on requested host \2%s\2", hc->host);
							break;

						default:
							LOG_DEBUG_SNOOP(s_SocksMonitor, "Ack! Return value error!");
							send_notice_to_nick(s_SocksMonitor, hc->req, "Ack! Return value error!");
							break;
					}
				}
			}				
			else if ((status <= HC_NORMAL) && (IS_NOT_NULL(hc->req))) {

				switch (status) {

					case HC_NORMAL:
						LOG_PROXY(s_SocksMonitor, "Nothing found on \2%s\2 [Requested by \2%s\2]", hc->host, hc->req);
						send_notice_to_nick(s_SocksMonitor, hc->req, "Nothing found on requested host \2%s\2", hc->host);
						break;

					case HC_SKIPPED:
						LOG_PROXY(s_SocksMonitor, "Could not resolve \2%s\2 [Requested by \2%s\2]", hc->host, hc->req);
						send_notice_to_nick(s_SocksMonitor, hc->req, "The requested host \2%s\2 could not be resolved.", hc->host);
						break;

					case HC_EXEMPT:
						LOG_PROXY(s_SocksMonitor, "Host \2%s\2 matches an exception entry [Requested by \2%s\2]", hc->host, hc->req);
						send_notice_to_nick(s_SocksMonitor, hc->req, "The requested host \2%s\2 matches an exception entry.", hc->host);
						break;

					default:
						LOG_DEBUG_SNOOP(s_SocksMonitor, "Ack! Contact a Services Coder ASAP. Requested host: \2%s\2, Status: \2%d\2.", hc->host, status);
						send_notice_to_nick(s_SocksMonitor, hc->req, "Ack! Contact a Services Coder ASAP. Requested host: \2%s\2, Status: \2%d\2.", hc->host, status);
						break;
				}
			}

			hc->status = status;
			--iProgress;
		}
	}
	
	return NULL;		
}

/*********************************************************/

/* Socks Monitor's CACHE command */

static void do_cache(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *cmd = strtok(NULL, " ");
	
	if (IS_NULL(cmd))
		send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2CACHE\2 [DEL|INFO|LIST] hostname|pattern [ALL|EXEMPT|INPROGRESS|NORMAL|QUEUED|PROXY|SKIPPED|SOCKS|WINGATES]");

	else if (str_equals_nocase(cmd, "INFO")) {

		HostCache *hc;
		char *pattern = strtok(NULL, " ");

		if (IS_NULL(pattern)) {

			send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2CACHE\2 [DEL|INFO|LIST] hostname|pattern [ALL|EXEMPT|INPROGRESS|NORMAL|QUEUED|PROXY|SKIPPED|SOCKS|WINGATES]");
			return;
		}

		if (IS_NULL(hc = findcache(pattern))) {

			send_notice_to_user(s_SocksMonitor, callerUser, "\2%s\2 was not found in the cache.", pattern);
			return;
		}

		send_notice_to_user(s_SocksMonitor, callerUser, "Info for cached host \2%s\2 :", pattern);
		send_notice_to_user(s_SocksMonitor, callerUser, s_SPACE);

		send_notice_to_user(s_SocksMonitor, callerUser, "Nick: \2%s\2", hc->nick);
		send_notice_to_user(s_SocksMonitor, callerUser, "Host: \2%s\2", hc->host);
		send_notice_to_user(s_SocksMonitor, callerUser, "Last Used: \2%ld\2", hc->used);
		send_notice_to_user(s_SocksMonitor, callerUser, "Status: \2%d\2", hc->status);

		if (hc->req)
			send_notice_to_user(s_SocksMonitor, callerUser, "Requested by: \2%s\2", hc->req);

		send_notice_to_user(s_SocksMonitor, callerUser, s_SPACE);
		send_notice_to_user(s_SocksMonitor, callerUser, "\2*** End of Info ***\2");
	}
	else if (str_equals_nocase(cmd, "LIST")) {

		char *pattern = strtok(NULL, " ");
		char *option = strtok(NULL, " ");
		int i, restrict = 0, count = 0, total = 0;
		HostCache *hc;

		static char *statusdesc[16] = {
			"Exempt",
			"Skipped",
			"Queued",
			"In progress",
			"Normal",
			"Wingate",
			"Socks 4",
			"Socks 5",
			"Proxy (3128)",
			"Proxy (8080)",
			"Proxy (80)",
			"Proxy (6588)"
		};

		if (IS_NULL(pattern)) {

			send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2CACHE\2 [DEL|INFO|LIST] hostname|pattern [ALL|EXEMPT|INPROGRESS|NORMAL|QUEUED|PROXY|SKIPPED|SOCKS|WINGATES]");
			return;
		}

		if (IS_NULL(option) && !strchr(pattern, '*') && ((!strchr(pattern, '@')) || (!strchr(pattern, '!')))) {

			option = str_duplicate(pattern);
			strcpy(pattern, "*");
		}
		
		if (option) {

			if (str_equals_nocase(option, "EXEMPT"))
				restrict = 1;

			else if (str_equals_nocase(option, "INPROGRESS"))
				restrict = 2;
		
			else if (str_equals_nocase(option, "NORMAL"))
				restrict = 3;

			else if (str_equals_nocase(option, "QUEUED"))
				restrict = 4;

			else if (str_equals_nocase(option, "PROXY")) {

				char *value = strtok(NULL, " ");

				if (IS_NULL(value))
					restrict = 5;

				else if (str_equals_nocase(value, "3128"))
					restrict = 51;

				else if (str_equals_nocase(value, "8080"))
					restrict = 52;

				else if (str_equals_nocase(value, "80"))
					restrict = 53;

				else if (str_equals_nocase(value, "6588"))
					restrict = 54;

				else
					restrict = 5;
			}

			else if (str_equals_nocase(option, "SKIPPED"))
				restrict = 6;

			else if (str_equals_nocase(option, "SOCKS"))
				restrict = 7;

			else if (str_equals_nocase(option, "WINGATES"))
				restrict = 8;

			else if (str_equals_nocase(option, "ALL"))
				restrict = 0;

			else {

				send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2CACHE LIST\2 [hostname|pattern] [ALL|EXEMPT|INPROGRESS|NORMAL|QUEUED|PROXY|SKIPPED|SOCKS|WINGATES]");
				return;
			}
		}

		send_notice_to_user(s_SocksMonitor, callerUser, "\2%s\2 Cache list:", s_SocksMonitor);
		
		for (i = FIRST_VALID_HOST_CHAR; i <= LAST_VALID_HOST_CHAR; ++i) {

			for (hc = hcache[i]; hc; hc = hc->next) {

				if (!str_match_wild_nocase(pattern, hc->host))
					continue;

				if ((restrict == 1 && hc->status != HC_EXEMPT) ||
					(restrict == 2 && hc->status != HC_PROGRESS) ||
					(restrict == 3 && hc->status != HC_NORMAL) ||
					(restrict == 4 && hc->status != HC_QUEUED) ||
					(restrict == 5 && hc->status < HC_HTTP1) ||
					(restrict == 6 && hc->status != HC_SKIPPED) ||
					(restrict == 7 && (hc->status < HC_SOCKS4 || hc->status > HC_SOCKS5)) ||
					(restrict == 8 && hc->status != HC_WINGATE) ||
					(restrict == 51 && hc->status != HC_HTTP1) ||
					(restrict == 52 && hc->status != HC_HTTP2) ||
					(restrict == 53 && hc->status != HC_HTTP3) ||
					(restrict == 54 && hc->status != HC_HTTP4))
					continue;

				++total;

				if (count >= 50)
					continue; 	

				++count;
				send_notice_to_user(s_SocksMonitor, callerUser, "%d) %s [Status: %s]", count, hc->host, statusdesc[hc->status+4]);

				if (IS_NOT_NULL(hc->req))
					send_notice_to_user(s_SocksMonitor, callerUser, "Last used by: Requested by \2%s\2", hc->req);
				else
					send_notice_to_user(s_SocksMonitor, callerUser, "Last used by: \2%s\2", hc->nick);
			}
		}

		send_notice_to_user(s_SocksMonitor, callerUser, "*** End of list. \2%d\2/\2%d\2 matches shown.", count, total);
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SOP))
		send_notice_to_user(s_SocksMonitor, callerUser, "Access denied.");

	else if (str_equals_nocase(cmd, "DEL")) {

		HostCache *hc;
		char *pattern = strtok(NULL, " ");

		if (IS_NULL(pattern)) {

			send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2CACHE\2 [DEL|INFO|LIST] hostname|pattern [ALL|EXEMPT|INPROGRESS|NORMAL|QUEUED|PROXY|SKIPPED|SOCKS|WINGATES]");
			return;
		}

		if (IS_NULL(hc = findcache(pattern))) {

			send_notice_to_user(s_SocksMonitor, callerUser, "\2%s\2 was not found in the cache.", pattern);
			return;
		}

		delcache(hc, TRUE);
		send_globops(s_SocksMonitor, "\2%s\2 removed \2%s\2 from the cache.", source, pattern);
		send_notice_to_user(s_SocksMonitor, callerUser, "\2%s\2 has been removed from the cache.", pattern);
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SA))
		send_notice_to_user(s_SocksMonitor, callerUser, "Access denied.");

	else if (str_equals_nocase(cmd, "CLEAR")) {

		int i, hctotal = 0, nexp = 0, pexp = 0;
		HostCache *hc, *next;

		for (i = FIRST_VALID_HOST_CHAR; i <= LAST_VALID_HOST_CHAR; ++i) {

			TRACE();

			for (hc = hcache[i]; hc; hc = next) {

				TRACE();

				++hctotal;
				next = hc->next;

				TRACE();

				/* Don't expire not scanned yet entries */
				if ((hc->status == HC_QUEUED) || (hc->status == HC_PROGRESS))
					continue;

				TRACE();

				if (hc->status == HC_NORMAL) {

					TRACE();
					++nexp;
					delcache(hc, TRUE);
					TRACE();
					continue;
				}

				if (hc->status > HC_NORMAL) {

					TRACE();
					++pexp;
					delcache(hc, TRUE);
					TRACE();
				}
			}
		}

		TRACE();

		send_globops(s_SocksMonitor, "\2%s\2 cleared the cache (\2%d\2/\2%d\2/\2%d\2)", source, nexp, pexp, hctotal);
		send_notice_to_user(s_SocksMonitor, callerUser, "Cache has been cleared.");
	}
	else if (str_equals_nocase(cmd, "RESET")) {

		int i, hctotal = 0, reset = 0;
		HostCache *hc, *next;

		for (i = FIRST_VALID_HOST_CHAR; i <= LAST_VALID_HOST_CHAR; ++i) {

			for (hc = hcache[i]; hc; hc = next) {

				next = hc->next;
				++hctotal;

				if (hc->status != HC_QUEUED)
					continue;

				++reset;
				delcache(hc, TRUE);
			}
		}

		TRACE();

		send_globops(s_SocksMonitor, "\2%s\2 reset the cache (\2%d\2/\2%d\2)", source, reset, hctotal);
		send_notice_to_user(s_SocksMonitor, callerUser, "Cache has been reset.");
	}
	else
		send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2CACHE\2 [CLEAR|DEL|LIST|RESET] [hostname|pattern] [ALL|EXEMPT|INPROGRESS|NORMAL|QUEUED|PROXY|SKIPPED|SOCKS|WINGATES]");
}

/*********************************************************/

BOOL check_ngi_lamer(CSTR nick, CSTR username, CSTR host, CSTR realname, const unsigned long int ip) {

	const char charset[] = "abcdefghijklmnopqrstuvwxyz";
	const char nickset[] = "abcdefghijklmnopqrstuvwxyz_1234567890";

	if ((((ip & 16777215) == 12891728) ||	// 80.182.192.0/24
		((ip & 16777215) == 12826192) ||	// 80.182.195.0/24
		((ip & 16777215) == 12891728) ||	// 80.182.196.0/24
		((ip & 15794175) == 10492055) ||	// 151.24.160.0/20
		((ip & 16777215) == 10164375) ||	// 151.24.155.0/24
		((ip & 16777215) == 2151893) ||		// 213.213.32.0/24
		((ip & 16777215) == 2348501)) &&	// 213.213.35.0/24
		(str_len(username) < 6) && str_spn(username, charset) &&
		(str_len(realname) < 6) && str_spn(realname, charset) && str_not_equals_nocase(username, "user") &&
		(str_spn(nick, nickset) || str_equals_partial(nick, "Guest", 5))) {

		send_globops(s_SocksMonitor, "\2\3%02dWARNING\3\2: Possible NGI lamer detected on \2%s\2 (%s@%s) [%s]", 5, nick, username, host, realname);
//		send_SHUN(s_SocksMonitor, nick, "NGI lamer detected");
		return TRUE;
	}

	return FALSE;
}

/*********************************************************/

BOOL check_flooder(CSTR nick, CSTR username, CSTR host, const unsigned long ip, CSTR realname, const LANG_ID lang) {

	const char *ident;
	size_t nick_len, ident_len, realname_len;

	if (username[0] != '~')
		return FALSE;

	ident = (username + 1);

	nick_len = str_len(nick);
	ident_len = str_len(ident);
	realname_len = str_len(realname);

	if (CONF_PROMIRC_DETECT) {

		if ((nick_len == 9) && str_spn(nick, "abcdefghijklmnopqrstuvwxyz") &&
			(ident_len == 3) && str_equals(ident, realname)) {

			if (islower(ident[0]) && isdigit(ident[1]) && islower(ident[2])) {

				send_KILL(s_SocksMonitor, nick, lang_msg(lang, FLOODER_KILL_REASON), TRUE);
				flood_hit(host, lang);
				return TRUE;
			}
		}
	}

	if (CONF_WARMACHINE_DETECT) {

		if ((nick_len == 4) && (ident_len == 4)) {

			if (isupper(ident[0]) && isdigit(ident[1]) && islower(ident[2]) && isdigit(ident[3])
				&& isupper(nick[0]) && islower(nick[1]) && islower(nick[2]) && isupper(nick[3])) {

				send_KILL(s_SocksMonitor, nick, lang_msg(lang, FLOODER_KILL_REASON), TRUE);
				flood_hit(host, lang);
				return TRUE;
			}
		}
	}

	if (CONF_UNKNOWN_CLONER_DETECT) {

		if ((nick_len == 7) && (ident_len == 5)) {

			if (isupper(ident[0]) && isdigit(ident[1]) && islower(ident[2]) && isdigit(ident[3])
				&& isupper(ident[4]) && isupper(nick[0]) && isdigit(nick[1]) && islower(nick[2])
				&& islower(nick[3]) && isdigit(nick[4]) && isupper(nick[5]) && isdigit(nick[6])) {

				send_KILL(s_SocksMonitor, nick, lang_msg(lang, FLOODER_KILL_REASON), TRUE);
				flood_hit(host, lang);
				return TRUE;
			}
		}
	}

	if (CONF_UNUTNET_WORM_DETECT) {

		if ((nick_len == 8) && (ident_len == 4) && str_equals(ident, realname)) {

			if (islower(ident[0]) && islower(ident[1]) && isdigit(ident[2]) && islower(ident[3])
				&& isupper(nick[0]) && isupper(nick[1]) && isupper(nick[2]) && islower(nick[3])
				&& islower(nick[4]) && islower(nick[5]) && islower(nick[6]) && isupper(nick[7])) {

				send_KILL(s_SocksMonitor, nick, lang_msg(lang, FLOODER_KILL_REASON), TRUE);
				flood_hit(host, lang);
				return TRUE;
			}
		}
	}

	if (CONF_VENOM_DETECT) {

		if ((nick_len == 9) && str_equals(nick, ident) && str_equals(nick, realname)
			&& str_spn(nick, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")) {

			send_KILL(s_SocksMonitor, nick, lang_msg(lang, FLOODER_KILL_REASON), TRUE);
			flood_hit(host, lang);
			return TRUE;
		}
	}

	if (CONF_WARSATAN_DETECT) {

		if ((nick_len >= 6) && (nick_len <= 7) && (ident_len == 2) && (realname_len == 2)
			&& str_not_equals(ident, realname)) {

			if (islower(ident[0]) && islower(ident[1]) && islower(realname[0]) && islower(realname[1])
				&& islower(nick[0]) && islower(nick[1]) && islower(nick[2]) && islower(nick[3])
				&& isdigit(nick[4]) && isdigit(nick[5]) && ((nick_len > 6) ? isdigit(nick[6]) : 1)) {

				send_KILL(s_SocksMonitor, nick, lang_msg(lang, FLOODER_KILL_REASON), TRUE);
				flood_hit(host, lang);
				return TRUE;
			}
		}
	}

	if (CONF_CLONESX_DETECT) {

		if ((realname_len == 6) && (nick_len >= 4) && (nick_len <= 5) && (ident_len >= 4) && (ident_len <= 5)) {

			if (islower(ident[0]) && isdigit(ident[1]) && isdigit(ident[2]) && isdigit(ident[3])
				&& (ident_len > 4 ? isdigit(ident[4]) : 1) && islower(nick[0]) && isdigit(nick[1])
				&& isdigit(nick[2]) && isdigit(nick[3])	&& (nick_len > 4 ? isdigit(nick[4]) : 1)
				&& islower(realname[0]) && islower(realname[1]) && islower(realname[2])
				&& islower(realname[3]) && islower(realname[4]) && islower(realname[5])) {

				send_KILL(s_SocksMonitor, nick, lang_msg(lang, FLOODER_KILL_REASON), TRUE);
				flood_hit(host, lang);
				return TRUE;
			}
		}
	}

	if (CONF_SABAN_DETECT) {

		if ((ident_len == 4) && nick_len >= 7 && nick_len <= 9) {

			if (islower(ident[0]) && islower(ident[1]) && islower(ident[2])	&& islower(ident[3])
				&& nick[0] == 'S' && nick[1] == 'b' && nick[2] == 'N' && islower(nick[3])
				&& islower(nick[4]) && islower(nick[5]) && islower(nick[6])
				&& (nick_len > 7 ? islower(nick[7]) : 1)) {

				send_KILL(s_SocksMonitor, nick, lang_msg(lang, FLOODER_KILL_REASON), TRUE);
				flood_hit(host, lang);
				return TRUE;
			}
		}
	}

	if (CONF_PROXER_DETECT) {

		if (lang != LANG_IT) {

			if (!str_spn(nick, "abcdefghijklmnopqrstuvwxyz") && (nick_len > 4) &&
				(realname_len == 1) && islower(realname[0])) {

				char buffer[16];

				snprintf(buffer, sizeof(buffer), "%s%s", ident, "*");

				if ((((nick_len < 10) && (ident_len == nick_len)) || ((nick_len >= 10) && (ident_len == 9)))
					&& str_match_wild(buffer, nick)) {

					LOG_DEBUG_SNOOP("[PD] Killing %s for proxy", nick);
//					send_KILL(s_SocksMonitor, nick, lang_msg(lang, FLOODER_KILL_REASON), TRUE);
//					flood_hit(host, lang);
//					return TRUE;
					return FALSE;
				}
			}
		}
	}

	if (CONF_MUHSTIK_DETECT) {

		if ((lang != LANG_IT) && (nick_len == 8) && (ident_len == 8)
			&& (realname_len == 8)) {

			static char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_|[]";

			if (str_spn(nick, charset) && str_spn(ident, charset) && str_spn(realname, charset)
				&& str_not_equals_nocase(nick, ident) && str_not_equals_nocase(nick, host)
				&& str_not_equals_nocase(ident, host)) {

				LOG_DEBUG_SNOOP("[MU] Killing %s for proxy", nick);
//				send_KILL(s_SocksMonitor, nick, lang_msg(lang, FLOODER_KILL_REASON), TRUE);
//				flood_hit(host, lang);
//				return TRUE;
				return FALSE;
			}
		}
	}

	if (CONF_DTHN_DETECT) {

		if ((realname[0] == c_SPACE) && str_equals(ident, "javauser")) {

			char buffer[51];
			char *ptr;
			int port;

			ptr = str_tokenize(realname + 1, buffer, sizeof(buffer), c_SPACE);

			if (IS_NOT_NULL(ptr) && IS_NOT_EMPTY_STR(buffer) &&
				(port = atoi(buffer)) > 1024 && port < 65536) {

				ptr = str_tokenize(ptr, buffer, sizeof(buffer), c_SPACE);

				if (IS_NOT_NULL(ptr) && IS_NOT_EMPTY_STR(buffer) && str_equals(buffer, "1")) {

					send_cmd(":%s SVSKILL %s :%s", s_SocksMonitor, nick, lang_msg(lang, TROJAN_AKILL_REASON));
					return TRUE;
				}
			}
		}
	}

	if (CONF_FIZZER_DETECT) {

		if ((nick_len > 4) && (nick_len < 10) && isdigit(nick[nick_len - 1])
			&& (realname_len > 6) && (realname_len >= ident_len)) {

			char name[64];
			const char *ptr = realname;
			size_t name_len = 0;
			BOOL clean  = FALSE;

			memset(name, 0, sizeof(name));

			while (*ptr) {

				if (*ptr == c_SPACE) {

					++ptr;
					name[name_len] = '\0';
					break;
				}

				if ((name_len == 0) ? (!isupper(*ptr)) : (!islower(*ptr))) {

					clean = TRUE;
					break;
				}

				name[name_len++] = *ptr;

				++ptr;
			}

			if (*ptr && (clean == FALSE)) {

				char surname[64];
				size_t surname_len = 0;

				memset(surname, 0, sizeof(surname));

				while (*ptr) {

					if ((surname_len == 0) ? (!isupper(*ptr)) : (!islower(*ptr))) {

						clean = TRUE;
						break;
					}

					surname[surname_len++] = *ptr;

					++ptr;
				}

				if (clean == FALSE) {

					char buffer[64];
					unsigned int idx;

					surname[surname_len] = 0;

					snprintf(buffer, sizeof(buffer), "%s%s", surname, name);

					for (idx = 0; idx < ident_len; ++idx) {

						if (ident[idx] != buffer[idx]) {

							clean = TRUE;
							break;
						}
					}

					if (clean == FALSE) {

						send_KILL(s_SocksMonitor, nick, lang_msg(lang, FLOODER_KILL_REASON), TRUE);
						return TRUE;
					}
				}
			}
		}
	}

	if (CONF_OPTIXPRO_DETECT) {

		if ((ident[0] == 'O') && (ident_len == 9) && str_equals(ident, nick) && str_equals(ident, realname)) {

			unsigned int i;
			BOOL clean = FALSE;

			for (i = 1; i < 9; ++i) {

				if (!isdigit(ident[i])) {

					clean = TRUE;
					break;
				}
			}

			if (clean == FALSE) {

				if (!is_already_akilled("*", host, 600, NULL, NULL))
					akill_add(s_SocksMonitor, "*", host, NULL, FALSE, FALSE, NULL, AKILL_TYPE_TROJAN, 600, 0, lang);
				else
					send_cmd(":%s SVSKILL %s :%s", s_SocksMonitor, nick, lang_msg(lang, TROJAN_AKILL_REASON));

				return TRUE;
			}
		}
	}

	if (CONF_GUEST_DETECT) {

		if (str_match_wild("Guest*", ident) && str_match_wild("Guest*", nick)
			&& (atoi(nick + 5) > 999) && (atoi(ident + 5) > 999)) {

			int idx;
			User *user;

			HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

				HASH_FOREACH_BRANCH_ITEM(onlineuser, idx, user) {

					if (((user->ip != 0) ? (user->ip == ip) : str_equals(user->host, host))
						&& str_equals(realname, user->nick) && str_not_equals(nick, user->nick)) {

						if (!is_already_akilled("*", host, 600, NULL, NULL))
							akill_add(s_SocksMonitor, "*", host, NULL, FALSE, FALSE, NULL, AKILL_TYPE_MIRCWORM, 600, 0, lang);
						else
							send_cmd(":%s SVSKILL %s :%s", s_SocksMonitor, nick, lang_msg(lang, MIRCWORM_AKILL_REASON));

						send_globops(s_SocksMonitor, "\2%s\2 added an AKILL on %s [Reason: mIRC Worm (Guest)]", s_SocksMonitor, user->nick);
						return TRUE;
					}
				}
			}
		}
	}

	if (CONF_MAIL_DETECT) {

		if ((nick_len > 1) && (nick_len < 10) && (ident_len == 9) && (realname_len == 23)
			&& (realname[9] == '@') && (realname[19] == '.') && (realname[20] == 'c')
			&& (realname[21] == 'o') && (realname[22] == 'm')) {

			unsigned int idx;
			size_t len = realname_len - 4;
			BOOL clean = FALSE;

			for (idx = 0; idx < len; ++idx) {

				if ((idx == 9) || (idx == 19))
					continue;

				if (!islower(realname[idx])) {

					clean = TRUE;
					break;
				}
			}

			if (clean == FALSE) {

				LOG_DEBUG_SNOOP("[MP] Killing %s for proxy", nick);
//				send_KILL(s_SocksMonitor, nick, lang_msg(lang, FLOODER_KILL_REASON), TRUE);
//				flood_hit(host, lang);
//				return TRUE;
				return FALSE;
			}
		}
	}

	return FALSE;
}

/*********************************************************/

/* Insert a nick into the database. */

static void alpha_insert_flood_cache(FloodCache *fc) {

	FloodCache	*branch_head;
	int			branch_name;

	branch_name = str_char_tolower(fc->host[0]);

	branch_head = fcache[branch_name];
	fcache[branch_name] = fc;

	fc->next = branch_head;
	fc->prev = NULL;

	if (IS_NOT_NULL(branch_head))
		branch_head->prev = fc;
}

/*********************************************************/

/* Add a nick to the database. Returns a pointer to the new NickInfo
 * structure if the nick was successfully registered, NULL otherwise.
 * Assumes nick does not already exist. */

static FloodCache *makefloodcache(const char *host) {

	FloodCache *fc;
	
	fc = mem_calloc(1, sizeof(FloodCache));
	fc->host = str_duplicate(host);
	fc->hits = 1;
	fc->last_hit = NOW;
	alpha_insert_flood_cache(fc);
	return fc;
}

/*********************************************************/

/* Remove a nick from the NickServ database. Return 1 on success, 0 otherwise.
 * Also deletes the nick from any channel access lists it is on. */

static void delfloodcache(FloodCache *fc, BOOL removeAkill) {

	if ((removeAkill == TRUE) && (fc->hits >= CONF_MAX_FLOOD_HITS))
		akill_remove("*", fc->host);

	if (fc->next)
		fc->next->prev = fc->prev;

	if (fc->prev)
		fc->prev->next = fc->next;
	else
		fcache[str_char_tolower(*fc->host)] = fc->next;

	TRACE();
	mem_free(fc->host);
	TRACE();
	mem_free(fc);
}

/*********************************************************/

/* Return the HostCache structure for the given host, or NULL if the host isn't in the cache. */

static FloodCache *findfloodcache(const char *host) {

	FloodCache *fc;
	
	if (IS_NOT_NULL(host) && IS_NOT_EMPTY_STR(host)) {

		for (fc = fcache[str_char_tolower(*host)]; fc; fc = fc->next) {

			if (str_equals_nocase(fc->host, host))
				return fc;
		}
	}

	return NULL;
}

/*********************************************************/

static void flood_hit(CSTR host, const LANG_ID lang) {

	FloodCache *fc;

	TRACE_FCLT(FACILITY_SOCKSMONITOR);

	TRACE();
	if ((fc = findfloodcache(host))) {

		LOG_DEBUG("Flooder: found cache for %s", fc->host);
		++(fc->hits);
		fc->last_hit = NOW;

		if (fc->hits == CONF_MAX_FLOOD_HITS) {

			if (!is_already_akilled("*", host, (CONF_FLOOD_CACHE_EXPIRE ? CONF_FLOOD_CACHE_EXPIRE : 1800), NULL, NULL))
				akill_add(s_SocksMonitor, "*", host, NULL, FALSE, FALSE, NULL, AKILL_TYPE_FLOODER, (CONF_FLOOD_CACHE_EXPIRE ? CONF_FLOOD_CACHE_EXPIRE : 1800), 0, fc->lang);

			LOG_SNOOP(s_SocksMonitor, "SM +A *@%s -- by %s", host, s_SocksMonitor);
			log_services(LOG_SERVICES_SOCKSMONITOR, "SM +A *@%s -- by %s", host, s_SocksMonitor);

			send_globops(s_SocksMonitor, "\2%s\2 added an AKILL on *@%s [Reason: Flooding]", s_SocksMonitor, host);
		}
	}
	else {

		if (IS_NULL(fc = makefloodcache(host)))
			LOG_DEBUG_SNOOP("Error creating floodcache for %s", host);
		else
			fc->lang = lang;
	}
}

/*********************************************************/

/* Socks Monitor's FLOOD command */

static void do_flood(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *cmd = strtok(NULL, " ");

	if (IS_NULL(cmd))
		send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2FLOOD\2 [DEL|INFO|LIST] hostname|pattern [ALL|EXEMPT|INPROGRESS|NORMAL|QUEUED|PROXY|SKIPPED|SOCKS|WINGATES]");

	else if (str_equals_nocase(cmd, "LIST")) {

		int i, count = 0, total = 0;
		FloodCache *fc;
		char *pattern = strtok(NULL, " ");

		send_notice_to_user(s_SocksMonitor, callerUser, "\2%s\2 Flood Cache list:", s_SocksMonitor);

		for (i = FIRST_VALID_HOST_CHAR; i <= LAST_VALID_HOST_CHAR; ++i) {

			for (fc = fcache[i]; fc; fc = fc->next) {

				++total;

				if ((count >= 50) || (pattern && !str_match_wild_nocase(pattern, fc->host)))
					continue; 	

				++count;
				send_notice_to_user(s_SocksMonitor, callerUser, "%d) %s [Hits: %d]", count, fc->host, fc->hits);
			}
		}

		send_notice_to_user(s_SocksMonitor, callerUser, "*** End of list. \2%d\2/\2%d\2 matches shown.", count, total);
	}
	else if (str_equals_nocase(cmd, "INFO")) {

		FloodCache *fc;
		char *pattern = strtok(NULL, " ");

		if (IS_NULL(pattern)) {

			send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2FLOOD\2 [CLEAR|DEL|INFO|LIST] hostname|pattern [ALL|EXEMPT|INPROGRESS|NORMAL|QUEUED|PROXY|SKIPPED|SOCKS|WINGATES]");
			return;
		}

		if (IS_NULL(fc = findfloodcache(pattern))) {

			send_notice_to_user(s_SocksMonitor, callerUser, "\2%s\2 was not found in the cache.", pattern);
			return;
		}

		send_notice_to_user(s_SocksMonitor, callerUser, "Info for cached host \2%s\2 :", pattern);
		send_notice_to_user(s_SocksMonitor, callerUser, s_SPACE);

		send_notice_to_user(s_SocksMonitor, callerUser, "Host: \2%s\2", fc->host);
		send_notice_to_user(s_SocksMonitor, callerUser, "Hits: \2%d\2", fc->hits);
		send_notice_to_user(s_SocksMonitor, callerUser, "Last Hit: \2%ld\2", fc->last_hit);

		send_notice_to_user(s_SocksMonitor, callerUser, s_SPACE);
		send_notice_to_user(s_SocksMonitor, callerUser, "\2*** End of Info ***\2");
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SOP))
		send_notice_to_user(s_SocksMonitor, callerUser, "Access denied.");

	else if (str_equals_nocase(cmd, "DEL")) {

		FloodCache *fc;
		char *pattern = strtok(NULL, " ");

		if (IS_NULL(pattern)) {

			send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2FLOOD\2 [CLEAR|DEL|INFO|LIST] hostname|pattern [ALL|EXEMPT|INPROGRESS|NORMAL|QUEUED|PROXY|SKIPPED|SOCKS|WINGATES]");
			return;
		}

		if (IS_NULL(fc = findfloodcache(pattern))) {

			send_notice_to_user(s_SocksMonitor, callerUser, "\2%s\2 was not found in the flood cache.", pattern);
			return;
		}

		delfloodcache(fc, TRUE);
		send_globops(s_SocksMonitor, "\2%s\2 removed \2%s\2 from the flood cache.", source, pattern);
		send_notice_to_user(s_SocksMonitor, callerUser, "\2%s\2 has been removed from the flood cache.", pattern);
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SA))
		send_notice_to_user(s_SocksMonitor, callerUser, "Access denied.");

	else if (str_equals_nocase(cmd, "CLEAR")) {

		int i, fctotal = 0;
		FloodCache *fc, *next;

		for (i = FIRST_VALID_HOST_CHAR; i <= LAST_VALID_HOST_CHAR; ++i) {

			TRACE();

			for (fc = fcache[i]; fc; fc = next) {

				TRACE();

				++fctotal;
				next = fc->next;

				delfloodcache(fc, TRUE);
			}
		}

		TRACE();

		send_globops(s_SocksMonitor, "\2%s\2 cleared the flood cache (\2%d\2 entries deleted)", source, fctotal);
		send_notice_to_user(s_SocksMonitor, callerUser, "Flood cache has been cleared.");
	}
	else
		send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2FLOOD\2 [DEL|LIST] [hostname]");
}

/****************************************************/
/************** APM related functions ***************/
/****************************************************/

void load_apm_dbase(void) {

	access_db_load(&APMList, APM_DB, &APMListLoadComplete);
}

void save_apm_dbase(void) {

	access_db_save(APMList, APM_DB, APMListLoadComplete);
}

void free_apm_list(void) {

	free_access_list(APMList, &APMListLoadComplete);
}

static void do_apm(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *cmd = strtok(NULL, " ");
	char *apmnick = strtok(NULL, " ");
	Access *apm;

	TRACE_MAIN_FCLT(FACILITY_SOCKSMONITOR_HANDLE_APM);

	if (IS_NULL(cmd))
		send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2APM\2 [ADD|DEL|SET|LIST|INFO] nick [value]");

	else if (str_equals_nocase(cmd, "ADD")) {

		TRACE_MAIN();
		if (apmnick) {

			apm = find_access(APMList, apmnick);

			if (IS_NOT_NULL(apm)) {

				send_notice_to_user(s_SocksMonitor, callerUser, "\2%s\2 is already on the APM list.", apmnick);
				return;
			}

			apm = access_add(&APMList, apmnick, source);

			send_globops(s_SocksMonitor, "\2%s\2 added \2%s\2 to the APM list", source, apm->nick);
			send_notice_to_user(s_SocksMonitor, callerUser, "APM \2%s\2 has been successfully added to the APM list.", apm->nick);

			TRACE_MAIN();
			if (APMListLoadComplete != 1)
				send_notice_to_user(s_SocksMonitor, callerUser, "\2Warning:\2 Not all APMs on the list have been loaded at startup. Changes will \2NOT\2 be saved.");
		}
		else
			send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2APM ADD\2 nick");
	}
	else if (str_equals_nocase(cmd, "DEL")) {

		TRACE_MAIN();
		if (apmnick) {

			char removed[NICKSIZE];

			memset(removed, 0, sizeof(removed));

			access_remove(&APMList, apmnick, removed);

			if (*removed) {

				TRACE_MAIN();
				send_globops(s_SocksMonitor, "\2%s\2 removed \2%s\2 from the APM list", source, removed);
				send_notice_to_user(s_SocksMonitor, callerUser, "APM \2%s\2 has been removed.", removed);
			}
			else {

				LOG_SNOOP(s_SocksMonitor, "SM -B* %s -- by %s (%s@%s) [Not Found]", apmnick, source, callerUser->username, callerUser->host);
				send_notice_to_user(s_SocksMonitor, callerUser, "APM \2%s\2 was not found on the list.", apmnick);
			}
		}
		else {

			send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2APM DEL\2 nick");
			send_notice_to_user(s_SocksMonitor, callerUser, "Type \2/msg %s HELP APM\2 for more information.", s_SocksMonitor);
		}
	}
	else if (str_equals_nocase(cmd, "SET")) {

		char *opt = strtok(NULL, " ");
		char *val = strtok(NULL, " ");

		TRACE_MAIN();

		if (apmnick && opt && val) {

			apm = find_access(APMList, apmnick);

			if (apm) {

				TRACE_MAIN();
				if (str_equals_nocase(opt, "USER")) {

					if (apm->user) {

						TRACE_MAIN();
						LOG_SNOOP(s_SocksMonitor, "SM B %s -- by %s (%s@%s) [User: %s -> %s]", apm->nick, source, callerUser->username, callerUser->host, apm->user, val);
						send_notice_to_user(s_SocksMonitor, callerUser, "\2USER\2 field of APM \2%s\2 has been changed from \2%s\2 to \2%s\2.", apm->nick, apm->user, val);
						mem_free(apm->user);
					}
					else {

						LOG_SNOOP(s_SocksMonitor, "SM B %s -- by %s (%s@%s) [User: %s]", apm->nick, source, callerUser->username, callerUser->host, val);
						send_notice_to_user(s_SocksMonitor, callerUser, "\2USER\2 field of APM \2%s\2 has been set to \2%s\2.",	apm->nick, val);
					}

					TRACE_MAIN();
					apm->user = str_duplicate(val);
					apm->lastUpdate = NOW;
				}
				else if (str_equals_nocase(opt, "HOST")) {

					if (apm->host) {

						TRACE_MAIN();
						LOG_SNOOP(s_SocksMonitor, "SM B %s -- by %s (%s@%s) [Host: %s -> %s]", apm->nick, source, callerUser->username, callerUser->host, apm->host, val);
						send_notice_to_user(s_SocksMonitor, callerUser, "\2HOST\2 field of APM \2%s\2 has been changed from \2%s\2 to \2%s\2.", apm->nick, apm->host, val);
						mem_free(apm->host);
					}
					else {

						LOG_SNOOP(s_SocksMonitor, "SM B %s -- by %s (%s@%s) [Host: %s]", apm->nick, source, callerUser->username, callerUser->host, val);
						send_notice_to_user(s_SocksMonitor, callerUser, "\2HOST\2 field of APM \2%s\2 has been set to \2%s\2.", apm->nick, val);
					}

					TRACE_MAIN();
					apm->host = str_duplicate(val);
					apm->lastUpdate = NOW;
				}
				else if (str_equals_nocase(opt, "HOST2")) {

					if (apm->host2) {

						TRACE_MAIN();
						LOG_SNOOP(s_SocksMonitor, "SM B %s -- by %s (%s@%s) [Host2: %s -> %s]", apm->nick, source, callerUser->username, callerUser->host, apm->host2, val);
						send_notice_to_user(s_SocksMonitor, callerUser, "\2HOST2\2 field of APM \2%s\2 has been changed from \2%s\2 to \2%s\2.", apm->nick, apm->host2, val);
						mem_free(apm->host2);
					}
					else {

						LOG_SNOOP(s_SocksMonitor, "SM B %s -- by %s (%s@%s) [User: %s]", apm->nick, source, callerUser->username, callerUser->host, val);
						send_notice_to_user(s_SocksMonitor, callerUser, "\2HOST2\2 field of APM \2%s\2 has been set to \2%s\2.", apm->nick, val);
					}

					TRACE_MAIN();
					apm->host2 = str_duplicate(val);
					apm->lastUpdate = NOW;
				}
				else if (str_equals_nocase(opt, "SERVER")) {

					if (apm->server) {

						TRACE_MAIN();
						LOG_SNOOP(s_SocksMonitor, "SM B %s -- by %s (%s@%s) [Server: %s -> %s]", apm->nick, source, callerUser->username, callerUser->host, apm->server, val);
						send_notice_to_user(s_SocksMonitor, callerUser, "\2SERVER\2 field of APM \2%s\2 has been changed from \2%s\2 to \2%s\2.", apm->nick, apm->server, val);
						mem_free(apm->server);
					}
					else {

						LOG_SNOOP(s_SocksMonitor, "SM B %s -- by %s (%s@%s) [Server: %s]", apm->nick, source, callerUser->username, callerUser->host, val);
						send_notice_to_user(s_SocksMonitor, callerUser, "\2SERVER\2 field of APM \2%s\2 has been set to \2%s\2.", apm->nick, val);
					}

					TRACE_MAIN();
					apm->server = str_duplicate(val);
					apm->lastUpdate = NOW;
				}
				else if (str_equals_nocase(opt, "ENABLED")) {

					int enable;

					TRACE_MAIN();
					if (str_equals_nocase(val, "YES")) {

						if (IS_NULL(apm->user) || IS_NULL(apm->host) || IS_NULL(apm->server)) {

							LOG_SNOOP(s_SocksMonitor, "SM *B %s -- by %s (%s@%s) [Not Configured]", apm->nick, source, callerUser->username, callerUser->host);
							send_notice_to_user(s_SocksMonitor, callerUser, "The APM is not properly configured and cannot be enabled.");
							return;
						}
						enable = 1;
					}
					else if (str_equals_nocase(val, "NO"))
						enable = 0;
					
					else {

						send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2APM SET\2 ENABLED [YES|NO]");
						send_notice_to_user(s_SocksMonitor, callerUser, "Type \2/msg %s HELP APM\2 for more information.", s_SocksMonitor);
						return;
					}
					if ((enable == 1 && FlagSet(apm->flags, AC_FLAG_ENABLED)) ||
						(enable == 0 && FlagUnset(apm->flags, AC_FLAG_ENABLED))) {

						TRACE_MAIN();
						LOG_SNOOP(s_SocksMonitor, "SM *B %s -- by %s (%s@%s) [Already %s]", apm->nick, source, callerUser->username, callerUser->host, enable ? "Enabled" : "Disabled");
						send_notice_to_user(s_SocksMonitor, callerUser, "APM \2%s\2 is already \2%s\2.", apm->nick, enable ? "enabled" : "disabled");
					}
					else {

						TRACE_MAIN();

						if (enable)
							AddFlag(apm->flags, AC_FLAG_ENABLED);
						else
							RemoveFlag(apm->flags, AC_FLAG_ENABLED);

						apm->lastUpdate = NOW;

						LOG_SNOOP(s_SocksMonitor, "SM B %s -- by %s (%s@%s) [%s]", apm->nick, source, callerUser->username, callerUser->host, enable ? "Enabled" : "Disabled");
						send_notice_to_user(s_SocksMonitor, callerUser, "APM \2%s\2 has been \2%s\2.", apm->nick, enable ? "enabled" : "disabled");
					}
				}
				else
					send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2APM SET\2 nick [USER|HOST|HOST2|SERVER] value");

				if (APMListLoadComplete != 1)
					send_notice_to_user(s_SocksMonitor, callerUser, "\2Warning:\2 Not all APMs on the list have been loaded at startup. Changes will \2NOT\2 be saved.");
			}
			else {

				LOG_SNOOP(s_SocksMonitor, "SM *B %s -- by %s (%s@%s) [Not Registered]", apmnick, source, callerUser->username, callerUser->host);
				send_notice_to_user(s_SocksMonitor, callerUser, "APM \2%s\2 is not registered.", apmnick);
			}
		}
		else
			send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2APM SET\2 nick [ENABLED|USER|HOST|HOST2|SERVER] value");
	}
	else if (str_equals_nocase(cmd, "LIST")) {

		send_notice_to_user(s_SocksMonitor, callerUser, "Current \2APM\2 list:");

		send_access_list(APMList, s_SocksMonitor, callerUser);

		if (APMListLoadComplete != 1)
			send_notice_to_user(s_SocksMonitor, callerUser, "\2Warning:\2 Not all APMs on the list have been loaded at startup. Changes will \2NOT\2 be saved.");
	}
	else if (str_equals_nocase(cmd, "INFO")) {

		TRACE_MAIN();

		if (apmnick) {

			int found;

			found = send_access_info(APMList, apmnick, s_SocksMonitor, callerUser);

			if (found) {

				if (APMListLoadComplete != 1)
					send_notice_to_user(s_SocksMonitor, callerUser, "\2Warning:\2 Not all APMs on the list have been loaded at startup. Changes will \2NOT\2 be saved.");
			}
			else {

				send_notice_to_user(s_SocksMonitor, callerUser, "APM \2%s\2 is not registered.", apmnick);
				LOG_SNOOP(s_SocksMonitor, "SM *B %s -- by %s (%s@%s) [Not Registered]", apmnick, source, callerUser->username, callerUser->host);
			}
		}
		else
			send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2APM INFO\2 nick");
	}
	else
		send_notice_to_user(s_SocksMonitor, callerUser, "Syntax: \2APM\2 [ADD|DEL|SET|LIST|INFO] nick [value]");
}

/*********************************************************/

void remove_apm(const char *apmnick, char status) {

	Access *apm = find_access(APMList, apmnick);

	if (apm) {

		Server *server = findserver(apm->server);

		if (server) {

			if (FlagUnset(server->flags, SERVER_FLAG_HAVEAPM)) {

				LOG_DEBUG_SNOOP("Server %s was APMless, removing %s anyway.", server->name, apmnick);
				return;
			}

			RemoveFlag(server->flags, SERVER_FLAG_HAVEAPM);
			LOG_PROXY(s_SocksMonitor, "%s %s, removed. Resumed proxy scan for \2%s\2", apmnick, ((status == 'k' ? "was killed" : ((status == 'q') ? "quit" : "split"))), server->name);
		}
		else
			LOG_DEBUG_SNOOP("Could not find server [%s] used by %s [%s]", apm->server, apm->nick, ((status == 'k') ? "Kill" : ((status == 'q') ? "Quit" : "Split")));
	}
}

/*********************************************************/

static void do_apm_akill(CSTR source, User *callerUser, ServiceCommandData *data) {

	if (FlagUnset(callerUser->flags, USER_FLAG_IS_APM)) {

		send_notice_to_user(s_SocksMonitor, callerUser, "Comando sconosciuto: \2APMPRXAK\2");
		send_notice_to_user(s_SocksMonitor, callerUser, "Digita \2/SM HELP\2 per la lista dei comandi disponibili.");

		LOG_DEBUG_SNOOP("%s (%s@%s) tried acting as APM", source, callerUser->username, callerUser->host);
	}
	else {

		const char *ipmask = strtok(NULL, " ");
		const char *host = strtok(NULL, " ");
		const char *port = strtok(NULL, " ");
		const char *akillID = strtok(NULL, " ");
		const char *type = strtok(NULL, " ");
		char *err;
		int expiry, portNumber;
		flags_t typeFlag;
		unsigned long ip;
		LANG_ID lang;

		if (IS_NULL(type)) {

			log_error(FACILITY_SOCKSMONITOR, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
				"do_apm_akill() called with NULL parameter(s) (%s, %s, %s, %s, %s) by %s", ipmask, host, port, akillID, type, source);

			return;
		}

		/* Make sure the host is valid. */
		if (!validate_host(host, FALSE, FALSE, FALSE)) {

			log_error(FACILITY_SOCKSMONITOR, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
				"do_apm_akill() invalid host supplied by %s (%s)", source, host);

			return;
		}

		/* Make sure the IP is valid too. */
		ip = strtoul(ipmask, &err, 10);

		if ((ip == 0) || (*err != '\0')) {

			log_error(FACILITY_SOCKSMONITOR, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
				"do_apm_akill() invalid ip supplied by %s for %s (%s)", source, host, ipmask);

			return;
		}

		/* Make sure the port is valid. */
		portNumber = strtol(port, &err, 10);

		if ((*err != '\0') || (portNumber < 0) || (portNumber > 65535)) {

			log_error(FACILITY_SOCKSMONITOR, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
				"do_apm_akill() invalid port supplied by %s for %s (%s)", source, host, port);

			return;
		}

		/* Clear 'port' if it's 0, we need to pass a NULL pointer. */
		if (portNumber == 0)
			port = NULL;

		/* Set appropriate expire time depending on the region. */
		lang = LangFromRegionID(region_match(ip, host, REGIONTYPE_BOTH));

		switch (lang) {

			case LANG_IT:
				expiry = (CONF_PROXY_EXPIRE < 600) ? CONF_PROXY_EXPIRE : 600;
				break;

			case LANG_INVALID:
				lang = LANG_DEFAULT;
				/* Fall... */

			default:
				expiry = CONF_PROXY_EXPIRE;
				break;
		}

		/* Set the appropriate AutoKill type. */
		switch (type[0]) {

			case '4':	typeFlag = AKILL_TYPE_SOCKS4;	break;
			case '5':	typeFlag = AKILL_TYPE_SOCKS5;	break;
			case 'W':	typeFlag = AKILL_TYPE_WINGATE;	break;
			default:	typeFlag = AKILL_TYPE_PROXY;	break;
		}

		if (!is_already_akilled("*", host, expiry, NULL, NULL))
			akill_add(source, "*", host, port, FALSE, FALSE, NULL, typeFlag, expiry, strtoul(akillID, NULL, 10), lang);
	}
}

/*********************************************************/

void monitor_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	STR		cmd = strtok(request, s_SPACE);
	BOOL	needSyntax = FALSE;
	unsigned int i = 0;

	if (IS_NOT_NULL(cmd)) {

		if (str_equals_nocase(cmd, "EXCEPTIONS")) {

			for (i = 0; i < nexceptions; ++i) {

				send_notice_to_user(sourceNick, callerUser, "DUMP: Exceptions");

				send_notice_to_user(sourceNick, callerUser, "%d) Address 0x%08X, size %d B",		i+1, (unsigned long)i, sizeof(struct Exception));
				send_notice_to_user(sourceNick, callerUser, "Host: 0x%08X \2[\2%s\2]\2",			(unsigned long)exceptions[i].host, str_get_valid_display_value(exceptions[i].host));
				send_notice_to_user(sourceNick, callerUser, "Set by: 0x%08X \2[\2%s\2]\2",			(unsigned long)exceptions[i].who, str_get_valid_display_value(exceptions[i].who));
				send_notice_to_user(sourceNick, callerUser, "Reason: 0x%08X \2[\2%s\2]\2",			(unsigned long)exceptions[i].reason, str_get_valid_display_value(exceptions[i].reason));
				send_notice_to_user(sourceNick, callerUser, "Time Set C-time: %ld",					exceptions[i].time);
				send_notice_to_user(sourceNick, callerUser, "Last Used C-time: %ld",				exceptions[i].lastUsed);
			}

			LOG_DEBUG_SNOOP("Command: DUMP EXCEPTIONS -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
		}
		else if (str_equals_nocase(cmd, "HOST")) {

			char *value = strtok(NULL, " ");

			if (IS_NULL(value))
				needSyntax = TRUE;

			else {

				HostCache *hc;

				hc = findcache(value);

				if (IS_NULL(hc))
					send_notice_to_user(sourceNick, callerUser, "DUMP: Host Cache for \2%s\2 not found.", value);

				else {

					send_notice_to_user(sourceNick, callerUser, "DUMP: Host Cache \2%s\2", value);

					send_notice_to_user(sourceNick, callerUser, "Address 0x%08X, size %d B",						(unsigned long)hc, sizeof(HostCache));
					send_notice_to_user(sourceNick, callerUser, "Nick: 0x%08X \2[\2%s\2]\2",						(unsigned long)hc->nick, str_get_valid_display_value(hc->nick));
					send_notice_to_user(sourceNick, callerUser, "Host: 0x%08X \2[\2%s\2]\2",						(unsigned long)hc->host, str_get_valid_display_value(hc->host));
					send_notice_to_user(sourceNick, callerUser, "Requested by: 0x%08X \2[\2%s\2]\2",				(unsigned long)hc->req, str_get_valid_display_value(hc->req));
					send_notice_to_user(sourceNick, callerUser, "IP: %lu",											hc->ip);
					send_notice_to_user(sourceNick, callerUser, "Last Used C-time: %ld",							hc->used);
					send_notice_to_user(sourceNick, callerUser, "Status: %d",										hc->status);
					send_notice_to_user(sourceNick, callerUser, "Next / previous record: 0x%08X / 0x%08X",			(unsigned long)hc->next, (unsigned long)hc->prev);

					LOG_DEBUG_SNOOP("Command: DUMP SOCKSMONITOR HOST %s -- by %s (%s@%s)", value, callerUser->nick, callerUser->username, callerUser->host);
				}
			}
		}
		else if (str_equals_nocase(cmd, "FLOOD")) {

			char *value = strtok(NULL, " ");

			if (IS_NULL(value))
				needSyntax = TRUE;

			else {

				FloodCache *fc;

				fc = findfloodcache(value);

				if (IS_NULL(fc))
					send_notice_to_user(sourceNick, callerUser, "DUMP: Flood Cache for \2%s\2 not found.", value);

				else {

					send_notice_to_user(sourceNick, callerUser, "DUMP: Flood Cache \2%s\2", value);

					send_notice_to_user(sourceNick, callerUser, "Address 0x%08X, size %d B",						(unsigned long)fc, sizeof(FloodCache));
					send_notice_to_user(sourceNick, callerUser, "Host: 0x%08X \2[\2%s\2]\2",						(unsigned long)fc->host, str_get_valid_display_value(fc->host));
					send_notice_to_user(sourceNick, callerUser, "Hits: %d",											fc->hits);
					send_notice_to_user(sourceNick, callerUser, "Last Hit C-time: %ld",								fc->last_hit);
					send_notice_to_user(sourceNick, callerUser, "Next / previous record: 0x%08X / 0x%08X",			(unsigned long)fc->next, (unsigned long)fc->prev);

					LOG_DEBUG_SNOOP("Command: DUMP SOCKSMONITOR FLOOD %s -- by %s (%s@%s)", value, callerUser->nick, callerUser->username, callerUser->host);
				}
			}
		}
		else if (str_equals_nocase(cmd, "APM")) {

			char *value = strtok(NULL, " ");

			if (IS_NULL(value))
				needSyntax = TRUE;

			else if (str_equals_nocase(value, "LIST")) {

				access_ds_dump(APMList, sourceNick, callerUser, TRUE);

				LOG_DEBUG_SNOOP("Command: DUMP SOCKSMONITOR APM LIST -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
			}
			else if (str_equals_nocase(value, "FULL")) {

				access_ds_dump(APMList, sourceNick, callerUser, FALSE);

				LOG_DEBUG_SNOOP("Command: DUMP SOCKSMONITOR APM FULL -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
			}
			else
				needSyntax = TRUE;
		}
		else
			needSyntax = TRUE;
	}
	else
		needSyntax = TRUE;

	if (needSyntax) {

		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 CYBCOP HELP");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 CYBCOP [AKILLS|EXCEPTIONS|FLOOD|HOST]");
	}
}

/*********************************************************/

unsigned long monitor_mem_report(CSTR sourceNick, const User *callerUser) {

	HostCache			*hostCache;
	FloodCache			*floodCache;
	unsigned long		mem, total_mem;
	unsigned int		i;
	int					count;

	TRACE_FCLT(FACILITY_SOCKSMONITOR_MEM_REPORT);

	send_notice_to_user(sourceNick, callerUser, "\2%s\2:", s_SocksMonitor);

	/* Host Cache */
	count = mem = 0;
	for (i = FIRST_VALID_HOST_CHAR; i <= LAST_VALID_HOST_CHAR; ++i) {

		for (hostCache = hcache[i]; IS_NOT_NULL(hostCache); hostCache = hostCache->next) {

			count += 1;
			mem += sizeof(HostCache);

			TRACE();
			if (IS_NOT_NULL(hostCache->host))
				mem += str_len(hostCache->host) + 1;
			
			if (IS_NOT_NULL(hostCache->req))
				mem += str_len(hostCache->req) + 1;
		}
	}

	total_mem = mem;
	send_notice_to_user(sourceNick, callerUser, "Host-cache list: \2%d\2 -> \2%lu\2 KB (\2%lu\2 B)", count, mem / 1024, mem);

	TRACE();

	/* Flood Cache */
	count = mem = 0;
	for (i = FIRST_VALID_HOST_CHAR; i <= LAST_VALID_HOST_CHAR; ++i) {

		for (floodCache = fcache[i]; IS_NOT_NULL(floodCache); floodCache = floodCache->next) {

			++count;
			mem += sizeof(FloodCache);

			TRACE();

			if (IS_NOT_NULL(floodCache->host))
				mem += str_len(floodCache->host) + 1;
		}
	}

	total_mem += mem;
	send_notice_to_user(sourceNick, callerUser, "Flood-cache list: \2%d\2 -> \2%lu\2 KB (\2%lu\2 B)", count, mem / 1024, mem);

	TRACE();

	/* Exceptions */
	mem = sizeof(struct Exception) * exceptions_size;

	for (i = 0; i < nexceptions; ++i)
		mem += str_len(exceptions[i].host) + str_len(exceptions[i].reason) + str_len(exceptions[i].who) + 2;

	total_mem += mem;
	send_notice_to_user(sourceNick, callerUser, "Exceptions list: \2%u\2 -> \2%lu\2 KB (\2%lu\2 B)", nexceptions, mem / 1024, mem);

	/* APMs */
	mem = access_mem_report(APMList, &count);

	total_mem += mem;
	send_notice_to_user(sourceNick, callerUser, "APM list: \2%d\2 -> \2%lu\2 KB (\2%lu\2 B)", count, mem / 1024, mem);

	return total_mem;
}

#endif /* USE_SOCKSMONITOR */
