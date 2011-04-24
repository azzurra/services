/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* debugserv.c - debug routines
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h" 
#include "../inc/logging.h"
#include "../inc/send.h"
#include "../inc/memory.h"
#include "../inc/timeout.h"
#include "../inc/users.h"
#include "../inc/oper.h"
#include "../inc/main.h"
#include "../inc/process.h"
#include "../inc/misc.h"
#include "../inc/crypt_userhost.h"
#include "../inc/crypt_shs1.h"
#include "../inc/conf.h"
#include "../inc/channels.h"
#include "../inc/lang.h"
#include "../inc/servers.h"
#include "../inc/debugserv.h"
#include "../inc/akill.h"
#include "../inc/version.h"
#include "../inc/list.h"
#include "../inc/storage.h"
#include "../inc/nickserv.h"
#include "../inc/chanserv.h"
#include "../inc/memoserv.h"
#include "../inc/operserv.h"
#include "../inc/rootserv.h"
#include "../inc/trigger.h"
#include "../inc/ignore.h"
#include "../inc/sxline.h"
#include "../inc/reserved.h"
#include "../inc/blacklist.h"
#include "../inc/tagline.h"
#include "../inc/jupe.h"


/*********************************************************
 * Local strings                                         *
 *********************************************************/

static STDSTR	s_DS_IBD_ACTIVATED		= "Input buffer debugging \2ACTIVATED\2 by %s";
static STDSTR	s_DS_IBD_DEACTIVATED	= "Input buffer debugging \2DEACTIVATED\2 by %s";
static STDSTR	s_DS_IBD_FILTER			= "Input buffer filter set to \2%s\2";

/* Stuff to pass to the command handler. */
static Agent a_DebugServ;


/*********************************************************
 * Forward definitions                                   *
 *********************************************************/

static void do_mem(const char *source, User *callerUser, ServiceCommandData *data);
static void do_log(const char *source, User *callerUser, ServiceCommandData *data);
static void do_show(const char *source, User *callerUser, ServiceCommandData *data);
static void do_set(const char *source, User *callerUser, ServiceCommandData *data);
static void do_crypt(const char *source, User *callerUser, ServiceCommandData *data);
static void do_dump(const char *source, User *callerUser, ServiceCommandData *data);
static void do_inject(const char *source, User *callerUser, ServiceCommandData *data);
static void do_clones(const char *source, User *callerUser, ServiceCommandData *data);
static void do_svsnick(const char *source, User *callerUser, ServiceCommandData *data);
static void do_sraw(const char *source, User *callerUser, ServiceCommandData *data);
static void do_sysinfo(const char *source, User *callerUser, ServiceCommandData *data);
static void do_killuser(const char *source, User *callerUser, ServiceCommandData *data);
static void do_command(const char *source, User *callerUser, ServiceCommandData *data);


/*********************************************************
 * debugserv()                                           *
 *********************************************************/

// 'A' (65 / 0)
// 'B' (66 / 1)
// 'C' (67 / 2)
static ServiceCommand	debugserv_commands_C[] = {
	{ "COMMAND",	CMDLEVEL_CODER | CMDLEVEL_CANT_BE_DISABLED,	0, do_command },
	{ "CRYPT",		CMDLEVEL_CODER,			0, do_crypt },
	#ifdef ENABLE_DEBUG_COMMANDS
	{ "CLONES",		CMDLEVEL_CODER,			0, do_clones },
	#else
	{ "CLONES",		CMDLEVEL_CODER | CMDLEVEL_DISABLED,			0, do_clones },
	#endif
	{ NULL,			0,						0, NULL }
};
// 'D' (68 / 3)
static ServiceCommand	debugserv_commands_D[] = {
	{ "DUMP",		CMDLEVEL_CODER,			0, do_dump },
	{ NULL,			0,						0, NULL }
};
// 'E' (69 / 4)
// 'F' (70 / 5)
// 'G' (71 / 6)
// 'H' (72 / 7)
// 'I' (73 / 8)
static ServiceCommand	debugserv_commands_I[] = {
	{ "INJECT",		CMDLEVEL_CODER,			0, do_inject },
	{ NULL,			0,						0, NULL }
};
// 'J' (74 / 9)
// 'K' (75 / 10)
static ServiceCommand	debugserv_commands_K[] = {
	{ "KILLUSER",	CMDLEVEL_CODER,			0, do_killuser },
	{ NULL,			0,						0, NULL }
};
// 'L' (76 / 11)
static ServiceCommand	debugserv_commands_L[] = {
	{ "LOG",		CMDLEVEL_CODER,			0, do_log },
	{ NULL,			0,						0, NULL }
};
// 'M' (77 / 12)
static ServiceCommand	debugserv_commands_M[] = {
	{ "MEM",		CMDLEVEL_CODER,			0, do_mem },
	{ NULL,			0,						0, NULL }
};
// 'N' (78 / 13)
// 'O' (79 / 14)
// 'P' (80 / 15)
// 'Q' (81 / 16)
// 'R' (82 / 17)
// 'S' (83 / 18)
static ServiceCommand	debugserv_commands_S[] = {
	{ "SHOW",		CMDLEVEL_CODER,			0, do_show },
	{ "SET",		CMDLEVEL_CODER,			0, do_set },
	{ "SVSNICK",	CMDLEVEL_CODER,			0, do_svsnick },
	{ "SRAW",		CMDLEVEL_CODER,			0, do_sraw },
	{ "SYSINFO",	CMDLEVEL_CODER,			0, do_sysinfo },
	{ NULL,			0,						0, NULL }
};
// 'T' (84 / 19)
// 'U' (85 / 20)
// 'V' (86 / 21)
// 'W' (87 / 22)
// 'X' (88 / 23)
// 'Y' (89 / 24)
// 'Z' (90 / 25)

ServiceCommand	*debugserv_commands[26] = {
	NULL,					NULL,
	debugserv_commands_C,	debugserv_commands_D,
	NULL,					NULL,
	NULL,					NULL,
	debugserv_commands_I,	NULL,
	debugserv_commands_K,	debugserv_commands_L,
	debugserv_commands_M,	NULL,
	NULL,					NULL,
	NULL,					NULL,
	debugserv_commands_S,	NULL,
	NULL,					NULL,
	NULL,					NULL,
	NULL,					NULL
};


void debugserv(const char *source, User *callerUser, char *buf) {

	char *cmd = strtok(buf, " ");

	TRACE_MAIN_FCLT(FACILITY_DEBUGSERV);

	if (!cmd)
		return;

	else if (cmd[0] == '\001') {

		if (!++cmd)
			LOG_SNOOP(s_DebugServ, "Invalid CTCP from \2%s\2", source);

		if (str_equals_nocase(cmd, "PING")) {

			send_notice_to_user(s_DebugServ, callerUser, "\001PING\001");
			LOG_SNOOP(s_DebugServ, "CTCP: PING from \2%s\2", source);
		
		} else {

			char *action = strtok(NULL, "");

			if (action) {

				action[str_len(action) - 1] = '\0';
				LOG_SNOOP(s_DebugServ, "CTCP: %s %s from \2%s\2", cmd, action, source);
			
			} else {

				cmd[str_len(cmd) - 1] = '\0';
				LOG_SNOOP(s_DebugServ, "CTCP: %s from \2%s\2", cmd, source);
			}
		}
	}
	else
		oper_invoke_agent_command(cmd, debugserv_commands, callerUser, &a_DebugServ);
}


/*********************************************************
 * Funzioni interne                                      *
 *********************************************************/

void debugserv_init(void) {

	/* Initialize this struct. */
	a_DebugServ.nick = s_DebugServ;
	a_DebugServ.shortNick = s_DS;
	a_DebugServ.agentID = AGENTID_DEBUGSERV;
	a_DebugServ.logID = logid_from_agentid(AGENTID_DEBUGSERV);
}


/*********************************************************
 * Implementazione comandi                               *
 *********************************************************/


/*********************************************************
 * /msg DebugServ MEM                                    *
 *********************************************************/

static void do_mem(const char *source, User *callerUser, ServiceCommandData *data) {

	unsigned long total_memory = 0;
	const char *param = strtok(NULL, " ");


	TRACE_MAIN_FCLT(FACILITY_DEBUGSERV_HANDLE_MEM);

	if (IS_NULL(param)) {

		total_memory = user_mem_report(s_DebugServ, callerUser);
		total_memory += server_mem_report(s_DebugServ, callerUser);
		total_memory += oper_mem_report(s_DebugServ, callerUser);

		total_memory += chan_mem_report(s_DebugServ, callerUser);

		total_memory += chanserv_mem_report(s_DebugServ, callerUser);
		total_memory += memoserv_mem_report(s_DebugServ, callerUser);
		total_memory += nickserv_mem_report(s_DebugServ, callerUser);
		total_memory += operserv_mem_report(s_DebugServ, callerUser);
		total_memory += rootserv_mem_report(s_DebugServ, callerUser);
		total_memory += lang_mem_report(s_DebugServ, callerUser);
		total_memory += trigger_mem_report(s_DebugServ, callerUser);
		total_memory += ignore_mem_report(s_DebugServ, callerUser);
		total_memory += sxline_mem_report(s_DebugServ, callerUser);
		total_memory += reserved_mem_report(s_DebugServ, callerUser);
		total_memory += blacklist_mem_report(s_DebugServ, callerUser);
		total_memory += tagline_mem_report(s_DebugServ, callerUser);
		total_memory += jupe_mem_report(s_DebugServ, callerUser);
		total_memory += akill_mem_report(s_DebugServ, callerUser);
	}
	else if (str_equals_nocase(param, "USERS"))
		total_memory = user_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "OPERS"))
		total_memory = oper_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "SERVERS"))
		total_memory = server_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "CHANNELS"))
		total_memory = chan_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "AKILL"))
		total_memory = akill_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "CHANSERV"))
		total_memory = chanserv_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "MEMOSERV"))
		total_memory = memoserv_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "NICKSERV"))
		total_memory = nickserv_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "OPERSERV"))
		total_memory = operserv_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "ROOTSERV"))
		total_memory = rootserv_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "LANG"))
		total_memory = lang_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "TRIGGERS"))
		total_memory = trigger_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "IGNORES"))
		total_memory = ignore_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "SXLINES"))
		total_memory = sxline_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "RESERVED"))
		total_memory = reserved_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "BLACKLIST"))
		total_memory = blacklist_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "TAGLINE"))
		total_memory = tagline_mem_report(s_DebugServ, callerUser);

	else if (str_equals_nocase(param, "JUPE"))
		total_memory = jupe_mem_report(s_DebugServ, callerUser);

	else {
		send_notice_to_user(s_DebugServ, callerUser, "Syntax: MEM [CHANNELS|CHANSERV|LANG|MEMOSERV|NICKSERV|OPERSERV|ROOTSERV|USERS]");
		return;
	}

	send_notice_to_user(s_DebugServ, callerUser, s_SPACE);
	send_notice_to_user(s_DebugServ, callerUser, "Memory usage: \2%d\2 KB (\2%d\2 B)", total_memory / 1024, total_memory);
	send_notice_to_user(s_DebugServ, callerUser, s_SPACE);
	send_notice_to_user(s_DebugServ, callerUser, "*** \2End of MEM Stats\2 ***");

	LOG_DEBUG_SNOOP("Command: MEM -- by %s", source);
}


/*********************************************************
 * /msg DebugServ LOG                                    *
 *********************************************************/

static void do_log(const char *source, User *callerUser, ServiceCommandData *data) {

	const char	*cmd	= strtok(NULL, s_SPACE);

	TRACE_MAIN_FCLT(FACILITY_DEBUGSERV_HANDLE_LOG);

	if (IS_NULL(cmd)) {
		send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2LOG\2 SEARCH [TODAY|AAAA-MM-GG[>TODAY|AAAA-MM-GG] [SERV|ERR|DEB|PANIC [start [[+]end]]]]] *text*");
		send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2LOG\2 RESTART|ROTATE");
	}
	else if (str_equals_nocase(cmd, "SEARCH"))
		handle_search(source, callerUser, data);

	else if (str_equals_nocase(cmd, "RESTART")) {

		LOG_DEBUG_SNOOP("\2%s\2 had me restart the LOG subsystem.", source);
		send_notice_to_user(s_DebugServ, callerUser, "Restarting LOG subsystem...");
		log_done();
		log_init();
		send_notice_to_user(s_DebugServ, callerUser, "LOG subsystem restarted.");
	
	} else if (str_equals_nocase(cmd, "ROTATE")) {

		LOG_DEBUG_SNOOP("\2%s\2 forced a log rotation.", source);
		send_notice_to_user(s_DebugServ, callerUser, "Forcing LOG rotation...");
		log_rotate(TRUE);
		send_notice_to_user(s_DebugServ, callerUser, "LOG rotation complete.");
	}
}

/*********************************************************
 * /msg DebugServ SHOW                                   *
 *********************************************************/

static void do_show(const char *source, User *callerUser, ServiceCommandData *data) {

	char	*what = strtok(NULL, s_SPACE);

	TRACE_MAIN_FCLT(FACILITY_DEBUGSERV_HANDLE_SHOW);

	if (IS_NULL(what))
		send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2SHOW\2 LASTERRBUF|TS");
	
	else if (str_equals_nocase(what, "LASTERRBUF")) {

		TRACE_MAIN();
		send_notice_to_user(s_DebugServ, callerUser, "Last error input buffer:");
		send_notice_to_user(s_DebugServ, callerUser, "%s %s %s", log_get_last_error_timestamp(), log_get_last_error_signature(), log_get_last_error_trace());
		send_notice_to_user(s_DebugServ, callerUser, log_get_last_error_buffer());
		LOG_DEBUG_SNOOP("Command: SHOW LASTERRBUF -- by %s", source);
	
	} else if (str_equals_nocase(what, "TS")) {

		send_notice_to_user(s_DebugServ, callerUser, "Current TS: %ld", time(NULL));
		LOG_DEBUG_SNOOP("Command: SHOW TS -- by %s", source);
	}
}


/*********************************************************
 * /msg DebugServ SET                                    *
 *********************************************************/

static void do_set(const char *source, User *callerUser, ServiceCommandData *data) {

	STR		s_flag = strtok(NULL, s_SPACE);
	STR		s_value1 = strtok(NULL, s_SPACE);
	STDVAL	value1;

	TRACE_MAIN_FCLT(FACILITY_DEBUGSERV_HANDLE_SET);

	if (IS_NULL(s_flag) || IS_NULL(s_value1))
		send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2SET\2 MONITOR ON|OFF");

	else {

		TRACE_MAIN();
		value1 = str_parse_standard_value(s_value1);

		if (str_equals_nocase(s_flag, "DEBUG")) {

			switch (value1) {

				case STDVAL_ON:

					TRACE_MAIN();

					if (CONF_SET_DEBUG == TRUE)
						send_notice_to_user(s_DebugServ, callerUser, "Debug Mode already enabled.");

					else {

						LOG_DEBUG_SNOOP("\2%s\2 enabled Debug Mode.", source);
						send_notice_to_user(s_DebugServ, callerUser, "Debug Mode enabled.");
						CONF_SET_DEBUG = TRUE;
						LOG_DEBUG("Debug mode activated by %s", source);
					}
					break;

				case STDVAL_OFF:

					if (CONF_SET_DEBUG == FALSE)
						send_notice_to_user(s_DebugServ, callerUser, "Debug Mode already disabled.");

					else {

						LOG_DEBUG("Debug mode deactivated by %s", source);
						CONF_SET_DEBUG = FALSE;
						LOG_DEBUG_SNOOP("\2%s\2 disabled Debug Mode.", source);
						send_notice_to_user(s_DebugServ, callerUser, "Debug Mode disabled.");
					}
					break;

				default:
					send_notice_to_user(s_DebugServ, callerUser, "Setting for DEBUG must be \2ON\2, \2OFF\2.");
			}
		}
		else if (str_equals_nocase(s_flag, "MONITOR")) {

			switch (value1) {

				case STDVAL_ON:

					TRACE_MAIN();
					if (conf_monitor_inputbuffer == TRUE)
						send_notice_to_user(s_DebugServ, callerUser, "Input buffer debugging already active.");
					
					else {

						STR		s_filter = strtok(NULL, s_NULL);

						if (IS_NOT_NULL(s_filter)) {

							if (IS_NOT_NULL(debug_monitor_inputbuffer_filter))
								mem_free(debug_monitor_inputbuffer_filter);

							debug_monitor_inputbuffer_filter = str_duplicate(s_filter);
						}
						

						conf_monitor_inputbuffer = TRUE;

						snprintf(misc_buffer, sizeof(misc_buffer), s_DS_IBD_ACTIVATED, source);
						send_notice_to_user(s_DebugServ, callerUser, misc_buffer);
						LOG_DEBUG_SNOOP(misc_buffer);
						log_debug_direct(misc_buffer);

						if (IS_NOT_NULL(debug_monitor_inputbuffer_filter))
							LOG_DEBUG_SNOOP(s_DS_IBD_FILTER, debug_monitor_inputbuffer_filter);
					}

					break;

				case STDVAL_OFF:

					TRACE_MAIN();
					if (conf_monitor_inputbuffer == FALSE)
						send_notice_to_user(s_DebugServ, callerUser, "Input buffer debugging already inactive.");
					
					else {

						conf_monitor_inputbuffer = FALSE;

						snprintf(misc_buffer, sizeof(misc_buffer), s_DS_IBD_DEACTIVATED, source);
						send_notice_to_user(s_DebugServ, callerUser, misc_buffer);
						LOG_DEBUG_SNOOP(misc_buffer);
						log_debug_direct(misc_buffer);

						if (IS_NOT_NULL(debug_monitor_inputbuffer_filter)) {
							mem_free(debug_monitor_inputbuffer_filter);
							debug_monitor_inputbuffer_filter = NULL;
						}

					}

					break;

				default:
					send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2SET\2 DEBUG|MONITOR ON|OFF");
			}
		}
	}
}


/*********************************************************
 * /msg DebugServ CRYPT                                  *
 *********************************************************/

static void do_crypt(const char *source, User *callerUser, ServiceCommandData *data) {
	STR		type = strtok(NULL, s_SPACE);
	STR		what = strtok(NULL, s_SPACE);
	STR		crypted;
	long	hash;

	TRACE_MAIN_FCLT(FACILITY_DEBUGSERV_HANDLE_CRYPT);

	if (IS_NULL(type) || IS_NULL(what))
		send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2CRYPT\2 HOST|SHA1|FNV value");

	else if (str_equals_nocase(type, "HOST")) {

		HOST_TYPE	htype;
		short int	dotsCount;

		htype = host_type(what, &dotsCount);
		crypted = ((htype == htIPv4) || (htype == htHostname)) ? crypt_userhost(what, htype, dotsCount) : str_duplicate(what);

		send_notice_to_user(s_DebugServ, callerUser, "Crypted host for %s (type: %s / dots: %d) is \2%s\2", what,
			(htype == htIPv4) ? "IPv4" : ((htype == htHostname) ? "host" : ((htype == htIPv6) ? "IPv6" : ((htype == htIPv4_CIDR) ? "CIDR" : "invalid"))), dotsCount, crypted);

		mem_free(crypted);
		LOG_DEBUG_SNOOP("Command: CRYPT HOST %s -- by %s", what, source);

	} else if (str_equals_nocase(type, "SHA1")) {

		crypted = mem_malloc(CRYPT_SHA1_DIGEST_LEN + 1);
		hash = crypt_hash_SHA1(what, str_len(what), crypted, CRYPT_SHA1_DIGEST_LEN + 1);
		send_notice_to_user(s_DebugServ, callerUser, "SHA1 crypt for %s is \2%s\2 (FNV hash: %X)", what, crypted, hash);
		mem_free(crypted);
		LOG_DEBUG_SNOOP("Command: CRYPT SHA1 %s -- by %s", what, source);

	} else if (str_equals_nocase(type, "FNV")) {

		send_notice_to_user(s_DebugServ, callerUser, "FNV hash for %s is \2%X\2", what, crypt_hash_FNV(what, str_len(what)));
		LOG_DEBUG_SNOOP("Command: CRYPT FNV %s -- by %s", what, source);
	}
}


/*********************************************************
 * /msg DebugServ DUMP                                   *
 *********************************************************/

// void <facility>_ds_dump(CSTR sourceNick, const User *callerUser, STR request)
typedef void (*DS_DUMP_HANDLER)(CSTR, const User *, STR);

typedef struct _ds_dump_item {

	STR					facility;
	DS_DUMP_HANDLER		handler;

} DS_DUMP_ITEM;


static DS_DUMP_ITEM dump_handler_table[] = {

	{ "CONF", conf_ds_dump },
	{ "USER", user_ds_dump },
	{ "CRYPT", crypt_ds_dump },
	{ "SERVER", server_ds_dump },
	{ "OPER", oper_ds_dump },

	{ "CHAN", chan_ds_dump },

	{ "LANG", NULL },
	{ "TIMEOUT", timeout_ds_dump },
	{ "NICKSERV", nickserv_ds_dump },
	{ "CHANSERV", chanserv_ds_dump },
	{ "MEMOSERV", memoserv_ds_dump },
	{ "OPERSERV", operserv_ds_dump },
	{ "ROOTSERV", rootserv_ds_dump },
	{ "TRIGGERS", trigger_ds_dump },
	{ "IGNORES", ignore_ds_dump },
	{ "SGLINES", sxline_ds_dump },
	{ "SQLINES", sxline_ds_dump },
	{ "RESERVED", reserved_ds_dump },
	{ "AKILL", akill_ds_dump },

	{ NULL, NULL }
};


static void do_dump(const char *source, User *callerUser, ServiceCommandData *data) {

	/*
	DUMP facility value [options]
	*/

	STR		facility = strtok(NULL, s_SPACE);
	STR		value = strtok(NULL, s_NULL);

	if (IS_NULL(facility) || IS_NULL(value)) {

		send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2DUMP\2 LIST");
		send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2DUMP\2 facility HELP");
		send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2DUMP\2 facility value [options]");

	} else if (str_equals_nocase(facility, "LIST")) {

		send_notice_to_user(s_DebugServ, callerUser, "DUMP - facility is one of:");

		send_notice_to_user(s_DebugServ, callerUser, "CONF USER CHAN LANG NICKSERV CHANSERV MEMOSERV OPERSERV ROOTSERV TRIGGERS IGNORES SGLINES SQLINES RESERVED"); // altri?

	} else {

		int		i = 0;
		BOOL	found = FALSE;

		do {

			if (IS_NOT_NULL(dump_handler_table[i].facility)) {

				if (str_equals_nocase(dump_handler_table[i].facility, facility)) {

					found = TRUE;

					if (IS_NOT_NULL(dump_handler_table[i].handler)) {

						send_notice_to_user(s_DebugServ, callerUser, "DUMP \2%s %s ...\2", facility, value);
						dump_handler_table[i].handler(s_DebugServ, callerUser, value);
						send_notice_to_user(s_DebugServ, callerUser, "DUMP complete.");

					} else
						send_notice_to_user(s_DebugServ, callerUser, "Handler not defined for facility %s", facility);

					break;
				}
			} else
				break;			

			++i;

		} while (TRUE);

		if (!found)
			send_notice_to_user(s_DebugServ, callerUser, "Unknown facility.");
	}
}


/*********************************************************
 * /msg DebugServ INJECT                                 *
 *********************************************************/

static void do_inject(const char *source, User *callerUser, ServiceCommandData *data) {

	STR		store = strtok(NULL, s_SPACE);
	STR		command = strtok(NULL, s_NULL);
	CHAR	store_flag;

	if (IS_NOT_NULL(store))
		store_flag = str_char_toupper(store[0]);
	else
		store_flag = '\0';

	if (IS_NULL(store) || IS_NULL(command) || ((store_flag != 'Y') && (store_flag != 'N'))) {

		send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2INJECT\2 db-save-flag command");
		send_notice_to_user(s_DebugServ, callerUser, "Syntax: db-save-flag is either Y or N");
	}
	else {

		LOG_DEBUG_SNOOP("\2%s\2 had me INJECT the following command:", source);
		LOG_DEBUG_SNOOP(command);
		log_debug_direct(command);

		if (store_flag == 'Y') {

			LOG_DEBUG_SNOOP("Saving databases...");

			database_expire(NOW);
			database_store();
		}

		process_debug_inject(command);
		send_notice_to_user(s_DebugServ, callerUser, "Command injected.");
	}
}


/*********************************************************
 * /msg DebugServ CLONES                                 *
 *********************************************************/

static void do_clones(const char *source, User *callerUser, ServiceCommandData *data) {
#ifdef ENABLE_DEBUG_COMMANDS
	/*
	CLONES action number baseNick baseChan NickPerChan
	*/

	STR	action = strtok(NULL, s_SPACE);
	STR	number = strtok(NULL, s_SPACE);
	STR	base_nick = strtok(NULL, s_SPACE);
	STR	base_chan = strtok(NULL, s_SPACE);
	STR	perChan = strtok(NULL, s_SPACE);
	unsigned long	clone_count, perChanCount, n, c;

	if (IS_NULL(action) || IS_NULL(number) || IS_NULL(base_nick) || IS_NULL(base_chan) || IS_NULL(perChan) || (clone_count = atol(number)) == 0 || (perChanCount = atol(perChan)) == 0) {
		send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2CLONES\2 LOAD|UNLOAD number baseNick baseChan NickPerChan");

	} else {

		size_t	base_nick_size, base_chan_size;
		STR		nick, chan, pnick, pchan;
		BOOL	load;

		if (str_equals_nocase(action, "LOAD"))
			load = TRUE;
		else if (str_equals_nocase(action, "UNLOAD"))
			load = FALSE;
		else {
			send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2CLONES\2 LOAD|UNLOAD number baseNick baseChan NickPerChan");
			return;
		}

		base_nick_size = str_len(base_nick);
		base_chan_size = str_len(base_chan);
		nick = mem_calloc(sizeof(char), base_nick_size + 12);
		chan = mem_calloc(sizeof(char), base_chan_size + 12);

		strcpy(nick, base_nick);
		strcpy(chan, base_chan);
		pnick = nick + base_nick_size;		
		pchan = chan + base_chan_size;

		send_notice_to_user(s_DebugServ, callerUser, load ? "Loading clones ..." : "Unloading clones ...");
		for (n = 0, c = 0; n < clone_count; ++n) {

			sprintf(pnick, "%lu", n);
			if (load) {
				send_NICK(nick, "+i", CONF_SERVICES_USERNAME, CONF_SERVICES_NAME, "Imperial Drone");
				user_add_services_agent(nick, UMODE_i, "Imperial Drone");

				if (((n % perChanCount) == 0) && (c > 0))
					sprintf(pchan, "%lu", c++);

				send_SJOIN(nick, chan);
			
			} else
				send_QUIT(nick, "Assimilated");
		}

		mem_free(nick);
		mem_free(chan);

		send_notice_to_user(s_DebugServ, callerUser, "Done.");
	}
#endif
}


/*********************************************************
 * /msg DebugServ SVSNICK                                *
 *********************************************************/

static void do_svsnick(const char *source, User *callerUser, ServiceCommandData *data) {

	char *nick = strtok(NULL, " ");
	char *newnick = strtok(NULL, " ");

	TRACE_MAIN();
	if (!nick || !newnick)
		send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2SVSNICK\2 nick newnick");

	else {

		User *user;

		if (!validate_nick(newnick, FALSE)) {

			send_notice_to_user(s_DebugServ, callerUser, "Nickname \2%s\2 is invalid.", newnick);
			return;
		}

		if (IS_NULL(user = hash_onlineuser_find(nick))) {

			send_notice_to_user(s_DebugServ, callerUser, "User \2%s\2 is offline.", nick);
			return;
		}

		LOG_DEBUG_SNOOP("Command: SVSNICK -- by %s [%s -> %s]", source, user->nick, newnick);
		LOG_SNOOP(s_DebugServ, "DS SVSNICK -- by %s [%s -> %s]", source, user->nick, newnick);
		send_globops(s_DebugServ, "SVSNICK command used by \2%s\2 [%s -> %s]", source, user->nick, newnick);

		TRACE_MAIN();
		send_SVSNICK(user->nick, newnick);
		TRACE_MAIN();
	}
}


/*********************************************************
 * /msg DebugServ SRAW                                   *
 *********************************************************/

static void do_sraw(const char *source, User *callerUser, ServiceCommandData *data) {

	char *text = strtok(NULL, "");

	TRACE_MAIN();
	if (!text)
		send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2SRAW\2 parameters");

	else {

		LOG_DEBUG_SNOOP("Command: RAW -- by %s [%s]", source, text);
		LOG_SNOOP(s_DebugServ, "DS RAW -- by %s [%s]", source, text);
		send_globops(s_DebugServ, "SRAW command used by \2%s\2 [\2%s\2]", source, text);

		TRACE_MAIN();
		send_cmd(text);
		TRACE_MAIN();
	}
}


/*********************************************************
 * /msg DebugServ KILLUSER                               *
 *********************************************************/

static void do_killuser(const char *source, User *callerUser, ServiceCommandData *data) {

	char *nick = strtok(NULL, " ");

	if (!nick)
		send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2KILLUSER\2 nick");

	else {

		User *user, *next;
		int idx;

		HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

			HASH_FOREACH_BRANCH_ITEM_SAFE(onlineuser, idx, user, next) {

				if (FlagSet(user->flags, USER_FLAG_ENFORCER) && IS_NOT_NULL(user->ni) &&
					str_equals_nocase(user->nick, nick)) {

					RemoveFlag(user->ni->flags, NI_TIMEOUT);
					RemoveFlag(user->ni->flags, NI_ENFORCED);
					RemoveFlag(user->ni->flags, NI_ENFORCE);

					send_notice_to_user(s_DebugServ, callerUser, "Services ghost \2%s\2 killed.", user->nick);
					LOG_DEBUG_SNOOP("Command: KILLUSER %s -- by %s", user->nick, source);

					user_delete_services_client(user->nick);
				}
			}
		}
	}
}


/*********************************************************
 * /msg DebugServ COMMAND                                *
 *********************************************************/

static void do_command(const char *source, User *callerUser, ServiceCommandData *data) {
	/*
	COMMAND SET agent command ENABLE|DISABLED
	COMMAND DLIST [agent]
	*/

	char			*action = strtok(NULL, " ");
	char			*agent;
	agentid_t		agent_id;
	ServiceCommand	**agent_cmd_map;
	BOOL			needSyntax = TRUE;

	if (IS_NOT_NULL(action)) {
		
		if (str_equals_nocase(action, "SET")) {

			char		*cmd;
			STDVAL		state;
			
			agent = strtok(NULL, " ");
			cmd = strtok(NULL, " ");
			action = strtok(NULL, " ");

			if (agent && cmd && action) {

				agent_id = oper_get_agentid(agent, TRUE);
				if (agent_id != AGENTID_UNKNOWN) {

					if (NULL != (agent_cmd_map = oper_get_agent_command_map(agent_id))) {

						state = str_parse_standard_value(action);
						if (state == STDVAL_ENABLED || state == STDVAL_DISABLED) {

							STDSTR	state_desc;
							int		log_id;

							state_desc = (state == STDVAL_ENABLED ? s_ENABLED : s_DISABLED);

							switch (oper_enable_command(cmd, agent_cmd_map, state == STDVAL_ENABLED)) {

								case RESULT_SUCCESS:

									log_id = logid_from_agentid(agent_id);
									send_notice_to_user(s_DebugServ, callerUser, "The command has been \2%s\2", state_desc);

									if (data->operMatch) {

										send_globops(s_DebugServ, "\2%s\2 %s %s command \2%s\2", source, state_desc, agent, cmd);
										log_services(log_id, "%s %s %s command %s", source, state_desc, agent, cmd);
									}
									else {

										send_globops(s_DebugServ, "\2%s\2 [through \2%s\2] %s %s command \2%s\2", source, data->operName, state_desc, agent, cmd);
										log_services(log_id, "%s [through %s] %s %s command %s", source, data->operName, state_desc, agent, cmd);
									}
									break;

								case RESULT_ALREADY:
									send_notice_to_user(s_DebugServ, callerUser, "The command is already \2%s\2", state_desc);
									break;

								case RESULT_DENIED:
									send_notice_to_user(s_DebugServ, callerUser, "The command \2%s\2 can't be disabled.", cmd);
									break;

								case RESULT_FAILURE:
									send_notice_to_user(s_DebugServ, callerUser, "Unknown command: \2%s\2", cmd);
									break;
							}

							return;

						}
					} else
						send_notice_to_user(s_DebugServ, callerUser, "Invalid agent name");
				} else
					send_notice_to_user(s_DebugServ, callerUser, "Invalid agent name");
			}
		
		} else if (str_equals_nocase(action, "DLIST")) {

			agent = strtok(NULL, " ");
			if (agent) {

				agent_id = oper_get_agentid(agent, TRUE);
				if (agent_id != AGENTID_UNKNOWN) {
					if (NULL != (agent_cmd_map = oper_get_agent_command_map(agent_id))) {

						oper_send_disabled_command_list(agent_cmd_map, agent, callerUser, s_DebugServ);

					} else
						send_notice_to_user(s_DebugServ, callerUser, "Invalid agent name");
				} else
					send_notice_to_user(s_DebugServ, callerUser, "Invalid agent name");

			} else {

				for (agent_id = AGENTID_FIRST; agent_id <= AGENTID_LAST; ++agent_id) {

					if (NULL != (agent_cmd_map = oper_get_agent_command_map(agent_id))) {
						oper_send_disabled_command_list(agent_cmd_map, oper_get_agent_name(agent_id), callerUser, s_DebugServ);
					}
				}
			}

			return;
		}
	}

	if (needSyntax) {

		send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2COMMAND\2 SET agent command ENABLE|DISABLED");
		send_notice_to_user(s_DebugServ, callerUser, "Syntax: \2COMMAND\2 DLIST [agent]");
	}
}


/*********************************************************
 * /msg DebugServ SYSINFO                                *
 *********************************************************/

static void do_sysinfo(const char *source, User *callerUser, ServiceCommandData *data) {

	send_notice_to_user(s_DebugServ, callerUser, "*** System Informations ***");
	send_notice_to_user(s_DebugServ, callerUser, "%s - \2%s\2", s_vers_name, s_vers_build_name);
	send_notice_to_user(s_DebugServ, callerUser, "Version: %s", s_vers_version);
	send_notice_to_user(s_DebugServ, callerUser, "Build time: %s", s_vers_buildtime);

	// build options
	send_notice_to_user(s_DebugServ, callerUser, "Build options: %s%s%s%s%s%s%s%s%s%s",
		#ifdef ENABLE_TRACE
			"ENABLE_TRACE ",
		#else
			"",
		#endif
		#ifdef ENABLE_DEBUG_COMMANDS
			"ENABLE_DEBUG_COMMANDS ",
		#else
			"",
		#endif
		#ifdef NEW_SOCK
			"NEW_SOCK ",
		#else
			"",
		#endif
		#ifdef FIX_USE_MPOOL
			"FIX_USE_MPOOL ",
		#else
			"",
		#endif
		#ifdef FIX_RF
			"FIX_RF ",
		#else
			"",
		#endif
		#ifdef FIX_FLAGS
			"FIX_FLAGS ",
		#else
			"",
		#endif
		#ifdef FIX_NS_REGMAIL_DB
			"FIX_NS_REGMAIL_DB ",
		#else
			"",
		#endif
		#ifdef FIX_NICKNAME_ACCESS_COUNT
			"FIX_NICKNAME_ACCESS_COUNT ",
		#else
			"",
		#endif
		#ifdef FIX_CHANNEL_ACCESS_TYPE
			"FIX_CHANNEL_ACCESS_TYPE ",
		#else
			"",
		#endif
		#ifdef FIX_PASSWORD_SPACE
			"FIX_PASSWORD_SPACE "
		#else
			""
		#endif
			);

	// supported CAPAB
	send_notice_to_user(s_DebugServ, callerUser, "Supported CAPAB: %s%s%s%s%s%s%s%s%s",
		#ifdef ENABLE_CAPAB_TS3
			FlagSet(uplink_capab, CAPAB_TS3) ? "\2TS3\2 " : "TS3 ",
		#else
			"",
		#endif
		#ifdef ENABLE_CAPAB_NOQUIT
			FlagSet(uplink_capab, CAPAB_NOQUIT) ? "\2NOQUIT\2 " : "NOQUIT ",
		#else
			"",
		#endif
		#ifdef ENABLE_CAPAB_BURST
			FlagSet(uplink_capab, CAPAB_BURST) ? "\2BURST\2 " : "BURST ",
		#else
			"",
		#endif
		#ifdef ENABLE_CAPAB_UNCONNECT
			FlagSet(uplink_capab, CAPAB_UNCONNECT) ? "\2UNCONNECT\2 " : "UNCONNECT ",
		#else
			"",
		#endif
		#ifdef ENABLE_CAPAB_ZIP
			FlagSet(uplink_capab, CAPAB_ZIP) ? "\2ZIP\2 " : "ZIP ",
		#else
			"",
		#endif
		#ifdef ENABLE_CAPAB_NICKIP
			FlagSet(uplink_capab, CAPAB_NICKIP) ? "\2NICKIP\2 " : "NICKIP ",
		#else
			"",
		#endif
		#ifdef ENABLE_CAPAB_TSMODE
			FlagSet(uplink_capab, CAPAB_TSMODE) ? "\2TSMODE\2 " : "TSMODE ",
		#else
			"",
		#endif
		#ifdef ENABLE_CAPAB_DKEY
			FlagSet(uplink_capab, CAPAB_DKEY) ? "\2DKEY\2 " : "DKEY ",
		#else
			"",
		#endif
		#ifdef ENABLE_CAPAB_SSJOIN
			FlagSet(uplink_capab, CAPAB_SSJOIN) ? "\2SSJOIN\2 " : "SSJOIN "
		#else
			""
		#endif
			);
	
	// Database options
	send_notice_to_user(s_DebugServ, callerUser, "Database options: Read-only \2%s\2 - No-expire \2%s\2 - Backup \2%s\2 - Update frequency: \2%d\2 secs",
		CONF_SET_READONLY ? s_ENABLED : s_DISABLED, CONF_SET_NOEXPIRE ? s_ENABLED : s_DISABLED, CONF_DATABASE_BACKUP_FREQUENCY ? s_ENABLED : s_DISABLED, CONF_DATABASE_UPDATE_FREQUENCY);

	stg_report_sysinfo(s_DebugServ, callerUser->nick);

	// logging options
	send_notice_to_user(s_DebugServ, callerUser, "Logging options: Snoop \2%s\2 - Extra snoop \2%s\2 - Snoop chan: \2%s\2",
		CONF_SET_SNOOP ? s_ENABLED : s_DISABLED, CONF_SET_EXTRASNOOP ? s_ENABLED : s_DISABLED, CONF_SNOOP_CHAN);

	// debug options
	send_notice_to_user(s_DebugServ, callerUser, "Debug options: Debug-mode \2%s\2 - Debug-snoop chan: \2%s\2 - Input monitor \2%s\2 [%s] - Inject flag is currently \2%s\2",
		CONF_SET_DEBUG ? s_ENABLED : s_DISABLED, CONF_DEBUG_CHAN, conf_monitor_inputbuffer ? s_ENABLED : s_DISABLED, conf_monitor_inputbuffer ? debug_monitor_inputbuffer_filter : s_NULL, debug_inject ? s_ON : s_OFF);

	// misc options
	send_notice_to_user(s_DebugServ, callerUser, "Misc options: Timeout-check frequency \2%d\2 secs", CONF_TIMEOUT_CHECK);

	#ifndef NEW_SOCK
	send_notice_to_user(s_DebugServ, callerUser, "Timeout-check startup delta \2%d\2 secs", CONF_TIMEOUT_STARTUP_DELTA);
	#endif

	send_notice_to_user(s_DebugServ, callerUser, "Misc options: Return mail address \2%s\2 - MTA path \2%s\2", CONF_RETURN_EMAIL, CONF_SENDMAIL_PATH);

	send_notice_to_user(s_DebugServ, callerUser, "Misc options: Services master default nick: \2%s\2", CONF_SERVICES_MASTER);

	send_notice_to_user(s_DebugServ, callerUser, "*** \2End of System Information\2 ***");
}
