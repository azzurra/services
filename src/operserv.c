/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* operserv.c - OperServ
*
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
*
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"

#ifdef USE_SERVICES

#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/logging.h"
#include "../inc/memory.h"
#include "../inc/send.h"
#include "../inc/conf.h"
#include "../inc/storage.h"
#include "../inc/misc.h"
#include "../inc/main.h"
#include "../inc/servers.h"
#include "../inc/version.h"
#include "../inc/oper.h"
#include "../inc/timeout.h"
#include "../inc/cidr.h"
#include "../inc/akill.h"
#include "../inc/memoserv.h"
#include "../inc/rootserv.h"
#include "../inc/helpserv.h"
#include "../inc/operserv.h"
#include "../inc/list.h"
#include "../inc/trigger.h"
#include "../inc/ignore.h"
#include "../inc/sxline.h"
#include "../inc/reserved.h"
#include "../inc/blacklist.h"
#include "../inc/tagline.h"
#include "../inc/jupe.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _clone_warning	CloneWarning;

struct _clone_warning {

	char				*host;
	unsigned long int	ip;
	time_t				timeAdded;
	short int			cloneCount;
	tiny_flags_t		flags;
};

#define WARNINGS_FLAG_USED	0x0001
#define WARNINGS_FLAG_HOST	0x0002
#define WARNINGS_FLAG_IPV6	0x0004


/*********************************************************
 * Local variables                                       *
 *********************************************************/

/* List of clone warnings. Statically initialized to zeros. */
static CloneWarning warnings[CLONE_DETECT_SIZE + 1];

/* Stuff to pass to the command handler. */
static Agent a_OperServ;


/*********************************************************
 * Prototypes                                            *
 *********************************************************/

static void do_find(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_global(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_kick_ban(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_masskill(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_mass_op_voice(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_settings(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_stats(CSTR source, User *callerUser, ServiceCommandData *data);


/*********************************************************
 * Initialization/cleanup routines                       *
 *********************************************************/

void operserv_init(void) {

	/* Initialize this struct. */
	a_OperServ.nick = s_OperServ;
	a_OperServ.shortNick = s_OS;
	a_OperServ.agentID = AGENTID_OPERSERV;
	a_OperServ.logID = logid_from_agentid(AGENTID_OPERSERV);
}


/*********************************************************
 * Command handlers                                      *
 *********************************************************/

// 'A' (65 / 0)
static ServiceCommand	operserv_commands_A[] = {
	{ "AKILL",		ULEVEL_OPER,			0, handle_akill },
	{ NULL,			0,						0, NULL }
};
// 'B' (66 / 1)
static ServiceCommand	operserv_commands_B[] = {
	{ "BAN",		ULEVEL_SOP,				0, do_kick_ban },
	{ "BLACKLIST",	ULEVEL_SOP,				0, handle_blacklist },
	{ NULL,			0,						0, NULL }
};
// 'C' (67 / 2)
static ServiceCommand	operserv_commands_C[] = {
	{ "COUNT",		ULEVEL_SRA,				0, handle_count },
	{ NULL,			0,						0, NULL }
};
// 'D' (68 / 3)
// 'E' (69 / 4)
// 'F' (70 / 5)
static ServiceCommand	operserv_commands_F[] = {
	{ "FIND",		ULEVEL_OPER,			0, do_find },
	{ NULL,			0,						0, NULL }
};
// 'G' (71 / 6)
static ServiceCommand	operserv_commands_G[] = {
	{ "GLOBAL",		ULEVEL_SA,				0, do_global },
	{ NULL,			0,						0, NULL }
};
// 'H' (72 / 7)
// 'I' (73 / 8)
static ServiceCommand	operserv_commands_I[] = {
	{ "IGNORE",		ULEVEL_SOP,				0, handle_ignore },
	{ NULL,			0,						0, NULL }
};
// 'J' (74 / 9)
static ServiceCommand	operserv_commands_J[] = {
	{ "JUPE",		ULEVEL_OPER,			0, handle_jupe },	/* Opers only get to LIST. */
	{ NULL,			0,						0, NULL }
};
// 'K' (75 / 10)
static ServiceCommand	operserv_commands_K[] = {
	{ "KICK",		ULEVEL_SOP,				0, do_kick_ban },
	{ NULL,			0,						0, NULL }
};
// 'L' (76 / 11)
// 'M' (77 / 12)
static ServiceCommand	operserv_commands_M[] = {
	{ "MOP",		ULEVEL_SA,				0, do_mass_op_voice },
	{ "MDEOP",		ULEVEL_SA,				0, handle_masscmds },
	{ "MKICK",		ULEVEL_SA,				0, handle_masscmds },
	{ "MODE",		ULEVEL_SA,				0, handle_mode },
	{ "MDEVOICE",	ULEVEL_SA,				0, handle_masscmds },
	{ "MUNBAN",		ULEVEL_SA,				0, handle_masscmds },
	{ "MVOICE",		ULEVEL_SA,				0, do_mass_op_voice },
	{ "MKILL",		ULEVEL_SA,				0, do_masskill },
	{ "MHALFOP",		ULEVEL_SA,				0, do_mass_op_voice },
	{ "MDEHALFOP",	ULEVEL_SA,				0, handle_masscmds },
	{ NULL,			0,						0, NULL }
};
// 'N' (78 / 13)
// 'O' (79 / 14)
static ServiceCommand	operserv_commands_O[] = {
	{ "OHELP",		ULEVEL_OPER,			0, handle_help },
	{ "OPER",		ULEVEL_OPER,			0, handle_oper },
	{ NULL,			0,						0, NULL }
};
// 'P' (80 / 15)
// 'Q' (81 / 16)
// 'R' (82 / 17)
static ServiceCommand	operserv_commands_R[] = {
	{ "RESETMODES",	ULEVEL_SA,				0, handle_masscmds },
	{ "RESERVED",	ULEVEL_OPER,			0, handle_reserved },	/* Opers only get to LIST. */
	{ NULL,			0,						0, NULL }
};
// 'S' (83 / 18)
static ServiceCommand	operserv_commands_S[] = {
	{ "STATS",		ULEVEL_OPER,			0, do_stats },
	{ "SETTINGS",	ULEVEL_SA,				0, do_settings },
	{ "SQLINE",		ULEVEL_SA,				0, handle_sxline },
	{ "SGLINE",		ULEVEL_SA,				0, handle_sxline },
	{ NULL,			0,						0, NULL }
};
// 'T' (84 / 19)
static ServiceCommand	operserv_commands_T[] = {
	{ "TRIGGER",	ULEVEL_SOP,				0, handle_trigger },
	{ "TAGLINE",	ULEVEL_SOP,				0, handle_tagline },
	{ NULL,			0,						0, NULL }
};
// 'U' (85 / 20)
static ServiceCommand	operserv_commands_U[] = {
	{ "UINFO",		ULEVEL_SOP,				0, handle_uinfo },
	{ "UPTIME",		ULEVEL_OPER,			0, handle_uptime },
	{ "UPDATE",		ULEVEL_SA,				0, handle_update },
	{ NULL,			0,						0, NULL }
};
// 'V' (86 / 21)
static ServiceCommand	operserv_commands_V[] = {
	{ "VERSION",	ULEVEL_OPER,			0, handle_version },
	{ NULL,			0,						0, NULL }
};
// 'W' (87 / 22)
// 'X' (88 / 23)
// 'Y' (89 / 24)
// 'Z' (90 / 25)

ServiceCommand	*operserv_commands[26] = {
	operserv_commands_A,	operserv_commands_B,
	operserv_commands_C,	NULL,
	NULL,					operserv_commands_F,
	operserv_commands_G,	NULL,
	operserv_commands_I,	operserv_commands_J,
	operserv_commands_K,	NULL,
	operserv_commands_M,	NULL,
	operserv_commands_O,	NULL,
	NULL,					operserv_commands_R,
	operserv_commands_S,	operserv_commands_T,
	operserv_commands_U,	operserv_commands_V,
	NULL,					NULL,
	NULL,					NULL
};


/* Main OperServ routine. */
void operserv(CSTR source, User *callerUser, char *buf) {

	char *cmd = strtok(buf, " ");

	TRACE_MAIN_FCLT(FACILITY_OPERSERV);

	if (IS_NULL(cmd))
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP\2 for a listing of OperServ commands.");

	else if (cmd[0] == '\001') {

		++cmd;

		if (IS_EMPTY_STR(cmd))
			LOG_SNOOP(s_OperServ, "Invalid CTCP from \2%s\2", source);

		else {

			char *action = strtok(NULL, "");

			if (action) {

				action[str_len(action) - 1] = '\0';
				LOG_SNOOP(s_OperServ, "CTCP: %s %s from \2%s\2", cmd, action, source);
			}
			else {

				cmd[str_len(cmd) - 1] = '\0';
				LOG_SNOOP(s_OperServ, "CTCP: %s from \2%s\2", cmd, source);
			}
		}
	}
	else
		oper_invoke_agent_command(cmd, operserv_commands, callerUser, &a_OperServ);
}


/*********************************************************
 * Clone detection.                                      *
 *********************************************************/

/* We just got a new user; does it look like a clone? If so, send out a globops. */
void check_clones(const User *newUser) {

	char				clone_nicks[IRCBUFSIZE];
	BOOL				too_many_clone_nicks = FALSE, more_nicks = FALSE, nick_oper = FALSE, nick_exempt = FALSE;
	BOOL				triggered = FALSE, sameHost = TRUE, isExempt = FALSE;
	int					cloneCount = 0, clone_nicks_freespace = 220, position = 0;
	User				*user = NULL;
	char				*ptr = clone_nicks, *reason;
	User_AltListItem	*host_item;


	TRACE_FCLT(FACILITY_OPERSERV_CHECK_CLONES);

	memset(clone_nicks, 0, sizeof(clone_nicks));

	HASH_FOREACH_BRANCH_ITEM(onlinehost, USER_ONLINEHOST_HASHFUNC(newUser->ip), host_item) {

		user = host_item->user;

		TRACE();
		if ((newUser->ip != 0) ? (newUser->ip == user->ip) : str_equals_nocase(newUser->host, user->host)) {

			++cloneCount;
			TRACE();

			if ((newUser->ip != 0) && (sameHost == TRUE) && str_not_equals_nocase(newUser->host, user->host))
				sameHost = FALSE;

			/* Make sure we don't AKill opers/agents if over the limit. */
			if (user_is_ircop(user) || is_services_valid_oper(user) ||
				user_is_services_agent(user) || user_is_services_client(user))
				nick_oper = TRUE;

			/*
			if (exempt_match(user->realname, &position))
				nick_exempt = TRUE;
			*/

			if (!too_many_clone_nicks) {

				const char *nickPtr = user->nick;

				if (IS_NOT_EMPTY_STR(clone_nicks)) {

					*ptr++ = c_COMMA;
					*ptr++ = c_SPACE;

					clone_nicks_freespace -= 2;
				}

				/* Bold if it's an oper, underline it if it's exempt. */
				if ((nick_oper == TRUE) || (nick_exempt == TRUE)) {

					*ptr++ = (nick_oper ? ((char) 2) : ((char) 31));
					--clone_nicks_freespace;
				}

				while (*nickPtr != c_NULL) {

					*ptr++ = *nickPtr++;
					--clone_nicks_freespace;
				}

				/* Close bold/underline if needed. */
				if ((nick_oper == TRUE) || (nick_exempt == TRUE)) {

					*ptr++ = (nick_oper ? ((char) 2) : ((char) 31));
					--clone_nicks_freespace;
				}

				*ptr = c_NULL;

				if (clone_nicks_freespace <= 0)
					too_many_clone_nicks = TRUE;
			}
			else
				more_nicks = TRUE;
		}

		if ((nick_oper == TRUE) || (nick_exempt == TRUE)) {

			isExempt = TRUE;
			nick_oper = FALSE;
			nick_exempt = FALSE;
		}
	}

	if (more_nicks == TRUE) {

		*ptr++ = c_COMMA;
		*ptr++ = c_SPACE;
		*ptr++ = c_DOT;
		*ptr++ = c_DOT;
		*ptr++ = c_DOT;
		*ptr = c_NULL;
	}

	TRACE();

	/* Check if this host is triggered. */
	switch (trigger_match(newUser->username, newUser->host, newUser->ip, cloneCount, &reason, &position)) {

		case triggerExempt:
			/* This host is triggered but we're below the limit. Don't do anything. */
			return;

		case triggerFound:
			/* This host is triggered. */
			triggered = TRUE;
			break;

		default:
		case triggerNotFound:
			/* This host is not triggered. Continue normally. */
			break;
	}

	if ((triggered == TRUE) || (cloneCount >= CONF_CLONE_MIN_USERS)) {

		int warningIdx;


		if ((CONF_AKILL_CLONES) && (cloneCount >= CONF_AKILL_CLONES) && (triggered == FALSE) && (isExempt == FALSE)) {

			char *akillHost;

			if (newUser->ip != 0)
				akillHost = get_ip(newUser->ip);
			else
				akillHost = newUser->host;

			if (!is_already_akilled("*", akillHost, 0, NULL, NULL)) {

				CIDR_IP cidr;
				BOOL haveCIDR = FALSE;


				if (newUser->ip != 0) {

					cidr_ip_fill_direct(newUser->ip, 32, &cidr);
					haveCIDR = TRUE;
				}

				if (sameHost)
					send_globops(s_OperServ, "\2WARNING: %d\2 clones \2%c03autokilled%c\2 from \2%s\2 [ %s ]", cloneCount, 3, 3, newUser->host, clone_nicks);
				else
					send_globops(s_OperServ, "\2WARNING: %d\2 clones \2%c03autokilled%c\2 from IP \2%s\2 [ %s ]", cloneCount, 3, 3, akillHost, clone_nicks);

				/* Pass the IP as host to avoid desynch if someone connects and the IP is not resolved. */
				akill_add(s_OperServ, "*", akillHost, NULL, FALSE, haveCIDR, &cidr, AKILL_TYPE_CLONES, CONF_DEFAULT_CLONEKILL_EXPIRY, 0, newUser->current_lang);
			}

			return;
		}

		/* Okay, we have clones. Check first to see if we already know about them. */

		TRACE();
		for (warningIdx = CLONE_DETECT_SIZE; warningIdx >= 0; --warningIdx) {

			/* Make sure this is a valid entry and not an empty one. */
			if (FlagUnset(warnings[warningIdx].flags, WARNINGS_FLAG_USED))
				continue;

			/* Skip IPv6 warning entries. */
			if (FlagSet(warnings[warningIdx].flags, WARNINGS_FLAG_IPV6))
				continue;

			if (FlagSet(warnings[warningIdx].flags, WARNINGS_FLAG_HOST) ?
				str_equals(warnings[warningIdx].host, newUser->host) :
				(warnings[warningIdx].ip == newUser->ip)) {

				/* We already have a warning for this host. What to do with it? */
				if (((cloneCount - warnings[warningIdx].cloneCount) >= 5) ||
					((NOW - warnings[warningIdx].timeAdded) >= (isExempt ? 300 : CONF_CLONE_WARNING_DELAY))) {

					/* More than 5 new clones have joined, or it's too old. Reset time and notify opers. */

					warnings[warningIdx].timeAdded = NOW;
					warnings[warningIdx].cloneCount = cloneCount;
					break;
				}
				else {

					/* It has already been notified a few seconds ago. Do nothing. */
					return;
				}
			}
		}

		if (warningIdx < 0) {

			/* No warning found for this host. Add a new one and notify opers. */

			TRACE();
			if (IS_NOT_NULL(warnings[0].host))
				mem_free(warnings[0].host);

			TRACE();
			/* Move the existent ones up one slot. This overrides the first entry. */
			memmove(warnings, warnings + 1, sizeof(CloneWarning) * CLONE_DETECT_SIZE);

			/* Create a new entry at the bottom. */

			warnings[CLONE_DETECT_SIZE].flags = WARNINGS_FLAG_USED;
			warnings[CLONE_DETECT_SIZE].timeAdded = NOW;
			warnings[CLONE_DETECT_SIZE].cloneCount = cloneCount;

			if (newUser->ip == 0) {

				AddFlag(warnings[CLONE_DETECT_SIZE].flags, WARNINGS_FLAG_HOST);
				warnings[CLONE_DETECT_SIZE].host = str_duplicate(newUser->host);
				warnings[CLONE_DETECT_SIZE].ip = 0;
			}
			else {

				warnings[CLONE_DETECT_SIZE].host = NULL;
				warnings[CLONE_DETECT_SIZE].ip = newUser->ip;
			}
		}

		/* Now actually notify opers. */

		TRACE();
		if (cloneCount < CONF_CLONE_MIN_USERS) {

			if (sameHost)
				send_globops(s_OperServ, "\2Clones:%c04 %d%c\2 from \2%s\2 [ %s ] [Triggered: %s]", 3, cloneCount, 3, newUser->host, clone_nicks, reason);
			else
				send_globops(s_OperServ, "\2Clones:%c04 %d%c\2 from IP \2%s\2 [ %s ] [Triggered: %s]", 3, cloneCount, 3, get_ip(newUser->ip), clone_nicks, reason);
		}
		else if (triggered == TRUE) {

			if (sameHost)
				send_globops(s_OperServ, "\2Clones: %d\2 %ctriggered%c [%d] from \2%s\2 [ %s ]", cloneCount, 31, 31, position, newUser->host, clone_nicks);
			else
				send_globops(s_OperServ, "\2Clones: %d\2 %ctriggered%c [%d] from IP \2%s\2 [ %s ]", cloneCount, 31, 31, position, get_ip(newUser->ip), clone_nicks);
		}
		else if (isExempt == TRUE) {

			if (sameHost)
				send_globops(s_OperServ, "\2Clones: %d\2 %cexempt%c [%d] from \2%s\2 [ %s ]", cloneCount, 31, 31, position, newUser->host, clone_nicks);
			else
				send_globops(s_OperServ, "\2Clones: %d\2 %cexempt%c [%d] from IP \2%s\2 [ %s ]", cloneCount, 31, 31, position, get_ip(newUser->ip), clone_nicks);
		}
		else {

			if (sameHost)
				send_globops(s_OperServ, "\2Clones: %d\2 from \2%s\2 [ %s ]", cloneCount, newUser->host, clone_nicks);
			else
				send_globops(s_OperServ, "\2Clones: %d\2 from IP \2%s\2 [ %s ]", cloneCount, get_ip(newUser->ip), clone_nicks);
		}
	}
}

/* We just got a new user; does it look like a clone? If so, send out a globops. */
void check_clones_v6(const User *newUser) {

	/* define the buffer for the nick and a final buffer including space for "..." wheter they are necessary or not */
	
	char	clone_nicks[220], ipbuf[42], tmp_clones[220 - 4];
	BOOL    more_clones = FALSE;
	int		idx, warningIdx, cloneCount = 0;
	User_AltListItem	*userIPv6_item = NULL;


	TRACE_FCLT(FACILITY_OPERSERV_CHECK_CLONES);

	memset(clone_nicks, 0, sizeof(clone_nicks));
	memset(tmp_clones, 0, sizeof(tmp_clones));
	
	for (idx = 0; idx < (CONF_CLONE_SCAN_V6 * 5); ++idx) 
		ipbuf[idx] = newUser->maskedHost[idx];
	
	ipbuf[idx++] = '*';
	ipbuf[idx] = '\0';
	
		
	
	LIST_FOREACH(userIPv6_item, list_onlineuser_ipv6) {

			TRACE();

		if (FlagUnset(userIPv6_item->user->flags, USER_FLAG_HAS_IPV6))
			continue;

		if (str_match_wild_nocase(ipbuf, userIPv6_item->user->maskedHost)) {

			++cloneCount;
		
			if (IS_NOT_EMPTY_STR(tmp_clones)) {
				/*Check if there is enought space to store the nick + ", " */
				if(sizeof(tmp_clones) < strlen(userIPv6_item->user->nick) + strlen(tmp_clones) + 3) 
					more_clones = TRUE;
				else {
					/* Concatenate the last nick to the list */
					strcat(tmp_clones,  userIPv6_item->user->nick);
					strcat(tmp_clones, ", ");
				}
			}	
			else {
				strncpy(tmp_clones, userIPv6_item->user->nick, strlen( userIPv6_item->user->nick));
				strcat(tmp_clones, ", ");
			}			
		}	
	}
		
	/* if there are more nicks than the buffer can afford, the add "..." to the buffer */
	if(more_clones == TRUE) {
		strcpy(clone_nicks, tmp_clones);
		strcat(clone_nicks, "...");
	}
	else
		strcpy(clone_nicks, tmp_clones);
	
	/* if the buffer is not terminated by "..." delete ", " from the last nick */
	if(!strstr(clone_nicks, "...")) {
		
		char buffer[220];
		
		memset(buffer, 0, sizeof(buffer));
		
		strncpy(buffer, clone_nicks, strlen(clone_nicks) - 2);
		memset(clone_nicks, 0, sizeof(clone_nicks));
		
		strcpy(clone_nicks, buffer);
		memset(buffer, 0, sizeof(buffer));
	}
	
	
	if (cloneCount >= CONF_CLONE_MIN_USERS) {

		/* Okay, we have clones. Check first to see if we already know about them. */

		const char *host = newUser->host;
		int fields = 0;


		idx = 0;

		while (*host) {

			if (*host == ':') {

				if (++fields == CONF_CLONE_SCAN_V6)
					break;

				if (*(host + 1) == ':') {

					fields += (7 - fields - str_count(host + 2, ':'));

					if (fields >= CONF_CLONE_SCAN_V6)
						break;

					ipbuf[idx++] = ':';
					ipbuf[idx++] = ':';
					host += 2;
					continue;
				}
			}

			ipbuf[idx++] = *host;
			++host;
		}

		ipbuf[idx++] = ':';
		ipbuf[idx++] = '*';
		ipbuf[idx] = '\0';

		str_tolower(ipbuf);

		TRACE();
		for (warningIdx = CLONE_DETECT_SIZE; warningIdx >= 0; --warningIdx) {

			/* Make sure this is a valid entry and not an empty one. */
			if (FlagUnset(warnings[warningIdx].flags, WARNINGS_FLAG_USED))
				continue;

			/* Only check IPv6 warnings. */
			if (FlagUnset(warnings[warningIdx].flags, WARNINGS_FLAG_IPV6))
				continue;

			if (str_equals(warnings[warningIdx].host, ipbuf)) {

				/* We already have a warning for this host. What to do with it? */
				if ((warnings[warningIdx].timeAdded > (NOW - 10)) && ((cloneCount - warnings[warningIdx].cloneCount) < 5)) {

					/* It has already been notified less than 10 secs ago. Do nothing. */
					return;
				}
				else {

					/* It's too old. Reset time and notify opers. */
					warnings[warningIdx].timeAdded = NOW;
					warnings[warningIdx].cloneCount = cloneCount;
					break;
				}
			}
		}

		if (warningIdx < 0) {

			/* No warning found for this host. Add a new one and notify opers. */

			TRACE();
			if (IS_NOT_NULL(warnings[0].host))
				mem_free(warnings[0].host);

			TRACE();
			/* Move the existent ones up one slot. This overrides the first entry. */
			memmove(warnings, warnings + 1, sizeof(CloneWarning) * CLONE_DETECT_SIZE);

			/* Create a new entry at the bottom. */
			warnings[CLONE_DETECT_SIZE].flags = (WARNINGS_FLAG_USED | WARNINGS_FLAG_IPV6);
			warnings[CLONE_DETECT_SIZE].host = str_duplicate(ipbuf);
			warnings[CLONE_DETECT_SIZE].ip = 0;
			warnings[CLONE_DETECT_SIZE].timeAdded = NOW;
			warnings[CLONE_DETECT_SIZE].cloneCount = cloneCount;
		}

		/* Now actually notify opers. */

		TRACE();
		send_globops(s_OperServ, "\2WARNING: %d\2 clones detected from \2%s\2 [ %s ]", cloneCount, ipbuf, clone_nicks);
	}
}



/*********************************************************
 * OperServ command functions.                           *
 *********************************************************/

static void do_settings(CSTR source, User *callerUser, ServiceCommandData *data) {

	char	buffer[IRCBUFSIZE];
	size_t	len = 0;


	TRACE_MAIN_FCLT(FACILITY_OPERSERV_HANDLE_SETTINGS);

	if (data->operMatch)
		LOG_SNOOP(s_OperServ, "OS Se -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
	else
		LOG_SNOOP(s_OperServ, "OS Se -- by %s (%s@%s) through %s", callerUser->nick, callerUser->username, callerUser->host, data->operName);

	send_notice_to_user(s_OperServ, callerUser, "*** \2Services Settings List\2 ***", s_OperServ);
	send_notice_to_user(s_OperServ, callerUser, s_SPACE);

	send_notice_to_user(s_OperServ, callerUser, "CAPABs enabled: %s", (CAPAB[5] == '\0') ?  "None" : (CAPAB + 6));

	send_notice_to_user(s_OperServ, callerUser, "Default AKILL expiry time: %s", (CONF_DEFAULT_AKILL_EXPIRY > 0) ? convert_time(buffer, sizeof(buffer), CONF_DEFAULT_AKILL_EXPIRY, LANG_DEFAULT) : "None");
	send_notice_to_user(s_OperServ, callerUser, "Default IGNORE expiry time: %s", (CONF_DEFAULT_IGNORE_EXPIRY > 0) ? convert_time(buffer, sizeof(buffer), CONF_DEFAULT_IGNORE_EXPIRY, LANG_DEFAULT) : "None");
	send_notice_to_user(s_OperServ, callerUser, "DataBase Update Frequency: %s", convert_time(buffer, sizeof(buffer), CONF_DATABASE_UPDATE_FREQUENCY, LANG_DEFAULT));

	TRACE_MAIN();
	send_notice_to_user(s_OperServ, callerUser, "Clones: Trigger: \2%d\2 - Wait Warnings: \2%d\2 - Max Clones: \2%d\2 - Timed: \2%ds\2 - ScanV6: \2%d\2",
		CONF_CLONE_MIN_USERS, CONF_CLONE_WARNING_DELAY, CONF_AKILL_CLONES, CONF_DEFAULT_CLONEKILL_EXPIRY, CONF_CLONE_SCAN_V6);

	send_notice_to_user(s_OperServ, callerUser, "Default Memo Limit: \2%d\2 - Max Memo Length:\2 450\2 - Memo Send Delay: \2%d\2",
		CONF_DEF_MAX_MEMOS, CONF_MEMO_SEND_DELAY);

	send_notice_to_user(s_OperServ, callerUser, "Maximums: User Chan Access: \2%d\2 - Access List Entries: \2%d\2 - Chan Access Nicks: \2%d\2 - Chan AutoKicks: \2%d\2",
		CONF_USER_CHAN_ACCESS_MAX, CONF_USER_ACCESS_MAX, CONF_CHAN_ACCESS_MAX, CONF_AKICK_MAX);

	send_notice_to_user(s_OperServ, callerUser, "Invalid Password Max Attempts: \2%d\2 - Invalid Password Reset Time: \2%d\2 - Return E-Mail: \2%s\2",
		CONF_INVALID_PASSWORD_MAX_ATTEMPTS, CONF_INVALID_PASSWORD_RESET, CONF_RETURN_EMAIL);

	send_notice_to_user(s_OperServ, callerUser, "Flood Levels: \2%d\2/\2%d\2/\2%d\2 [MAXMSG:MSGRESET:LEVELRESET]",
		CONF_FLOOD_MAX_MESSAGES, CONF_FLOOD_MESSAGE_RESET, CONF_FLOOD_LEVEL_RESET);

	send_notice_to_user(s_OperServ, callerUser, "Snoop Chan: \2%s\2 - Debug Chan: \2%s\2 - AutoKill Percent: \2%.0f\2 - Default Chan Modelock: \2%s\2",
		CONF_SNOOP_CHAN, CONF_DEBUG_CHAN, CONF_AKILL_PERCENT, get_channel_mode(CONF_DEF_MLOCKON, 0));

	send_notice_to_user(s_OperServ, callerUser, "Nick Release Timeout: \2%ds\2 - ChanServ/NickServ Register Delay: \2%ds\2 - Chan Inhabit: \2%ds\2",
		CONF_RELEASE_TIMEOUT, CONF_REGISTER_DELAY, CONF_CHANNEL_INHABIT);

	send_notice_to_user(s_OperServ, callerUser, "Expiry Times: Nicks: \2%d\2 - Chans: \2%d\2 - Memos: \2%d\2",
		CONF_NICK_EXPIRE, CONF_CHANNEL_EXPIRE, CONF_MEMO_EXPIRE);

	if (CONF_SEND_REMINDER == 0) {

		if (CONF_AUTHDEL_DAYS > 0)
			send_notice_to_user(s_OperServ, callerUser, "Expiry Reminder: \2Disabled\2 - Auto Delete Unauthorized Nicks: \2Enabled\2 [Days: \2%d\2]", CONF_AUTHDEL_DAYS);
		else
			send_notice_to_user(s_OperServ, callerUser, "Expiry Reminder: \2Disabled\2 - Auto Delete Unauthorized Nicks: \2Disabled\2");
	}
	else {

		if (CONF_AUTHDEL_DAYS > 0)
			send_notice_to_user(s_OperServ, callerUser, "Expiry Reminder: \2Enabled\2 [Days: \2%d\2] - Auto Delete Unauthorized Nicks: \2Enabled\2 [Days: \2%d\2]", CONF_SEND_REMINDER, CONF_AUTHDEL_DAYS);
		else
			send_notice_to_user(s_OperServ, callerUser, "Expiry Reminder: \2Enabled\2 [Days: \2%d\2] - Auto Delete Unauthorized Nicks: \2Disabled\2", CONF_SEND_REMINDER);
	}

	send_notice_to_user(s_OperServ, callerUser, "Database Backup: \2%s\2 - Display Updates: \2%s\2 - Show Taglines: \2%s\2",
		CONF_DATABASE_BACKUP_FREQUENCY ? "Enabled" : "Disabled", CONF_DISPLAY_UPDATES ? "Enabled" : "Disabled", CONF_SHOW_TAGLINES ? "Enabled" : "Disabled");

	send_notice_to_user(s_OperServ, callerUser, "E-Mail: \2%s\2 - Force Auth: \2%s\2",
		CONF_USE_EMAIL ? "Enabled" : "Disabled", CONF_FORCE_AUTH ? "Enabled" : "Disabled");

	TRACE_MAIN();

	APPEND_BUFFER(CONF_SET_FLOOD, "\2Flood Levels\2")
	APPEND_BUFFER(CONF_SET_DEBUG, "\2Debug\2")
	APPEND_BUFFER(CONF_SET_CLONE, "\2Clone Detection\2")
	APPEND_BUFFER(CONF_SET_SNOOP, "\2Snooping\2")
	APPEND_BUFFER(CONF_SET_EXTRASNOOP, "\2Extra Snooping\2")
	APPEND_BUFFER(CONF_SET_NOEXPIRE, "\2No Expire\2")
	APPEND_BUFFER(CONF_SET_READONLY, "\2Read Only Mode\2")

	send_notice_to_user(s_OperServ, callerUser, "Options: %s", (len > 0) ? buffer : "None");

	send_notice_to_user(s_OperServ, callerUser, "*** \2End of Settings\2 ***");
}

/*********************************************************/

static void do_stats(CSTR source, User *callerUser, ServiceCommandData *data) {

	TRACE_MAIN_FCLT(FACILITY_OPERSERV_HANDLE_STATS);

	if (data->operMatch)
		LOG_SNOOP(s_OperServ, "OS St -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
	else
		LOG_SNOOP(s_OperServ, "OS St -- by %s (%s@%s) through %s", callerUser->nick, callerUser->username, callerUser->host, data->operName);

	send_notice_to_user(s_OperServ, callerUser, "*** \2Services Stats\2 ***");
	send_notice_to_user(s_OperServ, callerUser, "Current users: \2%d\2 (\2%d\2 ops)",
		user_online_user_count, user_online_operator_count);

	TRACE_MAIN();
	send_notice_to_user(s_OperServ, callerUser, "Nicks: \2%d\2/\2%d\2 - Chans: \2%d\2/\2%d\2",
		ns_regCount, dynConf.ns_regLimit, cs_regCount, dynConf.cs_regLimit);

	send_notice_to_user(s_OperServ, callerUser, "G:Lines: \2%d\2 - Q:Lines: \2%d\2 - Taglines: \2%d\2",
		sxline_get_count(SXLINE_TYPE_GLINE), sxline_get_count(SXLINE_TYPE_QLINE), TaglineCount);

	send_notice_to_user(s_OperServ, callerUser, "Services uptime: %s", convert_time(misc_buffer, MISC_BUFFER_SIZE, (NOW - start_time), LANG_DEFAULT));

	TRACE_MAIN();
	send_notice_to_user(s_OperServ, callerUser, "*** \2End of Stats\2 ***");
}

/*********************************************************/

static void do_mass_op_voice(CSTR source, User *callerUser, ServiceCommandData *data) {

	char	*chan_name;
	Channel *chan;


	TRACE_MAIN_FCLT(FACILITY_OPERSERV_HANDLE_MASS_OP_VOICE);

	if (IS_NULL(chan_name = strtok(NULL, " "))) {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2%s\2 #channel", data->commandName);
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP %s\2 for more information.", data->commandName);
	}
	else if (IS_NULL(chan = hash_channel_find(chan_name))) {

		send_notice_to_user(s_OperServ, callerUser, "Channel \2%s\2 does not exist.", chan_name);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "OS *MA %s -- by %s (%s@%s) [Non Existant]", chan_name, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "OS *MA %s -- by %s (%s@%s) through %s [Non Existant]", chan_name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else {

		char			modes[SERVER_MAX_MODES + 2]; // '+' + modi + '\0'
		char			nicks[((NICKMAX + 1) * SERVER_MAX_MODES) + 1];
		int				mode_count = 0;
		UserListItem	*item;
		char			mode = tolower(data->commandName[1]);
		size_t			nickLen = 0;


		TRACE_MAIN();

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "OS MA %s -- by %s (%s@%s) [%s]", chan_name, callerUser->nick, callerUser->username, callerUser->host, mode == 'o' ? "Op" : (mode == 'h' ? "HalfOp" : "Voice"));
			log_services(LOG_SERVICES_OPERSERV, "MA %s -- by %s (%s@%s) [%s]", chan_name, callerUser->nick, callerUser->username, callerUser->host, mode == 'o' ? "Op" : (mode == 'h' ? "HalfOp" : "Voice"));

			if (mode == 'o')
				send_cmd(lang_msg((chan->ci) ? EXTRACT_LANG_ID(chan->ci->langID) : LANG_DEFAULT, CS_VERBOSE_OPNOTICE_MASS_OP), s_OperServ, chan_name, source);
			else if (mode == 'h')
				send_cmd(lang_msg((chan->ci) ? EXTRACT_LANG_ID(chan->ci->langID) : LANG_DEFAULT, CS_VERBOSE_OPNOTICE_MASS_HALFOP), s_OperServ, chan_name, source);
			else if (mode == 'v')
				send_cmd(lang_msg((chan->ci) ? EXTRACT_LANG_ID(chan->ci->langID) : LANG_DEFAULT, CS_VERBOSE_OPNOTICE_MASS_VOICE), s_OperServ, chan_name, source);
		}
		else {

			LOG_SNOOP(s_OperServ, "OS MA %s -- by %s (%s@%s) through %s [%s]", chan_name, callerUser->nick, callerUser->username, callerUser->host, data->operName, mode == 'o' ? "Op" : (mode == 'h' ? "HalfOp" : "Voice"));
			log_services(LOG_SERVICES_OPERSERV, "MA %s -- by %s (%s@%s) through %s [%s]", chan_name, callerUser->nick, callerUser->username, callerUser->host, data->operName, mode == 'o' ? "Op" : (mode == 'h' ? "HalfOp" : "Voice"));

			if (mode == 'o')
				send_cmd(lang_msg((chan->ci) ? EXTRACT_LANG_ID(chan->ci->langID) : LANG_DEFAULT, CS_VERBOSE_OPNOTICE_MASS_OP_THROUGH), s_OperServ, chan_name, source, data->operName);
			else if (mode == 'h')
				send_cmd(lang_msg((chan->ci) ? EXTRACT_LANG_ID(chan->ci->langID) : LANG_DEFAULT, CS_VERBOSE_OPNOTICE_MASS_HALFOP_THROUGH), s_OperServ, chan_name, source, data->operName);
			else if (mode == 'v')
				send_cmd(lang_msg((chan->ci) ? EXTRACT_LANG_ID(chan->ci->langID) : LANG_DEFAULT, CS_VERBOSE_OPNOTICE_MASS_VOICE_THROUGH), s_OperServ, chan_name, source, data->operName);
		}

		memset(modes, 0, SERVER_MAX_MODES + 2);
		modes[0] = '+';

		TRACE_MAIN();

		item = chan->users;

		while (IS_NOT_NULL(item)) {

			if (((mode == 'o') && !user_is_chanop(item->user->nick, chan_name, chan)) ||
				((mode == 'h') && !user_is_chanhalfop(item->user->nick, chan_name, chan)) ||
				((mode == 'v') && !user_is_chanvoice(item->user->nick, chan_name, chan))) {

				TRACE_MAIN();
				++mode_count;
				modes[mode_count] = mode;

				if (nickLen > 0)
					*(nicks + nickLen++) = c_SPACE;

				nickLen += str_copy_checked(item->user->nick, (nicks + nickLen), (sizeof(nicks) - nickLen));

				if (mode == 'o')
					chan_add_op(chan, item->user);
				else if (mode == 'h')
					chan_add_halfop(chan, item->user);
				else
					chan_add_voice(chan, item->user);

				TRACE_MAIN();

				if (mode_count >= SERVER_MAX_MODES) {
					
					TRACE_MAIN();
					modes[mode_count+1] = '\0';
					send_cmd(":%s MODE %s %s %s", s_OperServ, chan_name, modes, nicks);

					mode_count = 0;
					memset(modes, 0, (SERVER_MAX_MODES + 2));

					TRACE_MAIN();
					modes[0] = '+';
					nickLen = 0;
				}
			}

			TRACE_MAIN();
			item = item->next;
		}

		if (mode_count > 0) { // utenti rimanenti...

			TRACE_MAIN();
			modes[mode_count+1] = '\0';
			send_cmd(":%s MODE %s %s %s", s_OperServ, chan_name, modes, nicks);
		}
	}
}

/*********************************************************/

static void do_find(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *mask_prm;


	TRACE_MAIN_FCLT(FACILITY_OPERSERV_HANDLE_FIND);

	if (IS_NULL(mask_prm = strtok(NULL, " "))) {
		
		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2FIND\2 mask");
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP FIND\2 for more information.");
	}
	else {

		char *mask = str_duplicate(mask_prm);
		char *user_nick = NULL, *user_username, *user_host, *user_xhost;
		char *nick, *username, *host;
		int count = 0;
		User *user;
		unsigned int idx;

		// - recupero parametri di ricerca

		TRACE_MAIN();

		str_tolower(mask);

		if (strchr(mask, '!')) {

			nick = strtok(mask, "!");
			username = strtok(NULL, "@");
		}
		else {

			nick = NULL;
			username = strtok(mask, "@");
		}

		TRACE_MAIN();

		host = strtok(NULL, " ");

		if (IS_NULL(username) || IS_NULL(host)) {

			send_notice_to_user(s_OperServ, callerUser, "Hostmask must be in [nick!]user@host format.");

			if (data->operMatch)
				LOG_SNOOP(s_OperServ, "OS *F %s -- by %s (%s@%s) [Invalid Mask]", mask_prm, callerUser->nick, callerUser->username, callerUser->host);
			else
				LOG_SNOOP(s_OperServ, "OS *F %s -- by %s (%s@%s) through %s [Invalid Mask]", mask_prm, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			mem_free(mask);
			return;
		}

		// - inizio ricerca

		TRACE_MAIN();

		if (nick) {

			send_notice_to_user(s_OperServ, callerUser, "Users matching \2%s!%s@%s\2:", nick, username, host);

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "OS F %s!%s@%s -- by %s (%s@%s)", nick, username, host, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "F %s!%s@%s -- by %s (%s@%s)", nick, username, host, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				LOG_SNOOP(s_OperServ, "OS F %s!%s@%s -- by %s (%s@%s) through %s", nick, username, host, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "F %s!%s@%s -- by %s (%s@%s) through %s", nick, username, host, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}

			user_nick = mem_malloc(NICKSIZE * sizeof(char));
		}
		else {

			send_notice_to_user(s_OperServ, callerUser, "Users matching \2%s@%s\2:", username, host);

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "OS F %s@%s -- by %s (%s@%s)", username, host, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "F %s@%s -- by %s (%s@%s)", username, host, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				LOG_SNOOP(s_OperServ, "OS F %s@%s -- by %s (%s@%s) through %s", username, host, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "F %s@%s -- by %s (%s@%s) through %s", username, host, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}
		}

		TRACE_MAIN();
		user_username = mem_malloc(USERSIZE * sizeof(char));
		user_host = mem_malloc(HOSTSIZE * sizeof(char));
		user_xhost = mem_malloc(HOSTSIZE * sizeof(char));

		TRACE_MAIN();

		HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

			user = hashtable_onlineuser[idx];

			while (IS_NOT_NULL(user)) {

				if (nick) {

					str_copy_checked(user->nick, user_nick, NICKSIZE);
					user_nick[str_len(user->nick)] = '\0';
					str_tolower(user_nick);
				}

				str_copy_checked(user->username, user_username, USERSIZE);
				user_username[str_len(user->username)] = '\0';

				str_copy_checked(user->host, user_host, HOSTSIZE);
				user_host[str_len(user->host)] = '\0';

				str_copy_checked(user->maskedHost, user_xhost, HOSTSIZE);
				user_xhost[str_len(user->maskedHost)] = '\0';

				str_tolower(user_username);
				str_tolower(user_host);
				str_tolower(user_xhost);

				TRACE_MAIN();

				if ((nick ? str_match_wild(nick, user_nick) : 1 ) && str_match_wild(username, user_username) &&
					(str_match_wild(host, user_host) || str_match_wild(host, user_xhost)) ) {

					++count;
					send_notice_to_user(s_OperServ, callerUser, "\2%d\2) \2%s\2 (%s@%s) [%s]", count, user->nick, user->username, user->host, user->server->name);
				}

				user = user->next;
			}
		}

		TRACE_MAIN();
		send_notice_to_user(s_OperServ, callerUser, "End of search. Users found: \2%d\2.", count);

		if (nick)
			mem_free(user_nick);

		mem_free(user_username);
		mem_free(user_host);
		mem_free(user_xhost);

		TRACE_MAIN();
		mem_free(mask);
	}
}

/*********************************************************/

static void do_kick_ban(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *chan_name, *nick, *reason;
	Channel *chan;
	User *user;
	BOOL isBan = (data->commandName[0] == 'B');


	TRACE_MAIN_FCLT(FACILITY_OPERSERV_HANDLE_KICK_BAN);

	if (IS_NULL(chan_name = strtok(NULL, " ")) || IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2%s\2 #channel nick [reason]", isBan ? "BAN" : "KICK");
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP %s\2 for more information.", isBan ? "BAN" : "KICK");
		return;
	}

	if (IS_NULL(chan = hash_channel_find(chan_name))) {

		send_notice_to_user(s_OperServ, callerUser, "Channel \2%s\2 does not exist.", chan_name);
		return;
	}

	if (IS_NULL(user = hash_onlineuser_find(nick))) {

		send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is not online.", nick);
		return;
	}

	if (!user_isin_chan(user, chan->name)) {

		send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is not on %s.", user->nick, chan->name);
		return;
	}

	if (user_is_services_agent(user)) {

		send_notice_to_user(s_OperServ, callerUser, "Cannot kick%s a services agent.", isBan ? "ban" : s_NULL);
		return;
	}

	TRACE_MAIN();
	if (IS_NULL(reason = strtok(NULL, "")))
		reason = "Banned";
	else if (str_len(reason) > 200)
		reason[200] = '\0';

	TRACE_MAIN();

	if (isBan) { // un bel ban ...

		char *mask;


		if (IS_NOT_NULL(mask = user_usermask_create(user, 2))) {

			TRACE_MAIN();

			/* If this ban is not already present and the banlist is not full, send it. */
			if (!chan_has_ban(chan, mask, NULL) && chan_add_ban(chan, mask))
				send_cmd(":%s MODE %s +b %s %lu", s_OperServ, chan_name, mask, NOW);

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "OS B %s %s -- by %s (%s@%s) [%s]", chan->name, nick, callerUser->nick, callerUser->username, callerUser->host, reason);
				log_services(LOG_SERVICES_OPERSERV, "B %s -- by %s (%s@%s) [%s]", chan->name, nick, callerUser->nick, callerUser->username, callerUser->host, reason);
			}
			else {

				LOG_SNOOP(s_OperServ, "OS B %s %s -- by %s (%s@%s) through %s [%s]", chan->name, nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, reason);
				log_services(LOG_SERVICES_OPERSERV, "B %s -- by %s (%s@%s) through %s [%s]", chan->name, nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, reason);
			}

			TRACE_MAIN();
			mem_free(mask);
		}
	}
	else {

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "OS K %s %s -- by %s (%s@%s) [%s]", chan->name, nick, callerUser->nick, callerUser->username, callerUser->host, reason);
			log_services(LOG_SERVICES_OPERSERV, "K %s %s -- by %s (%s@%s) [%s]", chan->name, nick, callerUser->nick, callerUser->username, callerUser->host, reason);
		}
		else {

			LOG_SNOOP(s_OperServ, "OS K %s %s -- by %s (%s@%s) through %s [%s]", chan->name, nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, reason);
			log_services(LOG_SERVICES_OPERSERV, "K %s %s -- by %s (%s@%s) through %s [%s]", chan->name, nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, reason);
		}
	}

	TRACE_MAIN();
	send_cmd(":%s KICK %s %s :%s", s_OperServ, chan_name, nick, reason);

	user_handle_services_kick(chan_name, user);
}

/*********************************************************/

static void do_global(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *target, *message;
	User *user;
	Server *server;
	int idx, count = 0;
	size_t len;


	TRACE_MAIN();

	if (IS_NULL(target = strtok(NULL, " ")) || IS_NULL(message = strtok(NULL, ""))) {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2GLOBAL\2 target message");
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP GLOBAL\2 for more information.");

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "OS *G -- by %s (%s@%s) [Target: %s]", callerUser->nick, callerUser->username, callerUser->host, target);
		else
			LOG_SNOOP(s_OperServ, "OS *G -- by %s (%s@%s) through %s [Target: %s]", callerUser->nick, callerUser->username, callerUser->host, data->operName, target);
	}
	else if ((len = str_len(target)) > MASKMAX) {

		if (data->operMatch)
			send_globops(s_OperServ, "\2%s\2 tried to send a Global Notice to \2%s\2", source, target);
		else
			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried to send a Global Notice to \2%s\2", source, data->operName, target);

		send_notice_to_user(s_OperServ, callerUser, "Bogus target supplied.");
	}
	else if (str_equals_nocase(target, "ALL")) {

		HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

			HASH_FOREACH_BRANCH_ITEM(onlineuser, idx, user) {

				if (!user_is_services_client(user)) {

					send_notice_to_user(s_GlobalNoticer, user, "\2Global Notice:\2 %s", message);
					++count;
				}
			}
		}

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 used the Global Notice Command [Target: \2ALL\2] [Users: \2%d\2]", source, count);

			LOG_SNOOP(s_OperServ, "OS G -- by %s (%s@%s) [Target: ALL] [Users: %d]", callerUser->nick, callerUser->username, callerUser->host, count);
			log_services(LOG_SERVICES_OPERSERV, "G -- by %s (%s@%s) [Target: ALL] [Users: %d] [Message: %s]", callerUser->nick, callerUser->username, callerUser->host, count, message);
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) used the Global Notice Command [Target: \2ALL\2] [Users: \2%d\2]", source, data->operName, count);

			LOG_SNOOP(s_OperServ, "OS G -- by %s (%s@%s) through %s [Target: ALL] [Users: %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, count);
			log_services(LOG_SERVICES_OPERSERV, "G -- by %s (%s@%s) through %s [Target: ALL] [Users: %d] [Message: %s]", callerUser->nick, callerUser->username, callerUser->host, data->operName, count, message);
		}
	}
	else if (IS_NOT_NULL(server = findserver(target))) {

		if (FlagUnset(server->flags, SERVER_FLAG_LINKED)) {

			send_notice_to_user(s_OperServ, callerUser, "Server \2%s\2 is offline.", server->name);
			return;
		}

		HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

			HASH_FOREACH_BRANCH_ITEM(onlineuser, idx, user) {

				if (!user_is_services_client(user) && str_equals_nocase(target, user->server->name)) {

					send_notice_to_user(s_GlobalNoticer, user, "\2Server Notice:\2 %s", message);
					++count;
				}
			}
		}

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 used the Global Notice Command [Target: server \2%s\2] [Users: \2%d\2]", source, target, count);

			LOG_SNOOP(s_OperServ, "OS G -- by %s (%s@%s) [Target: server %s] [Users: %d]", callerUser->nick, callerUser->username, callerUser->host, target, count);
			log_services(LOG_SERVICES_OPERSERV, "G -- by %s (%s@%s) [Target: server %s] [Users: %d] [Message: %s]", callerUser->nick, callerUser->username, callerUser->host, target, count, message);
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) used the Global Notice Command [Target: server \2%s\2] [Users: \2%d\2]", source, data->operName, target, count);

			LOG_SNOOP(s_OperServ, "OS G -- by %s (%s@%s) through %s [Target: server %s] [Users: %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, target, count);
			log_services(LOG_SERVICES_OPERSERV, "G -- by %s (%s@%s) through %s [Target: server %s] [Users: %d] [Message: %s]", callerUser->nick, callerUser->username, callerUser->host, data->operName, target, count, message);
		}
	}
	else if (len == 2) {

		LANG_ID lang_id;


		if ((lang_id = lang_lookup_langid(target)) == LANG_INVALID) {

			send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is not a valid language.", target);
			return;
		}

		HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

			HASH_FOREACH_BRANCH_ITEM(onlineuser, idx, user) {

				if (!user_is_services_client(user) && (user->current_lang == lang_id)) {

					send_notice_to_user(s_GlobalNoticer, user, "\2Global Notice:\2 %s", message);
					++count;
				}
			}
		}

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 used the Global Notice Command [Target: all \2%s\2 users] [Users: \2%d\2]", source, lang_get_shortname(lang_id), count);

			LOG_SNOOP(s_OperServ, "OS G -- by %s (%s@%s) [Target: all %s users] [Users: %d]", callerUser->nick, callerUser->username, callerUser->host, lang_get_shortname(lang_id), count);
			log_services(LOG_SERVICES_OPERSERV, "G -- by %s (%s@%s) [Target: all %s users] [Users: %d] [Message: %s]", callerUser->nick, callerUser->username, callerUser->host, lang_get_shortname(lang_id), count, message);
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) used the Global Notice Command [Target: all \2%s\2 users] [Users: \2%d\2]", source, data->operName, lang_get_shortname(lang_id), count);

			LOG_SNOOP(s_OperServ, "OS G -- by %s (%s@%s) through %s [Target: all %s users] [Users: %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, lang_get_shortname(lang_id), count);
			log_services(LOG_SERVICES_OPERSERV, "G -- by %s (%s@%s) through %s [Target: all %s users] [Users: %d] [Message: %s]", callerUser->nick, callerUser->username, callerUser->host, data->operName, lang_get_shortname(lang_id), count, message);
		}
	}
	else {

		if (!validate_mask(target, TRUE, FALSE, FALSE)) {

			send_notice_to_user(s_OperServ, callerUser, "Mask must be in [nick!]user@host format.");
			return;
		}

		HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

			HASH_FOREACH_BRANCH_ITEM(onlineuser, idx, user) {

				if (!user_is_services_client(user) && user_usermask_match(target, user, FALSE, FALSE)) {

					send_notice_to_user(s_GlobalNoticer, user, "\2Global Notice:\2 %s", message);
					++count;
				}
			}
		}

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 used the Global Notice Command [Target: \2%s\2] [Users: \2%d\2]", source, target, count);

			LOG_SNOOP(s_OperServ, "OS G -- by %s (%s@%s) [Target: %s] [Users: %d]", callerUser->nick, callerUser->username, callerUser->host, target, count);
			log_services(LOG_SERVICES_OPERSERV, "G -- by %s (%s@%s) [Target: %s] [Users: %d] [Message: %s]", callerUser->nick, callerUser->username, callerUser->host, target, count, message);
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) used the Global Notice Command [Target: \2%s\2] [Users: \2%d\2]", source, data->operName, target, count);

			LOG_SNOOP(s_OperServ, "OS G -- by %s (%s@%s) through %s [Target: %s] [Users: %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, target, count);
			log_services(LOG_SERVICES_OPERSERV, "G -- by %s (%s@%s) through %s [Target: %s] [Users: %d] [Message: %s]", callerUser->nick, callerUser->username, callerUser->host, data->operName, target, count, message);
		}
	}
}

/*********************************************************/

static void do_masskill(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *target, *reason;
	User *user, *next;
	unsigned int idx;


	TRACE_MAIN_FCLT(FACILITY_OPERSERV_HANDLE_MASSKILL);

	if (IS_NULL(target = strtok(NULL, " ")) || IS_NULL(reason = strtok(NULL, ""))) {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2MKILL\2 <nick|host> [reason]");
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP MKILL\2 for more information.");
	}
	else if (!strchr(target, '.') && !strchr(target, '?') && !strchr(target, '*')) {

		// nick
		User *targetUser;
		char *mask, defreason[16];
		int count = 0, size = 0;

		if (IS_NULL(targetUser = hash_onlineuser_find(target))) {

			send_notice_to_user(s_OperServ, callerUser, "User %s is offline.", target);
			return;
		}

		if (user_is_services_client(targetUser) || str_match_wild_nocase("*azzurra.org", targetUser->host)) {

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 tried to masskill services client \2%s\2", source, targetUser->nick);

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) [Lamer]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) [Lamer]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried to masskill services client \2%s\2", source, data->operName, targetUser->nick);

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) through %s [Lamer]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) through %s [Lamer]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}

			send_notice_to_user(s_OperServ, callerUser, "You cannot masskill services!");
			return;
		}

		if (user_is_services_agent(targetUser)) {

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 tried to masskill services agent \2%s\2", source, targetUser->nick);

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) [Lamer]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) [Lamer]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried to masskill services agent \2%s\2", source, data->operName, targetUser->nick);

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) through %s [Lamer]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) through %s [Lamer]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}

			send_notice_to_user(s_OperServ, callerUser, "You cannot masskill a service agent!");
			return;
		}

		if (user_is_ircop(targetUser)) {

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 tried to masskill operator \2%s\2", source, targetUser->nick);

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) [Oper]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) [Oper]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried to masskill operator \2%s\2", source, data->operName, targetUser->nick);

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) through %s [Oper]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) through %s [Oper]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}

			send_notice_to_user(s_OperServ, callerUser, "You cannot masskill an IRC Operator!");
			return;
		}

		if (is_services_valid_oper(targetUser)) {

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 tried to masskill services operator \2%s\2", source, targetUser->nick);

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) [Services Oper]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) [Services Oper]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried to masskill services operator \2%s\2", source, data->operName, targetUser->nick);

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) through %s [Services Oper]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) through %s [Services Oper]", targetUser->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}

			send_notice_to_user(s_OperServ, callerUser, "You cannot masskill a Services Operator!");
			return;
		}

		size = (str_len(targetUser->host) + 5);
		mask = mem_malloc(size);
		snprintf(mask, size, "*!*@%s", targetUser->host);

		HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

			HASH_FOREACH_BRANCH_ITEM_SAFE(onlineuser, idx, user, next) {

				if (user_usermask_match(mask, user, TRUE, TRUE)) {

					if (!user_is_services_agent(user) && !user_is_ircop(user)) {

						++count;
						if (IS_NULL(reason)) {

							snprintf(defreason, sizeof(defreason), "Cloning [%d]", count);
							send_KILL(NULL, user->nick, defreason, TRUE);
						}
						else
							send_KILL(NULL, user->nick, reason, TRUE);
					}
				}
			}
		}

		if (count == 0) {

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) [No Match]", mask, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) [No Match]", mask, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) through %s [No Match]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) through %s [No Match]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}

			send_notice_to_user(s_OperServ, callerUser, "No users matching \2%s\2 found.", mask);
			return;
		}
		TRACE_MAIN();

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 killed all users (\2%d\2) matching \2%s\2 [Reason: %s]", source, count, mask, reason ? reason : "Cloning");
			LOG_SNOOP(s_OperServ, "OS Mk %s -- by %s (%s@%s) [Users: %d, Reason: %s]", mask, callerUser->nick, callerUser->username, callerUser->host, count, reason ? reason : "Cloning");
			log_services(LOG_SERVICES_OPERSERV, "Mk %s -- by %s (%s@%s) [Users: %d, Reason: %s]", mask, callerUser->nick, callerUser->username, callerUser->host, count, reason ? reason : "Cloning");
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) killed all users (\2%d\2) matching \2%s\2 [Reason: %s]", source, data->operName, count, mask, reason ? reason : "Cloning");
			LOG_SNOOP(s_OperServ, "OS Mk %s -- by %s (%s@%s) through %s [Users: %d, Reason: %s]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName, count, reason ? reason : "Cloning");
			log_services(LOG_SERVICES_OPERSERV, "Mk %s -- by %s (%s@%s) through %s [Users: %d, Reason: %s]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName, count, reason ? reason : "Cloning");
		}

		send_notice_to_user(s_OperServ, callerUser, "Killed \2%d\2 user%s matching \2%s\2", count, count == 1 ? "" : "s", mask);
		mem_free(mask);
	}
	else {

		char defreason[16];
		int i, count = 0, x = 0, check = 0, valid = 0;
		float percent;
		User *matches[512];
		unsigned char c;
		char *ptr;

		TRACE_MAIN();

		if (!validate_mask(target, TRUE, FALSE, FALSE)) {

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) [Invalid Mask]", target, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) [Invalid Mask]", target, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) through %s [Invalid Mask]", target, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) through %s [Invalid Mask]", target, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}

			send_notice_to_user(s_OperServ, callerUser, "Invalid mask.");
			return;
		}

		ptr = target;

		while (*ptr) {

			c = *(ptr++);

			if (!strchr("*.?!@", c))
				++valid;
		}

		if (valid < 4) {

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 tried to masskill \2%s\2", source, target);

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) [Lamer]", target, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) [Lamer]", target, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried to masskill \2%s\2", source, data->operName, target);

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) through %s [Lamer]", target, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) through %s [Lamer]", target, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}

			send_notice_to_user(s_OperServ, callerUser, "Hrmmm, target would your admin think of that?");
			return;
		}

		for (i = 0; i < 512; ++i)
			matches[i] = NULL;

		HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

			HASH_FOREACH_BRANCH_ITEM_SAFE(onlineuser, idx, user, next) {

				if (user_usermask_match(target, user, TRUE, TRUE)) {

					matches[x] = user;

					if (user_is_services_client(user) || user_is_services_agent(user) ||
						user_is_ircop(user) || str_match_wild_nocase("*azzurra.org", user->host)) {

						check = 1;
						break;
					}

					++x;
				}
			}

			if (check == 1)
				break;
		}

		if (check == 1) {

			user = matches[x];

			if (IS_NULL(user)) {

				LOG_DEBUG_SNOOP("MK: No user!");
				return;
			}

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 tried to masskill \2%s\2", source, user->nick);

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) [Matches %s]", target, callerUser->nick, callerUser->username, callerUser->host, user->nick);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) [Matches %s]", target, callerUser->nick, callerUser->username, callerUser->host, user->nick);
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried to masskill \2%s\2", source, data->operName, user->nick);

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) through %s [Matches %s]", target, callerUser->nick, callerUser->username, callerUser->host, data->operName, user->nick);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) through %s [Matches %s]", target, callerUser->nick, callerUser->username, callerUser->host, data->operName, user->nick);
			}

			send_notice_to_user(s_OperServ, callerUser, "That host belongs to \2%s\2!", user->nick);
			return;
		}

		if (x == 0) {

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) [No Match]", target, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) [No Match]", target, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) through %s [No Match]", target, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) through %s [No Match]", target, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}

			send_notice_to_user(s_OperServ, callerUser, "No users matching \2%s\2 found.", target);
			return;
		}

		percent = ((x + .0) * 100.0) / user_online_user_count;

		if (percent > CONF_AKILL_PERCENT) {

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 tried to masskill \2%.3f%s\2 of the network! (Limit: %.3f%s)", source, percent, "%", CONF_AKILL_PERCENT, "%");

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) [%.3f%s > %.3f%s]", target, callerUser->nick, callerUser->username, callerUser->host, percent, "%", CONF_AKILL_PERCENT, "%");
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) [%.3f%s > %.3f%s]", target, callerUser->nick, callerUser->username, callerUser->host, percent, "%", CONF_AKILL_PERCENT, "%");
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried to masskill \2%.3f%s\2 of the network! (Limit: %.3f%s)", source, data->operName, percent, "%", CONF_AKILL_PERCENT, "%");

				LOG_SNOOP(s_OperServ, "OS *Mk %s -- by %s (%s@%s) through %s [%.3f%s > %.3f%s]", target, callerUser->nick, callerUser->username, callerUser->host, data->operName, percent, "%", CONF_AKILL_PERCENT, "%");
				log_services(LOG_SERVICES_OPERSERV, "*Mk %s -- by %s (%s@%s) through %s [%.3f%s > %.3f%s]", target, callerUser->nick, callerUser->username, callerUser->host, data->operName, percent, "%", CONF_AKILL_PERCENT, "%");
			}

			send_notice_to_user(s_OperServ, callerUser, "Masskill rejected. Affected users would be greater than %.3f%s", CONF_AKILL_PERCENT, "%");
			return;
		}

		for (i = 0; i < x && matches[i]; ++i) {

			TRACE_MAIN();

			user = matches[i];

			if (IS_NULL(user))
				continue;

			++count;

			if (IS_NULL(reason)) {

				snprintf(defreason, sizeof(defreason), "Cloning [%d]", count);
				send_KILL(NULL, user->nick, defreason, TRUE);
			}
			else
				send_KILL(NULL, user->nick, reason, TRUE);
		}

		TRACE_MAIN();

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 killed all users (\2%d\2) matching \2%s\2 [Reason: %s]", source, count, target, reason ? reason : "Cloning");
			LOG_SNOOP(s_OperServ, "OS Mk %s -- by %s (%s@%s) [Users: %d, Reason: %s]", target, callerUser->nick, callerUser->username, callerUser->host, count, reason ? reason : "Cloning");
			log_services(LOG_SERVICES_OPERSERV, "Mk %s -- by %s (%s@%s) [Users: %d, Reason: %s]", target, callerUser->nick, callerUser->username, callerUser->host, count, reason ? reason : "Cloning");
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) killed all users (\2%d\2) matching \2%s\2 [Reason: %s]", source, data->operName, count, target, reason ? reason : "Cloning");
			LOG_SNOOP(s_OperServ, "OS Mk %s -- by %s (%s@%s) through %s [Users: %d, Reason: %s]", target, callerUser->nick, callerUser->username, callerUser->host, data->operName, count, reason ? reason : "Cloning");
			log_services(LOG_SERVICES_OPERSERV, "Mk %s -- by %s (%s@%s) through %s [Users: %d, Reason: %s]", target, callerUser->nick, callerUser->username, callerUser->host, data->operName, count, reason ? reason : "Cloning");
		}

		send_notice_to_user(s_OperServ, callerUser, "Killed \2%d\2 user%s matching \2%s\2", count, count == 1 ? "" : "s", target);
	}
}

/*********************************************************/

void operserv_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	char	*command;
	BOOL	needSyntax = FALSE;


	if (IS_NULL(command = strtok(request, s_SPACE)))
		needSyntax = TRUE;

	else if (str_equals_nocase(command, "WARNINGS")) {

		unsigned long int idx;

		send_notice_to_user(sourceNick, callerUser, "DUMP: Clone Warnings List");

		for (idx = 0; idx < CLONE_DETECT_SIZE; ++idx) {

			send_notice_to_user(sourceNick, callerUser, "%d) Address 0x%08X, size %d B",		idx + 1, (unsigned long)idx, sizeof(CloneWarning));
			send_notice_to_user(sourceNick, callerUser, "Host: 0x%08X \2[\2%s\2]\2",			(unsigned long)warnings[idx].host, str_get_valid_display_value(warnings[idx].host));
			send_notice_to_user(sourceNick, callerUser, "IP: %lu \2[\2%s\2]\2",					warnings[idx].ip, get_ip(warnings[idx].ip));
			send_notice_to_user(sourceNick, callerUser, "Time Set C-time: %d",					warnings[idx].timeAdded);
			send_notice_to_user(sourceNick, callerUser, "Clone count: %d",						warnings[idx].cloneCount);
			send_notice_to_user(sourceNick, callerUser, "Flags: %d",							warnings[idx].flags);
		}

		LOG_DEBUG_SNOOP("Command: DUMP WARNINGS -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
	}
	else
		needSyntax = TRUE;

	if (needSyntax) {

		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 OPERSERV list [start [end]] [pattern]");
		send_notice_to_user(sourceNick, callerUser, "Available lists: WARNINGS");
	}
}

/*********************************************************/

unsigned long int operserv_mem_report(CSTR sourceNick, const User *callerUser) {

	unsigned long int	mem = 0;
	int					warningIdx;


	TRACE_FCLT(FACILITY_OPERSERV_MEM_REPORT);

	send_notice_to_user(sourceNick, callerUser, "\2%s\2:", s_OperServ);


	/* Clone warnings list */
	mem += (sizeof(CloneWarning) * (CLONE_DETECT_SIZE + 1));

	for (warningIdx = 0; warningIdx <= CLONE_DETECT_SIZE; ++warningIdx) {

		if (IS_NOT_NULL(warnings[warningIdx].host))
			mem += str_len(warnings[warningIdx].host) + 1;
	}

	send_notice_to_user(sourceNick, callerUser, "Clone warnings list: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", CLONE_DETECT_SIZE, mem / 1024, mem);
	return mem;
}

#endif /* USE_SERVICES */
