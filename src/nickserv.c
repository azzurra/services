/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* nickserv.c - NickServ service
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
#include "../inc/lang.h"
#include "../inc/conf.h"
#include "../inc/main.h"
#include "../inc/misc.h"
#include "../inc/cidr.h"
#include "../inc/datafiles.h"
#include "../inc/timeout.h"
#include "../inc/memoserv.h"
#include "../inc/rootserv.h"
#include "../inc/helpserv.h"
#include "../inc/nickserv.h"
#include "../inc/reserved.h"
#include "../inc/blacklist.h"


/*********************************************************
 * Global variables                                      *
 *********************************************************/

#ifdef	FIX_USE_MPOOL
MemoryPool			*nickdb_mempool;
#endif

unsigned long int ns_regCount;


/*********************************************************
 * Local variables                                       *
 *********************************************************/

static NickInfo *nicklists[256]; /* One for each initial character */

/* Stuff to pass to the command handler. */
static Agent a_NickServ;


/*********************************************************
 * Timeouts and collide stuff                            *
 *********************************************************/

/* For local timeout use: */

#define TO_COLLIDE_STEP_40		1
#define TO_COLLIDE_STEP_20		2
#define TO_COLLIDE_STEP_COLLIDE	3

// GuestXXXX anti-collide

unsigned char	*nickserv_used_guest_list = NULL;

static void timeout_start_collide(NickInfo *ni, int type);
static void timeout_collide_countdown(Timeout *t);
static void timeout_release(Timeout *to);

static void collide(NickInfo *ni, BOOL from_timeout);
static void release(NickInfo *ni, BOOL from_timeout);

static void nickserv_create_enforcer(NickInfo *ni);

static void database_insert_nick(NickInfo *ni);
static void delnick(NickInfo *ni);
static char *get_nick_flags(long flags);

/* Handlers */

static void do_acc(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_access(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_auth(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_drop(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_ghost(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_identify(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_info(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_recover(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_register(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_release(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_listchans(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_isonaccess(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_show_umode(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_authnick(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_authreset(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_delete(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_forbid(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_freeze(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_getpass(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_hold(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_listreg(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_mark(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_nickset(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_sendcode(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_sendpass(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_unforbid(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_unfreeze(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_unhold(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_unmark(CSTR source, User *callerUser, ServiceCommandData *data);

static void do_set(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_set_email(const User *callerUser, CSTR param, BOOL hasmail);
static void do_set_kill(const User *callerUser, CSTR param);
static void do_set_lang(User *callerUser, CSTR param, short status);
static void do_set_option(const User *callerUser, CSTR option, CSTR param);
static void do_set_password(User *callerUser, CSTR param);
static void do_set_url(const User *callerUser, CSTR param);

/*********************************************************/

void nickserv_init(void) {

	if (IS_NULL(nickserv_used_guest_list))
		nickserv_used_guest_list = mem_calloc(99999 - 10000 + 1, sizeof(unsigned char));

	#ifdef FIX_USE_MPOOL
	nickdb_mempool = mempool_create(MEMPOOL_ID_NICKDB, sizeof(NickInfo), MP_IPB_NICKDB, MB_IBC_NICKDB);
	#endif

	/* Initialize this struct. */
	a_NickServ.nick = s_NickServ;
	a_NickServ.shortNick = s_NS;
	a_NickServ.agentID = AGENTID_NICKSERV;
	a_NickServ.logID = logid_from_agentid(AGENTID_NICKSERV);
}

void nickserv_terminate(void) {

	#ifdef FIX_USE_MPOOL
	mempool_destroy(nickdb_mempool);
	nickdb_mempool = NULL;
	#endif
}

/*********************************************************/

// 'A' (65 / 0)
static ServiceCommand	nickserv_commands_A[] = {
	{ "ACC",		ULEVEL_USER,			0, do_acc },
	{ "AUTH",		ULEVEL_USER,			0, do_auth },
	{ "ACCESS",		ULEVEL_USER,			0, do_access },
	{ "AUTHNICK",	ULEVEL_HOP,				0, do_authnick },
	{ "AUTHRESET",	ULEVEL_HOP,				0, do_authreset },
	{ NULL,			0,						0, NULL }
};
// 'B' (66 / 1)
// 'C' (67 / 2)
// 'D' (68 / 3)
static ServiceCommand	nickserv_commands_D[] = {
	{ "DROP",		ULEVEL_USER,			0, do_drop },
	{ "DELETE",		ULEVEL_SRA,				0, do_delete },
	{ NULL,			0,						0, NULL }
};
// 'E' (69 / 4)
// 'F' (70 / 5)
static ServiceCommand	nickserv_commands_F[] = {
	{ "FREEZE",		ULEVEL_SOP,				0, do_freeze },
	{ "FORBID",		ULEVEL_SA,				0, do_forbid },
	{ NULL,			0,						0, NULL }
};
// 'G' (71 / 6)
static ServiceCommand	nickserv_commands_G[] = {
	{ "GHOST",		ULEVEL_USER,			0, do_ghost },
	{ "GETPASS",	ULEVEL_SA,				0, do_getpass },
	{ NULL,			0,						0, NULL }
};
// 'H' (72 / 7)
static ServiceCommand	nickserv_commands_H[] = {
	{ "HELP",		ULEVEL_USER,			0, handle_help },
	{ "HHELP",		ULEVEL_HOP,				0, handle_help },
	{ "HOLD",		ULEVEL_SA,				0, do_hold },
	{ NULL,			0,						0, NULL }
};
// 'I' (73 / 8)
static ServiceCommand	nickserv_commands_I[] = {
	{ "IDENTIFY",	ULEVEL_USER,			0, do_identify },
	{ "INFO",		ULEVEL_USER,			0, do_info },
	{ "ID",			ULEVEL_USER,			0, do_identify },
	{ "IDENT",		ULEVEL_USER,			0, do_identify },
	{ "ISONACCESS",	ULEVEL_HOP,				0, do_isonaccess },
	{ NULL,			0,						0, NULL }
};
// 'J' (74 / 9)
// 'K' (75 / 10)
// 'L' (76 / 11)
static ServiceCommand	nickserv_commands_L[] = {
	{ "LISTCHANS",	ULEVEL_USER,			0, do_listchans },
	{ "LISTREG",	ULEVEL_SOP,				0, do_listreg },
	{ NULL,			0,						0, NULL }
};
// 'M' (77 / 12)
static ServiceCommand	nickserv_commands_M[] = {
	{ "MARK",		ULEVEL_SRA,				0, do_mark },
	{ NULL,			0,						0, NULL }
};
// 'N' (78 / 13)
static ServiceCommand	nickserv_commands_N[] = {
	{ "NICKSET",	ULEVEL_SRA,				0, do_nickset },
	{ NULL,			0,						0, NULL }
};
// 'O' (79 / 14)
static ServiceCommand	nickserv_commands_O[] = {
	{ "OHELP",		ULEVEL_OPER,			0, handle_help },
	{ NULL,			0,						0, NULL }
};
// 'P' (80 / 15)
static ServiceCommand	nickserv_commands_P[] = {
	{ "PASS",		ULEVEL_USER,			0, do_identify },
	{ NULL,			0,						0, NULL }
};
// 'Q' (81 / 16)
// 'R' (82 / 17)
static ServiceCommand	nickserv_commands_R[] = {
	{ "REGISTER",	ULEVEL_USER,			0, do_register },
	{ "RECOVER",	ULEVEL_USER,			0, do_recover },
	{ "RELEASE",	ULEVEL_USER,			0, do_release },
	{ NULL,			0,						0, NULL }
};
// 'S' (83 / 18)
static ServiceCommand	nickserv_commands_S[] = {
	{ "SIDENTIFY",	ULEVEL_USER,			0, do_identify },
	{ "SET",		ULEVEL_USER,			0, do_set },
	{ "SENDCODE",	ULEVEL_HOP,				0, do_sendcode },
	{ "SENDPASS",	ULEVEL_HOP,				0, do_sendpass },
	{ NULL,			0,						0, NULL }
};
// 'T' (84 / 19)
// 'U' (85 / 20)
static ServiceCommand	nickserv_commands_U[] = {
	{ "UNFREEZE",	ULEVEL_SOP,				0, do_unfreeze },
	{ "UNFORBID",	ULEVEL_SA,				0, do_unforbid },
	{ "UNMARK",		ULEVEL_SRA,				0, do_unmark },
	{ "UNHOLD",		ULEVEL_SA,				0, do_unhold },
	{ "UMODE",		ULEVEL_HOP,				0, do_show_umode },
	{ NULL,			0,						0, NULL }
};
// 'V' (86 / 21)
// 'W' (87 / 22)
// 'X' (88 / 23)
// 'Y' (89 / 24)
// 'Z' (90 / 25)

ServiceCommand	*nickserv_commands[26] = {
	nickserv_commands_A,	NULL,
	NULL,					nickserv_commands_D,
	NULL,					nickserv_commands_F,
	nickserv_commands_G,	nickserv_commands_H,
	nickserv_commands_I,	NULL,
	NULL,					nickserv_commands_L,
	nickserv_commands_M,	nickserv_commands_N,
	nickserv_commands_O,	nickserv_commands_P,
	NULL,					nickserv_commands_R,
	nickserv_commands_S,	NULL,
	nickserv_commands_U,	NULL,
	NULL,					NULL,
	NULL,					NULL
};


/* Main NickServ routine. */

void nickserv(CSTR source, User *callerUser, char *buf) {

	char *cmd = strtok(buf, " ");


	TRACE_MAIN_FCLT(FACILITY_NICKSERV);

	if (IS_NULL(cmd))
		log_error(FACILITY_NICKSERV, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, "%s: Main routine called with no command by %s", s_NickServ, source);

	else if (cmd[0] == '\001') {

		++cmd;

		if (IS_EMPTY_STR(cmd))
			LOG_SNOOP(s_NickServ, "Invalid CTCP from \2%s\2", source);

		else if (str_equals_nocase(cmd, "PING")) {

			send_notice_to_user(s_NickServ, callerUser, "\001PING\001");
			LOG_SNOOP(s_NickServ, "CTCP: PING from \2%s\2", source);
		}
		else {

			char *action = strtok(NULL, "");

			if (action) {

				action[str_len(action) - 1] = '\0';
				LOG_SNOOP(s_NickServ, "CTCP: %s %s from \2%s\2", cmd, action, source);
			}
			else {

				cmd[str_len(cmd) - 1] = '\0';
				LOG_SNOOP(s_NickServ, "CTCP: %s from \2%s\2", cmd, source);
			}
		}
	}
	else
		oper_invoke_agent_command(cmd, nickserv_commands, callerUser, &a_NickServ);
}

/*********************************************************/

/* Load/save data files. */
void load_ns_dbase(void) {

	FILE		*f;
	int			ver, i = 0, j;
	NickInfo	*ni;


	TRACE_FCLT(FACILITY_NICKSERV_LOAD_NS_DB);

	if (IS_NULL(f = open_db_read(s_NickServ, NICKSERV_DB)))
		return;

	for (i = 0; i < 256; ++i)
		nicklists[i] = NULL;

	ns_regCount = 0;

	TRACE();
	switch (ver = get_file_version(f, NICKSERV_DB)) {

		case NICKSERV_DB_CURRENT_VERSION:

			for (i = 65; i < 126; ++i) {

				while (fgetc(f) == 1) {

					#ifdef FIX_PASSWORD_SPACE
					char	*space;
					#endif
				
					TRACE();
					
					#ifdef	FIX_USE_MPOOL
					ni = mempool_alloc(NickInfo*, nickdb_mempool, FALSE);
					#else
					ni = mem_malloc(sizeof(NickInfo));
					#endif

					if (fread(ni, sizeof(NickInfo), 1, f) != 1)
						fatal_error(FACILITY_NICKSERV_LOAD_NS_DB, __LINE__, "Read error on %s", NICKSERV_DB);

					TRACE();
					// crashfix
					if (ni->langID == LANG_DE)
						ni->langID = LANG_ES;


					RemoveFlag(ni->flags, NI_TIMEOUT | NI_ENFORCE | NI_ENFORCED);

					#ifdef FIX_FLAGS
					RemoveFlag(ni->flags, NI_EMAILMEMOS);
					RemoveFlag(ni->flags, NI_REMIND);
					RemoveFlag(ni->flags, NI_IDENTIFIED);
					#endif

					#ifdef FIX_DROP_REQUEST
					RemoveFlag(ni->flags, NI_DROP);

					ni->last_drop_request = 0;

					if (FlagUnset(ni->flags, NI_AUTH) && FlagUnset(ni->flags, NI_MAILCHANGE))
						ni->auth = 0;
					#endif

					database_insert_nick(ni);

					#ifdef FIX_PASSWORD_SPACE
					space = ni->pass;

					while (IS_NOT_NULL(space = strchr(space, ' '))) {
						*space = '_';
						++space;
					}
					#endif

					++ns_regCount;

					if (ni->url)
						ni->url = read_string(f, NICKSERV_DB);
					if (ni->email)
						ni->email = read_string(f, NICKSERV_DB);
					if (ni->forward)
						ni->forward = read_string(f, NICKSERV_DB);
					if (ni->hold)
						ni->hold = read_string(f, NICKSERV_DB);
					if (ni->mark)
						ni->mark = read_string(f, NICKSERV_DB);
					if (ni->forbid)
						ni->forbid = read_string(f, NICKSERV_DB);
					if (ni->freeze)
						ni->freeze = read_string(f, NICKSERV_DB);
					if (ni->regemail)
						ni->regemail = read_string(f, NICKSERV_DB);				

					#ifdef FIX_NS_REGMAIL_DB

					if (ni->regemail) {

						RemoveFlag(ni->flags, NI_AUTH);
						ni->auth = 0;

						if (ni->email)
							mem_free(ni->email);
						ni->email = str_duplicate(ni->regemail);

						mem_free(ni->regemail);
						ni->regemail = NULL;

						AddFlag(ni->flags, NI_HIDE_EMAIL);
					}
					else if (ni->email) {

						ni->regemail = NULL;
						RemoveFlag(ni->flags, NI_AUTH);
						ni->auth = 0;
						AddFlag(ni->flags, NI_HIDE_EMAIL);
					}
					else
						AddFlag(ni->flags, NI_AUTH);

					ni->last_email_request = 0;
					ni->last_drop_request = 0;

					#endif

					TRACE();
					ni->last_usermask = read_string(f, NICKSERV_DB);
					ni->last_realname = read_string(f, NICKSERV_DB);

					if (ni->accesscount) {

						char **anAccess;

						TRACE();
						anAccess = mem_malloc(sizeof(char *) * ni->accesscount);
						ni->access = anAccess;

						for (j = 0; j < ni->accesscount; ++j, ++anAccess)
							*anAccess = read_string(f, NICKSERV_DB);
					}

					#ifdef FIX_NICKNAME_ACCESS_COUNT
					ni->channelcount = 0;
					#endif
				}
			}
			break;

		default:
			fatal_error(FACILITY_NICKSERV_LOAD_NS_DB, __LINE__, "Unsupported version number (%d) on %s", ver, NICKSERV_DB);
	}

	TRACE();
	close_db(f, NICKSERV_DB);
}

/*********************************************************/

void save_ns_dbase(void) {

	FILE		*f;
	int			i, j;
	NickInfo	*ni;
	char		**anAccess;


	TRACE_FCLT(FACILITY_NICKSERV_SAVE_NS_DB);

	if (IS_NULL(f = open_db_write(s_NickServ, NICKSERV_DB, NICKSERV_DB_CURRENT_VERSION)))
		return;

	TRACE();

	for (i = 65; i < 126; ++i) {

		for (ni = nicklists[i]; ni; ni = ni->next) {

			TRACE();
			fputc(1, f);

			if (fwrite(ni, sizeof(NickInfo), 1, f) != 1)
				fatal_error(FACILITY_NICKSERV_LOAD_NS_DB, __LINE__, "Write error on %s", NICKSERV_DB);

			TRACE();
			if (ni->url)
				write_string(ni->url, f, NICKSERV_DB);
			if (ni->email)
				write_string(ni->email, f, NICKSERV_DB);
			if (ni->forward)
				write_string(ni->forward, f, NICKSERV_DB);
			if (ni->hold)
				write_string(ni->hold, f, NICKSERV_DB);
			if (ni->mark)
				write_string(ni->mark, f, NICKSERV_DB);
			if (ni->forbid)
				write_string(ni->forbid, f, NICKSERV_DB);
			if (ni->freeze)
				write_string(ni->freeze, f, NICKSERV_DB);
			if (ni->regemail)
				write_string(ni->regemail, f, NICKSERV_DB);
			
			write_string(ni->last_usermask ? ni->last_usermask : "", f, NICKSERV_DB);
			write_string(ni->last_realname ? ni->last_realname : "", f, NICKSERV_DB);

			for (anAccess = ni->access, j = 0; j < ni->accesscount; ++anAccess, ++j)
				write_string(*anAccess, f, NICKSERV_DB);

		}
		TRACE();
		fputc(0, f);
	}
	TRACE();

	close_db(f, NICKSERV_DB);

}

/*********************************************************/

/* Remove all nicks which have expired. */
void expire_nicks() {

	NickInfo *ni, *next;
	int i;
	const time_t expire_limit = (NOW - (CONF_NICK_EXPIRE * ONE_DAY));
	const time_t expire_mail = (NOW - (CONF_AUTHDEL_DAYS * ONE_DAY));
	long count = 0, rcount = 0, xcount = 0;


	TRACE_FCLT(FACILITY_NICKSERV_EXPIRE_NICKS);

	if (CONF_SET_NOEXPIRE)
		return;

	for (i = 65; i < 126; ++i) {

		for (ni = nicklists[i]; ni; ni = next) {
			
			TRACE();
			next = ni->next;
			++count;

			if (FlagSet(ni->flags, NI_FORBIDDEN) || FlagSet(ni->flags, NI_FROZEN) || FlagSet(ni->flags, NI_HOLD))
				continue;

			if (ni->last_seen < expire_limit) {

				TRACE();
				++xcount;
				LOG_SNOOP(s_OperServ, "NS X %s", ni->nick);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "X %s", ni->nick);

				LOG_DEBUG("Expiring nickname %s", ni->nick);
				delnick(ni);
			}
			else if ((CONF_AUTHDEL_DAYS > 0) && FlagSet(ni->flags, NI_AUTH) && (ni->auth != 0)
				&& (ni->time_registered < expire_mail)) {

				TRACE();
				++xcount;
				LOG_SNOOP(s_OperServ, "NS X %s [AUTH]", ni->nick);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "X %s [AUTH]", ni->nick);

				LOG_DEBUG("Expiring nickname %s [AUTH]", ni->nick);
				delnick(ni);
			}
			else if ((CONF_SEND_REMINDER > 0) && CONF_USE_EMAIL && IS_NOT_NULL(ni->email) &&
				FlagUnset(ni->flags, NI_REMIND) && (expire_limit >= (ni->last_seen - (ONE_DAY * CONF_SEND_REMINDER)))) {

				FILE *mailfile;

				TRACE();

				AddFlag(ni->flags, NI_REMIND);
				LOG_SNOOP(s_OperServ, "NS X+ %s", ni->nick);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "X+ %s", ni->nick);
				++rcount;

				if (IS_NOT_NULL(mailfile = fopen("nsremind.txt", "w"))) {

					char timebuf[64];

					lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_MAILTIME, NOW);

					fprintf(mailfile, "Date: %s\n", timebuf);
					fprintf(mailfile, "From: %s <%s>\n", CONF_NETWORK_NAME, CONF_RETURN_EMAIL);
					fprintf(mailfile, "To: %s\n", ni->email);

					fprintf(mailfile, lang_msg(GetNickLang(ni), NS_REMIND_EMAIL_SUBJECT), CONF_NETWORK_NAME);
					fprintf(mailfile, lang_msg(GetNickLang(ni), NS_REMIND_EMAIL_TEXT), ni->nick, CONF_SEND_REMINDER, CONF_NETWORK_NAME, s_NickServ, CONF_NETWORK_NAME);
					fclose(mailfile);

					snprintf(misc_buffer, MISC_BUFFER_SIZE, "%s -f %s -t < nsremind.txt", CONF_SENDMAIL_PATH, CONF_RETURN_EMAIL);
					system(misc_buffer);

					snprintf(misc_buffer, MISC_BUFFER_SIZE, "rm -f nsremind.txt");
					system(misc_buffer);
				}
				else
					log_error(FACILITY_NICKSERV_EXPIRE_NICKS, __LINE__, LOG_TYPE_ERROR_RTL, LOG_SEVERITY_ERROR_SKIPPED,
						"expire_nicks(): unable to create nsremind.txt");
			}
		}
	}

	TRACE();
	if (CONF_DISPLAY_UPDATES)
		send_globops(NULL, "Completed Nick Expire (\2%d\2/\2%d\2/\2%d\2)", xcount, rcount, count);
}

/*********************************************************/

void nickserv_daily_expire() {

	NickInfo *ni, *next;
	int i;
	const time_t expireTime = (NOW - ONE_WEEK);
	long count = 0;
	long xcount = 0;


	TRACE_FCLT(FACILITY_NICKSERV_EXPIRE_NICKS);

	for (i = 65; i < 126; ++i) {

		for (ni = nicklists[i]; ni; ni = next) {

			TRACE();
			next = ni->next;
			++count;

			if ((ni->last_email_request != 0) && (expireTime > ni->last_email_request)) {

				if (ni->regemail) {

					if (ni->email)
						mem_free(ni->email);

					ni->email = str_duplicate(ni->regemail);
					mem_free(ni->regemail);
					ni->regemail = NULL;
				}
				else {

					LOG_DEBUG_SNOOP("E AUTH [daily] - regemail empty for %s!", ni->nick);

					if (IS_NULL(ni->email))
						LOG_DEBUG_SNOOP("Warning: \2%s\2 authorized nonexistant e-mail address at daily expire!", ni->nick);
				}

				ni->auth = 0;
				ni->last_email_request = 0;

				RemoveFlag(ni->flags, NI_MAILCHANGE);

				LOG_SNOOP(s_OperServ, "NS E+ %s", ni->nick);
				++xcount;
			}

			if ((ni->last_drop_request != 0) && (expireTime > ni->last_drop_request)) {

				ni->last_drop_request = 0;
				ni->auth = 0;
			}

			if (FlagSet(ni->flags, NI_NOMAIL))
				RemoveFlag(ni->flags, NI_NOMAIL);
		}
	}

	TRACE();
	if (CONF_DISPLAY_UPDATES)
		send_globops(s_NickServ, "Completed Nick Daily Expire (\2%d\2/\2%d\2)", xcount, count);
}


/*********************************************************
 * NickServ private routines.                            *
 *********************************************************/

/* Insert a nick into the database. */
static void database_insert_nick(NickInfo *item) {

	NickInfo	*branch_head;
	int			branch_name;


	TRACE_FCLT(FACILITY_NICKSERV_DATABASE_INSERT_NICK);

	if (IS_NULL(item)) {

		log_error(FACILITY_NICKSERV_DATABASE_INSERT_NICK, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "database_insert_nick()", s_LOG_NULL, "item");

		return;
	}

	branch_name = str_char_tolower(item->nick[0]);

	TRACE();
	branch_head = nicklists[branch_name];
	nicklists[branch_name] = item;

	TRACE();
	item->next = branch_head;
	item->prev = NULL;

	if (IS_NOT_NULL(branch_head))
		branch_head->prev = item;
}

/*********************************************************/

/* Add a nick to the database. Returns a pointer to the new NickInfo
 * structure if the nick was successfully registered, NULL otherwise.
 * Assumes nick does not already exist. */

static NickInfo *makenick(CSTR nick) {

	NickInfo *ni;


	TRACE_FCLT(FACILITY_NICKSERV_MAKENICK);

	#ifdef	FIX_USE_MPOOL
	ni = mempool_alloc(NickInfo*, nickdb_mempool, TRUE);
	#else
	ni = mem_calloc(1, sizeof(NickInfo));
	#endif

	str_copy_checked(nick, ni->nick, NICKMAX);

	TRACE();
	database_insert_nick(ni);
	return ni;
}

/*********************************************************/

/* Return the NickInfo structure for the given nick, or NULL if the nick isn't registered. */
NickInfo *findnick(CSTR nickname) {

	NickInfo *ni;

	
	TRACE_FCLT(FACILITY_NICKSERV_FINDNICK);

	if (IS_NOT_NULL(nickname)) {

		for (ni = nicklists[str_char_tolower(*nickname)]; ni; ni = ni->next) {

			TRACE();
			if (str_equals_nocase(ni->nick, nickname))
				return ni;
		}
	}

	return NULL;
}

/*********************************************************/

/* Remove a nick from the NickServ database. Return 1 on success, 0 otherwise.
 * Also deletes the nick from any channel access lists it is on. */

static void delnick(NickInfo *ni) {

	User	*user;


	TRACE_FCLT(FACILITY_NICKSERV_DELNICK);

	/* If the user is online and identified, remove their +r status. */
	if (IS_NOT_NULL(user = hash_onlineuser_find(ni->nick)) && FlagSet(user->mode, UMODE_r))
		send_user_SVSMODE(s_NickServ, ni->nick, "-r", user->tsinfo);

	/* Remove identification to this nick from all users. */
	user_remove_id(ni->nick, TRUE);

	TRACE();

	/* Remove this nick from all channel Access Lists. */
	cs_remove_nick(ni->nick);

	TRACE();

	/* Clear all memos for this nick. */
	clear_memos(ni->nick);

	TRACE();

	/* Remove this nick from all operator lists. */
	oper_remove_nick(ni->nick);

	/* Stop a countdown if there's one going. We don't want to load an enforcer for an expired nick. */
	if (FlagSet(ni->flags, NI_TIMEOUT)) {

		if (!timeout_remove(toNickServ, TOTYPE_NICKSERV_COUNTDOWN, (unsigned long) ni))
			log_error(FACILITY_NICKSERV_DELNICK, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING, 
				"delnick(): Timeout not found for %s (NickServ/Countdown)", ni->nick);
	}

	TRACE();

	/* Remove the release timeout (if any), and quit the enforcer. */
	if (FlagSet(ni->flags, NI_ENFORCED)) {

		if (!timeout_remove(toNickServ, TOTYPE_NICKSERV_RELEASE, (unsigned long) ni))
			log_error(FACILITY_NICKSERV_DELNICK, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING, 
				"delnick(): Timeout not found for %s (NickServ/Release)", ni->nick);

		send_QUIT(ni->nick, "Enforcer quitting due to nick expiration.");
	}

	TRACE();

	/* Link around it. */
	if (ni->next)
		ni->next->prev = ni->prev;

	if (ni->prev)
		ni->prev->next = ni->next;
	else
		nicklists[str_char_tolower(*ni->nick)] = ni->next;

	TRACE();

	/* Now actually free it. */
	if (ni->last_usermask)
		mem_free(ni->last_usermask);

	if (ni->last_realname)
		mem_free(ni->last_realname);

	if (ni->access) {

		int accessIdx;

		for (accessIdx = 0; accessIdx < ni->accesscount; ++accessIdx)
			mem_free(ni->access[accessIdx]);

		mem_free(ni->access);
	}

	if (ni->url)
		mem_free(ni->url);

	if (ni->email)
		mem_free(ni->email);

	if (ni->regemail)
		mem_free(ni->regemail);

	if (ni->forward)
		mem_free(ni->forward);

	if (ni->hold)
		mem_free(ni->hold);

	if (ni->mark)
		mem_free(ni->mark);

	if (ni->forbid)
		mem_free(ni->forbid);

	if (ni->freeze)
		mem_free(ni->freeze);

	TRACE();

	#ifdef FIX_USE_MPOOL
	mempool_free(nickdb_mempool, ni);
	#else
	mem_free(ni);
	#endif
}

/*********************************************************/

/* Used by MemoServ's GLOBAL command. */

NickInfo *retnick(int i) {

	return nicklists[i];
}

/*********************************************************/

/* Is the given user's address on the given nick's access list? Return 1 if so, 0 if not. */
BOOL is_on_access(const User *user, const NickInfo *ni) {

	size_t	len;
	char	buffer[IRCBUFSIZE];
	STR		ptr;
	int		accessIdx;


	TRACE_FCLT(FACILITY_NICKSERV_IS_ON_ACCESS);

	if (IS_NULL(user) || IS_NULL(ni)) {

		log_error(FACILITY_NICKSERV_IS_ON_ACCESS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "is_on_access()", s_LOG_NULL, IS_NULL(user) ? "user" : "ni");

		return FALSE;
	}

	if ((ni->accesscount == 0) || FlagSet(ni->flags, NI_SECURE))
		return FALSE;

	len = str_len(user->username);
	memcpy(buffer, user->username, len);
	ptr = buffer + len;

	TRACE();
	*(ptr++) = c_AT;
	len = str_len(user->host);
	memcpy(ptr, user->host, len);
	ptr += len;

	*ptr = c_NULL;

	TRACE();
	for (accessIdx = 0; (accessIdx < ni->accesscount); ++accessIdx) {

		if (str_match_wild_nocase(ni->access[accessIdx], buffer))
			return TRUE;
	}

	return FALSE;
}

/*********************************************************/

/* Check whether a user is allowed to keep the nick they're using. */
void validate_user(const User *user) {

	LANG_ID		lang_id;
	BOOL		onAccess = FALSE;
	NickInfo	*ni;


	TRACE_FCLT(FACILITY_NICKSERV_VALIDATE_USER);

	if (IS_NULL(user)) {

		log_error(FACILITY_NICKSERV_VALIDATE_USER, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "validate_user()", s_LOG_NULL, "user");

		return;
	}

	if (IS_NULL(ni = user->ni))
		return;

	lang_id = EXTRACT_LANG_ID(ni->langID);

	TRACE();
	if (FlagSet(ni->flags, NI_FORBIDDEN)) {

		send_notice_lang_to_user(s_NickServ, user, GetCallerLang(), NS_VALIDATE_ERROR_NICK_FORBIDDEN);
		send_notice_lang_to_user(s_NickServ, user, GetCallerLang(), EMAIL_NETWORK_FOR_MORE_INFO, MAIL_KLINE);

		timeout_start_collide(ni, NI_KILL_NORMAL);
		return;
	}

	if (FlagSet(ni->flags, NI_FROZEN)) {

		send_notice_lang_to_user(s_NickServ, user, GetCallerLang(), NS_VALIDATE_ERROR_NICK_FROZEN);
		send_notice_lang_to_user(s_NickServ, user, GetCallerLang(), EMAIL_NETWORK_FOR_MORE_INFO, MAIL_KLINE);

		timeout_start_collide(ni, NI_KILL_NORMAL);
		return;
	}
	
	TRACE();

	if (user_is_identified_to(user, user->nick) || (onAccess = is_on_access(user, ni))) {

		ni->last_seen = NOW;

		if (ni->last_usermask)
			mem_free(ni->last_usermask);

		ni->last_usermask = mem_malloc(str_len(user->username) + str_len(user_public_host(user)) + 2);
		sprintf(ni->last_usermask, "%s@%s", user->username, user_public_host(user));

		if (ni->last_realname)
			mem_free(ni->last_realname);

		ni->last_realname = str_duplicate(user->realname);

		if (FlagSet(ni->flags, NI_MEMO_SIGNON) && !onAccess)
			check_memos(user, ni);

		return;
	}

	send_notice_lang_to_user(s_NickServ, user, lang_id, NS_VALIDATE_NICK_REGISTERED);
	send_notice_lang_to_user(s_NickServ, user, lang_id, NS_VALIDATE_PASSWORD_REQUEST);

	TRACE();
	if (FlagUnset(ni->flags, NI_TIMEOUT)) {

		if (FlagSet(ni->flags, NI_KILL_SLOW)) {

			send_notice_lang_to_user(s_NickServ, user, lang_id, NS_TIMEOUT_KILL_TIMER_1, 60);
			timeout_start_collide(ni, NI_KILL_SLOW);
		}
		else if (FlagSet(ni->flags, NI_KILL_NORMAL)) {

			send_notice_lang_to_user(s_NickServ, user, lang_id, NS_TIMEOUT_KILL_TIMER_1, 20);
			timeout_start_collide(ni, NI_KILL_NORMAL);
		}
		else if (FlagSet(ni->flags, NI_KILL_FAST)) {

			send_notice_lang_to_user(s_NickServ, user, lang_id, NS_TIMEOUT_KILL_TIMER_1, 5);
			timeout_start_collide(ni, NI_KILL_FAST);
		}
	}
}


/*********************************************************
 * Enforcer-related functions.                           *
 *********************************************************/

static void timeout_start_collide(NickInfo *ni, int type) {

	if (FlagUnset(ni->flags, NI_TIMEOUT) && FlagUnset(ni->flags, NI_ENFORCE) && FlagUnset(ni->flags, NI_ENFORCED)) {

		NickTimeoutData *data;

		TRACE();
		data = mem_malloc(sizeof(NickTimeoutData));

		data->ni = ni;
		data->user_online = TRUE;
		AddFlag(ni->flags, NI_TIMEOUT);

		TRACE();

		switch (type) {

			case NI_KILL_SLOW:
				/* Slow-type kill. First notice at 60s, set the next at 40. */
				data->step = TO_COLLIDE_STEP_40;
				timeout_add(toNickServ, TOTYPE_NICKSERV_COUNTDOWN, (unsigned long) ni, 20, TRUE, timeout_collide_countdown, (void *)data);
				return;

			case NI_KILL_NORMAL:
				/* Normal-type kill. First notice at 20s, set it to collide after 20 seconds. */
				data->step = TO_COLLIDE_STEP_COLLIDE;
				timeout_add(toNickServ, TOTYPE_NICKSERV_COUNTDOWN, (unsigned long) ni, 20, TRUE, timeout_collide_countdown, (void *)data);
				return;

			case NI_KILL_FAST:
				/* Fast-type kill. First notice at 5s, set it to collide after 5 seconds. */
				data->step = TO_COLLIDE_STEP_COLLIDE;
				timeout_add(toNickServ, TOTYPE_NICKSERV_COUNTDOWN, (unsigned long) ni, 5, TRUE, timeout_collide_countdown, (void *)data);
				return;
		}
	}
}

/*********************************************************/

static void timeout_collide_countdown(Timeout *to) {

	NickInfo			*ni;
	NickTimeoutData		*ntd;
	LANG_ID				lang_id;


	TRACE_FCLT(FACILITY_NICKSERV_TIMEOUT_COLLIDE_COUNTDOWN);

	if (IS_NULL(to) || IS_NULL(to->data))
		return;

	ntd = (NickTimeoutData *)to->data;

	ni = ntd->ni;

	if (IS_NULL(ni))
		return;

	lang_id = EXTRACT_LANG_ID(ni->langID);

	TRACE();
	switch (ntd->step) {

		case TO_COLLIDE_STEP_40:
			if (ntd->user_online)
				send_notice_lang_to_nick(s_NickServ, ni->nick, lang_id, NS_TIMEOUT_KILL_TIMER_2, 40);
			break;

		case TO_COLLIDE_STEP_20:
			if (ntd->user_online)
				send_notice_lang_to_nick(s_NickServ, ni->nick, lang_id, NS_TIMEOUT_KILL_TIMER_2, 20);
			break;

		case TO_COLLIDE_STEP_COLLIDE:
			if (ntd->user_online) {

				if (FlagSet(ni->flags, NI_FORBIDDEN))
					send_notice_lang_to_nick(s_NickServ, ni->nick, lang_id, NS_TIMEOUT_NICK_FORBIDDEN, ni->nick);

				else if (FlagSet(ni->flags, NI_FROZEN))		
					send_notice_lang_to_nick(s_NickServ, ni->nick, lang_id, NS_TIMEOUT_NICK_FROZEN, ni->nick);

				else	
					send_notice_lang_to_nick(s_NickServ, ni->nick, lang_id, NS_TIMEOUT_NICK_REGISTERED, ni->nick);
			}

			TRACE();
			to->repeat = FALSE;

			collide(ni, TRUE);
			return;
	}

	TRACE();
	++(ntd->step);
}

/*********************************************************/

static void collide(NickInfo *ni, BOOL from_timeout) {

	TRACE_FCLT(FACILITY_NICKSERV_COLLIDE);

	/*  Rimuovere un eventuale countdown se viene mandato un recover.
		Non rimuovere un collide visto che se c'e' NI_ENFORCED il recover chiama la release(). */

	if (!from_timeout && FlagSet(ni->flags, NI_TIMEOUT)) {

		if (!timeout_remove(toNickServ, TOTYPE_NICKSERV_COUNTDOWN, (unsigned long) ni))
			log_error(FACILITY_NICKSERV_COLLIDE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING, 
				"collide(): Timeout not found for %s (NickServ/Countdown)", ni->nick);
	}

	RemoveFlag(ni->flags, NI_TIMEOUT);

	/* Se l'utente e' offline, e non e' un recover, creare direttamente l'enforcer. */
	if (from_timeout && IS_NULL(hash_onlineuser_find(ni->nick)))
		nickserv_create_enforcer(ni);

	else {

		char			newnick[NICKSIZE];
		unsigned int	grn, idx;

		TRACE();
		srand(randomseed());

		while (1) {

			grn = getrandom(10000, 99999);

			idx = grn - 10000;

			if (nickserv_used_guest_list[idx] == 0) {

				nickserv_used_guest_list[idx] = 1;
				break;
			}
		}

		if (from_timeout)
			AddFlag(ni->flags, NI_ENFORCE);

		snprintf(newnick, sizeof(newnick), "Guest%d", grn);
		send_SVSNICK(ni->nick, newnick);
	}
}

/*********************************************************/

void nickserv_guest_reserve(unsigned int guestNumber) {

	if ((guestNumber >= 10000) && (guestNumber <= 99999))
		nickserv_used_guest_list[guestNumber - 10000] = 1;
}

/*********************************************************/

void nickserv_guest_free(unsigned int guestNumber) {

	if ((guestNumber >= 10000) && (guestNumber <= 99999))
		nickserv_used_guest_list[guestNumber - 10000] = 0;
}

/*********************************************************/

void check_enforce(NickInfo *ni) {

	TRACE_FCLT(FACILITY_NICKSERV_CHECK_ENFORCE);

	if (FlagSet(ni->flags, NI_ENFORCE))
		nickserv_create_enforcer(ni);
}

/*********************************************************/

static void nickserv_create_enforcer(NickInfo *ni) {

	NickTimeoutData		*data;

	TRACE_FCLT(FACILITY_NICKSERV_CREATE_ENFORCER);

	RemoveFlag(ni->flags, NI_ENFORCE);
	AddFlag(ni->flags, NI_ENFORCED);

	send_NICK(ni->nick, "+i", "enforcer", CONF_SERVICES_HOST, "Nick Protection Enforcement");
	user_add_enforcer(ni);

	TRACE();
	data = mem_malloc(sizeof(NickTimeoutData));

	data->ni = ni;
	data->step = 0;
	data->user_online = TRUE;

	TRACE();
	timeout_add(toNickServ, TOTYPE_NICKSERV_RELEASE, (unsigned long) ni, CONF_RELEASE_TIMEOUT, FALSE, timeout_release, (void *)data);
}

/*********************************************************/

/* Release a nick on timeout. */
static void timeout_release(Timeout *to) {

	NickInfo *ni;


	TRACE_FCLT(FACILITY_NICKSERV_TIMEOUT_RELEASE);

	if (IS_NULL(to) || IS_NULL(to->data))
		return;

	ni = ((NickTimeoutData *)to->data)->ni;

	if (IS_NULL(ni))
		return;

	to->repeat = FALSE;

	TRACE();
	release(ni, TRUE);
}

/*********************************************************/

/* Release hold on a nick. */
static void release(NickInfo *ni, BOOL from_timeout) {

	TRACE_FCLT(FACILITY_NICKSERV_RELEASE);

	if (!from_timeout) {
		
		if (FlagSet(ni->flags, NI_TIMEOUT)) {

			if (!timeout_remove(toNickServ, TOTYPE_NICKSERV_COUNTDOWN, (unsigned long) ni))
				log_error(FACILITY_NICKSERV_RELEASE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING, 
					"release(): Timeout not found for %s (NickServ/Countdown)", ni->nick);
		}

		if (FlagSet(ni->flags, NI_ENFORCED)) {

			if (!timeout_remove(toNickServ, TOTYPE_NICKSERV_RELEASE, (unsigned long) ni))
				log_error(FACILITY_NICKSERV_RELEASE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING, 
					"release(): Timeout not found for %s (NickServ/Release)", ni->nick);
		}

		send_QUIT(ni->nick, "Enforcer quitting from timeout.");
	}
	else
		send_QUIT(ni->nick, "Enforcer quitting.");

	TRACE();

	RemoveFlag(ni->flags, NI_TIMEOUT);
	RemoveFlag(ni->flags, NI_ENFORCED);
}

/*********************************************************/

void nickserv_dispose_timeout_data(void *data) {

	mem_free(data);
}

/*********************************************************/

void nickserv_update_news(const LANG_ID lang_id) {

	int idx, nickCount = 0;
	NickInfo *ni;
	User *user;


	for (idx = 65; idx < 126; ++idx) {

		for (ni = nicklists[idx]; ni; ni = ni->next) {

			if (GetNickLang(ni) == lang_id) {

				++nickCount;

				RemoveFlag(ni->flags, NI_READNEWS);

				if (IS_NOT_NULL(user = hash_onlineuser_find(ni->nick)))
					send_notice_lang_to_user(s_MemoServ, user, lang_id, MS_NEWS_AVAILABLE, CONF_NETWORK_NAME);
			}
		}
	}

	send_globops(s_MemoServ, "Updated news for language \2%s\2 [Nicks: %d]", lang_get_shortname(lang_id), nickCount);
}


/*********************************************************
 * NickServ command routines.                            *
 *********************************************************/

/* Register a nick. */
static void do_register(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *pass, *email;
	RESERVED_RESULT reserved;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_REGISTER);

	if (CONF_SET_READONLY) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_REGISTER_ERROR_READONLY);
		return;
	}

	if (dynConf.ns_regLimit > 0) {

		if (dynConf.ns_regLimit <= ns_regCount) {

			send_globops(s_NickServ, "\2%s\2 hit the maximum number of registrations allowed (\2%d\2/\2%d\2)", s_NickServ, ns_regCount, dynConf.ns_regLimit);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_MAX_REG_REACHED);
			return;

		}
		else if (dynConf.ns_regLimit <= (ns_regCount + 10))
			send_globops(s_NickServ, "\2%s\2 is about to hit the maximum number of registrations allowed (\2%d\2/\2%d\2)", s_NickServ, ns_regCount, dynConf.ns_regLimit);
	}

	TRACE_MAIN();
	if (IS_NULL(pass = strtok(NULL, " ")) || IS_NULL(email = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_REGISTER_SYNTAX_ERROR);	
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");	
	}
	else if ((NOW < callerUser->lastnickreg + CONF_REGISTER_DELAY) && !is_services_valid_oper(callerUser)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_REGISTER_REG_DELAY, CONF_REGISTER_DELAY);
		callerUser->lastnickreg = NOW;
	}
	else if (callerUser->ni) {

		if (FlagSet(callerUser->ni->flags, NI_FORBIDDEN))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_REGISTER_ERROR_NICK_FORBIDDEN, callerUser->ni->nick);
		else
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_REGISTER_ERROR_NICK_ALREADY_REG, callerUser->ni->nick);
	}
	else if ((reserved = reserved_match(source, RESERVED_NICK, 1, s_NickServ, source, callerUser->username, callerUser->host, callerUser->ip, (IS_NOT_NULL(callerUser->oper) || user_is_ircop(callerUser) || user_is_admin(callerUser) || user_is_services_agent(callerUser)), callerUser->current_lang)) == reservedKill)
		send_KILL(s_NickServ, source, lang_msg(GetCallerLang(), RESERVED_NAME_KILL_REASON_REG), TRUE);

	else if (reserved == reservedAutoKill)
		return;

	else if (reserved == reservedBlock)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_REGISTER_ERROR_NICK_RESERVED, source);

	else if (str_len(pass) > PASSMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_MAX_LENGTH, PASSMAX);

	else if (string_has_ccodes(pass))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_WITH_CCODES);

	else if (strchr(pass, '@') && strchr(pass, '.')) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_REGISTER_ERROR_PASS_AS_EMAIL);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");
	}
	else if (str_equals_nocase(pass, "PASSWORD")) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_AS_PASS);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");
	}
	else if (str_equals_nocase(source, pass) && IS_NOT_NULL(strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_REGISTER_SYNTAX_ERROR);	
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");	
	}
	else if (str_equals_nocase(source, pass) || (str_len(pass) < 5)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_INSECURE_PASSWORD);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");
	}
	else if (str_len(email) > MAILMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_MAIL_MAX_LENGTH, MAILMAX);

	else if (string_has_ccodes(email) || !validate_email(email) || str_equals_nocase(email, "ident@home.com") || str_equals_nocase(email, "user@home.com")) // GDPChat sux
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_INVALID_EMAIL, email);

	else if (blacklist_match(callerUser, email, 'r'))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_EMAIL_BLACKLISTED, email);

	else {

		TRACE_MAIN();

		callerUser->ni = makenick(source);

		TRACE_MAIN();
		++ns_regCount;

		str_copy_checked(pass, callerUser->ni->pass, PASSMAX);

		if (!user_is_identified_to(callerUser, source)) {

			++(callerUser->idcount);
			callerUser->id_nicks = mem_realloc(callerUser->id_nicks, sizeof(char *) * callerUser->idcount);
			callerUser->id_nicks[callerUser->idcount - 1] = str_duplicate(source);
		}

		TRACE_MAIN();
		AddFlag(callerUser->ni->flags, NI_MEMO_SIGNON);
		AddFlag(callerUser->ni->flags, NI_MEMO_RECEIVE);
		AddFlag(callerUser->ni->flags, NI_READNEWS);
		AddFlag(callerUser->ni->flags, NI_KILL_SLOW);

		callerUser->ni->last_usermask = mem_malloc(str_len(callerUser->username) + str_len(user_public_host(callerUser)) + 2);
		sprintf(callerUser->ni->last_usermask, "%s@%s", callerUser->username, user_public_host(callerUser));

		callerUser->ni->email = str_tolower(str_duplicate(email));
		AddFlag(callerUser->ni->flags, NI_HIDE_EMAIL);

		TRACE_MAIN();

		/* Nick auto-auth se non mandiamo E-Mail e' off */
		if (CONF_USE_EMAIL)
			AddFlag(callerUser->ni->flags, NI_AUTH);

		callerUser->ni->last_realname = str_duplicate(callerUser->realname);
		callerUser->ni->time_registered = callerUser->ni->last_seen = NOW;

		TRACE_MAIN();
		callerUser->ni->accesscount = 0;
		callerUser->ni->access = NULL;

		callerUser->ni->langID = IS_NULL(callerUser) ? LANG_DEFAULT : COMPACT_LANG_ID(callerUser->current_lang);

		callerUser->ni->memomax = CONF_DEF_MAX_MEMOS;

		clear_memos(callerUser->ni->nick);

		LOG_SNOOP(s_OperServ, "NS R %s -- by %s (%s@%s) [E: %s]", source, source, callerUser->username, callerUser->host, callerUser->ni->email);
		log_services(LOG_SERVICES_NICKSERV_GENERAL, "R %s -- by %s (%s@%s) [E: %s] [P: %s]", source, source, callerUser->username, callerUser->host, callerUser->ni->email, callerUser->ni->pass);

		if (CONF_USE_EMAIL) {

			FILE *mailfile;

			srand(randomseed());

			callerUser->ni->auth = callerUser->ni->time_registered + (getrandom(1, 99999) * getrandom(1, 9999));

			if (IS_NOT_NULL(mailfile = fopen("authnick.txt", "w"))) {

				char timebuf[64];

				lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_MAILTIME, NOW);

				fprintf(mailfile, "Date: %s\n", timebuf);
				fprintf(mailfile, "From: %s <%s>\n", CONF_NETWORK_NAME, CONF_RETURN_EMAIL);
				fprintf(mailfile, "To: %s\n", callerUser->ni->email);

				fprintf(mailfile, lang_msg(GetCallerLang(), NS_REGISTER_EMAIL_SUBJECT), callerUser->ni->nick);
				fprintf(mailfile, lang_msg(GetCallerLang(), NS_REGISTER_EMAIL_TEXT_1), CONF_NETWORK_NAME, callerUser->ni->auth, CONF_NETWORK_NAME, callerUser->ni->nick, s_NickServ, callerUser->ni->auth);
				fprintf(mailfile, lang_msg(GetCallerLang(), NS_REGISTER_EMAIL_TEXT_2));
				fprintf(mailfile, lang_msg(GetCallerLang(), NS_REGISTER_EMAIL_TEXT_3));
				fprintf(mailfile, lang_msg(GetCallerLang(), NS_REGISTER_EMAIL_TEXT_4));
				fprintf(mailfile, lang_msg(GetCallerLang(), NS_REGISTER_EMAIL_TEXT_5), CONF_NETWORK_NAME, CONF_NETWORK_NAME);
				fprintf(mailfile, lang_msg(GetCallerLang(), NS_REGISTER_EMAIL_TEXT_6), CONF_NETWORK_NAME, CONF_NETWORK_NAME);
				fprintf(mailfile, lang_msg(GetCallerLang(), NS_REGISTER_EMAIL_TEXT_7), CONF_NETWORK_NAME);
				fclose(mailfile);

				snprintf(misc_buffer, MISC_BUFFER_SIZE, "%s -f %s -t < authnick.txt", CONF_SENDMAIL_PATH, CONF_RETURN_EMAIL);
				system(misc_buffer);

				snprintf(misc_buffer, MISC_BUFFER_SIZE, "rm -f authnick.txt");		
				system(misc_buffer);
			}
			else
				log_error(FACILITY_NICKSERV_HANDLE_REGISTER, __LINE__, LOG_TYPE_ERROR_RTL, LOG_SEVERITY_ERROR_SKIPPED, "do_register(): unable to create authnick.txt");
		}

#ifndef USE_ENCRYPTION
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_REGISTER_REG_OK_1, pass);
#endif

		if (CONF_USE_EMAIL) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_REGISTER_REG_OK_2);

			if (CONF_FORCE_AUTH)
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_REGISTER_REG_OK_3);
		}

		TRACE_MAIN();
		callerUser->lastnickreg = NOW;
	}
}

/*********************************************************/

static void do_auth(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *auth;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_AUTH);

	if (IS_NULL(auth = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_AUTH_SYNTAX_ERROR_1);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_AUTH_SYNTAX_ERROR_2);
	}
	else if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");
	}
	else if (FlagUnset(callerUser->ni->flags, NI_AUTH))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_ALREADY_AUTH);

	else {

		unsigned long int authcode;
		char *err;

		authcode = strtoul(auth, &err, 10);

		if ((*err == '\0') && (authcode != 0) && (authcode == callerUser->ni->auth)) {

			TRACE_MAIN();
			RemoveFlag(callerUser->ni->flags, NI_AUTH);
			callerUser->ni->auth = 0;

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_AUTH_CODE_ACCEPTED);

			if (FlagUnset(callerUser->mode, UMODE_r) && user_is_identified_to(callerUser, callerUser->ni->nick)) {

				send_user_SVSMODE(s_NickServ, source, "+r", callerUser->tsinfo);
				AddFlag(callerUser->mode, UMODE_r);
			}
		}
		else {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_AUTH_ERROR_WRONG_CODE);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
		}
	}
}

/*********************************************************/

static void do_identify(CSTR source, User *callerUser, ServiceCommandData *data) {

	char		*nick, *pass;
	NickInfo	*ni;
	BOOL		sameNick = FALSE, freeMe = FALSE;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_IDENTIFY);

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_IDENTIFY_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "IDENTIFY");
		return;
	}

	if (IS_NOT_NULL(pass = strtok(NULL, " "))) {

		if (str_len(nick) > NICKMAX) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_MAX_LENGTH, NICKMAX);
			return;
		}
		else if (str_len(pass) > PASSMAX) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_MAX_LENGTH, PASSMAX);
			return;
		}
	}

	if (IS_NULL(pass)) {

		if (str_len(nick) > PASSMAX) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_MAX_LENGTH, PASSMAX);
			return;
		}

		pass = str_duplicate(nick);
		nick = str_duplicate(source);

		freeMe = TRUE;
		sameNick = TRUE;
	}
	else if (str_equals_nocase(source, nick))
		sameNick = TRUE;

	if (IS_NULL(ni = findnick(nick)))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_NOT_REG, nick);

	else if (FlagSet(ni->flags, NI_FROZEN)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FROZEN, ni->nick);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), EMAIL_NETWORK_FOR_MORE_INFO, MAIL_KLINE);
	}
	else if (FlagSet(ni->flags, NI_FORBIDDEN)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), EMAIL_NETWORK_FOR_MORE_INFO, MAIL_KLINE);
	}
	else if (str_not_equals(pass, ni->pass)) {

		TRACE_MAIN();
		LOG_SNOOP(s_OperServ, "NS *I %s -- by %s (%s@%s) [%s]", ni->nick, source, callerUser->username, callerUser->host, user_is_ircop(callerUser) ? "OPER-HIDDEN" : pass);
		log_services(LOG_SERVICES_NICKSERV_ID, "*I %s -- by %s (%s@%s) [%s]", ni->nick, source, callerUser->username, callerUser->host, pass);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_BAD_PASS, nick);

		update_invalid_password_count(callerUser, s_NickServ, nick);
	}
	else {

		char accessLevel[256], modebuf[16];
		int modeIdx = 1;
		BOOL isOper = FALSE;

		memset(accessLevel, 0, sizeof(accessLevel));

		TRACE_MAIN();

		if (!user_is_identified_to(callerUser, ni->nick)) {

			++(callerUser->idcount);
			callerUser->id_nicks = mem_realloc(callerUser->id_nicks, sizeof(char *) * callerUser->idcount);
			callerUser->id_nicks[callerUser->idcount - 1] = str_duplicate(ni->nick);
		}

		TRACE_MAIN();

		if (sameNick) {

			if (FlagSet(ni->flags, NI_TIMEOUT)) {

				if (!timeout_remove(toNickServ, TOTYPE_NICKSERV_COUNTDOWN, (unsigned long) ni))
					log_error(FACILITY_NICKSERV_HANDLE_IDENTIFY, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING, 
						"do_identify(): Timeout not found for %s (NickServ/Countdown)", ni->nick);

				RemoveFlag(ni->flags, NI_TIMEOUT);
			}

			// l'utente si e' identificato al nick corrente -> cambiare il lang
			callerUser->current_lang = EXTRACT_LANG_ID(ni->langID);
			current_caller_lang = callerUser->current_lang;
		}
		else {

			// l'utente si e' identificando ad un altro nick
			// se NON e' identificato al nick corrente, cambiare il lang
			if (!user_is_identified_to(callerUser, source)) {

				callerUser->current_lang = EXTRACT_LANG_ID(ni->langID);
				current_caller_lang = callerUser->current_lang;
			}
		}

		/* Don't update Last Seen/Usermask/Realname if it's an oper identifying remotely. */
		if (sameNick || FlagUnset(callerUser->mode, UMODE_I)) {

			ni->last_seen = NOW;
			if (ni->last_usermask)
				mem_free(ni->last_usermask);

			ni->last_usermask = mem_malloc(str_len(callerUser->username) + str_len(user_public_host(callerUser)) + 2);
			sprintf(ni->last_usermask, "%s@%s", callerUser->username, user_public_host(callerUser));

			if (ni->last_realname)
				mem_free(ni->last_realname);
			ni->last_realname = str_duplicate(callerUser->realname);
		}

		if (FlagSet(ni->flags, NI_REMIND))
			RemoveFlag(ni->flags, NI_REMIND);

		if (IS_NULL(ni->email))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_IDENTIFY_NO_REGEMAIL_SET);

		isOper = user_is_ircop(callerUser);

		modebuf[0] = '+';

		switch (check_oper(callerUser, nick, NULL)) {

			case ULEVEL_USER:
				if (sameNick && FlagUnset(callerUser->mode, UMODE_r) && FlagUnset(ni->flags, NI_AUTH)) {

					modebuf[modeIdx++] = 'r';
					AddFlag(callerUser->mode, UMODE_r);
				}
				break;

			case ULEVEL_HOP:
				if (FlagUnset(callerUser->mode, UMODE_h)) {

					modebuf[modeIdx++] = 'h';
					AddFlag(callerUser->mode, UMODE_h);
				}

				if (sameNick && FlagUnset(callerUser->mode, UMODE_r)) {

					modebuf[modeIdx++] = 'r';
					AddFlag(callerUser->mode, UMODE_r);
				}

				str_copy_checked(lang_msg(GetCallerLang(), NS_IDENTIFY_SOURCE_IS_HELPOP), accessLevel, sizeof(accessLevel));
				break;

			case ULEVEL_SOP:
				if (sameNick && FlagUnset(callerUser->mode, UMODE_r)) {

					modebuf[modeIdx++] = 'r';
					AddFlag(callerUser->mode, UMODE_r);
				}

				str_copy_checked(lang_msg(GetCallerLang(), NS_IDENTIFY_SOURCE_IS_SOP), accessLevel, sizeof(accessLevel));
				break;

			case ULEVEL_SA:
				if (isOper && FlagUnset(callerUser->mode, UMODE_a)) {

					modebuf[modeIdx++] = 'a';
					AddFlag(callerUser->mode, UMODE_a);
				}

				if (sameNick && FlagUnset(callerUser->mode, UMODE_r)) {

					modebuf[modeIdx++] = 'r';
					AddFlag(callerUser->mode, UMODE_r);
				}

				str_copy_checked(lang_msg(GetCallerLang(), NS_IDENTIFY_SOURCE_IS_ADMIN), accessLevel, sizeof(accessLevel));
				break;

			case ULEVEL_SRA:
				if (isOper && FlagUnset(callerUser->mode, UMODE_a)) {

					modebuf[modeIdx++] = 'a';
					AddFlag(callerUser->mode, UMODE_a);
				}

				if (sameNick && FlagUnset(callerUser->mode, UMODE_r)) {

					modebuf[modeIdx++] = 'r';
					AddFlag(callerUser->mode, UMODE_r);
				}

				str_copy_checked(lang_msg(GetCallerLang(), NS_IDENTIFY_SOURCE_IS_ROOT), accessLevel, sizeof(accessLevel));
				break;

			case ULEVEL_CODER:
				if (isOper && FlagUnset(callerUser->mode, UMODE_a)) {

					modebuf[modeIdx++] = 'a';
					AddFlag(callerUser->mode, UMODE_a);
				}

				if (sameNick && FlagUnset(callerUser->mode, UMODE_r)) {

					modebuf[modeIdx++] = 'r';
					AddFlag(callerUser->mode, UMODE_r);
				}

				str_copy_checked(lang_msg(GetCallerLang(), NS_IDENTIFY_SOURCE_IS_CODER), accessLevel, sizeof(accessLevel));
				break;

			case ULEVEL_MASTER:
				if (isOper && FlagUnset(callerUser->mode, UMODE_a)) {

					modebuf[modeIdx++] = 'a';
					AddFlag(callerUser->mode, UMODE_a);
				}

				if (sameNick && FlagUnset(callerUser->mode, UMODE_r)) {

					modebuf[modeIdx++] = 'r';
					AddFlag(callerUser->mode, UMODE_r);
				}

				str_copy_checked(lang_msg(GetCallerLang(), NS_IDENTIFY_SOURCE_IS_MASTER), accessLevel, sizeof(accessLevel));
				break;

			default:
				LOG_DEBUG_SNOOP("Unknown access return (%d) for user %s", check_oper(callerUser, nick, NULL), callerUser->nick);
				break;
		}

		if (CONF_SET_EXTRASNOOP)
			LOG_SNOOP(s_OperServ, "NS I %s -- by %s (%s@%s) [%s]", nick, source, callerUser->username, callerUser->host, user_is_ircop(callerUser) ? "OPER-HIDDEN" : pass);

		log_services(LOG_SERVICES_NICKSERV_ID, "I %s -- by %s (%s@%s) [%s]", nick, source, callerUser->username, callerUser->host, pass);

		if (modeIdx > 1) {

			modebuf[modeIdx] = '\0';
			send_user_SVSMODE(s_NickServ, source, modebuf, callerUser->tsinfo);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_IDENTIFY_ID_OK, ni->nick, accessLevel);

		if (sameNick && FlagSet(ni->flags, NI_AUTH))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_IDENTIFY_NOT_AUTH, ni->email);

		if (FlagSet(ni->flags, NI_MEMO_SIGNON))
			check_memos(callerUser, ni);
	}

	if (freeMe) {

		mem_free(nick);
		mem_free(pass);
	}
}

/*********************************************************/

static void do_drop(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *nick;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_DROP);

	if (CONF_SET_READONLY)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DROP_ERROR_READONLY);

	else if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DROP_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "DROP");
	}
	else if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_MAX_LENGTH, NICKMAX);

	else if (str_not_equals_nocase(nick, source))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DROP_ERROR_NOT_CURRENT_NICK);

	else if (IS_NULL(ni = callerUser->ni))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_NOT_REG, nick);

	else if (!user_is_identified_to(callerUser, nick)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, ni->nick);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, ni->nick);
	}
	else {

		const char *auth;

		if (IS_NULL(auth = strtok(NULL, " "))) {

			/* This user wants to drop their nickname. */

			if (get_services_access(NULL, nick) == ULEVEL_MASTER)
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DROP_ERROR_NICK_IS_MASTER);

			else if (FlagSet(ni->flags, NI_AUTH)) {

				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DROP_ERROR_NOT_AUTH);
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
			}
			else if (FlagSet(ni->flags, NI_MAILCHANGE)) {

				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DROP_ERROR_MAILCHANGE_ON);
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
			}
			else if (FlagSet(ni->flags, NI_DROP)) {

				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_DROP_CODE_ALREADY_SENT);
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DROP_UNDO_HOWTO, ni->nick);
			}
			else if ((NOW - ni->last_drop_request) < ONE_DAY)
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DROP_ERROR_WAIT);

			else {

				FILE *mailfile;

				AddFlag(ni->flags, NI_DROP);

				srand(randomseed());

				ni->auth = ni->time_registered + (getrandom(1, 99999) * getrandom(1, 9999));
				ni->last_drop_request = NOW;

				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DROP_CODE_SENT, ni->email);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "D! %s -- by %s (%s@%s)", ni->nick, source, callerUser->username, callerUser->host);

				if (IS_NOT_NULL(mailfile = fopen("nickdrop.txt", "w"))) {

					char timebuf[64];

					lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_MAILTIME, NOW);

					fprintf(mailfile, "Date: %s\n", timebuf);
					fprintf(mailfile, "From: %s <%s>\n", CONF_NETWORK_NAME, CONF_RETURN_EMAIL);
					fprintf(mailfile, "To: %s\n", ni->email);

					fprintf(mailfile, lang_msg(GetCallerLang(), NS_DROP_EMAIL_SUBJECT), CONF_NETWORK_NAME);
					fprintf(mailfile, lang_msg(GetCallerLang(), NS_DROP_EMAIL_TEXT), ni->auth, CONF_NETWORK_NAME, ni->nick, s_NickServ, ni->nick, ni->auth);
					fprintf(mailfile, lang_msg(GetCallerLang(), CSNS_EMAIL_TEXT_ABUSE), MAIL_ABUSE, CONF_NETWORK_NAME);
					fclose(mailfile);

					snprintf(misc_buffer, MISC_BUFFER_SIZE, "%s -f %s -t < nickdrop.txt", CONF_SENDMAIL_PATH, CONF_RETURN_EMAIL);
					system(misc_buffer);

					snprintf(misc_buffer, MISC_BUFFER_SIZE, "rm -f nickdrop.txt");
					system(misc_buffer);
				}
				else
					log_error(FACILITY_NICKSERV_HANDLE_DROP, __LINE__, LOG_TYPE_ERROR_RTL, LOG_SEVERITY_ERROR_SKIPPED, "do_drop(): unable to create nickdrop.txt");
			}
		}

		else if (FlagUnset(ni->flags, NI_DROP))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DROP_ERROR_NOT_DROPPING, ni->nick);

		else {

			/* The user supplied an auth code. Check whether he wants to undo the request or proceed with it. */

			if (str_equals_nocase(auth, "UNDO")) {

				RemoveFlag(ni->flags, NI_DROP);
				ni->auth = 0;

				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DROP_REQUEST_UNDONE, ni->nick);
			}
			else {

				unsigned long int authcode = 0;
				char *err;

				authcode = strtoul(auth, &err, 10);

				if ((*err != '\0') || (authcode == 0) || (authcode != ni->auth)) {

					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_WRONG_DROP_CODE);
					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
				}
				else {

					LOG_SNOOP(s_OperServ, "NS D %s -- by %s (%s@%s)", ni->nick, source, callerUser->username, callerUser->host);
					log_services(LOG_SERVICES_NICKSERV_GENERAL, "D %s -- by %s (%s@%s)", ni->nick, source, callerUser->username, callerUser->host);

					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DROP_NICK_DROPPED);

					delnick(ni);
				}
			}
		}
	}
}

/*********************************************************/

static void do_set(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *cmd, *param;

	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_SET);

	if (CONF_SET_READONLY) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_ERROR_READONLY);
		return;
	}

	if (IS_NOT_NULL(cmd = strtok(NULL, " "))) {

		str_toupper(cmd);

		if (str_equals(cmd, "PASSWD"))
			param = strtok(NULL, "");
		else
			param = strtok(NULL, " ");
	}
	else
		param = NULL;

	if (IS_NULL(cmd) || IS_NULL(param)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "SET");
	}
	else if (IS_NULL(callerUser->ni)) {

		if (str_equals(cmd, "LANG"))
			do_set_lang(callerUser, param, 1);

		else {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");
		}
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		if (str_equals(cmd, "LANG"))
			do_set_lang(callerUser, param, 2);

		else {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
		}
	}
	else if (CONF_FORCE_AUTH && IS_NULL(callerUser->ni->email)) {

		/* This nick has no E-Mail address set. Let them use SET LANG & SET EMAIL only. */

		if (str_equals(cmd, "LANG"))
			do_set_lang(callerUser, param, 3);

		else if (str_equals(cmd, "EMAIL"))
			do_set_email(callerUser, param, FALSE);

		else {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_ERROR_NO_MAIL);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
		}
	}
	else if (CONF_FORCE_AUTH && FlagSet(callerUser->ni->flags, NI_AUTH)) {

		/* This nick has not yet authorized. */

		if (str_equals(cmd, "LANG"))
			do_set_lang(callerUser, param, 3);

		else {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_ERROR_MUST_AUTH);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
		}
	}
	else if (str_equals(cmd, "PASSWD"))
		do_set_password(callerUser, param);

	else if (str_equals(cmd, "URL"))
		do_set_url(callerUser, param);

	else if (str_equals(cmd, "KILL"))
		do_set_kill(callerUser, param);

	else if (str_equals(cmd, "EMAIL"))
		do_set_email(callerUser, param, TRUE);

	else if (str_equals(cmd, "LANG"))
		do_set_lang(callerUser, param, 0);

	else
		do_set_option(callerUser, cmd, param);
}

/*********************************************************/

static void do_set_password(User *callerUser, CSTR param) {

	char	*newpass;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_SET_PASSWORD);

	if (param && IS_NOT_NULL(newpass = strchr(param, ' '))) {

		*newpass++ = '\0';

		if (strchr(newpass, ' '))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_WITH_SPACES);

		else if (str_equals_nocase(callerUser->nick, newpass) || (str_len(newpass) < 5))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_INSECURE_PASSWORD);

		else if (str_len(newpass) > PASSMAX)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_MAX_LENGTH, PASSMAX);

		else if (str_equals(callerUser->ni->pass, newpass))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_SAME_PASSWORD);

		else if (string_has_ccodes(newpass))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_WITH_CCODES);

		else {
		
			/* "param" holds the old password. */

			if (str_equals(param, callerUser->ni->pass)) {

				if (str_not_equals(param, newpass)) {

					TRACE_MAIN();

					if (CONF_SET_EXTRASNOOP && !user_is_ircop(callerUser))
						LOG_SNOOP(s_OperServ, "NS P %s -- by %s (%s@%s) [%s -> %s]", callerUser->ni->nick, callerUser->nick, callerUser->username, callerUser->host, callerUser->ni->pass, newpass);
					else
						LOG_SNOOP(s_OperServ, "NS P %s -- by %s (%s@%s) [Logged]", callerUser->ni->nick, callerUser->nick, callerUser->username, callerUser->host);

					log_services(LOG_SERVICES_NICKSERV_GENERAL, "P %s -- by %s (%s@%s) [%s -> %s]", callerUser->ni->nick, callerUser->nick, callerUser->username, callerUser->host, callerUser->ni->pass, newpass);

					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_PASSWD_PASSWORD_CHANGED, callerUser->ni->nick, newpass);

					str_copy_checked(newpass, callerUser->ni->pass, PASSMAX);

					user_remove_id(callerUser->nick, FALSE);

					++(callerUser->idcount);
					callerUser->id_nicks = mem_realloc(callerUser->id_nicks, sizeof(char *) * callerUser->idcount);
					callerUser->id_nicks[callerUser->idcount - 1] = str_duplicate(callerUser->nick);
				}
				else
					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_SAME_PASSWORD);
			}
			else {

				TRACE_MAIN();
				LOG_SNOOP(s_OperServ, "NS *P %s -- by %s (%s@%s) [Wrong Old Pass: %s ]", callerUser->ni->nick, callerUser->nick, callerUser->username, callerUser->host, param);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "*P %s -- by %s (%s@%s) [Old Pass: %s - Given: %s ]", callerUser->ni->nick, callerUser->nick, callerUser->username, callerUser->host, callerUser->ni->pass, param);

				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_PASSWD_ERROR_WRONG_OLD_PASS, callerUser->ni->nick);

				update_invalid_password_count(callerUser, s_NickServ, callerUser->ni->nick);
			}
		}
	}
	else {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_PASSWD_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "SET PASSWD");
	}
}

/*********************************************************/

static void do_set_url(const User *callerUser, CSTR param) {

	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_SET_URL);

	if (str_len(param) > URLMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_URL_MAX_LENGTH, URLMAX);

	else if (str_equals_nocase(param, "NONE")) {

		TRACE_MAIN();
		if (IS_NULL(callerUser->ni->url)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_URL_ERROR_NO_URL);
			return;
		}

		mem_free(callerUser->ni->url);
		callerUser->ni->url = NULL;

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_URL_DELETED, callerUser->ni->nick);
	}
	else if (string_has_ccodes(param) || !strchr(param, '.'))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_URL_FORMAT);

	else {

		if (callerUser->ni->url)
			mem_free(callerUser->ni->url);
		callerUser->ni->url = str_duplicate(param);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_URL_CHANGED, callerUser->ni->nick, param);
	}
}

/*********************************************************/

static void do_set_email(const User *callerUser, CSTR param, BOOL hasmail) {

	NickInfo *ni = callerUser->ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_SET_EMAIL);

	if (str_equals_nocase(param, "HIDE")) {

		if (hasmail == FALSE) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_ERROR_NO_MAIL);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
			return;
		}

		if (FlagSet(ni->flags, NI_HIDE_EMAIL)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_ERROR_ALREADY_HIDDEN);
			return;
		}

		AddFlag(ni->flags, NI_HIDE_EMAIL);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_HIDDEN, ni->nick);
	}
	else if (str_equals_nocase(param, "SHOW")) {

		if (hasmail == FALSE) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_ERROR_NO_MAIL);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
			return;
		}

		if (FlagUnset(ni->flags, NI_HIDE_EMAIL)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_ERROR_NOT_HIDDEN);
			return;
		}

		RemoveFlag(ni->flags, NI_HIDE_EMAIL);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_SHOW, ni->nick);
	}
	else if (str_equals_nocase(param, "UNDO")) {

		if (hasmail == FALSE) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_ERROR_NO_MAIL);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
			return;
		}

		if (FlagUnset(ni->flags, NI_MAILCHANGE)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_ERROR_NO_MAILCHANGE, ni->nick);
			return;
		}

		RemoveFlag(ni->flags, NI_MAILCHANGE);

		if (ni->regemail)
			mem_free(ni->regemail);
		ni->regemail = NULL;

		ni->auth = 0;
		ni->last_email_request = 0;

		AddFlag(ni->flags, NI_NOMAIL);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_UNDO, ni->nick);
	}
	else if (str_equals_nocase(param, "AUTH")) {

		if (FlagSet(ni->flags, NI_DROP))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_ERROR_DROP_ON);

		else if (FlagUnset(ni->flags, NI_MAILCHANGE) && (hasmail == FALSE))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_ERROR_NO_MAILCHANGE, ni->nick);

		else {

			const char *auth;
			unsigned long int authcode = 0;

			if (IS_NOT_NULL(auth = strtok(NULL, s_NULL))) {

				char *err;

				authcode = strtoul(auth, &err, 10);

				if (*err != '\0')
					authcode = 0;
			}

			if ((authcode != 0) && (authcode == ni->auth)) {

				TRACE_MAIN();

				if (ni->regemail) {

					if (ni->email)
						mem_free(ni->email);

					ni->email = str_duplicate(ni->regemail);
					mem_free(ni->regemail);
					ni->regemail = NULL;
				}
				else {

					if (IS_NULL(ni->email))
						LOG_DEBUG_SNOOP("Warning: \2%s\2 authorized nonexistant e-mail address!", ni->nick);
				}

				ni->auth = 0;
				ni->last_email_request = 0;

				RemoveFlag(ni->flags, NI_MAILCHANGE);
				RemoveFlag(ni->flags, NI_AUTH);

				AddFlag(ni->flags, NI_NOMAIL);
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_COMPLETED, ni->nick, ni->email);

				LOG_SNOOP(s_OperServ, "NS E! %s -- by %s (%s@%s) [%s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->email);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "E! %s -- by %s (%s@%s) [%s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->email);
			}
			else {

				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_AUTH_ERROR_WRONG_CODE);
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
			}
		}
	}
	else {

		TRACE_MAIN();
		if (FlagSet(ni->flags, NI_NOMAIL))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_ERROR_WAIT);

		else if (FlagSet(ni->flags, NI_MAILCHANGE))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_ERROR_MAILCHANGE_ON, ni->nick, ni->regemail);

		else if (FlagSet(ni->flags, NI_DROP))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_ERROR_DROP_ON);

		else if (str_len(param) > MAILMAX)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_MAIL_MAX_LENGTH, MAILMAX);

		else if (ni->email && (str_equals_nocase(ni->email, param)))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_ERROR_SAME, ni->nick, ni->email);

		else if (string_has_ccodes(param) || !validate_email(param))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_ERROR_INVALID_EMAIL, param);

		else if (blacklist_match(callerUser, param, 'c'))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_EMAIL_BLACKLISTED, param);

		else {

			FILE *mailfile;

			if (ni->regemail)
				mem_free(ni->regemail);

			if (hasmail == FALSE) {

				LOG_SNOOP(s_OperServ, "NS +E %s -- by %s (%s@%s) [%s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, param);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "+E %s -- by %s (%s@%s) [%s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, param);

				ni->email = str_duplicate(param);
				AddFlag(ni->flags, NI_HIDE_EMAIL);
				ni->regemail = NULL;
			}
			else {

				LOG_SNOOP(s_OperServ, "NS E %s -- by %s (%s@%s) [%s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->email, param);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "E %s -- by %s (%s@%s) [%s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->email, param);

				AddFlag(ni->flags, NI_MAILCHANGE);
				ni->regemail = str_duplicate(param);
			}

			AddFlag(ni->flags, NI_NOMAIL);

			srand(randomseed());

			ni->auth = ni->time_registered + (getrandom(1, 99999) * getrandom(1, 9999));
			ni->last_email_request = NOW;

			if (hasmail == TRUE)
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_CONFIRM_ACTUAL, ni->email);
			else
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_CONFIRM_OLD, ni->email);

			if (IS_NOT_NULL(mailfile = fopen("email.txt", "w"))) {

				char timebuf[64];

				lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_MAILTIME, NOW);

				fprintf(mailfile, "Date: %s\n", timebuf);
				fprintf(mailfile, "From: %s <%s>\n", CONF_NETWORK_NAME, CONF_RETURN_EMAIL);
				fprintf(mailfile, "To: %s\n", ni->email);

				fprintf(mailfile, lang_msg(GetCallerLang(), NS_SET_EMAIL_SUBJECT), ni->nick);

				lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, NOW);

				if (hasmail == TRUE) {

					fprintf(mailfile, lang_msg(GetCallerLang(), NS_SET_EMAIL_TEXT_1), callerUser->nick, timebuf, ni->auth, ni->email, ni->regemail, ni->auth);
					fprintf(mailfile, lang_msg(GetCallerLang(), NS_SET_EMAIL_TEXT_2), CONF_NETWORK_NAME, CONF_NETWORK_NAME);
				}
				else
					fprintf(mailfile, lang_msg(GetCallerLang(), NS_SET_EMAIL_TEXT_3), callerUser->nick, timebuf, ni->auth, ni->email, ni->auth);

				fclose(mailfile);

				snprintf(misc_buffer, MISC_BUFFER_SIZE, "%s -f %s -t < email.txt", CONF_SENDMAIL_PATH, CONF_RETURN_EMAIL);
				system(misc_buffer);

				snprintf(misc_buffer, MISC_BUFFER_SIZE, "rm -f email.txt");		
				system(misc_buffer);
			}
			else
				log_error(FACILITY_NICKSERV_HANDLE_DROP, __LINE__, LOG_TYPE_ERROR_RTL, LOG_SEVERITY_ERROR_SKIPPED, "do_set_email(): unable to create email.txt");
		}
	}
}

/*********************************************************/

static void do_set_lang(User *callerUser, CSTR param, short status) {

	LANG_ID lang_id;
	char *err;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_SET_LANG);

	if (str_equals_nocase(param, "LIST"))
		lang_send_list(s_NickServ, callerUser);

	else if (((lang_id = (unsigned int) strtoul(param, &err, 10)) == 0) || (*err != '\0')) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_LANG_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "SET LANG");
	}
	else {

		TRACE_MAIN();
		--lang_id;

		if (lang_is_active_language(lang_id)) {

			switch (status) {

				case 0:
					/* This is a registered and identified user changing their language. */
				case 3:
					/* This is an unauthorized user changing their language. */

					callerUser->ni->langID = COMPACT_LANG_ID(lang_id);
					send_notice_lang_to_user(s_NickServ, callerUser, lang_id, NS_SET_LANG_SET, lang_get_name(lang_id, TRUE), lang_get_name(lang_id, FALSE));

					log_services(LOG_SERVICES_NICKSERV_ACCESS, "SET L %s -- by %s (%s@%s)", param, callerUser->nick, callerUser->username, callerUser->host);
					break;

				case 1:
					/* This is an unregistered user. Change is temporary. */
					send_notice_lang_to_user(s_NickServ, callerUser, lang_id, NS_SET_LANG_SET_USER_NOTREG, lang_get_name(lang_id, TRUE), lang_get_name(lang_id, FALSE));
					send_notice_lang_to_user(s_NickServ, callerUser, lang_id, GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");
					break;

				case 2:
					/* This is an unidentified user. Change is temporary. ni is non null here. */
					send_notice_lang_to_user(s_NickServ, callerUser, lang_id, NS_SET_LANG_SET_USER_NOTID, lang_get_name(lang_id, TRUE), lang_get_name(lang_id, FALSE), callerUser->ni->nick);
					send_notice_lang_to_user(s_NickServ, callerUser, lang_id, CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
					break;
			}

			callerUser->current_lang = lang_id;
			current_caller_lang = lang_id;
		}
		else
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_LANG_ERROR_INVALID_ID);
	}
}

/*********************************************************/

static void do_set_kill(const User *callerUser, CSTR param) {

	NickInfo *ni = callerUser->ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_SET_URL);

	if (str_equals_nocase(param, "OFF")) {

		if (FlagUnset(ni->flags, NI_KILL_SLOW) && FlagUnset(ni->flags, NI_KILL_NORMAL) && FlagUnset(ni->flags, NI_KILL_FAST)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_ERROR_OPTION_ALREADY_OFF, "Kill", callerUser->ni->nick);
			return;
		}

		RemoveFlag(ni->flags, NI_KILL_SLOW);
		RemoveFlag(ni->flags, NI_KILL_NORMAL);
		RemoveFlag(ni->flags, NI_KILL_FAST);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_OPTION_OFF, "Kill", ni->nick);
		log_services(LOG_SERVICES_NICKSERV_ACCESS, "SET K OFF -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
	}
	else if (str_equals_nocase(param, "SLOW") || str_equals_nocase(param, "ON")) {

		TRACE_MAIN();
		if (FlagSet(ni->flags, NI_KILL_SLOW)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_KILL_ERROR_ALREADY_SLOW, ni->nick);
			return;
		}

		AddFlag(ni->flags, NI_KILL_SLOW);
		RemoveFlag(ni->flags, NI_KILL_NORMAL);
		RemoveFlag(ni->flags, NI_KILL_FAST);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_KILL_SLOW, ni->nick);
		log_services(LOG_SERVICES_NICKSERV_ACCESS, "SET K SLOW -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
	}
	else if (str_equals_nocase(param, "NORMAL")) {

		if (FlagSet(ni->flags, NI_KILL_NORMAL)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_KILL_ERROR_ALREADY_NORMAL, ni->nick);
			return;
		}

		AddFlag(ni->flags, NI_KILL_NORMAL);
		RemoveFlag(ni->flags, NI_KILL_SLOW);
		RemoveFlag(ni->flags, NI_KILL_FAST);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_KILL_NORMAL, ni->nick);

		log_services(LOG_SERVICES_NICKSERV_ACCESS, "SET K NORMAL -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
	}
	else if (str_equals_nocase(param, "FAST")) {

		if (FlagSet(ni->flags, NI_KILL_FAST)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_KILL_ERROR_ALREADY_FAST, ni->nick);
			return;
		}

		AddFlag(ni->flags, NI_KILL_FAST);
		RemoveFlag(ni->flags, NI_KILL_SLOW);
		RemoveFlag(ni->flags, NI_KILL_NORMAL);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_KILL_FAST, ni->nick);

		log_services(LOG_SERVICES_NICKSERV_ACCESS, "SET K FAST -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
	}
	else {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_KILL_SYNTAX_ERROR, "Kill");
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_SET_COMMAND, s_NS, "Kill");
	}
}

/*********************************************************/

static void do_set_option(const User *callerUser, CSTR option, CSTR param) {

	long int flag;
	char *optname, *logType;
	BOOL enable;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_SET);

	if (str_equals_nocase(param, "ON"))
		enable = TRUE;

	else if (str_equals_nocase(param, "OFF"))
		enable = FALSE;

	else {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_OPTION_SYNTAX_ERROR, option);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_SET_COMMAND, s_NS, option);
		return;
	}

	if (str_equals(option, "NOOP")) {

		flag = NI_NOOP;
		optname = "No Op";
		logType = "N";
	}
	else if (str_equals(option, "NOMEMO")) {

		flag = NI_NOMEMO;
		optname = "No Memo";
		logType = "M";
	}
	else if (str_equals(option, "NOCHANMEMO")) {

		flag = NI_NOCHANMEMO;
		optname = "No Chan Memo";
		logType = "C";
	}
	else if (str_equals(option, "NEVEROP")) {

		flag = NI_NEVEROP;
		optname = "Never Op";
		logType = "V";
	}
	else if (str_equals(option, "SECURE")) {

		flag = NI_SECURE;
		optname = "Secure";
		logType = "S";
	}
	else if (str_equals(option, "NOWELCOME")) {

		flag = NI_NOWELCOME;
		optname = "No Welcome";
		logType = "W";
	}
	else if (str_equals(option, "EMAILMEMOS")) {

		if (!CONF_SEND_REMINDER) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAILMEMOS_ERROR_DISABLED);
			return;
		}

		if ((enable == TRUE) && IS_NULL(callerUser->ni->email)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAILMEMOS_ERROR_NO_EMAIL_SET);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "SET EMAIL");
			return;
		}

		flag = NI_EMAILMEMOS;
		optname = "E-Mail Memos";
		logType = "E";
	}
	else {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_UNKNOWN_SET_COMMAND, option);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "SET");
		return;
	}

	if (enable == TRUE) {

		TRACE_MAIN();
		if (FlagSet(callerUser->ni->flags, flag)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_ERROR_OPTION_ALREADY_ON, optname, callerUser->ni->nick);
			return;
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_OPTION_ON, optname, callerUser->ni->nick);
		AddFlag(callerUser->ni->flags, flag);

		log_services(LOG_SERVICES_NICKSERV_ACCESS, "SET %s ON -- by %s (%s@%s)", logType, callerUser->nick, callerUser->username, callerUser->host);
	}
	else {

		TRACE_MAIN();
		if (FlagUnset(callerUser->ni->flags, flag)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_ERROR_OPTION_ALREADY_OFF, optname, callerUser->ni->nick);
			return;
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_OPTION_OFF, optname, callerUser->ni->nick);
		RemoveFlag(callerUser->ni->flags, flag);

		log_services(LOG_SERVICES_NICKSERV_ACCESS, "SET %s OFF -- by %s (%s@%s)", logType, callerUser->nick, callerUser->username, callerUser->host);
	}
}

/*********************************************************/

static void do_access(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *cmd;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_ACCESS);

	if (IS_NULL(cmd = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "ACCESS");
	}
	else if (str_equals_nocase(cmd, "LIST")) {

		int accessIdx;
		char **anAccess;
		const char *mask;

		if (IS_NOT_NULL(mask = strtok(NULL, " "))) {

			if (is_services_helpop(callerUser)) {

				NickInfo *ni;

				if (str_not_equals_nocase(mask, source) && (get_services_access(NULL, mask) > get_services_access(callerUser, source))) {

					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
					return;
				}

				if (IS_NOT_NULL(ni = findnick(mask))) {

					const char *pattern;

					if (FlagSet(ni->flags, NI_FORBIDDEN)) {

						send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);
						return;
					}

					pattern = strtok(NULL, " ");

					TRACE_MAIN();
					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_LIST_HEADER, ni->nick);

					for (anAccess = ni->access, accessIdx = 0; (accessIdx < ni->accesscount); ++anAccess, ++accessIdx) {

						if (pattern && !str_match_wild_nocase(pattern, *anAccess))
							continue;

						send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_LIST_ENTRIES, (accessIdx + 1), *anAccess);
					}

					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), END_OF_LIST);
					return;
				}
			}
			else if (str_not_equals_nocase(mask, source)) {

				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
				return;
			}
		}

		if (IS_NULL(callerUser->ni)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");
			return;
		}

		if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
			return;
		}

		TRACE_MAIN();
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_LIST_HEADER, callerUser->ni->nick);
		
		for (anAccess = callerUser->ni->access, accessIdx = 0; (accessIdx < callerUser->ni->accesscount); ++anAccess, ++accessIdx) {

			if (mask && !str_match_wild_nocase(mask, *anAccess))
				continue;

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_LIST_ENTRIES, (accessIdx + 1), *anAccess);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), END_OF_LIST);
	}
	else if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
	}
	else if (FlagSet(callerUser->ni->flags, NI_AUTH)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_ERROR_MUST_AUTH);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
	}
	else if (str_equals_nocase(cmd, "ADD")) {

		char *string, mask[IRCBUFSIZE];

		if (CONF_SET_READONLY) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_ERROR_READONLY);
			return;
		}

		if (IS_NULL(string = strtok(NULL, " "))) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_SYNTAX_ERROR);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "ACCESS");
			return;
		}

		str_copy_checked(string, mask, sizeof(mask));

		if (!strchr(mask, '@') || strchr(mask, '!')) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_NO_USER_AT_HOST_MASK);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "ACCESS");
		}
		else if (str_len(mask) > MASKMAX)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_MASK_MAX_LENGTH, MASKMAX);

		else if (mask_contains_crypt(mask))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_INVALID_ENTRY);

		else if (!validate_mask(mask, TRUE, FALSE, FALSE))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_MASK);

		else if (str_spn(mask, "*.@?-:"))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_ERROR_INSECURE_MASK);

		else {

			int accessIdx;
			char **anAccess;

			switch (validate_access(mask)) {

				case 3:
					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_QUESTION_MARK);
					return;

				case 2:
					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_MASK);
					return;

				case 1:
					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CS_XOP_ADD_WARNING_MASK_CHANGED, mask);
					break;

				default:
					/* Mask accepted without modifications. */
					break;
			}

			TRACE_MAIN();
			for (anAccess = callerUser->ni->access, accessIdx = 0; (accessIdx < callerUser->ni->accesscount); ++anAccess, ++accessIdx) {

				if (str_equals_nocase(*anAccess, mask)) {

					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_ERROR_MASK_ALREADY_PRESENT, *anAccess);
					return;
				}
			}

			if ((CONF_USER_ACCESS_MAX > 0) && (callerUser->ni->accesscount >= CONF_USER_ACCESS_MAX)) {

				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_ERROR_LIST_FULL, callerUser->ni->nick);
				return;
			}

			TRACE_MAIN();
			++(callerUser->ni->accesscount);
			callerUser->ni->access = mem_realloc(callerUser->ni->access, sizeof(char *) * callerUser->ni->accesscount);
			callerUser->ni->access[callerUser->ni->accesscount - 1] = str_duplicate(mask);

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_MASK_ADDED, mask);
			
			log_services(LOG_SERVICES_NICKSERV_ACCESS, "ADD %s -- by %s (%s@%s)", mask, source, callerUser->username, callerUser->host);
		}
	}
	else if (str_equals_nocase(cmd, "DEL")) {

		const char *mask;

		if (IS_NULL(mask = strtok(NULL, " "))) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_SYNTAX_ERROR);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "ACCESS");
		}
		else {

			int accessIdx;
			char **anAccess;
			char *err;

			accessIdx = strtol(mask, &err, 10);

			TRACE_MAIN();
			if (*err == '\0') {

				if ((accessIdx > 0) && (accessIdx <= callerUser->ni->accesscount))
					anAccess = &(callerUser->ni->access[--accessIdx]);

				else {

					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_LIST_NOT_FOUND, accessIdx, callerUser->ni->nick);
					return;
				}
			}
			else {

				TRACE_MAIN();
				for (anAccess = callerUser->ni->access, accessIdx = 0; (accessIdx < callerUser->ni->accesscount); ++anAccess, ++accessIdx) {

					if (str_equals_nocase(*anAccess, mask))
						break;
				}

				if (accessIdx == callerUser->ni->accesscount) {

					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_ERROR_MASK_NOT_PRESENT, mask);
					return;
				}
			}

			TRACE_MAIN();
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_MASK_DELETED, *anAccess);

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), WARNING_READONLY);

			log_services(LOG_SERVICES_NICKSERV_ACCESS, "DEL %s -- by %s (%s@%s)", *anAccess, source, callerUser->username, callerUser->host);

			mem_free(*anAccess);
			--(callerUser->ni->accesscount);

			if (accessIdx < callerUser->ni->accesscount)	/* If it wasn't the last entry... */
				memmove(anAccess, anAccess + 1, (callerUser->ni->accesscount - accessIdx) * sizeof(char *));

			TRACE_MAIN();
			if (callerUser->ni->accesscount)	/* If there are any entries left... */
				callerUser->ni->access = mem_realloc(callerUser->ni->access, callerUser->ni->accesscount * sizeof(char *));

			else {

				mem_free(callerUser->ni->access);
				callerUser->ni->access = NULL;
			}
		}
	}
	else if (str_equals_nocase(cmd, "WIPE")) {

		int accessIdx;
		char **anAccess;

		TRACE_MAIN();
		for (anAccess = callerUser->ni->access, accessIdx = 0; (accessIdx < callerUser->ni->accesscount); ++anAccess, ++accessIdx)
			mem_free(*anAccess);

		callerUser->ni->accesscount = 0;
		mem_free(callerUser->ni->access);
		callerUser->ni->access = NULL;
		
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_LIST_WIPED);

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), WARNING_READONLY);

		log_services(LOG_SERVICES_NICKSERV_ACCESS, "WIPE -- by %s (%s@%s)", source, callerUser->username, callerUser->host);
	}
	else {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACCESS_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "ACCESS");
	}
}

/*********************************************************/

static void do_acc(CSTR source, User *callerUser, ServiceCommandData *data) {
	
	const char *nick;
	User *user;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_ACC);

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACC_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "ACC");
	}
	else if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_MAX_LENGTH, NICKMAX);

	else if (IS_NULL(ni = findnick(nick)))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACC_NICK_NOT_REG, nick);

	else if (FlagSet(ni->flags, NI_FORBIDDEN))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACC_NICK_FORBIDDEN, ni->nick);

	else if (FlagSet(ni->flags, NI_FROZEN))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACC_NICK_FROZEN, ni->nick);

	else if (IS_NULL(user = hash_onlineuser_find(nick)))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACC_NICK_OFFLINE, nick);

	else if (user_is_identified_to(user, ni->nick))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACC_NICK_ID, ni->nick);

	else if (is_on_access(user, ni))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACC_NICK_ON_ACCESS, ni->nick);

	else
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ACC_NICK_NOT_ID, ni->nick);
}

/*********************************************************/

static void do_info(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *nick;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_INFO);

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "INFO");
	}
	else if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_MAX_LENGTH, NICKMAX);
	
	else if (IS_NULL(ni = findnick(nick)))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_NOT_REG, nick);

	else if (FlagSet(ni->flags, NI_FROZEN) && !is_services_oper(callerUser)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_HEADER, ni->nick);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FROZEN, ni->nick);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), END_OF_INFO);
	}
	else if FlagSet(ni->flags, NI_FORBIDDEN) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_HEADER, ni->nick);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), END_OF_INFO);
	}
	else {

		char		buffer[IRCBUFSIZE];
		time_t		seenTime = (NOW - ni->last_seen);
		BOOL		isHelper = (is_services_helpop(callerUser) || user_is_services_agent(callerUser));
		LANG_ID		langID;
		User		*user;
		size_t		len = 0;


		TRACE_MAIN();
		user = hash_onlineuser_find(nick);

		langID = EXTRACT_LANG_ID(ni->langID);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_HEADER, ni->nick);

		if (ni->last_realname)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_REAL_NAME, ni->last_realname);

		if (IS_NOT_NULL(user)) {
			
			if (user_is_identified_to(user, ni->nick))
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_IS_ONLINE_ID, ni->nick);

			else if (is_on_access(user, ni))
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_IS_ONLINE_ON_ACCESS, ni->nick);
		}

		if (ni->last_usermask)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_LAST_USERMASK, ni->last_usermask);

		TRACE_MAIN();
		lang_format_localtime(buffer, sizeof(buffer), GetCallerLang(), TIME_FORMAT_DATETIME, ni->time_registered);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_INFO_DATE_REG, buffer);

		lang_format_localtime(buffer, sizeof(buffer), GetCallerLang(), TIME_FORMAT_DATETIME, ni->last_seen);

		if (seenTime > ONE_DAY) {

			if (seenTime / ONE_DAY == 1)
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_LAST_SEEN_1D, buffer);
			else
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_LAST_SEEN_XD, buffer, seenTime / ONE_DAY);
		}
		else if (seenTime > ONE_HOUR) {

			if (seenTime / ONE_HOUR == 1)
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_LAST_SEEN_1H, buffer);
			else
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_LAST_SEEN_XH, buffer, seenTime / ONE_HOUR);
		}
		else
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_LAST_SEEN_LESS_THAN_1H, buffer);

		TRACE_MAIN();
		lang_format_localtime(buffer, sizeof(buffer), GetCallerLang(), TIME_FORMAT_DATETIME, NOW);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), INFO_CURRENT_TIME, buffer);

		if (ni->url)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_INFO_URL, ni->url);

		if (ni->email && (FlagUnset(ni->flags, NI_HIDE_EMAIL)))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_INFO_EMAIL_ADDRESS, ni->email);

		TRACE_MAIN();

		/* Send options. */
		if (FlagSet(ni->flags, NI_KILL_SLOW))
			len += str_copy_checked("Kill (Slow)", buffer, sizeof(buffer));
		else if (FlagSet(ni->flags, NI_KILL_NORMAL))
			len += str_copy_checked("Kill (Normal)", buffer, sizeof(buffer));
		else if (FlagSet(ni->flags, NI_KILL_FAST))
			len += str_copy_checked("Kill (Fast)", buffer, sizeof(buffer));

		APPEND_FLAG(ni->flags, NI_SECURE, "Secure")
		APPEND_FLAG(ni->flags, NI_NEVEROP, "Never Op")
		APPEND_FLAG(ni->flags, NI_NOOP, "No Op")
		APPEND_FLAG(ni->flags, NI_NOMEMO, "No Memo")
		APPEND_FLAG(ni->flags, NI_NOWELCOME, "No Welcome")
		APPEND_FLAG(ni->flags, NI_NOCHANMEMO, "No Chan Memo")

		if (len == 0)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_INFO_NO_OPTIONS_SET);
		else
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_INFO_OPTIONS_LIST_HEADER, buffer);

		/* Send language. */
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_INFO_LANGUAGE, lang_get_name(langID, TRUE), lang_get_name(langID, FALSE));

		/* Send forward, if any. */
		if (ni->forward)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_MEMO_FORWARD, ni->forward);

		if (user_is_identified_to(callerUser, ni->nick) && !isHelper) {

			if (FlagSet(ni->flags, NI_HOLD))
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_PUB_NICK_HELD);

			TRACE_MAIN();
			if (FlagSet(ni->flags, NI_AUTH) || IS_NULL(ni->email))
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_NICK_NOT_AUTH);
			else
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_NICK_AUTH, ni->email);

			if (FlagSet(ni->flags, NI_MAILCHANGE))
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_MAIL_CHANGE, ni->regemail);

			if (FlagSet(ni->flags, NI_DROP))
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_DROP_REQUEST);
		}
		else if (isHelper) {

			TRACE_MAIN();
			if (FlagSet(ni->flags, NI_FROZEN))
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_OPER_NICK_FROZEN, ni->freeze);
		
			if (FlagSet(ni->flags, NI_MARK))
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_OPER_NICK_MARKED, ni->mark);
			
			if (FlagSet(ni->flags, NI_HOLD))
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_OPER_NICK_HELD, ni->hold);

			if (IS_NULL(ni->email))
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_OPER_NO_REGEMAIL);
			else if (FlagSet(ni->flags, NI_AUTH))
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_OPER_NOT_AUTH, ni->email, ni->auth);
			else
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_NICK_AUTH, ni->email);

			if (FlagSet(ni->flags, NI_MAILCHANGE))
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_OPER_MAILCHANGE, ni->regemail, ni->auth);

			if (FlagSet(ni->flags, NI_DROP))
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_INFO_OPER_DROP_REQUEST, ni->auth);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), END_OF_INFO);
	}
}

/*********************************************************/
			
static void do_recover(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *nick, *pass;
	User *user;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_RECOVER);

	if (IS_NULL(nick = strtok(NULL, " ")) || IS_NULL(pass = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_RECOVER_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "RECOVER");
	}
	else if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_MAX_LENGTH, NICKMAX);

	else if (str_len(pass) > PASSMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_MAX_LENGTH, PASSMAX);

	else if (IS_NULL(ni = findnick(nick)))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_NOT_REG, nick);

	else if (FlagSet(ni->flags, NI_FROZEN)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FROZEN, ni->nick);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), EMAIL_NETWORK_FOR_MORE_INFO, MAIL_KLINE);
	}
	else if (FlagSet(ni->flags, NI_FORBIDDEN)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), EMAIL_NETWORK_FOR_MORE_INFO, MAIL_KLINE);
	}
	else if (IS_NULL(user = hash_onlineuser_find(nick)))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_NOT_IN_USE, ni->nick);

	else if (str_equals_nocase(nick, source))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_RECOVER_ERROR_CANT_RECOVER_SELF);

	else if (str_equals(pass, ni->pass)) {

		TRACE_MAIN();
		if (FlagSet(ni->flags, NI_ENFORCED))
			release(ni, FALSE);
		else
			collide(ni, FALSE);

		TRACE_MAIN();
		if (!user_is_identified_to(callerUser, ni->nick)) {

			++(callerUser->idcount);
			callerUser->id_nicks = mem_realloc(callerUser->id_nicks, sizeof(char *) * callerUser->idcount);
			callerUser->id_nicks[callerUser->idcount - 1] = str_duplicate(ni->nick);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_RECOVER_NICK_RECOVERED, ni->nick);

//		Bahamut currently dislikes this.
//		send_SVSNICK(source, ni->nick);

		if (CONF_SET_EXTRASNOOP)
			LOG_SNOOP(s_OperServ, "NS Rc %s -- by %s (%s@%s) [%s]", ni->nick, source, callerUser->username, callerUser->host, pass);

		log_services(LOG_SERVICES_NICKSERV_GENERAL, "Rc %s -- by %s (%s@%s) [%s]", ni->nick, source, callerUser->username, callerUser->host, pass);
	}
	else {

		TRACE_MAIN();
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_BAD_PASS, ni->nick);

		TRACE_MAIN();
		if (CONF_SET_EXTRASNOOP)
			LOG_SNOOP(s_OperServ, "NS *Rc %s -- by %s (%s@%s) [%s]", ni->nick, source, callerUser->username, callerUser->host, pass);

		log_services(LOG_SERVICES_NICKSERV_GENERAL, "*Rc %s -- by %s (%s@%s) [%s]", ni->nick, source, callerUser->username, callerUser->host, pass);

		update_invalid_password_count(callerUser, s_NickServ, nick);
	}
}

/*********************************************************/

static void do_release(CSTR source, User *callerUser, ServiceCommandData *data) {
				
	const char *nick, *pass;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_RELEASE);

	if (IS_NULL(nick = strtok(NULL, " ")) || IS_NULL(pass = strtok(NULL, " "))) {
		
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_RELEASE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "RELEASE");
	}
	else if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_MAX_LENGTH, NICKMAX);

	else if (str_len(pass) > PASSMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_MAX_LENGTH, PASSMAX);

	else if (IS_NULL(ni = findnick(nick)))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_NOT_REG, nick);

	else if (FlagUnset(ni->flags, NI_ENFORCED))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_RELEASE_ERROR_NICK_NOT_HELD, ni->nick);

	else if (FlagSet(ni->flags, NI_FROZEN)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FROZEN, ni->nick);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), EMAIL_NETWORK_FOR_MORE_INFO, MAIL_KLINE);
	}
	else if (FlagSet(ni->flags, NI_FORBIDDEN)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), EMAIL_NETWORK_FOR_MORE_INFO, MAIL_KLINE);
	}
	else if (str_equals(pass, ni->pass)) {

		TRACE_MAIN();
		release(ni, FALSE);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_RELEASE_NICK_RELEASED, ni->nick);

		if (CONF_SET_EXTRASNOOP)
			LOG_SNOOP(s_OperServ, "NS Re %s -- by %s (%s@%s) [%s]", ni->nick, source, callerUser->username, callerUser->host, pass);

		log_services(LOG_SERVICES_NICKSERV_GENERAL, "Re %s -- by %s (%s@%s) [%s]", ni->nick, source, callerUser->username, callerUser->host, pass);
	}
	else {

		TRACE_MAIN();
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_BAD_PASS, ni->nick);

		TRACE_MAIN();
		if (CONF_SET_EXTRASNOOP)
			LOG_SNOOP(s_OperServ, "NS *Re %s -- by %s (%s@%s) [%s]", ni->nick, source, callerUser->username, callerUser->host, pass);

		log_services(LOG_SERVICES_NICKSERV_GENERAL, "*Re %s -- by %s (%s@%s) [%s]", ni->nick, source, callerUser->username, callerUser->host, pass);

		update_invalid_password_count(callerUser, s_NickServ, nick);
	}
}

/*********************************************************/

static void do_ghost(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *nick, *pass;
	User *user;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_GHOST);

	if (IS_NULL(nick = strtok(NULL, " ")) || IS_NULL(pass = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_GHOST_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "GHOST");
	}
	else if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_MAX_LENGTH, NICKMAX);

	else if (str_len(pass) > PASSMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_MAX_LENGTH, PASSMAX);

	else if (IS_NULL(ni = findnick(nick)))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_NOT_REG, nick);

	else if (IS_NULL(user = hash_onlineuser_find(nick)))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_NOT_IN_USE, nick);

	else if (FlagSet(user->mode, UMODE_z))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_GHOST_ERROR_CANT_GHOST_AGENT, ni->nick);

	else if (str_equals_nocase(nick, source))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_GHOST_ERROR_CANT_GHOST_SELF);

	else if (FlagSet(ni->flags, NI_FORBIDDEN)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), EMAIL_NETWORK_FOR_MORE_INFO, MAIL_KLINE);
	}
	else if (FlagSet(ni->flags, NI_FROZEN)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FROZEN, ni->nick);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), EMAIL_NETWORK_FOR_MORE_INFO, MAIL_KLINE);
	}
	else if (str_equals(pass, ni->pass)) {

		TRACE_MAIN();
		if (FlagSet(ni->flags, NI_ENFORCED))
			release(ni, FALSE);

		else {

			char reason[IRCBUFSIZE];

			snprintf(reason, sizeof(reason), lang_msg(user->current_lang, NS_GHOST_KILL_REASON), source);
			send_KILL(s_NickServ, nick, reason, TRUE);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_GHOST_NICK_GHOSTED);

		if (CONF_SET_EXTRASNOOP)
			LOG_SNOOP(s_OperServ, "NS K %s -- by %s (%s@%s) [%s]", ni->nick, source, callerUser->username, callerUser->host, pass);

		log_services(LOG_SERVICES_NICKSERV_GENERAL, "K %s -- by %s (%s@%s) [%s]", ni->nick, source, callerUser->username, callerUser->host, pass);
	}
	else {

		TRACE_MAIN();
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_BAD_PASS, ni->nick);

		if (CONF_SET_EXTRASNOOP)
			LOG_SNOOP(s_OperServ, "NS *K %s -- by %s (%s@%s) [%s]", ni->nick, source, callerUser->username, callerUser->host, pass);

		log_services(LOG_SERVICES_NICKSERV_GENERAL, "*K %s -- by %s (%s@%s) [%s]", ni->nick, source, callerUser->username, callerUser->host, pass);

		update_invalid_password_count(callerUser, s_NickServ, nick);
	}
}

/*********************************************************/

static void do_delete(CSTR source, User *callerUser, ServiceCommandData *data) {
	
	const char *nick;
	NickInfo *ni;

	
	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_DELETE);
	
	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DELETE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "DELETE");
	}
	else if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);

	else if (IS_NULL(ni = findnick(nick))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_NOT_REG, nick);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS *De %s -- by %s (%s@%s) [Not Registered]", nick, source, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS *De %s -- by %s (%s@%s) through %s [Not Registered]", nick, source, callerUser->username, callerUser->host, data->operName);
	}
	else if (FlagSet(ni->flags, NI_FORBIDDEN))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);

	else if (FlagSet(ni->flags, NI_MARK)) {

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS *De %s -- by %s (%s@%s) [Marked]", ni->nick, source, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "*De %s -- by %s (%s@%s) [Marked]", ni->nick, source, callerUser->username, callerUser->host);

			send_globops(s_NickServ, "\2%s\2 tried deleting Marked nick \2%s\2", source, ni->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS *De %s -- by %s (%s@%s) through %s [Marked]", ni->nick, source, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "*De %s -- by %s (%s@%s) through %s [Marked]", ni->nick, source, callerUser->username, callerUser->host, data->operName);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) tried deleting Marked nick \2%s\2", source, data->operName, ni->nick);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DELETE_ERROR_NICK_IS_MARKED);
	}
	else if (get_services_access(NULL, nick) == ULEVEL_MASTER) {

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS *De %s -- by %s (%s@%s) [Services Master]", ni->nick, source, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "*De %s -- by %s (%s@%s) [Services Master]", ni->nick, source, callerUser->username, callerUser->host);

			send_globops(s_NickServ, "\2%s\2 tried deleting Services Master \2%s\2", source, ni->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS *De %s -- by %s (%s@%s) through %s [Services Master]", ni->nick, source, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "*De %s -- by %s (%s@%s) through %s [Services Master]", ni->nick, source, callerUser->username, callerUser->host, data->operName);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) tried deleting Services Master \2%s\2", source, data->operName, ni->nick);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DELETE_ERROR_NICK_IS_MASTER);
	}
	else if ((get_services_access(NULL, nick) >= ULEVEL_OPER) && !is_services_master(callerUser)) {

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS *De %s -- by %s (%s@%s) [Services Valid Oper]", ni->nick, source, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "*De %s -- by %s (%s@%s) [Services Valid Oper]", ni->nick, source, callerUser->username, callerUser->host);

			send_globops(s_NickServ, "\2%s\2 tried deleting Services valid Oper \2%s\2", source, ni->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS *De %s -- by %s (%s@%s) through %s [Services Valid Oper]", ni->nick, source, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "*De %s -- by %s (%s@%s) through %s [Services Valid Oper]", ni->nick, source, callerUser->username, callerUser->host, data->operName);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) tried deleting Services valid Oper \2%s\2", source, data->operName, ni->nick);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DELETE_ERROR_NICK_IS_VALID_OPER);
	}
	else {

		TRACE_MAIN();

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS De %s -- by %s (%s@%s)", ni->nick, source, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "De %s -- by %s (%s@%s)", ni->nick, source, callerUser->username, callerUser->host);

			send_globops(s_NickServ, "\2%s\2 deleted nickname \2%s\2", source, ni->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS De %s -- by %s (%s@%s) through %s", ni->nick, source, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "De %s -- by %s (%s@%s) through %s", ni->nick, source, callerUser->username, callerUser->host, data->operName);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) deleted nickname \2%s\2", source, data->operName, ni->nick);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_DELETE_NICK_DELETED, ni->nick);

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), WARNING_READONLY);

		delnick(ni);
	}
}

/*********************************************************/

static void do_sendcode(CSTR source, User *callerUser, ServiceCommandData *data) {
	
	const char *nick;
	NickInfo *ni;
	
	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_SENDCODE);
	
	if (IS_NULL(nick = strtok(NULL, " "))) {
		
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SENDCODE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "SENDCODE");
	}
	else if (str_len(nick) > NICKMAX) {
		
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);
		
		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS *SC -- by %s (%s@%s) [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, NICKMAX);
		else	
			LOG_SNOOP(s_OperServ, "NS *SC -- by %s (%s@%s) through %s [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, NICKMAX);
	}
	else if (IS_NULL(ni = findnick(nick))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_NOT_REG, nick);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS *SC %s -- by %s (%s@%s) [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS *SC %s -- by %s (%s@%s) through %s [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (FlagSet(ni->flags, NI_FORBIDDEN))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);
	
	else if (!FlagSet(ni->flags, NI_AUTH | NI_DROP | NI_MAILCHANGE) && (ni->auth == 0))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SENDCODE_ERROR_NO_CODE, ni->nick);
	
	else {
		
		FILE *mailfile;
		char type[8];
		LANG_MSG_ID operation_msg_id;
		
		if (FlagSet(ni->flags, NI_DROP)) {
			snprintf(type, 7, "DROP");
			operation_msg_id = NS_SENDCODE_EMAIL_SUBJECT_DROP;
		}
		else if (FlagSet(ni->flags, NI_MAILCHANGE)) {
			snprintf(type, 7, "MAIL");
			operation_msg_id = NS_SENDCODE_EMAIL_SUBJECT_MAIL;
		} 
		else {  /* It must be a registration code then... */
			snprintf(type, 7, "AUTH");
			operation_msg_id = NS_SENDCODE_EMAIL_SUBJECT_AUTH;
		}
		
		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS SC %s -- by %s (%s@%s) [%s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, type);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "SC %s -- by %s (%s@%s) [%s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, type);

			send_globops(s_NickServ, "\2%s\2 used SENDCODE on nick \2%s\2 [%s]", callerUser->nick, ni->nick, type);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS SC %s -- by %s (%s@%s) through %s [%s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, type);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "SC %s -- by %s (%s@%s) through %s [%s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, type);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) used SENDCODE on nick \2%s\2 [%s]", callerUser->nick, data->operName, ni->nick, type);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_SENDCODE_CODE_SENT, ni->nick, ni->email);

		if (IS_NOT_NULL(mailfile = fopen("sendcode.txt", "w"))) {

			char timebuf[64];

			lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_MAILTIME, NOW);

			fprintf(mailfile, "Date: %s\n", timebuf);
			fprintf(mailfile, "From: %s <%s>\n", CONF_NETWORK_NAME, CONF_RETURN_EMAIL);
			fprintf(mailfile, "To: %s\n", ni->email);

			lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, NOW);

			fprintf(mailfile, lang_msg(GetNickLang(ni), NS_SENDCODE_EMAIL_SUBJECT), lang_msg(GetNickLang(ni), operation_msg_id), ni->nick);
			fprintf(mailfile, lang_msg(GetNickLang(ni), NS_SENDCODE_EMAIL_TEXT), data->operName, timebuf, ni->auth);
			
			if (FlagSet(ni->flags, NI_AUTH)) {
				fprintf(mailfile, lang_msg(GetNickLang(ni), NS_SENDCODE_EMAIL_AUTH), CONF_NETWORK_NAME, ni->nick, ni->auth);
			}
			else if (FlagSet(ni->flags, NI_DROP)) {
				fprintf(mailfile, lang_msg(GetNickLang(ni), NS_SENDCODE_EMAIL_DROP), CONF_NETWORK_NAME, ni->nick, ni->nick, ni->auth);
			}
			else if (FlagSet(ni->flags, NI_MAILCHANGE)) {
				fprintf(mailfile, lang_msg(GetNickLang(ni), NS_SENDCODE_EMAIL_MAIL1), ni->email, ni->regemail, CONF_NETWORK_NAME, ni->nick, ni->auth);
				fprintf(mailfile, lang_msg(GetNickLang(ni), NS_SENDCODE_EMAIL_MAIL2), CONF_NETWORK_NAME, ni->nick);
			}
			
			fprintf(mailfile, lang_msg(GetNickLang(ni), CSNS_EMAIL_TEXT_ABUSE), MAIL_ABUSE, CONF_NETWORK_NAME);
			fclose(mailfile);

			snprintf(misc_buffer, MISC_BUFFER_SIZE, "%s -f %s -t < sendcode.txt", CONF_SENDMAIL_PATH, CONF_RETURN_EMAIL);
			system(misc_buffer);

			snprintf(misc_buffer, MISC_BUFFER_SIZE, "rm -f sendcode.txt");		
			system(misc_buffer);
		}
		else
			log_error(FACILITY_NICKSERV_HANDLE_SENDCODE, __LINE__, LOG_TYPE_ERROR_RTL, LOG_SEVERITY_ERROR_SKIPPED, "do_sendcode(): unable to create sendcode.txt");
	}
}

static void do_sendpass(CSTR source, User *callerUser, ServiceCommandData *data) {
				
	const char *nick;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_SENDPASS);

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SENDPASS_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "SENDPASS");
	}
	else if (str_len(nick) > NICKMAX) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS *S -- by %s (%s@%s) [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, NICKMAX);
		else
			LOG_SNOOP(s_OperServ, "NS *S -- by %s (%s@%s) through %s [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, NICKMAX);
	}
	else if (IS_NULL(ni = findnick(nick))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_NOT_REG, nick);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS *S %s -- by %s (%s@%s) [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS *S %s -- by %s (%s@%s) through %s [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (FlagSet(ni->flags, NI_FORBIDDEN))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);

	else if (FlagSet(ni->flags, NI_MARK)) {

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS *S %s -- by %s (%s@%s) [Marked]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
			send_globops(s_NickServ, "\2%s\2 tried to use SENDPASS on MARKed nick \2%s\2", source, ni->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS *S %s -- by %s (%s@%s) through %s [Marked]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) tried to use SENDPASS on MARKed nick \2%s\2", source, data->operName, ni->nick);
		}
		
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_NS_ERROR_NICK_MARKED, ni->nick);
	}
	else if (FlagSet(ni->flags, NI_AUTH) || !ni->email)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SENDPASS_ERROR_NICK_NOT_AUTH, ni->nick);

	else {

		FILE *mailfile;

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS S %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "S %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_NickServ, "\2%s\2 used SENDPASS on nick \2%s\2", callerUser->nick, ni->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS S %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "S %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) used SENDPASS on nick \2%s\2", callerUser->nick, data->operName, ni->nick);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_SENDPASS_PASSWORD_SENT, ni->nick, ni->email);

		if (IS_NOT_NULL(mailfile = fopen("sendpass.txt", "w"))) {

			char timebuf[64];

			lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_MAILTIME, NOW);

			fprintf(mailfile, "Date: %s\n", timebuf);
			fprintf(mailfile, "From: %s <%s>\n", CONF_NETWORK_NAME, CONF_RETURN_EMAIL);
			fprintf(mailfile, "To: %s\n", ni->email);

			lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, NOW);

			fprintf(mailfile, lang_msg(GetNickLang(ni), NS_SENDPASS_EMAIL_SUBJECT), ni->nick);
			fprintf(mailfile, lang_msg(GetNickLang(ni), NS_SENDPASS_EMAIL_TEXT), data->operName, timebuf, ni->nick, ni->pass);
			fprintf(mailfile, lang_msg(GetNickLang(ni), CSNS_EMAIL_TEXT_ABUSE), MAIL_ABUSE, CONF_NETWORK_NAME);
			fclose(mailfile);

			snprintf(misc_buffer, MISC_BUFFER_SIZE, "%s -f %s -t < sendpass.txt", CONF_SENDMAIL_PATH, CONF_RETURN_EMAIL);
			system(misc_buffer);

			snprintf(misc_buffer, MISC_BUFFER_SIZE, "rm -f sendpass.txt");		
			system(misc_buffer);
		}
		else
			log_error(FACILITY_NICKSERV_HANDLE_SENDPASS, __LINE__, LOG_TYPE_ERROR_RTL, LOG_SEVERITY_ERROR_SKIPPED, "do_sendpass(): unable to create sendpass.txt");
	}
}

/*********************************************************/

static void do_getpass(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *nick;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_GETPASS);

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_GETPASS_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "GETPASS");
	}
	else if (str_len(nick) > NICKMAX) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS *G -- by %s (%s@%s) [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, NICKMAX);
		else
			LOG_SNOOP(s_OperServ, "NS *G -- by %s (%s@%s) through %s [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, NICKMAX);
	}
	else if (IS_NULL(ni = findnick(nick))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_NOT_REG, nick);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS *G %s -- by %s (%s@%s) [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS *G %s -- by %s (%s@%s) through %s [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (get_services_access(NULL, nick) == ULEVEL_MASTER) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_GETPASS_ERROR_NICK_IS_MASTER);
		send_globops(s_NickServ, "\2%s\2 tried GETPASSing the Services Master's nick", source);
	}
	else if (FlagSet(ni->flags, NI_FORBIDDEN)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_GETPASS_ERROR_NICK_FORBIDDEN, ni->nick);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS *G %s -- by %s (%s@%s) [Forbidden]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS *G %s -- by %s (%s@%s) through %s [Forbidden]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (str_not_equals_nocase(source, nick) && (get_services_access(NULL, nick) > get_services_access(callerUser, source))) {

		TRACE_MAIN();

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS *G %s -- by %s (%s@%s) [SA]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "*G %s -- by %s (%s@%s) [SA]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_NickServ, "\2%s\2 tried GETPASSing Services Admin \2%s\2.", callerUser->nick, ni->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS *G %s -- by %s (%s@%s) through %s [SA]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "*G %s -- by %s (%s@%s) through %s [SA]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) tried GETPASSing Services Admin \2%s\2.", callerUser->nick, data->operName, ni->nick);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_GETPASS_ERROR_NICK_IS_SA);
	}
	else if (FlagSet(ni->flags, NI_MARK) && !is_services_root(callerUser)) {

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS *G %s -- by %s (%s@%s) [MARKed]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
			send_globops(s_NickServ, "\2%s\2 tried GETPASSing MARKed nickname \2%s\2", source, ni->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS *G %s -- by %s (%s@%s) through %s [MARKed]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) tried GETPASSing MARKed nickname \2%s\2", source, data->operName, ni->nick);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_NS_ERROR_NICK_MARKED, ni->nick);
	}
	else {

		TRACE_MAIN();
		if (FlagSet(ni->flags, NI_MARK)) {

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "NS G %s -- by %s (%s@%s) [SRA->MARK]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "G %s -- by %s (%s@%s) [SRA->MARK - Pass: %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->pass);

				send_globops(s_NickServ, "\2%s\2 used GETPASS on MARKed nick \2%s\2", callerUser->nick, ni->nick);
			}
			else {

				LOG_SNOOP(s_OperServ, "NS G %s -- by %s (%s@%s) through %s [SRA->MARK]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "G %s -- by %s (%s@%s) through %s [SRA->MARK - Pass: %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->pass);

				send_globops(s_NickServ, "\2%s\2 (through \2%s\2) used GETPASS on MARKed nick \2%s\2", callerUser->nick, data->operName, ni->nick);
			}

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_GETPASS_SHOW_PASSWORD, ni->nick, ni->pass);
		}
		else {

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "NS G %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "G %s -- by %s (%s@%s) [Pass: %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->pass);

				send_globops(s_NickServ, "\2%s\2 used GETPASS on \2%s\2", source, ni->nick);
			}
			else {

				LOG_SNOOP(s_OperServ, "NS G %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "G %s -- by %s (%s@%s) through %s [Pass: %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->pass);

				send_globops(s_NickServ, "\2%s\2 (through \2%s\2) used GETPASS on \2%s\2", source, data->operName, ni->nick);
			}

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_GETPASS_SHOW_PASSWORD, ni->nick, ni->pass);
		}
	}
}

/*********************************************************/

static void do_forbid(CSTR source, User *callerUser, ServiceCommandData *data) {

	NickInfo *ni;
	const char *nick;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_FORBID);

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_SYNTAX_ERROR, "FORBID");
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "FORBID");
	}
	else if (str_len(nick) > NICKMAX) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS +F* -- by %s (%s@%s) [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, NICKMAX);
		else
			LOG_SNOOP(s_OperServ, "NS +F* -- by %s (%s@%s) through %s [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, NICKMAX);
	}
	else if (!validate_nick(nick, FALSE)) {

		send_notice_to_user(s_NickServ, callerUser, "Invalid nick.");

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS +F* -- by %s (%s@%s) [Lamer]", callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS +F* -- by %s (%s@%s) through %s [Lamer]", callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (IS_NOT_NULL(ni = findnick(nick))) {

		if (FlagSet(ni->flags, NI_FORBIDDEN)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_ERROR_NICK_ALREADY_FLAGGED, ni->nick, "FORBIDDEN");

			if (data->operMatch)
				LOG_SNOOP(s_OperServ, "NS +F* %s -- by %s (%s@%s) [Already Forbidden]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
			else
				LOG_SNOOP(s_OperServ, "NS +F* %s -- by %s (%s@%s) through %s [Already Forbidden]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
		}
		else {

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "NS +F* %s -- by %s (%s@%s) [Registered]", nick, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "+F* %s -- by %s (%s@%s) [Registered]", nick, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				LOG_SNOOP(s_OperServ, "NS +F* %s -- by %s (%s@%s) through %s [SA]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "+F* %s -- by %s (%s@%s) through %s [SA]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}

			send_notice_to_user(s_NickServ, callerUser, "You may not forbid registered nicks. Please use FREEZE instead.");
		}
	}
	else {

		ni = makenick(nick);

		TRACE_MAIN();
		AddFlag(ni->flags, NI_FORBIDDEN);

		if (ni->forbid)
			mem_free(ni->forbid);
		ni->forbid = str_duplicate(data->operName);

		user_remove_id(ni->nick, FALSE);

		if (IS_NOT_NULL(hash_onlineuser_find(nick))) {

			char			newnick[NICKSIZE];
			unsigned int	grn, idx;

			TRACE();
			srand(randomseed());

			while (1) {

				grn = getrandom(10000, 99999);

				idx = grn - 10000;

				if (nickserv_used_guest_list[idx] == 0) {

					nickserv_used_guest_list[idx] = 1;
					break;
				}
			}

			snprintf(newnick, sizeof(newnick), "Guest%d", grn);

			TRACE();

			send_SVSNICK(nick, newnick);
		}

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS +F %s -- by %s (%s@%s)", nick, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "+F %s -- by %s (%s@%s)", nick, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_NickServ, "\2%s\2 FORBID nickname \2%s\2", source, nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS +F %s -- by %s (%s@%s) through %s", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "+F %s -- by %s (%s@%s) through %s", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) FORBID nickname \2%s\2", source, data->operName, nick);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_NICK_FLAGGED, nick, "FORBIDDEN");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_unforbid(CSTR source, User *callerUser, ServiceCommandData *data) {
				
	const char *nick;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_UNFORBID);

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_SYNTAX_ERROR, "UNFORBID");
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "UNFORBID");
	}
	else if (str_len(nick) > NICKMAX) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS -F* -- by %s (%s@%s) [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, NICKMAX);
		else
			LOG_SNOOP(s_OperServ, "NS -F* -- by %s (%s@%s) through %s [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, NICKMAX);
	}
	else {

		if (IS_NOT_NULL(ni = findnick(nick))) {

			TRACE_MAIN();
			if (FlagUnset(ni->flags, NI_FORBIDDEN)) {

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "NS -F* %s -- by %s (%s@%s) [Not Forbidden]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(s_OperServ, "NS -F* %s -- by %s (%s@%s) through %s [Not Forbidden]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_ERROR_NICK_NOT_FLAGGED, ni->nick, "FORBIDDEN");

				if (ni->forbid)
					mem_free(ni->forbid);
				ni->forbid = NULL;

				return;
			}

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "NS -F %s -- by %s (%s@%s) [Dropped]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "-F %s -- by %s (%s@%s) [Dropped]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);

				send_globops(s_NickServ, "\2%s\2 removed \2%s\2 from the FORBIDDEN list [Automatically Dropped]", source, ni->nick);
			}
			else {

				LOG_SNOOP(s_OperServ, "NS -F %s -- by %s (%s@%s) through %s [Dropped]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "-F %s -- by %s (%s@%s) through %s [Dropped]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_globops(s_NickServ, "\2%s\2 (through \2%s\2) removed \2%s\2 from the FORBIDDEN list [Automatically Dropped]", source, data->operName, ni->nick);
			}

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_NICK_FLAGGED, nick, "UNFORBIDDEN");

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), WARNING_READONLY);

			TRACE_MAIN();
			delnick(ni);
		}
		else {

			if (data->operMatch)
				LOG_SNOOP(s_OperServ, "NS -F* %s -- by %s (%s@%s) [Not Forbidden]", nick, callerUser->nick, callerUser->username, callerUser->host);
			else
				LOG_SNOOP(s_OperServ, "NS -F* %s -- by %s (%s@%s) through %s [Not Forbidden]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_ERROR_NICK_NOT_FLAGGED, nick, "FORBIDDEN");
		}
	}
}

/*********************************************************/

static void do_freeze(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *nick;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_FREEZE);

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_SYNTAX_ERROR, "FREEZE");
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "FREEZE");
	}
	else if (str_len(nick) > NICKMAX) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS +Z* -- by %s (%s@%s) [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, NICKMAX);
		else
			LOG_SNOOP(s_OperServ, "NS +Z* -- by %s (%s@%s) through %s [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, NICKMAX);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);
	}
	else if (IS_NULL(ni = findnick(nick))) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS +Z* %s -- by %s (%s@%s) [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS +Z* %s -- by %s (%s@%s) through %s [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_NOT_REG, nick);
	}
	else if (FlagSet(ni->flags, NI_FORBIDDEN))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);

	else if (FlagSet(ni->flags, NI_FROZEN)) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS +Z* %s -- by %s (%s@%s) [Already Frozen]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS +Z* %s -- by %s (%s@%s) through %s [Already Frozen]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_ERROR_NICK_ALREADY_FLAGGED, ni->nick, "FROZEN");
	}
	else if (get_services_access(NULL, ni->nick) >= ULEVEL_HOP) {

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS +Z* %s -- by %s (%s@%s) [Lamer]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
			send_globops(s_NickServ, "\2%s\2 tried to FREEZE \2%s\2", source, ni->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS +Z* %s -- by %s (%s@%s) through %s [Lamer]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) tried to FREEZE \2%s\2", source, data->operName, ni->nick);
		}

		send_notice_to_user(s_NickServ, callerUser, "You are not allowed to freeze this nick.");
	}
	else {

		TRACE_MAIN();
		AddFlag(ni->flags, NI_FROZEN);

		if (ni->freeze)
			mem_free(ni->freeze);
		ni->freeze = str_duplicate(data->operName);

		user_remove_id(ni->nick, FALSE);

		if (IS_NOT_NULL(hash_onlineuser_find(nick))) {

			char			newnick[NICKSIZE];
			unsigned int	grn, idx;

			TRACE();
			srand(randomseed());

			while (1) {

				grn = getrandom(10000, 99999);

				idx = grn - 10000;

				if (nickserv_used_guest_list[idx] == 0) {

					nickserv_used_guest_list[idx] = 1;
					break;
				}
			}

			snprintf(newnick, sizeof(newnick), "Guest%d", grn);

			TRACE();

			send_SVSNICK(nick, newnick);
		}

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS +Z %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "+Z %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_NickServ, "\2%s\2 FROZE nickname \2%s\2", callerUser->nick, ni->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS +Z %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "+Z %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) FROZE nickname \2%s\2", callerUser->nick, data->operName, ni->nick);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_NICK_FLAGGED, ni->nick, "FROZEN");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_unfreeze(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *nick;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_UNFREEZE);

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_SYNTAX_ERROR, "UNFREEZE");
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "UNFREEZE");
	}
	else if (str_len(nick) > NICKMAX) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS -Z* -- by %s (%s@%s) [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, NICKMAX);
		else
			LOG_SNOOP(s_OperServ, "NS -Z* -- by %s (%s@%s) through %s [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, NICKMAX);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);
	}
	else if (IS_NULL(ni = findnick(nick))) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS -Z* %s -- by %s (%s@%s) [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS -Z* %s -- by %s (%s@%s) through %s [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_NOT_REG, nick);
	}
	else if (FlagUnset(ni->flags, NI_FROZEN)) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS -Z* %s -- by %s (%s@%s) [Not Frozen]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS -Z* %s -- by %s (%s@%s) through %s [Not Frozen]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_ERROR_NICK_NOT_FLAGGED, ni->nick, "FROZEN");
	}
	else {

		TRACE_MAIN();
		RemoveFlag(ni->flags, NI_FROZEN);

		if (ni->freeze)
			mem_free(ni->freeze);
		ni->freeze = NULL;

		/* Quit the enforcer and remove timeouts, if any. */
		if (FlagSet(ni->flags, NI_ENFORCED))
			release(ni, FALSE);

		/* Avoid right-away expiration */
		ni->last_seen = NOW;

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS -Z %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "-Z %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host); 

			send_globops(s_NickServ, "\2%s\2 UNFROZE nickname \2%s\2", callerUser->nick, ni->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS -Z %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "-Z %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName); 

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) UNFROZE nickname \2%s\2", callerUser->nick, data->operName, ni->nick);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_NICK_FLAGGED, ni->nick, "UNFROZEN");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_hold(CSTR source, User *callerUser, ServiceCommandData *data) {
	
	const char *nick;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_HOLD);
	
	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_SYNTAX_ERROR, "HOLD");
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "HOLD");
	}
	else if (str_len(nick) > NICKMAX) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS +H* -- by %s (%s@%s) [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, NICKMAX);
		else
			LOG_SNOOP(s_OperServ, "NS +H* -- by %s (%s@%s) through %s [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, NICKMAX);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);
	}
	else if (IS_NULL(ni = findnick(nick))) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS +H* %s -- by %s (%s@%s) [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS +H* %s -- by %s (%s@%s) through %s [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_NOT_REG, nick);
	}
	else if (FlagSet(ni->flags, NI_FORBIDDEN))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);

	else if (FlagSet(ni->flags, NI_HOLD)) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS +H* %s -- by %s (%s@%s) [Already Held]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS +H* %s -- by %s (%s@%s) through %s [Already Held]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_ERROR_NICK_ALREADY_FLAGGED, ni->nick, "HELD");
	}
	else {

		TRACE_MAIN();
		AddFlag(ni->flags, NI_HOLD);
		
		if (ni->hold)
			mem_free(ni->hold);
		ni->hold = str_duplicate(data->operName);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS +H %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "+H %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_NickServ, "\2%s\2 set the HELD flag for \2%s\2", callerUser->nick, ni->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS +H %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "+H %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) set the HELD flag for \2%s\2", callerUser->nick, data->operName, ni->nick);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_NICK_FLAGGED, ni->nick, "HELD");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_unhold(CSTR source, User *callerUser, ServiceCommandData *data) {
	
	const char *nick;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_UNHOLD);
	
	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_SYNTAX_ERROR, "UNHOLD");
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "UNHOLD");
	}
	else if (str_len(nick) > NICKMAX) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS -H* -- by %s (%s@%s) [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, NICKMAX);
		else
			LOG_SNOOP(s_OperServ, "NS -H* -- by %s (%s@%s) through %s [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, NICKMAX);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);
	}
	else if (IS_NULL(ni = findnick(nick))) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS -H* %s -- by %s (%s@%s) [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS -H* %s -- by %s (%s@%s) through %s [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_NOT_REG, nick);
	}
	else if (FlagUnset(ni->flags, NI_HOLD)) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS -H* %s -- by %s (%s@%s) [Not Held]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS -H* %s -- by %s (%s@%s) through %s [Not Held]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_ERROR_NICK_NOT_FLAGGED, ni->nick, "HELD");
	}
	else {

		TRACE_MAIN();
		RemoveFlag(ni->flags, NI_HOLD);

		if (ni->hold)
			mem_free(ni->hold);
		ni->hold = NULL;

		/* Avoid right-away expiration */
		ni->last_seen = NOW;

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS -H %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "-H %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_NickServ, "\2%s\2 UNHELD nickname \2%s\2", callerUser->nick, ni->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS -H %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "-H %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) UNHELD nickname \2%s\2", callerUser->nick, data->operName, ni->nick);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_NICK_FLAGGED, ni->nick, "UNHELD");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_mark(CSTR source, User *callerUser, ServiceCommandData *data) {
	
	const char *nick;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_MARK);
	
	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_SYNTAX_ERROR, "MARK");
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "MARK");
	}
	else if (str_len(nick) > NICKMAX) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS +M* -- by %s (%s@%s) [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, NICKMAX);
		else
			LOG_SNOOP(s_OperServ, "NS +M* -- by %s (%s@%s) through %s [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, NICKMAX);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);
	}
	else if (IS_NULL(ni = findnick(nick))) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS +M* %s -- by %s (%s@%s) [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS +M* %s -- by %s (%s@%s) through %s [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_NOT_REG, nick);
	}
	else if (FlagSet(ni->flags, NI_FORBIDDEN))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);

	else if (FlagSet(ni->flags, NI_MARK)) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS +M* %s -- %s (%s@%s) [Already Marked]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS +M* %s -- %s (%s@%s) through %s [Already Marked]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_ERROR_NICK_ALREADY_FLAGGED, ni->nick, "MARKed");
	}
	else {

		TRACE_MAIN();
		AddFlag(ni->flags, NI_MARK);

		if (ni->mark)
			mem_free(ni->mark);
		ni->mark = str_duplicate(data->operName);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS +M %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "+M %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_NickServ, "\2%s\2 MARKED nickname \2%s\2", callerUser->nick, ni->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS +M %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "+M %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) MARKED nickname \2%s\2", callerUser->nick, data->operName, ni->nick);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_NICK_FLAGGED, ni->nick, "MARKed");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_unmark(CSTR source, User *callerUser, ServiceCommandData *data) {
	
	const char *nick;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_UNMARK);
	
	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_SYNTAX_ERROR, "UNMARK");
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "UNMARK");
	}
	else if (str_len(nick) > NICKMAX) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS -M* -- by %s (%s@%s) [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, NICKMAX);
		else
			LOG_SNOOP(s_OperServ, "NS -M* -- by %s (%s@%s) through %s [Nick > %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, NICKMAX);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);
	}
	else if (IS_NULL(ni = findnick(nick))) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS -M* %s -- by %s (%s@%s) [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS -M* %s -- by %s (%s@%s) through %s [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_NOT_REG, nick);
	}
	else if ((get_services_access(NULL, nick) >= ULEVEL_SA) && !is_services_master(callerUser)) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS -M* %s -- by %s (%s@%s) [No Permission]", nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS -M* %s -- by %s (%s@%s) through %s [No Permission]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_UNMARK_ERROR_NO_PERMISSION);
	}
	else if (FlagUnset(ni->flags, NI_MARK)) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "NS -M* %s -- by %s (%s@%s) [Not Marked]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "NS -M* %s -- by %s (%s@%s) through %s [Not Marked]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_ERROR_NICK_NOT_FLAGGED, ni->nick, "MARKed");
	}
	else {

		TRACE_MAIN();
		RemoveFlag(ni->flags, NI_MARK);

		if (ni->mark)
			mem_free(ni->mark);
		ni->mark = NULL;

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS -M %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "-M %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_NickServ, "\2%s\2 UNMARKED nickname \2%s\2", callerUser->nick, ni->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS -M %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "-M %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) UNMARKED nickname \2%s\2", callerUser->nick, data->operName, ni->nick);
		}

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_FLAG_NICK_FLAGGED, ni->nick, "UNMARKed");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_authnick(CSTR source, User *callerUser, ServiceCommandData *data) {

	char		*nick = strtok(NULL, " ");
	char		*email = strtok(NULL, " ");
	NickInfo	*ni;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_AUTHNICK);

	if (IS_NULL(nick)) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_AUTHNICK_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "AUTHNICK");
	}
	else if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);

	else if (IS_NULL(ni = findnick(nick)))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_NOT_REG, nick);

	else if (FlagSet(ni->flags, NI_FROZEN))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FROZEN, ni->nick);

	else if (FlagSet(ni->flags, NI_FORBIDDEN))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);

	else if (IS_NULL(ni->email) && IS_NULL(email))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_AUTHNICK_ERROR_NO_EMAIL, ni->nick);

	else if (IS_NOT_NULL(email) && (str_len(email) > MAILMAX))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_MAIL_MAX_LENGTH, MAILMAX);

	else if (IS_NOT_NULL(email) && (string_has_ccodes(email) || !validate_email(email)))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_SET_EMAIL_ERROR_INVALID_EMAIL, email);

	else {

		TRACE_MAIN();
		if (FlagSet(ni->flags, NI_AUTH)) {

			User *user;

			RemoveFlag(ni->flags, NI_AUTH);
			RemoveFlag(ni->flags, NI_MAILCHANGE);
			RemoveFlag(ni->flags, NI_DROP);
			RemoveFlag(ni->flags, NI_NOMAIL);

			ni->auth = 0;
			ni->last_drop_request = 0;
			ni->last_email_request = 0;

			if (ni->email && email) {

				mem_free(ni->email);
				ni->email = str_duplicate(email);
			}
			else if (IS_NULL(ni->email))
				ni->email = str_duplicate(email);

			if (ni->regemail) {

				mem_free(ni->regemail);
				ni->regemail = NULL;
			}

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "NS AN %s -- by %s (%s@%s) [%s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->email);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "AN %s -- by %s (%s@%s) [%s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->email);

				send_globops(s_NickServ, "\2%s\2 authorized nickname \2%s\2 [%s]", callerUser->nick, ni->nick, ni->email);
			}
			else {

				LOG_SNOOP(s_OperServ, "NS AN %s -- by %s (%s@%s) through %s [%s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->email);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "AN %s -- by %s (%s@%s) through %s [%s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->email);

				send_globops(s_NickServ, "\2%s\2 (through \2%s\2) authorized nickname \2%s\2 [%s]", callerUser->nick, data->operName, ni->nick, ni->email);
			}

			if (IS_NOT_NULL(user = hash_onlineuser_find(nick)) && user_is_identified_to(user, nick)) {

				send_user_SVSMODE(s_NickServ, nick, "+r", user->tsinfo);
				AddFlag(callerUser->mode, UMODE_r);
			}

			send_notice_to_user(s_NickServ, callerUser, "\2%s\2 has been authorized with the following address: \2%s\2", ni->nick, ni->email);
		}
		else
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_AUTHNICK_ERROR_NICK_ALREADY_AUTH, ni->nick);
	}
}

/*********************************************************/

static void do_authreset(CSTR source, User *callerUser, ServiceCommandData *data) {
	
	NickInfo *ni;
	const char *nick;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_AUTHRESET);
	
	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_AUTHRESET_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "AUTHRESET");
	}
	else if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);

	else if (IS_NULL(ni = findnick(nick)))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_NOT_REG, nick);

	else if (FlagSet(ni->flags, NI_FROZEN))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FROZEN, ni->nick);

	else if (FlagSet(ni->flags, NI_FORBIDDEN))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);

	else {

		const char *what;

		if (IS_NULL(what = strtok(NULL, " "))) {

			TRACE_MAIN();
			AddFlag(ni->flags, NI_AUTH);
			RemoveFlag(ni->flags, NI_DROP);
			RemoveFlag(ni->flags, NI_MAILCHANGE);
			RemoveFlag(ni->flags, NI_NOMAIL);

			if (ni->email)
				mem_free(ni->email);
			ni->email = NULL;

			if (ni->regemail)
				mem_free(ni->regemail);
			ni->regemail = NULL;

			ni->auth = 0;
			ni->last_email_request = 0;
			ni->last_drop_request = 0;

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "NS AR %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "AR %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);

				send_globops(s_NickServ, "\2%s\2 removed authorization for nickname \2%s\2", callerUser->nick, ni->nick);
			}
			else {

				LOG_SNOOP(s_OperServ, "NS AR %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "AR %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_globops(s_NickServ, "\2%s\2 (through \2%s\2) removed authorization for nickname \2%s\2", callerUser->nick, data->operName, ni->nick);
			}

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_AUTHRESET_AUTH_RESET, ni->nick);
		}
		else if (str_equals_nocase(what, "MAILCHANGE")) {

			RemoveFlag(ni->flags, NI_MAILCHANGE);
			RemoveFlag(ni->flags, NI_NOMAIL);

			if (ni->regemail)
				mem_free(ni->regemail);
			ni->regemail = NULL;

			ni->auth = 0;
			ni->last_email_request = 0;

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "NS AR %s -- by %s (%s@%s) [MailChange]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "AR %s -- by %s (%s@%s) [MailChange]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);

				send_globops(s_NickServ, "\2%s\2 removed MailChange status for nickname \2%s\2", callerUser->nick, ni->nick);
			}
			else {

				LOG_SNOOP(s_OperServ, "NS AR %s -- by %s (%s@%s) through %s [MailChange]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "AR %s -- by %s (%s@%s) through %s [MailChange]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_globops(s_NickServ, "\2%s\2 (through \2%s\2) removed MailChange status for nickname \2%s\2", callerUser->nick, data->operName, ni->nick);
			}

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_AUTHRESET_AUTH_RESET, ni->nick);
		}
		else if (str_equals_nocase(what, "DROP")) {

			RemoveFlag(ni->flags, NI_DROP);
			ni->auth = 0;
			ni->last_drop_request = 0;

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "NS AR %s -- by %s (%s@%s) [Drop]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "AR %s -- by %s (%s@%s) [Drop]", ni->nick, callerUser->nick, callerUser->username, callerUser->host);

				send_globops(s_NickServ, "\2%s\2 removed Drop status for nickname \2%s\2", callerUser->nick, ni->nick);
			}
			else {

				LOG_SNOOP(s_OperServ, "NS AR %s -- by %s (%s@%s) through %s [Drop]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_NICKSERV_GENERAL, "AR %s -- by %s (%s@%s) through %s [Drop]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_globops(s_NickServ, "\2%s\2 (through \2%s\2) removed Drop status for nickname \2%s\2", callerUser->nick, data->operName, ni->nick);
			}

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_AUTHRESET_AUTH_RESET, ni->nick);
		}
		else {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_AUTHRESET_SYNTAX_ERROR);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "AUTHRESET");
		}
	}
}

/*********************************************************/

static void do_show_umode(CSTR source, User *callerUser, ServiceCommandData *data) {

	User *targetUser;
	char *nick;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_UMODE);

	if (!is_services_helpop(callerUser) && !user_is_ircop(callerUser)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_UNKNOWN_COMMAND, "UMODE");
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_SERVICE_COMMAND_LIST, s_NS);
	}
	else if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_UMODE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "UMODE");
	}
	else if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);

	else if (IS_NOT_NULL(targetUser = hash_onlineuser_find(nick))) {

		if ((user_is_ircop(targetUser) || is_services_valid_oper(targetUser)) && !is_services_admin(callerUser))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
		else
			send_notice_to_user(s_NickServ, callerUser, "UMODE \2%s\2: %s", nick, get_user_modes(targetUser->mode, 0));
	}
	else
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_OFFLINE, nick);
}

/*********************************************************/

static void do_listchans(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *nick;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_LISTCHANS);

	if (IS_NULL(nick = strtok(NULL, " ")) || str_equals_nocase(nick, source)) {

		/* No nick specified by the user. */

		if (IS_NULL(callerUser->ni)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");
		}
		else if (FlagSet(callerUser->ni->flags, NI_FORBIDDEN))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, callerUser->ni->nick);

		else if (FlagSet(callerUser->ni->flags, NI_FROZEN)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FROZEN, callerUser->ni->nick);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), EMAIL_NETWORK_FOR_MORE_INFO, MAIL_KLINE);
		}
		else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
		}
		else
			chanserv_listchans(callerUser, callerUser->ni->nick, TRUE);
	}
	else {

		/* A nick different than the one in use was specified. */

		NickInfo *ni;

		if (!is_services_helpop(callerUser))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

		else if (str_len(nick) > NICKMAX)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_MAX_LENGTH, NICKMAX);

		else if (IS_NULL(ni = findnick(nick)))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_NOT_REG, nick);

		else if (FlagSet(ni->flags, NI_FORBIDDEN))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);

		else if ((get_services_access(NULL, nick) >= get_services_access(callerUser, source)) && !user_is_identified_to(callerUser, ni->nick))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

		else
			chanserv_listchans(callerUser, ni->nick, FALSE);
	}
}

/*********************************************************/

/*
NS LISTREG [TYPE [FIRST [LAST]]] pattern
NS LISTREG TYPE [pattern] [FIRST [LAST]]

TYPE:
- NICK : nick	N
- last mask		M
- realname		RN
- email			E
- noemail		NE
- nick not auth NA
- nick in auth	IA
- HELD			H
- MARKED		K
- FORBID		F
- FREEZE		Z

- last seen >= X
- altre...
*/


typedef BOOL (*ns_listreg_match_proc)(const NickInfo *ni, CSTR pattern);

static BOOL ns_listreg_match_nick(const NickInfo *ni, CSTR pattern) {

	return str_match_wild_nocase(pattern, ni->nick);
}

static BOOL ns_listreg_match_seenmask(const NickInfo *ni, CSTR pattern) {

	if (IS_NOT_NULL(ni->last_usermask)) {

		str_copy_checked(ni->last_usermask, misc_buffer, MISC_BUFFER_SIZE);
		str_tolower(misc_buffer);

		return str_match_wild(pattern, misc_buffer);
	} else
		return FALSE;
}

static BOOL ns_listreg_match_realname(const NickInfo *ni, CSTR pattern) {

	if (IS_NOT_NULL(ni->last_realname)) {

		str_copy_checked(ni->last_realname, misc_buffer, MISC_BUFFER_SIZE);
		str_tolower(misc_buffer);

		return str_match_wild(pattern, misc_buffer);
	} else
		return FALSE;
}

static BOOL ns_listreg_match_email(const NickInfo *ni, CSTR pattern) {

	if (IS_NOT_NULL(ni->email)) {

		str_copy_checked(ni->email, misc_buffer, MISC_BUFFER_SIZE);
		str_tolower(misc_buffer);
		return str_match_wild(pattern, misc_buffer);

	} else
		return FALSE;
}

static BOOL ns_listreg_match_noemail(const NickInfo *ni, CSTR pattern) {

	return IS_NULL(ni->email);
}

static BOOL ns_listreg_match_bugged(const NickInfo *ni, CSTR pattern) {

	return (FlagUnset(ni->flags, NI_AUTH) && (ni->auth != 0));
}

static BOOL ns_listreg_match_is_not_auth(const NickInfo *ni, CSTR pattern) {

	return FlagSet(ni->flags, NI_AUTH);
}

static BOOL ns_listreg_match_is_in_auth(const NickInfo *ni, CSTR pattern) {

	return FlagUnset(ni->flags, NI_AUTH);
}

static BOOL ns_listreg_match_is_held(const NickInfo *ni, CSTR pattern) {

	return FlagSet(ni->flags, NI_HOLD);
}

static BOOL ns_listreg_match_is_marked(const NickInfo *ni, CSTR pattern) {

	return FlagSet(ni->flags, NI_MARK);
}

static BOOL ns_listreg_match_is_forbidded(const NickInfo *ni, CSTR pattern) {

	return FlagSet(ni->flags, NI_FORBIDDEN);
}

static BOOL ns_listreg_match_is_frozen(const NickInfo *ni, CSTR pattern) {

	return FlagSet(ni->flags, NI_FROZEN);
}

/*********************************************************/

static void do_listreg(CSTR source, User *callerUser, ServiceCommandData *data) {

	ns_listreg_match_proc	compare = NULL;
	NickInfo			*ni;
	char				*prms[4] = {NULL, NULL, NULL, NULL};
	char				*type	= NULL;
	char				*start	= NULL;
	char				*end	= NULL;
	char				*search	= NULL;
	unsigned long int	start_line, end_line, line, idx = 0;
	BOOL				error = FALSE;

	#define	LR_OUT_STANDARD		0
	#define	LR_OUT_REALNAME		1
	#define	LR_OUT_EMAIL		2
	int					output_type = LR_OUT_STANDARD;

	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_LISTREG);

	while ((idx < 4) && IS_NOT_NULL((prms[idx] = strtok(NULL, s_SPACE))))
		++idx;

	if (idx < 1)
		error = TRUE;

	else {

		type = prms[0];

		TRACE_MAIN();
		/* Tipo */

		if (str_equals_nocase(type, "NICK") || str_equals_nocase(type, "N")) {

			compare = ns_listreg_match_nick;
			search = prms[1];
			start = prms[2];
			end = prms[3];

			if (IS_NOT_NULL(search)) {

				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by Nickname: ", search);
				str_tolower(search);
			}
		}
		else if (str_equals_nocase(type, "MASK") || str_equals_nocase(type, "M")) {

			compare = ns_listreg_match_seenmask;
			search = prms[1];
			start = prms[2];
			end = prms[3];

			if (IS_NOT_NULL(search)) {

				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by Mask: ", search);
				str_tolower(search);
			}
		}
		else if (str_equals_nocase(type, "REALNAME") || str_equals_nocase(type, "RN")) {

			compare = ns_listreg_match_realname;
			search = prms[1];
			start = prms[2];
			end = prms[3];
			output_type = LR_OUT_REALNAME;

			if (IS_NOT_NULL(search)) {

				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by Real Name: ", search);
				str_tolower(search);
			}
		}
		else if (str_equals_nocase(type, "EMAIL") || str_equals_nocase(type, "E")) {

			compare = ns_listreg_match_email;
			search = prms[1];
			start = prms[2];
			end = prms[3];
			output_type = LR_OUT_EMAIL;

			if (IS_NOT_NULL(search)) {

				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by E-Mail Address: ", search);
				str_tolower(search);
			}
		}
		else if (str_equals_nocase(type, "NOEMAIL") || str_equals_nocase(type, "NE")) {

			compare = ns_listreg_match_noemail;
			search = (STR)s_STAR;
			start = prms[1];
			end = prms[2];

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "\2without\2 E-Mail Address: ", search);
		}
		else if (str_equals_nocase(type, "BUGGED") || str_equals_nocase(type, "B")) {

			compare = ns_listreg_match_bugged;
			search = (STR)s_STAR;
			start = prms[1];
			end = prms[2];

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by Bugged Registration: ", search);
		}
		else if (str_equals_nocase(type, "NOTAUTH") || str_equals_nocase(type, "NA")) {

			compare = ns_listreg_match_is_not_auth;
			search = (STR)s_STAR;
			start = prms[1];
			end = prms[2];

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "\2without\2 authorization: ", s_NULL);
		}
		else if (str_equals_nocase(type, "INAUTH") || str_equals_nocase(type, "IA")) {

			compare = ns_listreg_match_is_in_auth;
			search = (STR)s_STAR;
			start = prms[1];
			end = prms[2];

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "\2waiting for\2 authorization: ", s_NULL);
		}
		else if (str_equals_nocase(type, "HOLD") || str_equals_nocase(type, "H")) {

			compare = ns_listreg_match_is_held;
			search = (STR)s_STAR;
			start = prms[1];
			end = prms[2];

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by HELD flag: ", s_NULL);
		}
		else if (str_equals_nocase(type, "MARK") || str_equals_nocase(type, "K")) {

			compare = ns_listreg_match_is_marked;
			search = (STR)s_STAR;
			start = prms[1];
			end = prms[2];

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by MARK flag: ", s_NULL);
		}
		else if (str_equals_nocase(type, "FORBID") || str_equals_nocase(type, "F")) {

			compare = ns_listreg_match_is_forbidded;
			search = (STR)s_STAR;
			start = prms[1];
			end = prms[2];

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by FORBID flag: ", s_NULL);
		}
		else if (str_equals_nocase(type, "FREEZE") || str_equals_nocase(type, "Z")) {

			compare = ns_listreg_match_is_frozen;
			search = (STR)s_STAR;
			start = prms[1];
			end = prms[2];

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by FREEZE flag: ", s_NULL);
		}
		else
			error = TRUE;
	}

	/* Convalida parametri */
	TRACE_MAIN();

	error |= IS_NULL(search);

	if (error) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_LISTREG_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "LISTREG");
		return;
	}

	if (IS_NULL(start))
		start = "0";

	if (IS_NULL(end))
		end = "+50";

	TRACE_MAIN();
	
	/* Intervallo */
	start_line = strtoul(start, NULL, 10);

	if (end[0] == c_PLUS)
		end_line = start_line + strtoul(end + 1, NULL, 10);
	else
		end_line = strtoul(end, NULL, 10);

	/* Ricerca */

	if (end_line == 0)
		end_line = start_line + 50;

	line = 0;

	for (idx = 65; idx < 126; ++idx) {

		for (ni = nicklists[idx]; IS_NOT_NULL(ni); ni = ni->next) {

			if (compare(ni, search)) {

				TRACE_MAIN();
				++line;

				if ((line < start_line) || (line >= end_line))
					continue;

				switch (output_type) {

					case LR_OUT_STANDARD:
						if (FlagSet(ni->flags, NI_FORBIDDEN))
							send_notice_to_user(s_NickServ, callerUser, "%d) \2%s\2 [Forbidden by %s]", line, ni->nick, ni->forbid);
						else
							send_notice_to_user(s_NickServ, callerUser, "%d) \2%s\2 [%s]", line, ni->nick, ni->last_usermask);
						break;
					
					case LR_OUT_REALNAME:
						send_notice_to_user(s_NickServ, callerUser, "%d) \2%s\2 [%s] [Real Name: %s]", line, ni->nick, ni->last_usermask, ni->last_realname);
						break;

					case LR_OUT_EMAIL:
						send_notice_to_user(s_NickServ, callerUser, "%d) \2%s\2 [%s] [E-Mail Address: %s]", line, ni->nick, ni->last_usermask, ni->email);
						break;
				}
			}
		}
	}

	send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_LISTREG_END_OF_SEARCH, line, line == 1 ? "nick" : "nicks");

	#undef	LR_OUT_STANDARD
	#undef	LR_OUT_REALNAME
	#undef	LR_OUT_EMAIL
}

/*********************************************************/

static void do_isonaccess(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *nick;
	User *user;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_ISONACCESS);

	if (!user_is_ircop(callerUser) && !user_is_services_agent(callerUser) && !is_services_helpop(callerUser)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_UNKNOWN_COMMAND, "ISONACCESS");
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_SERVICE_COMMAND_LIST, s_NS);
	}
	else if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ISONACCESS_SYNTAX_ERROR);
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "ISONACCESS");
	}
	else if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_MAX_LENGTH, NICKMAX);

	else if (IS_NULL(user = hash_onlineuser_find(nick)))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ISONACCESS_ERROR_OFFLINE, nick);

	else if ((user_is_ircop(user) || IS_NOT_NULL(user->oper)) && !is_services_admin(callerUser))
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

	else {

		NickInfo *ni;
		const char *who;

		ni = IS_NOT_NULL(who = strtok(NULL, " ")) ? findnick(who) : user->ni;

		if (IS_NULL(ni)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ISONACCESS_ERROR_NOTREG, who ? who : nick);
			return;
		}

		if (is_on_access(user, ni))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ISONACCESS_REPLY, "1", nick, who ? who : nick);
		else
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_ISONACCESS_REPLY, "0", nick, who ? who : nick);
	}
}

/*********************************************************/

static void do_nickset(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *nick, *what;
	NickInfo *ni;


	if (IS_NULL(nick = strtok(NULL, " ")) || IS_NULL(what = strtok(NULL, " "))) {

		send_notice_to_user(s_NickServ, callerUser, "Syntax: NICKSET nick [CHANNELCOUNT|LASTSEEN|PASS|REALNAME|REGDATE|URL|USERMASK] value");
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "NICKSET");
		return;
	}

	if (str_len(nick) > NICKMAX) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);
		return;
	}

	if (IS_NULL(ni = findnick(nick))) {

		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_NICK_NOT_REG, nick);
		return;
	}

	if (str_equals_nocase(what, "PASS")) {

		const char *newpass;

		if (IS_NULL(newpass = strtok(NULL, " "))) {

			send_notice_to_user(s_NickServ, callerUser, "Syntax: NICKSET nick [CHANNELCOUNT|LASTSEEN|PASS|REALNAME|REGDATE|URL|USERMASK] value");
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "NICKSET");
		}
		else if (str_len(newpass) > PASSMAX)
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_MAX_LENGTH, PASSMAX);

		else if (strchr(newpass, '<') || strchr(newpass, '>'))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_BRAKES_IN_PASS, "<", ">");

		else if (string_has_ccodes(newpass))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_WITH_CCODES);

		else if (str_equals_nocase(newpass, "password"))
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_AS_PASS);

		else {

			if (str_not_equals(ni->pass, newpass)) {

				TRACE_MAIN();

				if (data->operMatch) {

					LOG_SNOOP(s_OperServ, "NS N %s -- by %s (%s@%s) [P: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->pass, newpass);
					log_services(LOG_SERVICES_NICKSERV_GENERAL, "N %s -- by %s (%s@%s) [P: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->pass, newpass);

					send_globops(s_NickServ, "\2%s\2 changed nick password for \2%s\2", callerUser->nick, ni->nick);
				}
				else {

					LOG_SNOOP(s_OperServ, "NS N %s -- by %s (%s@%s) through %s [P: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->pass, newpass);
					log_services(LOG_SERVICES_NICKSERV_GENERAL, "N %s -- by %s (%s@%s) through %s [P: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->pass, newpass);

					send_globops(s_NickServ, "\2%s\2 (through \2%s\2) changed nick password for \2%s\2", callerUser->nick, data->operName, ni->nick);
				}

				send_notice_to_user(s_NickServ, callerUser, "Password for \2%s\2 set to: %s", ni->nick, newpass);

				str_copy_checked(newpass, ni->pass, PASSMAX);

				user_remove_id(nick, FALSE);
			}
			else
				send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_SAME_PASSWORD);
		}
	}
	else if (str_equals_nocase(what, "USERMASK")) {

		const char *mask;

		if (IS_NULL(mask = strtok(NULL, " ")) || !strchr(mask, '@')) {

			send_notice_to_user(s_NickServ, callerUser, "Syntax: NICKSET nick [CHANNELCOUNT|LASTSEEN|PASS|REALNAME|REGDATE|URL|USERMASK] value");
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "NICKSET");
			return;
		}

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS N %s -- by %s (%s@%s) [M: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->last_usermask, mask);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "N %s -- by %s (%s@%s) [M: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->last_usermask, mask);

			send_globops(s_NickServ, "\2%s\2 changed last usermask for \2%s\2 to: %s", callerUser->nick, ni->nick, mask);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS N %s -- by %s (%s@%s) through %s [M: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->last_usermask, mask);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "N %s -- by %s (%s@%s) through %s [M: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->last_usermask, mask);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) changed last usermask for \2%s\2 to: %s", callerUser->nick, data->operName, ni->nick, mask);
		}

		if (ni->last_usermask)
			mem_free(ni->last_usermask);
		ni->last_usermask = str_duplicate(mask);
	}
	else if (str_equals_nocase(what, "REALNAME")) {

		const char *realname;

		if (IS_NULL(realname = strtok(NULL, ""))) {

			send_notice_to_user(s_NickServ, callerUser, "Syntax: NICKSET nick [CHANNELCOUNT|LASTSEEN|PASS|REALNAME|REGDATE|URL|USERMASK] value");
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "NICKSET");
			return;
		}

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS N %s -- by %s (%s@%s) [R: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->last_realname, realname);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "N %s -- by %s (%s@%s) [R: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->last_realname, realname);

			send_globops(s_NickServ, "\2%s\2 changed real name for \2%s\2 to: %s", callerUser->nick, ni->nick, realname);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS N %s -- by %s (%s@%s) through %s [R: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->last_realname, realname);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "N %s -- by %s (%s@%s) through %s [R: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->last_realname, realname);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) changed real name for \2%s\2 to: %s", callerUser->nick, data->operName, ni->nick, realname);
		}

		if (ni->last_realname)
			mem_free(ni->last_realname);
		ni->last_realname = str_duplicate(realname);
	}
	else if (str_equals_nocase(what, "REGDATE")) {

		const char *date;
		char *err;
		time_t newdate;
		char timebuf[32], newtimebuf[32];
		struct tm tm;

		if (IS_NULL(date = strtok(NULL, " "))) {

			send_notice_to_user(s_NickServ, callerUser, "Syntax: NICKSET nick [CHANNELCOUNT|LASTSEEN|PASS|REALNAME|REGDATE|URL|USERMASK] value");
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "NICKSET");
			return;
		}

		newdate = strtol(date, &err, 10);

		if ((newdate <= 0) || (*err != '\0')) {

			send_notice_to_user(s_NickServ, callerUser, "Invalid date supplied.");
			return;
		}

		tm = *localtime(&ni->time_registered);
		strftime(timebuf, sizeof(timebuf), "%d/%m/%Y %H:%M:%S", &tm);

		tm = *localtime(&newdate);
		strftime(newtimebuf, sizeof(newtimebuf), "%d/%m/%Y %H:%M:%S", &tm);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS N %s -- by %s (%s@%s) [D: %lu -> %lu]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->time_registered, newdate);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "N %s -- by %s (%s@%s) [D: %lu -> %lu]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->time_registered, newdate);

			send_globops(s_NickServ, "\2%s\2 changed registration date for \2%s\2 to: %s (was: %s)", callerUser->nick, ni->nick, newtimebuf, timebuf);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS N %s -- by %s (%s@%s) through %s [D: %lu -> %lu]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->time_registered, newdate);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "N %s -- by %s (%s@%s) through %s [D: %lu -> %lu]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->time_registered, newdate);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) changed registration date for \2%s\2 to: %s (was: %s)", callerUser->nick, data->operName, ni->nick, newtimebuf, timebuf);
		}

		ni->time_registered = newdate;
	}
	else if (str_equals_nocase(what, "LASTSEEN")) {

		const char *date;
		time_t newdate;
		char timebuf[32], newtimebuf[32];
		struct tm tm;

		if (!CheckOperAccess(data->userLevel, CMDLEVEL_CODER)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
			return;
		}

		if (IS_NULL(date = strtok(NULL, " "))) {

			send_notice_to_user(s_NickServ, callerUser, "Syntax: NICKSET nick [CHANNELCOUNT|LASTSEEN|PASS|REALNAME|REGDATE|URL|USERMASK] value");
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "NICKSET");
			return;
		}

		if (str_equals_nocase(date, "NOW"))
			newdate = NOW;

		else {

			char *err;

			newdate = strtol(date, &err, 10);

			if ((newdate <= 0) || (*err != '\0')) {

				send_notice_to_user(s_NickServ, callerUser, "Invalid date supplied.");
				return;
			}
		}

		tm = *localtime(&(ni->last_seen));
		strftime(timebuf, sizeof(timebuf), "%d/%m/%Y %H:%M:%S", &tm);

		tm = *localtime(&newdate);
		strftime(newtimebuf, sizeof(newtimebuf), "%d/%m/%Y %H:%M:%S", &tm);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS N %s -- by %s (%s@%s) [S: %lu -> %lu]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->last_seen, newdate);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "N %s -- by %s (%s@%s) [S: %lu -> %lu]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->last_seen, newdate);

			send_globops(s_NickServ, "\2%s\2 changed last seen for \2%s\2 to: %s (was: %s)", callerUser->nick, ni->nick, newtimebuf, timebuf);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS N %s -- by %s (%s@%s) through %s [S: %lu -> %lu]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->last_seen, newdate);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "N %s -- by %s (%s@%s) through %s [S: %lu -> %lu]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->last_seen, newdate);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) changed last seen for \2%s\2 to: %s (was: %s)", callerUser->nick, data->operName, ni->nick, newtimebuf, timebuf);
		}

		ni->last_seen = newdate;
	}
	else if (str_equals_nocase(what, "URL")) {

		const char *url;

		if (IS_NULL(url = strtok(NULL, " "))) {

			send_notice_to_user(s_NickServ, callerUser, "Syntax: NICKSET nick [CHANNELCOUNT|LASTSEEN|PASS|REALNAME|REGDATE|URL|USERMASK] value");
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "NICKSET");
			return;
		}

		if (string_has_ccodes(url) || !strchr(url, '.')) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), CSNS_ERROR_URL_FORMAT);
			return;
		}

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS N %s -- by %s (%s@%s) [U: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->url, url);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "N %s -- by %s (%s@%s) [U: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->url, url);

			send_globops(s_NickServ, "\2%s\2 changed URL for \2%s\2 to: %s", callerUser->nick, ni->nick, url);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS N %s -- by %s (%s@%s) through %s [U: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->url, url);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "N %s -- by %s (%s@%s) through %s [U: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->url, url);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) changed URL for \2%s\2 to: %s", callerUser->nick, data->operName, ni->nick, url);
		}

		if (ni->url)
			mem_free(ni->url);
		ni->url = str_duplicate(url);
	}
	else if (str_equals_nocase(what, "CHANNELCOUNT")) {

		const char *value;
		char *err;
		int newcount;

		if (!CheckOperAccess(data->userLevel, CMDLEVEL_CODER)) {

			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
			return;
		}

		if (IS_NULL(value = strtok(NULL, " "))) {

			send_notice_to_user(s_NickServ, callerUser, "Syntax: NICKSET nick [CHANNELCOUNT|LASTSEEN|PASS|REALNAME|REGDATE|URL|USERMASK] value");
			send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "NICKSET");
			return;
		}

		newcount = strtol(value, &err, 10);

		if ((newcount <= 0) || (*err != '\0')) {

			send_notice_to_user(s_NickServ, callerUser, "Invalid value supplied.");
			return;
		}

		if (newcount > CONF_USER_CHAN_ACCESS_MAX) {

			send_notice_to_user(s_NickServ, callerUser, "Channel count cannot be greater than \2%d\2.", CONF_USER_CHAN_ACCESS_MAX);
			return;
		}

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "NS N %s -- by %s (%s@%s) [C: %d -> %d]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->channelcount, newcount);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "N %s -- by %s (%s@%s) [C: %d -> %d]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ni->channelcount, newcount);

			send_globops(s_NickServ, "\2%s\2 changed channel count value for \2%s\2 to \2%d\2 (was: \2%d\2)", callerUser->nick, ni->nick, newcount, ni->channelcount);
		}
		else {

			LOG_SNOOP(s_OperServ, "NS N %s -- by %s (%s@%s) through %s [U: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->channelcount, newcount);
			log_services(LOG_SERVICES_NICKSERV_GENERAL, "N %s -- by %s (%s@%s) through %s [U: %s -> %s]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, ni->channelcount, newcount);

			send_globops(s_NickServ, "\2%s\2 (through \2%s\2) changed channel count value for \2%s\2 to \2%d\2 (was: \2%d\2)", callerUser->nick, data->operName, ni->channelcount, newcount);
		}

		ni->channelcount = newcount;
	}
	else {

		send_notice_to_user(s_NickServ, callerUser, "Syntax: NICKSET nick [CHANNELCOUNT|LASTSEEN|PASS|REALNAME|REGDATE|URL|USERMASK] value");
		send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_NS, "NICKSET");
	}
}

/*********************************************************/

static char *get_nick_flags(long int flags) {

	static char buffer[IRCBUFSIZE];
	size_t		len = 0;


	APPEND_FLAG(flags, NI_KILL_SLOW, "NI_KILL_SLOW")
	APPEND_FLAG(flags, NI_KILL_NORMAL, "NI_KILL_NORMAL")
	APPEND_FLAG(flags, NI_KILL_FAST, "NI_KILL_FAST")
	APPEND_FLAG(flags, NI_SECURE, "NI_SECURE")
	APPEND_FLAG(flags, NI_FORBIDDEN, "NI_FORBIDDEN")
	APPEND_FLAG(flags, NI_ENCRYPTEDPW, "NI_ENCRYPTEDPW")
	APPEND_FLAG(flags, NI_MEMO_SIGNON, "NI_MEMO_SIGNON")
	APPEND_FLAG(flags, NI_MEMO_RECEIVE, "NI_MEMO_RECEIVE")
	APPEND_FLAG(flags, NI_REVERSEIGN, "NI_REVERSEIGN")
	APPEND_FLAG(flags, NI_HIDE_EMAIL, "NI_HIDE_EMAIL")
	APPEND_FLAG(flags, NI_MARK, "NI_MARK")
	APPEND_FLAG(flags, NI_HOLD, "NI_HOLD")
	APPEND_FLAG(flags, NI_EMAILMEMOS, "NI_EMAILMEMOS")
	APPEND_FLAG(flags, NI_NOOP, "NI_NOOP")
	APPEND_FLAG(flags, NI_NOMEMO, "NI_NOMEMO")
	APPEND_FLAG(flags, NI_NOCHANMEMO, "NI_NOCHANMEMO")
	APPEND_FLAG(flags, NI_NOMAIL, "NI_NOMAIL")
	APPEND_FLAG(flags, NI_READNEWS, "NI_READNEWS")
	APPEND_FLAG(flags, NI_NEVEROP, "NI_NEVEROP")
	APPEND_FLAG(flags, NI_REMIND, "NI_REMIND")
	APPEND_FLAG(flags, NI_AUTH, "NI_AUTH")
	APPEND_FLAG(flags, NI_FROZEN, "NI_FROZEN")
	APPEND_FLAG(flags, NI_TIMEOUT, "NI_TIMEOUT")
	APPEND_FLAG(flags, NI_ENFORCE, "NI_ENFORCE")
	APPEND_FLAG(flags, NI_MAILCHANGE, "NI_MAILCHANGE")
	APPEND_FLAG(flags, NI_DROP, "NI_DROP")
	APPEND_FLAG(flags, NI_ENFORCED, "NI_ENFORCED")
	APPEND_FLAG(flags, NI_NOWELCOME, "NI_NOWELCOME")
	APPEND_FLAG(flags, NI_IDENTIFIED, "NI_IDENTIFIED")

	if (len == 0)
		return "None";

	return buffer;
}


/*********************************************************/

void nickserv_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	STR		cmd = strtok(request, s_SPACE);
	STR		value = strtok(NULL, s_SPACE);
	BOOL	needSyntax = FALSE;

	if (IS_NOT_NULL(cmd)) {

		if (str_equals_nocase(cmd, "HELP")) {

			/* HELP ! */
		} else if (str_equals_nocase(cmd, "NICK")) {

			if (IS_NULL(value))
				needSyntax = TRUE;

			else {

				NickInfo	*ni;

				ni = findnick(value);

				if (IS_NULL(ni))
					send_notice_to_user(sourceNick, callerUser, "DUMP: Nickname \2%s\2 not found.", value);

				else {

					send_notice_to_user(sourceNick, callerUser, "DUMP: nickname \2%s\2", value);

					send_notice_to_user(sourceNick, callerUser, "Address 0x%08X, size %d B",						(unsigned long)ni, sizeof(NickInfo));
					send_notice_to_user(sourceNick, callerUser, "Name: %s",											ni->nick);
					send_notice_to_user(sourceNick, callerUser, "Password: %s",										ni->pass);
					send_notice_to_user(sourceNick, callerUser, "Last Mask: 0x%08X \2[\2%s\2]\2",					(unsigned long)ni->last_usermask, str_get_valid_display_value(ni->last_usermask));
					send_notice_to_user(sourceNick, callerUser, "Last Real Name: 0x%08X \2[\2%s\2]\2",				(unsigned long)ni->last_realname, str_get_valid_display_value(ni->last_realname));
					send_notice_to_user(sourceNick, callerUser, "Registration C-time: %d",							ni->time_registered);
					send_notice_to_user(sourceNick, callerUser, "Last seen C-time: %d",								ni->last_seen);
					send_notice_to_user(sourceNick, callerUser, "Access count / list: %d / 0x%08X",					ni->accesscount, (unsigned long)ni->access);
					send_notice_to_user(sourceNick, callerUser, "Flags: 0x%08X (%s)",								(unsigned long)ni->flags, get_nick_flags(ni->flags));
					send_notice_to_user(sourceNick, callerUser, "Last Drop Request C-time: %d",						ni->last_drop_request);
					send_notice_to_user(sourceNick, callerUser, "Last E-Mail Request C-time: %d",					ni->last_email_request);
					send_notice_to_user(sourceNick, callerUser, "Max memos: %d",									ni->memomax);
					send_notice_to_user(sourceNick, callerUser, "Channels count: %d",								ni->channelcount);
					send_notice_to_user(sourceNick, callerUser, "News check value: %d",								ni->news);
					send_notice_to_user(sourceNick, callerUser, "Registration E-Mail: 0x%08X \2[\2%s\2]\2",			(unsigned long)ni->regemail, str_get_valid_display_value(ni->regemail));
					send_notice_to_user(sourceNick, callerUser, "URL: 0x%08X \2[\2%s\2]\2",							(unsigned long)ni->url, str_get_valid_display_value(ni->url));
					send_notice_to_user(sourceNick, callerUser, "New E-Mail: 0x%08X \2[\2%s\2]\2",					(unsigned long)ni->email, str_get_valid_display_value(ni->email));
					send_notice_to_user(sourceNick, callerUser, "Memo forwarded to: 0x%08X \2[\2%s\2]\2",			(unsigned long)ni->forward, str_get_valid_display_value(ni->forward));
					send_notice_to_user(sourceNick, callerUser, "Hold by: 0x%08X \2[\2%s\2]\2",						(unsigned long)ni->hold, str_get_valid_display_value(ni->hold));
					send_notice_to_user(sourceNick, callerUser, "Marked by: 0x%08X \2[\2%s\2]\2",					(unsigned long)ni->mark, str_get_valid_display_value(ni->mark));
					send_notice_to_user(sourceNick, callerUser, "Frozen by: 0x%08X \2[\2%s\2]\2",					(unsigned long)ni->freeze, str_get_valid_display_value(ni->freeze));
					send_notice_to_user(sourceNick, callerUser, "Forbidden by: 0x%08X \2[\2%s\2]\2",				(unsigned long)ni->forbid, str_get_valid_display_value(ni->forbid));
					send_notice_to_user(sourceNick, callerUser, "Auth code: %d",									ni->auth);
					send_notice_to_user(sourceNick, callerUser, "LangID: %d (%d)",									ni->langID, EXTRACT_LANG_ID(ni->langID));
					send_notice_to_user(sourceNick, callerUser, "reserved[3]: %d %d %d",							ni->reserved[0], ni->reserved[1], ni->reserved[2]);
					send_notice_to_user(sourceNick, callerUser, "Next / previous record: 0x%08X / 0x%08X",			(unsigned long)ni->next, (unsigned long)ni->prev);

					LOG_DEBUG_SNOOP("Command: DUMP NICKSERV NICK %s -- by %s (%s@%s)", value, callerUser->nick, callerUser->username, callerUser->host);
				}
			}
		} else if (str_equals_nocase(cmd, "ACCESS")) {

			if (IS_NULL(value))
				needSyntax = TRUE;

			else {

				NickInfo *ni = findnick(value);

				if (IS_NULL(ni))
					send_notice_to_user(sourceNick, callerUser, "DUMP: Nickname \2%s\2 not found.", value);

				else {

					char **anAccess;
					long i;

					if (ni->accesscount)
						send_notice_to_user(sourceNick, callerUser, "DUMP: Access List for nickname \2%s\2", value);

					for (anAccess = ni->access, i = 0; i < ni->accesscount; ++anAccess, ++i)
						send_notice_to_user(sourceNick, callerUser, "%d) Mask: 0x%08X \2[\2%s\2]\2", i+1, (unsigned long)*anAccess, *anAccess);

					LOG_DEBUG_SNOOP("Command: DUMP NICKSERV ACCESS %s -- by %s (%s@%s)", value, callerUser->nick, callerUser->username, callerUser->host);
				}
			}
		} else if (str_equals_nocase(cmd, "GUL")) {

			unsigned int	idx, n;

			send_notice_to_user(sourceNick, callerUser, "DUMP: Guest Used List (\2 0x%08X \2)", nickserv_used_guest_list);

			if (IS_NOT_NULL(nickserv_used_guest_list)) {

				for (idx = 0, n = 0; idx < 99999 - 10000 + 1; ++idx) {

					if (nickserv_used_guest_list[idx] == 1)
						send_notice_to_user(sourceNick, callerUser, "%d) \2%d\2", n++, idx + 10000);
				}
			}

			LOG_DEBUG_SNOOP("Command: DUMP NICKSERV GUL -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
		
		#ifdef FIX_USE_MPOOL
		} else if (str_equals_nocase(cmd, "POOL")) {

		} else if (str_equals_nocase(cmd, "POOLSTAT")) {

			MemoryPoolStats pstats;

			mempool_stats(nickdb_mempool, &pstats);
			send_notice_to_user(sourceNick, callerUser, "DUMP: NickServ memory pool - Address 0x%08X, ID: %d",	(unsigned long)nickdb_mempool, pstats.id);
			send_notice_to_user(sourceNick, callerUser, "Memory allocated / free: %d B / %d B",				pstats.memory_allocated, pstats.memory_free);
			send_notice_to_user(sourceNick, callerUser, "Items allocated / free: %d / %d",					pstats.items_allocated, pstats.items_free);
			send_notice_to_user(sourceNick, callerUser, "Items per block / block count: %d / %d",			pstats.items_per_block, pstats.block_count);
			//send_notice_to_user(sourceNick, callerUser, "Avarage use: %.2f%%",								pstats.block_avg_usage);

		#endif

		} else
			needSyntax = TRUE;
	}
	else
		needSyntax = TRUE;

	if (needSyntax) {

		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 NICKSERV HELP");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 NICKSERV NICK nickname");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 NICKSERV ACCESS nickname");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 NICKSERV GUL");
		#ifdef FIX_USE_MPOOL
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 NICKSERV POOLSTAT");
		#endif
	}
}

/*********************************************************/

unsigned long nickserv_mem_report(CSTR sourceNick, const User *callerUser) {

	NickInfo			*ni;
	unsigned long		count = 0, mem = 0, total_mem;
	int					idx, accessIdx;
	char				**anAccess;


	TRACE_FCLT(FACILITY_NICKSERV_GET_STATS);

	send_notice_to_user(sourceNick, callerUser, "\2%s\2:", s_NickServ);

	/* nick */

	for (idx = 65; idx < 126; ++idx) {

		for (ni = nicklists[idx]; IS_NOT_NULL(ni); ni = ni->next) {

			TRACE();

			++count;
			mem += sizeof(*ni);

			if (ni->last_usermask)
				mem += str_len(ni->last_usermask) + 1;

			if (ni->last_realname)
				mem += str_len(ni->last_realname) + 1;

			if (ni->url)
				mem += str_len(ni->url) + 1;

			if (ni->email)
				mem += str_len(ni->email) + 1;

			if (ni->forward)
				mem += str_len(ni->forward) + 1;

			if (ni->mark)
				mem += str_len(ni->mark) + 1;

			if (ni->hold)
				mem += str_len(ni->hold) + 1;

			if (ni->forbid)
				mem += str_len(ni->forbid) + 1;

			if (ni->freeze)
				mem += str_len(ni->freeze) + 1;

			TRACE();
			mem += sizeof(char *) * ni->accesscount;

			for (anAccess = ni->access, accessIdx = 0; (accessIdx < ni->accesscount); ++anAccess, ++accessIdx) {

				if (*anAccess)
					mem += str_len(*anAccess) + 1;
			}
		}
	}

	total_mem = mem;
	send_notice_to_user(sourceNick, callerUser, "Record: \2%d\2 [%d] -> \2%d\2 KB (\2%d\2 B)", count, ns_regCount, mem / 1024, mem);

	return total_mem;
}

#endif /* USE_SERVICES */
