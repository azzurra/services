/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* memoserv.c - Memo Services
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
#include "../inc/logging.h"
#include "../inc/memory.h"
#include "../inc/send.h"
#include "../inc/lang.h"
#include "../inc/datafiles.h"
#include "../inc/users.h"
#include "../inc/conf.h"
#include "../inc/main.h"
#include "../inc/misc.h"
#include "../inc/nickserv.h"
#include "../inc/helpserv.h"
#include "../inc/memoserv.h"


#ifdef	FIX_USE_MPOOL

MemoryPool			*memodb_mempool;

#endif /* FIX_USE_MPOOL */

static MemoList *memolists[256];	/* One for each initial character */

/* Stuff to pass to the command handler. */
static Agent a_MemoServ;

static void del_memolist(MemoList *ml);
static void database_insert_memolist(MemoList *ml);

static void do_set_notify(User *callerUser, const char *param);
static void do_set_ignoretype(User *callerUser, const char *param);

static void do_del(const char *source, User *callerUser, ServiceCommandData *data);
static void do_forward(const char *source, User *callerUser, ServiceCommandData *data);
static void do_ignore(const char *source, User *callerUser, ServiceCommandData *data);
static void do_list(const char *source, User *callerUser, ServiceCommandData *data);
static void do_news(const char *source, User *callerUser, ServiceCommandData *data);
static void do_purge(const char *source, User *callerUser, ServiceCommandData *data);
static void do_read(const char *source, User *callerUser, ServiceCommandData *data);
static void do_send(const char *source, User *callerUser, ServiceCommandData *data);
static void do_sendto(const char *source, User *callerUser, ServiceCommandData *data);
static void do_set(const char *source, User *callerUser, ServiceCommandData *data);
static void do_undel(const char *source, User *callerUser, ServiceCommandData *data);
static void do_unsend(const char *source, User *callerUser, ServiceCommandData *data);

static void do_global(const char *source, User *callerUser, ServiceCommandData *data);
static void do_info(const char *source, User *callerUser, ServiceCommandData *data);
static void do_limit(const char *source, User *callerUser, ServiceCommandData *data);

static MemoIgnore *memoserv_find_ignore(MemoIgnore *ignores_list, CSTR nick);
#define memoserv_is_ignored(ignores_list, nick) (BOOL)(memoserv_find_ignore((ignores_list), (nick)) != NULL)

/*********************************************************/

void memoserv_init(void) {

	#ifdef FIX_USE_MPOOL
	memodb_mempool = mempool_create(MEMPOOL_ID_MEMODB, sizeof(MemoList), MP_IPB_MEMODB, MB_IBC_MEMODB);
	#endif

	/* Initialize this struct. */
	a_MemoServ.nick = s_MemoServ;
	a_MemoServ.shortNick = s_MS;
	a_MemoServ.agentID = AGENTID_MEMOSERV;
	a_MemoServ.logID = logid_from_agentid(AGENTID_MEMOSERV);
}

void memoserv_terminate(void) {

	#ifdef FIX_USE_MPOOL
	mempool_destroy(memodb_mempool);
	memodb_mempool = NULL;
	#endif
}

/*********************************************************/

// 'A' (65 / 0)
// 'B' (66 / 1)
// 'C' (67 / 2)
// 'D' (68 / 3)
static ServiceCommand	memoserv_commands_D[] = {
	{ "DEL",		ULEVEL_USER,			0, do_del },
	{ NULL,			0,						0, NULL }
};
// 'E' (69 / 4)
// 'F' (70 / 5)
static ServiceCommand	memoserv_commands_F[] = {
	{ "FORWARD",	ULEVEL_USER,			0, do_forward },
	{ NULL,			0,						0, NULL }
};
// 'G' (71 / 6)
static ServiceCommand	memoserv_commands_G[] = {
	{ "GLOBAL",		ULEVEL_SRA,				0, do_global },
	{ NULL,			0,						0, NULL }
};
// 'H' (72 / 7)
static ServiceCommand	memoserv_commands_H[] = {
	{ "HELP",		ULEVEL_USER,			0, handle_help },
	{ NULL,			0,						0, NULL }
};
// 'I' (73 / 8)
static ServiceCommand	memoserv_commands_I[] = {
	{ "IGNORE",		ULEVEL_USER,			0, do_ignore },
	{ "INFO",		ULEVEL_SRA,				0, do_info },
	{ NULL,			0,						0, NULL }
};
// 'J' (74 / 9)
// 'K' (75 / 10)
// 'L' (76 / 11)
static ServiceCommand	memoserv_commands_L[] = {
	{ "LIST",		ULEVEL_USER,			0, do_list },
	{ "LIMIT",		ULEVEL_SA,				0, do_limit },
	{ NULL,			0,						0, NULL }
};
// 'M' (77 / 12)
// 'N' (78 / 13)
static ServiceCommand	memoserv_commands_N[] = {
	{ "NEWS",		ULEVEL_USER,			0, do_news },
	{ NULL,			0,						0, NULL }
};
// 'O' (79 / 14)
static ServiceCommand	memoserv_commands_O[] = {
	{ "OHELP",		ULEVEL_OPER,			0, handle_help },
	{ NULL,			0,						0, NULL }
};
// 'P' (80 / 15)
static ServiceCommand	memoserv_commands_P[] = {
	{ "PURGE",		ULEVEL_USER,			0, do_purge },
	{ NULL,			0,						0, NULL }
};
// 'Q' (81 / 16)
// 'R' (82 / 17)
static ServiceCommand	memoserv_commands_R[] = {
	{ "READ",		ULEVEL_USER,			0, do_read },
	{ NULL,			0,						0, NULL }
};
// 'S' (83 / 18)
static ServiceCommand	memoserv_commands_S[] = {
	{ "SEND",		ULEVEL_USER,			0, do_send },
	{ "SENDTO",		ULEVEL_USER,			0, do_sendto },
	{ "SET",		ULEVEL_USER,			0, do_set },
	{ NULL,			0,						0, NULL }
};
// 'T' (84 / 19)
// 'U' (85 / 20)
static ServiceCommand	memoserv_commands_U[] = {
	{ "UNDEL",		ULEVEL_USER,			0, do_undel },
	{ "UNSEND",		ULEVEL_USER,			0, do_unsend },
	{ NULL,			0,						0, NULL }
};
// 'V' (86 / 21)
// 'W' (87 / 22)
// 'X' (88 / 23)
// 'Y' (89 / 24)
// 'Z' (90 / 25)

ServiceCommand	*memoserv_commands[26] = {
	NULL,					NULL,
	NULL,					memoserv_commands_D,
	NULL,					memoserv_commands_F,
	memoserv_commands_G,	memoserv_commands_H,
	memoserv_commands_I,	NULL,
	NULL,					memoserv_commands_L,
	NULL,					memoserv_commands_N,
	memoserv_commands_O,	memoserv_commands_P,
	NULL,					memoserv_commands_R,
	memoserv_commands_S,	NULL,
	memoserv_commands_U,	NULL,
	NULL,					NULL,
	NULL,					NULL
};


/* memoserv: Main MemoServ routine. */

void memoserv(const char *source, User *callerUser, char *buf) {

	char *cmd;

	
	TRACE_MAIN_FCLT(FACILITY_MEMOSERV);

	if (IS_NULL(cmd = strtok(buf, " ")))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_SERVICE_COMMAND_LIST, s_MS);

	else if (cmd[0] == '\001') {

		++cmd;

		if (IS_EMPTY_STR(cmd))
			LOG_SNOOP(s_OperServ, "[%s] Invalid CTCP from \2%s\2", s_MemoServ, source);

		else if (str_equals_nocase(cmd, "PING")) {

			send_notice_to_user(s_MemoServ, callerUser, "\001PING\001");
			LOG_SNOOP(s_OperServ, "[%s] CTCP: PING from \2%s\2", s_MemoServ, source);
		}
		else {

			char *action = strtok(NULL, "");

			if (action) {

				action[str_len(action) - 1] = '\0';
				LOG_SNOOP(s_OperServ, "[%s] CTCP: %s %s from \2%s\2", s_MemoServ, cmd, action, source);
			}
			else {

				cmd[str_len(cmd) - 1] = '\0';
				LOG_SNOOP(s_OperServ, "[%s] CTCP: %s from \2%s\2", s_MemoServ, cmd, source);
			}
		}
	}
	else
		oper_invoke_agent_command(cmd, memoserv_commands, callerUser, &a_MemoServ);
}

/*********************************************************/

void load_ms_dbase(void) {

	FILE *f;
	int ver, idx, memoIdx;
	MemoList *ml;
	Memo *memo;

	TRACE_FCLT(FACILITY_MEMOSERV_LOAD_MS_DB);

	if (IS_NULL(f = open_db_read(s_MemoServ, MEMOSERV_DB)))
		return;

	for (idx = 0; idx < 256; ++idx)
		memolists[idx] = NULL;

	TRACE();
	switch (ver = get_file_version(f, MEMOSERV_DB)) {

		case MEMOSERV_DB_CURRENT_VERSION:

			for (idx = 65; idx < 126; ++idx) {

				MemoIgnore *ignore;

				while (fgetc(f) == 1) {

					TRACE();
					
					#ifdef FIX_USE_MPOOL
					ml = mempool_alloc(MemoList*, memodb_mempool, FALSE);
					#else
					ml = mem_malloc(sizeof(MemoList));
					#endif

					if (fread(ml, sizeof(MemoList), 1, f) != 1)
						fatal_error(FACILITY_MEMOSERV_LOAD_MS_DB, __LINE__, "Read error (1) on %s", MEMOSERV_DB);

					TRACE();
					database_insert_memolist(ml);

					if (ml->n_memos > 0) {

						ml->memos = mem_malloc(sizeof(Memo) * ml->n_memos);

						TRACE();
						if (fread(ml->memos, sizeof(Memo), ml->n_memos, f) != (size_t) ml->n_memos)
							fatal_error(FACILITY_MEMOSERV_LOAD_MS_DB, __LINE__, "Read error (2) on %s", MEMOSERV_DB);

						for (memo = ml->memos, memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx, ++memo) {

							memo->text = read_string(f, MEMOSERV_DB);

							if (IS_NOT_NULL(memo->chan))
								memo->chan = read_string(f, MEMOSERV_DB);
						}
					}
					else
						ml->memos = NULL;

					TRACE();
					ml->ignores = NULL;

					if (ml->n_ignores > 0) {

						for (memoIdx = 0; memoIdx < ml->n_ignores; ++memoIdx) {

							ignore = mem_malloc(sizeof(MemoIgnore));

							TRACE();
							if (fread(ignore, sizeof(MemoIgnore), 1, f) != 1)
								fatal_error(FACILITY_MEMOSERV_LOAD_MS_DB, __LINE__, "Read error (3) on %s", MEMOSERV_DB);

							if (IS_NOT_NULL(ignore->ignoredNick))
								ignore->ignoredNick = read_string(f, MEMOSERV_DB);

							TRACE();

							ignore->prev = NULL;
							ignore->next = ml->ignores;

							if (IS_NOT_NULL(ml->ignores))
								ml->ignores->prev = ignore;

							ml->ignores = ignore;
						}
					}
				}
			}

			break;

		default:
			fatal_error(FACILITY_MEMOSERV_LOAD_MS_DB, __LINE__, "Unsupported version number (%d) on %s", ver, MEMOSERV_DB);
	}

	TRACE();
	close_db(f, MEMOSERV_DB);
}

/*********************************************************/

void save_ms_dbase(void) {

	FILE *f;
	int idx, memoIdx;
	MemoList *ml;
	Memo *memo;
	
	TRACE_FCLT(FACILITY_MEMOSERV_SAVE_MS_DB);

	if (IS_NULL(f = open_db_write(s_MemoServ, MEMOSERV_DB, MEMOSERV_DB_CURRENT_VERSION)))
		return;

	TRACE();
	for (idx = 65; idx < 126; ++idx) {

		for (ml = memolists[idx]; IS_NOT_NULL(ml); ml = ml->next) {

			TRACE();
			fputc(1, f);

			if (fwrite(ml, sizeof(MemoList), 1, f) != 1)
				fatal_error(FACILITY_MEMOSERV_SAVE_MS_DB, __LINE__, "Write error (1) on %s", MEMOSERV_DB);

			if (fwrite(ml->memos, sizeof(Memo), ml->n_memos, f) != (size_t) ml->n_memos)
				fatal_error(FACILITY_MEMOSERV_SAVE_MS_DB, __LINE__, "Write error (2) on %s", MEMOSERV_DB);

			TRACE();
			for (memo = ml->memos, memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx, ++memo) {

				write_string(memo->text, f, MEMOSERV_DB);

				if (IS_NOT_NULL(memo->chan))
					write_string(memo->chan, f, MEMOSERV_DB);
			}

			if (ml->n_ignores > 0) {

				MemoIgnore *ignore;

				for (ignore = ml->ignores; IS_NOT_NULL(ignore); ignore = ignore->next) {

					if (fwrite(ignore, sizeof(MemoIgnore), 1, f) != 1)
						fatal_error(FACILITY_MEMOSERV_SAVE_MS_DB, __LINE__, "Write error (3) on %s", MEMOSERV_DB);

					if (IS_NOT_NULL(ignore->ignoredNick))
						write_string(ignore->ignoredNick, f, MEMOSERV_DB);
				}
			}
		}

		TRACE();
		fputc(0, f);
	}

	TRACE();
	close_db(f, MEMOSERV_DB);
}

/*********************************************************/

void expire_memos() {

	MemoList *ml, *next;
	Memo *memo = NULL;
	int idx, memoIdx, memoExpired;
	const time_t expire_limit = (NOW - (CONF_MEMO_EXPIRE * ONE_DAY));
	unsigned long int recordCount = 0, memoCount = 0, expiredRecordCount = 0, expiredMemoCount = 0;


	TRACE_FCLT(FACILITY_MEMOSERV_EXPIRE_MEMOS);

	if (CONF_SET_NOEXPIRE)
		return;

	for (idx = 65; idx < 126; ++idx) {

		for (ml = memolists[idx]; IS_NOT_NULL(ml); ml = next) {

			next = ml->next;

			++recordCount;

			TRACE();

			/* These two need to be reset before each loop. */
			memoExpired = 0;

			for (memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx) {

				++memoCount;

				memo = ml->memos + memoIdx;

				if (memo->time < expire_limit) {

					TRACE();

					/* Increase number of expired memos for this record. */
					++memoExpired;

					/* Increase total number of expired memos. */
					++expiredMemoCount;

					/* Log the expiration. */
					if (CONF_SET_EXTRASNOOP)
						LOG_SNOOP(s_OperServ, "MS X %s [%d]", ml->nick, (memoIdx + memoExpired));

					/* Free this memo. */
					mem_free(memo->text);

					if (IS_NOT_NULL(memo->chan))
						mem_free(memo->chan);

					/* Decrease user's memo count by one. */
					--(ml->n_memos);

					/* If it wasn't the last one, move the remaining memos down one slot. */
					if (memoIdx < ml->n_memos) {

						TRACE();
						memmove(ml->memos + memoIdx, (ml->memos + memoIdx + 1), (sizeof(Memo) * (ml->n_memos - memoIdx)));
						--memoIdx;
					}

					/* If we deleted all memos, take appropriate action. */
					if (ml->n_memos == 0) {

						if (ml->n_ignores == 0) {

							TRACE();
							++expiredRecordCount;

							if (CONF_SET_EXTRASNOOP)
								LOG_SNOOP(s_OperServ, "MS X %s [record]", ml->nick);

							del_memolist(ml);

							/* Break the for loop as ml is no longer valid. */
							break;
						}
						else {

							if (IS_NOT_NULL(ml->memos))
								mem_free(ml->memos);
							ml->memos = NULL;
						}
					}
				}
			}
		}
	}

	if (CONF_DISPLAY_UPDATES)
		send_globops(NULL, "Completed MemoServ Expire: (%d/%d) Record Expire: (%d/%d)", expiredMemoCount, memoCount, expiredRecordCount, recordCount);
	else
		LOG_SNOOP(s_OperServ, "Completed MemoServ Expire: (%d/%d) Record Expire: (%d/%d)", expiredMemoCount, memoCount, expiredRecordCount, recordCount);
}


/*********************************************************
 * MemoServ private routines.                            *
 *********************************************************/

static MemoList *create_memolist(const char *nickname) {

	MemoList *ml;


	TRACE_FCLT(FACILITY_MEMOSERV_CREATE_MEMOLIST);

	#ifdef FIX_USE_MPOOL
	ml = mempool_alloc(MemoList*, memodb_mempool, TRUE);
	#else
	ml = mem_calloc(1, sizeof(MemoList));
	#endif

	str_copy_checked(nickname, ml->nick, NICKMAX);
	database_insert_memolist(ml);
	TRACE();

	return ml;
}

/* find_memolist: Find the memo list for a given nick. Return NULL if none. */
static MemoList *find_memolist(const char *nickname) {

	MemoList *ml;


	TRACE_FCLT(FACILITY_MEMOSERV_FIND_MEMOLIST);

	if (IS_NOT_NULL(nickname)) {

		for (ml = memolists[str_char_tolower(*nickname)]; ml; ml = ml->next) {

			TRACE();
			if (str_equals_nocase(ml->nick, nickname))
				return ml;
		}
	}

	return NULL;
}

/*********************************************************/

/* Insert a memo list into the database. */
static void database_insert_memolist(MemoList *ml) {

	MemoList	*branch_head;
	int			branch_name;


	TRACE_FCLT(FACILITY_MEMOSERV_DATABASE_INSERT_MEMOLIST);

	if (IS_NULL(ml)) {

		log_error(FACILITY_MEMOSERV_DATABASE_INSERT_MEMOLIST, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "database_insert_memolist()", s_LOG_NULL, "ml");
		return;
	}

	branch_name = str_char_tolower(ml->nick[0]);
	branch_head = memolists[branch_name];

	memolists[branch_name] = ml;
	
	TRACE();

	ml->next = branch_head;
	ml->prev = NULL;

	if (IS_NOT_NULL(branch_head))
		branch_head->prev = ml;
}


/*********************************************************
 * Clears all memos from a MemoList and removes it from  *
 * our database.                                         *
 *********************************************************/

static void del_memolist(MemoList *ml) {

	int memoIdx;
	MemoIgnore *ignore, *next;


	TRACE_FCLT(FACILITY_MEMOSERV_DEL_MEMOLIST);

	if (ml->next)
		ml->next->prev = ml->prev;

	if (ml->prev)
		ml->prev->next = ml->next;
	else
		memolists[str_char_tolower(*ml->nick)] = ml->next;

	/* Clear all remaining memos. */
	for (memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx) {

		mem_free(ml->memos[memoIdx].text);

		if (ml->memos[memoIdx].chan)
			mem_free(ml->memos[memoIdx].chan);
	}

	if (ml->memos)
		mem_free(ml->memos);

	TRACE();

	/* Clear all ignores, if any. */
	for (ignore = ml->ignores; IS_NOT_NULL(ignore); ) {

		next = ignore->next;

		mem_free(ignore->ignoredNick);
		mem_free(ignore);

		ignore = next;
	}

	TRACE();

	#ifdef FIX_USE_MPOOL
	mempool_free(memodb_mempool, ml);
	#else
	mem_free(ml);
	#endif
}


/*********************************************************
 * See if an user has any waiting memos, and notify them *
 * about it if they do.                                  *
 *********************************************************/

void check_memos(const User *callerUser, NickInfo *ni) {

	MemoList *ml;
	BOOL sameNick;


	TRACE_FCLT(FACILITY_MEMOSERV_CHECK_MEMOS);

	if (IS_NULL(callerUser) || IS_NULL(ni)) {

		log_error(FACILITY_MEMOSERV_CHECK_MEMOS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "check_memos()", s_LOG_NULL, IS_NULL(callerUser) ? "callerUser" : "ni");

		return;
	}

	sameNick = (str_equals_nocase(callerUser->nick, ni->nick));

	/* If the user is identifying to the nickname he's currently using, see if there's a NEWS available. */
	if (sameNick && FlagUnset(ni->flags, NI_READNEWS) && lang_get_news(GetNickLang(ni)))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_NEWS_AVAILABLE, CONF_NETWORK_NAME);

	TRACE();
	if (IS_NOT_NULL(ml = find_memolist(ni->nick)) && (ml->n_memos > 0)) {

		int memoIdx, memoNumber = 0, newCount = 0;

		TRACE();
		for (memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx) {

			if (FlagSet(ml->memos[memoIdx].flags, MF_UNREAD) && FlagUnset(ml->memos[memoIdx].flags, MF_DEL)) {

				++newCount;
				memoNumber = (memoIdx + 1);
			}
		}

		if (newCount > 0) {

			if (!sameNick) {

				if (newCount == 1)
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_NOTIFY_REMOTE_1_NEW_MEMO, ni->nick);
				else
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_NOTIFY_REMOTE_X_NEW_MEMOS, ni->nick, newCount);
			}
			else {

				if (newCount == 1) {

					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_NOTIFY_1_NEW_MEMO);
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_NOTIFY_READ_NEW_MEMO, memoNumber);
				}
				else {

					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_NOTIFY_X_NEW_MEMOS, newCount);
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_NOTIFY_LIST_NEW_MEMOS);
				}
			}
		}

		if ((ni->memomax > 0) && (ml->n_memos >= ni->memomax)) {

			if (ml->n_memos > ni->memomax)
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_WARNING_OVER_MEMO_LIMIT);
			else
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_WARNING_REACHED_MEMO_LIMIT);
		}
	}
}


/*********************************************************
 * Check for marked deleted memos when an user logs      *
 * offline, and actually delete them.                    *
 *********************************************************/

void memoserv_delete_flagged_memos(CSTR nick, BOOL noMessage) {

	MemoList *ml;


	TRACE_FCLT(FACILITY_MEMOSERV_DELETE_FLAGGED_MEMOS);

	if (IS_NULL(nick)) {

		log_error(FACILITY_MEMOSERV_DELETE_FLAGGED_MEMOS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "memoserv_delete_flagged_memos()", s_LOG_NULL, "nick");
	}
	else if (IS_NULL(ml = find_memolist(nick)) || (ml->n_memos == 0)) {

		if (!noMessage)
			send_notice_lang_to_nick(s_MemoServ, nick, GetCallerLang(), MS_PURGE_ERROR_NO_MEMOS_TO_PURGE);
	}
	else {

		Memo *memo;
		int memoIdx, count = 0;

		TRACE();

		for (memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx) {

			TRACE();
			memo = ml->memos + memoIdx;

			if (FlagSet(memo->flags, MF_DEL)) {

				++count;

				TRACE();

				mem_free(memo->text);

				if (IS_NOT_NULL(memo->chan))
					mem_free(memo->chan);

				/* Decrease user's memo count by one. */
				--(ml->n_memos);

				/* If it wasn't the last one, move the remaining memos down one slot. */
				if (memoIdx < ml->n_memos) {

					TRACE();
					memmove(ml->memos + memoIdx, (ml->memos + memoIdx + 1), (sizeof(Memo) * (ml->n_memos - memoIdx)));
					--memoIdx;
				}
			}
		}

		TRACE();
		if (!noMessage) {

			if (count == 0)
				send_notice_lang_to_nick(s_MemoServ, nick, GetCallerLang(), MS_PURGE_ERROR_NO_MEMOS_TO_PURGE);
			else
				send_notice_lang_to_nick(s_MemoServ, nick, GetCallerLang(), MS_PURGE_ALL_MEMOS_PURGED);
		}

		TRACE();

		/* Did we delete the last memo? If so, if the user has no ignores, delete this MemoList. */
		if (ml->n_memos == 0) {

			if (ml->n_ignores == 0)
				del_memolist(ml);

			else {

				if (ml->memos)
					mem_free(ml->memos);
				ml->memos = NULL;
			}
		}
	}
}


/*********************************************************
 * Remove the MemoList for a given nick, if present.     *
 * Called upon nickname registration and expiration.     *
 *********************************************************/

void clear_memos(CSTR nick) {

	MemoList *ml;


	TRACE_FCLT(FACILITY_MEMOSERV_CLEAR_MEMOS);

	if (IS_NOT_NULL(ml = find_memolist(nick)))
		del_memolist(ml);
}

/*********************************************************/

static MemoIgnore *memoserv_find_ignore(MemoIgnore *ignores_list, CSTR nick) {

	MemoIgnore	*ignore;

	if (IS_NOT_NULL(nick)) {

		for (ignore = ignores_list; IS_NOT_NULL(ignore); ignore = ignore->next)

			if (str_equals_nocase(nick, ignore->ignoredNick))
				return ignore;
	}

	return NULL;
}


/*********************************************************
 * E-Mail a memo to the nick who received it, if they    *
 * enabled their Email Memos option.                     *
 *********************************************************/

static void email_memo(NickInfo *ni, Memo *memo) {

	FILE *memofile;

	if (IS_NULL(ni) || IS_NULL(memo)) {

		log_error(FACILITY_MEMOSERV_EMAIL_MEMO, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "email_memo()", s_LOG_NULL, IS_NULL(ni) ? "ni" : "memo");

		return;
	}

	if (!CONF_SEND_REMINDER || !CONF_USE_EMAIL || IS_NULL(ni->email))
		return;

	if (IS_NOT_NULL(memofile = fopen("memo.txt", "w"))) {

		char timebuf[64];

		TRACE_MAIN();
		fprintf(memofile, "From: %s <%s>\n", CONF_NETWORK_NAME, CONF_RETURN_EMAIL);
		fprintf(memofile, "To: %s\n", ni->email);

		lang_format_localtime(timebuf, sizeof(timebuf), GetNickLang(ni), TIME_FORMAT_DAYTIME, memo->time);

		if (memo->chan) {

			fprintf(memofile, lang_msg(GetNickLang(ni), MS_SENDTO_EMAIL_SUBJECT), ni->nick);
			fprintf(memofile, lang_msg(GetNickLang(ni), MS_SENDTO_EMAIL_TEXT), memo->sender, memo->chan, timebuf, memo->text, CONF_NETWORK_NAME);
		}
		else {

			fprintf(memofile, lang_msg(GetNickLang(ni), MS_SEND_EMAIL_SUBJECT), ni->nick);
			fprintf(memofile, lang_msg(GetNickLang(ni), MS_SEND_EMAIL_TEXT), memo->sender, timebuf, memo->text, CONF_NETWORK_NAME);
		}

		fclose(memofile);

		snprintf(misc_buffer, MISC_BUFFER_SIZE, "%s -f %s -t < memo.txt", CONF_SENDMAIL_PATH, CONF_RETURN_EMAIL);
		system(misc_buffer);

		snprintf(misc_buffer, MISC_BUFFER_SIZE, "rm -f memo.txt");
		system(misc_buffer);
	}
	else
		log_error(FACILITY_MEMOSERV_HANDLE_SEND, __LINE__, LOG_TYPE_ERROR_RTL, LOG_SEVERITY_ERROR_SKIPPED,
			"email_memo(): unable to create memo.txt");
}


/*********************************************************
 * Send a memo to a nick. Return TRUE if sent, FALSE if  *
 * not sent due to an error, or an option like No Memo.  *
 *********************************************************/

static BOOL send_memo(User *callerUser, CSTR sender, NickInfo *ni, CSTR message, CSTR channel, int level, BOOL reply) {

	Memo *memo;
	User *user;
	MemoList *ml;
	BOOL notify;
	char *forwarded = NULL;

	if (IS_NULL(ni) || IS_NULL(message) || IS_EMPTY_STR(message) ||
		(IS_NOT_NULL(channel) && IS_NOT_EMPTY_STR(channel) && !level)) {

		log_error(FACILITY_MEMOSERV_HANDLE_SEND, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "send_memo()", s_LOG_NULL, (!ni ? "ni" : (!message ? "message" : "level")));

		return FALSE;
	}

	if (IS_NULL(ml = find_memolist(ni->nick))) {

		if (FlagSet(ni->flags, NI_REVERSEIGN)) {

			if (reply)
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SEND_MEMO_SENT, ni->nick);

			return TRUE;
		}
	}
	else {

		BOOL isIgnored = memoserv_is_ignored(ml->ignores, callerUser->nick);

		if (FlagSet(ni->flags, NI_REVERSEIGN) != isIgnored) {

			if (reply)
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SEND_MEMO_SENT, ni->nick);

			return TRUE;
		}
	}

	notify = FlagSet(ni->flags, NI_MEMO_RECEIVE);

	TRACE_MAIN();

	if (IS_NOT_NULL(ni->forward)) {

		NickInfo *nif;

		if (IS_NOT_NULL(nif = findnick(ni->forward))) {

			/* Make sure the receiver is not rejecting the memo. */
			if (IS_NULL(channel) ? FlagSet(nif->flags, NI_NOMEMO) : FlagSet(nif->flags, NI_NOCHANMEMO)) {

				if (reply)
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_FORWARD_ERROR_REJECTED, nif->nick, IS_NULL(channel) ? "No Memo" : "No Chan Memo");

				return FALSE;
			}

			/* Make sure the receiver is not forwarding memos to the sender. */
			if (str_equals_nocase(nif->nick, callerUser->nick) || str_equals_nocase(nif->forward, callerUser->nick)) {

				if (reply)
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SEND_ERROR_FORWARD_TO_SELF);

				return FALSE;
			}

			if (IS_NOT_NULL(ml = find_memolist(nif->nick))) {

				BOOL isIgnored = memoserv_is_ignored(ml->ignores, callerUser->nick);

				if (FlagSet(ni->flags, NI_REVERSEIGN) != isIgnored) {

					if (reply)
						send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SEND_MEMO_SENT, ni->nick);

					return TRUE;
				}
			}

			notify = FlagSet(nif->flags, NI_MEMO_RECEIVE);

			forwarded = ni->nick;
			ni = nif;
		}
		else {

			mem_free(ni->forward);
			ni->forward = NULL;
		}
	}

	if (IS_NULL(ml))
		ml = create_memolist(ni->nick);

	else {

		if ((ni->memomax > 0) && (ml->n_memos >= ni->memomax)) {

			if (reply)
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), (forwarded ? MS_ERROR_FORWARDED_OVER_MAX_MEMOS : MS_ERROR_OVER_MAX_MEMOS), (forwarded ? forwarded : ni->nick));

			return FALSE;
		}
	}

	/* Increase the number of memos for this user. */
	++(ml->n_memos);

	/* Allocate a new slot. */
	ml->memos = mem_realloc(ml->memos, sizeof(Memo) * ml->n_memos);

	/* Point memo to the newly allocated slot. */
	memo = ml->memos + (ml->n_memos - 1);

	/* Fill in the memo structure. */
	str_copy_checked(sender, memo->sender, NICKMAX);

	TRACE_MAIN();

	memo->time = NOW;
	memo->chan = IS_NOT_NULL(channel) ? str_duplicate(channel) : NULL;
	memo->text = str_duplicate(message);
	memo->level = level;
	memo->flags = MF_UNREAD;

	TRACE_MAIN();
	if (notify && IS_NOT_NULL(user = hash_onlineuser_find(ni->nick)) && user_is_identified_to(user, ni->nick)) {

		/* The user is online and wants to be notified about the new memo. Do so. */
		send_notice_lang_to_user(s_MemoServ, user, GetNickLang(ni), MS_NOTIFY_NEW_MEMO_FROM_NICK, memo->sender);
		send_notice_lang_to_user(s_MemoServ, user, GetNickLang(ni), MS_HELP_HOW_TO_READ, ml->n_memos);
	}

	/* Check if the user wants this memo E-Mailed to them. */
	if (FlagSet(ni->flags, NI_EMAILMEMOS))
		email_memo(ni, memo);

	if (reply)
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SEND_MEMO_SENT, ni->nick);

	return TRUE;
}


/*********************************************************
 * Send a memo to a nick from services. Used to mail the *
 * new password after a founder transfer and the like.   *
 * Always successful: user ignores and options are       *
 * ignored.                                              *
 *********************************************************/

void send_memo_internal(NickInfo *ni, CSTR message) {

	Memo *memo;
	User *user;
	MemoList *ml;
	char *forwarded = NULL;


	if (IS_NULL(ni) || IS_NULL(message)) {

		log_error(FACILITY_MEMOSERV_HANDLE_SEND, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "send_memo_internal()", s_LOG_NULL, IS_NULL(ni) ? "ni" : "message");

		return;
	}

	if (IS_NOT_NULL(ni->forward)) {

		NickInfo *nif;

		if (IS_NOT_NULL(nif = findnick(ni->forward))) {

			forwarded = ni->nick;
			ni = nif;
		}
		else {

			mem_free(ni->forward);
			ni->forward = NULL;
		}
	}

	if (IS_NULL(ml = find_memolist(ni->nick)))
		ml = create_memolist(ni->nick);

	/* Increase the number of memos for this user. */
	++(ml->n_memos);

	/* Allocate a new slot. */
	ml->memos = mem_realloc(ml->memos, sizeof(Memo) * ml->n_memos);

	/* Point memo to the newly allocated slot. */
	memo = ml->memos + (ml->n_memos - 1);

	/* Fill in the memo structure. */
	str_copy_checked(s_GlobalNoticer, memo->sender, NICKMAX);

	TRACE_MAIN();

	memo->time = NOW;
	memo->chan = NULL;
	memo->text = str_duplicate(message);
	memo->level = 0;
	memo->flags = MF_UNREAD;

	TRACE_MAIN();
	if (IS_NOT_NULL(user = hash_onlineuser_find(ni->nick)) && user_is_identified_to(user, ni->nick)) {

		/* The user is online, let them know about the memo regardless of their notify setting. */
		send_notice_lang_to_user(s_MemoServ, user, GetNickLang(ni), MS_NOTIFY_NEW_MEMO_FROM_NICK, memo->sender);
		send_notice_lang_to_user(s_MemoServ, user, GetNickLang(ni), MS_HELP_HOW_TO_READ, ml->n_memos);
	}

	/* Check if the user wants this memo E-Mailed to them. */
	if (FlagSet(ni->flags, NI_EMAILMEMOS))
		email_memo(ni, memo);
}


/*********************************************************
 * Show a memo to a nick. Return TRUE if sent, FALSE if  *
 * not sent due to an error, or if the memo did not      *
 * match the user's search criteria.                     *
 *********************************************************/

static BOOL read_memo(const User *callerUser, const Memo *memo, const BOOL matchType, const int memoNumber) {

	char timebuf[64];
	BOOL unread;


	TRACE_FCLT(FACILITY_MEMOSERV_READ_MEMO);

	if (IS_NULL(callerUser) || IS_NULL(memo)) {

		log_error(FACILITY_MEMOSERV_READ_MEMO, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "read_memo()", s_LOG_NULL, IS_NULL(callerUser) ? "callerUser" : "memo");

		return FALSE;
	}

	unread = FlagSet(memo->flags, MF_UNREAD);

	if ((matchType == MEMO_TYPE_NEW) && !unread)
		return FALSE;

	if ((matchType == MEMO_TYPE_CHANNEL) && IS_NULL(memo->chan))
		return FALSE;

	if ((matchType == MEMO_TYPE_DIRECT) && IS_NOT_NULL(memo->chan))
		return FALSE;

	lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DAYTIME, memo->time);

	if (IS_NOT_NULL(memo->chan)) {

		char *levelName;

		switch (memo->level) {

			case CS_ACCESS_COFOUNDER:	levelName = "CF+"; break;
			case CS_ACCESS_SOP:			levelName = "SOP+";	break;
			case CS_ACCESS_AOP:			levelName = "AOP+";	break;
			case CS_ACCESS_HOP:			levelName = "HOP+";	break;
			default:					levelName = "VOP+";	break;
		}

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_LIST_HEADER_CHANNEL, unread ? '*' : ' ',
			FlagSet(memo->flags, MF_DEL) ? 'D' : ' ', memoNumber, memo->sender, memo->chan, levelName, timebuf);
	}
	else
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_LIST_HEADER_DIRECT, unread ? '*' : ' ',
			FlagSet(memo->flags, MF_DEL) ? 'D' : ' ', memoNumber, memo->sender, timebuf);

	return TRUE;
}

/*********************************************************
 * MemoServ command routines.                            *
 *********************************************************/

/* Send a memo to a channel. */
static void do_sendto(const char *source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo *ci;
	char *chan, *list, *text;
	size_t len;


	TRACE_MAIN_FCLT(FACILITY_MEMOSERV_HANDLE_SENDTO);

	if (CONF_SET_READONLY)
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SEND_ERROR_READONLY);

	else if (IS_NULL(chan = strtok(NULL, " ")) || IS_NULL(list = strtok(NULL, " ")) || IS_NULL(text = strtok(NULL, ""))) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SENDTO_SYNTAX_ERROR);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "SENDTO");
	}
	else if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");	
	}
	else if (((callerUser->lastmemosend + CONF_MEMO_SEND_DELAY) > NOW) && !is_services_valid_oper(callerUser)) {

		callerUser->lastmemosend = NOW;
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_MEMO_DELAY, CONF_MEMO_SEND_DELAY, "SENDTO");
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
	}
	else if (FlagSet(callerUser->ni->flags, NI_AUTH)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SEND_ERROR_MUST_AUTH);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
	}
	else if (IS_NULL(ci = cs_findchan(chan)))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, chan);

	else if (FlagSet(ci->flags, CI_FORBIDDEN))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

	else if (FlagSet(ci->flags, CI_FROZEN))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FROZEN, ci->name);

	else if (FlagSet(ci->flags, CI_CLOSED))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_CLOSED, ci->name);

	else if (FlagSet(ci->flags, CI_SUSPENDED))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_SUSPENDED, ci->name);

	else if (FlagSet(ci->flags, CI_MEMO_NONE))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SENDTO_ERROR_MEMOLEVEL_NONE, ci->name);

	else if ((len = str_len(text)) > 400)
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_MEMO_MAX_LENGTH, 400, len);

	else {

		NickInfo *ni;
		ChanAccess *anAccess;
		char message[IRCBUFSIZE];
		int memoIdx, level, memoLevel, accessLevel;
		char accessName[NICKSIZE];


		if (FlagSet(ci->flags, CI_MEMO_NONE))
			memoLevel = CS_ACCESS_NONE;
		else if (FlagSet(ci->flags, CI_MEMO_VOP))
			memoLevel = CS_ACCESS_VOP;
		else if (FlagSet(ci->flags, CI_MEMO_HOP))
			memoLevel = CS_ACCESS_HOP;
		else if (FlagSet(ci->flags, CI_MEMO_AOP))
			memoLevel = CS_ACCESS_AOP;
		else if (FlagSet(ci->flags, CI_MEMO_SOP))
			memoLevel = CS_ACCESS_SOP;
		else if (FlagSet(ci->flags, CI_MEMO_CF))
			memoLevel = CS_ACCESS_COFOUNDER;
		else if (FlagSet(ci->flags, CI_MEMO_FR))
			memoLevel = CS_ACCESS_FOUNDER;

		else {

			/* Channel was most likely created before channel memos were implemented. */
			memoLevel = CS_ACCESS_VOP;
			AddFlag(ci->flags, CI_MEMO_VOP);
		}

		accessLevel = get_access(callerUser, ci, accessName, NULL, NULL);

		if (accessLevel < CS_ACCESS_VOP) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
			return;
		}
		else if (accessLevel < memoLevel) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SENDTO_ERROR_NO_ACCESS);
			return;
		}

		TRACE_MAIN();
		if (str_equals_nocase(list, "VOP") || str_equals_nocase(list, "ALL")) {

			snprintf(message, sizeof(message), "(VOP+) >> %s", text);
			level = CS_ACCESS_VOP;
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SENDTO_MEMO_SENT_OTHER, "VOP", ci->name);
		}
		else if (str_equals_nocase(list, "HOP")) {

			snprintf(message, sizeof(message), "(HOP+) >> %s", text);
			level = CS_ACCESS_HOP;
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SENDTO_MEMO_SENT_HOP, ci->name);
		}
		else if (str_equals_nocase(list, "AOP")) {

			snprintf(message, sizeof(message), "(AOP+) >> %s", text);
			level = CS_ACCESS_AOP;
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SENDTO_MEMO_SENT_AOP, ci->name);
		}
		else if (str_equals_nocase(list, "SOP")) {

			snprintf(message, sizeof(message), "(SOP+) >> %s", text);
			level = CS_ACCESS_SOP;
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SENDTO_MEMO_SENT_OTHER, "SOP", ci->name);
		}
		else if (str_equals_nocase(list, "CF") || str_equals_nocase(list, "COFOUNDER") || str_equals_nocase(list, "CFOUNDER")) {

			snprintf(message, sizeof(message), "(CF+) >> %s", text);
			level = CS_ACCESS_COFOUNDER;
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SENDTO_MEMO_SENT_OTHER, "CF", ci->name);
		}
		else {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SENDTO_SYNTAX_ERROR);
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "SENDTO");
			return;
		}

		TRACE_MAIN();

		callerUser->lastmemosend = NOW;

		if (CONF_SET_EXTRASNOOP)
			LOG_SNOOP(s_OperServ, "MS T %s -- by %s (%s@%s) [Message: %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, message);

		log_services(LOG_SERVICES_MEMOSERV, "T %s -- by %s (%s@%s) [Message: %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, message);

		TRACE_MAIN();

		/* Send to Founder. */
		if (str_not_equals_nocase(source, ci->founder))
			send_memo(callerUser, accessName, findnick(ci->founder), message, ci->name, level, FALSE);

		TRACE_MAIN();

		/* Send to the selected list. */
		for (anAccess = ci->access, memoIdx = 0; memoIdx < ci->accesscount; ++anAccess, ++memoIdx) {

			/* Skip masks and lower lists. */
			if ((anAccess->status != ACCESS_ENTRY_NICK) || (anAccess->level < level))
				continue;

			/* Don't send back memo to the sender. */
			if (str_equals_nocase(source, anAccess->name))
				continue;

			if (IS_NULL(ni = findnick(anAccess->name)))
				continue;

			/* Don't send memos to forbidden/frozen nicks. */
			if (FlagSet(ni->flags, NI_FORBIDDEN) || FlagSet(ni->flags, NI_FROZEN))
				continue;

			/* Don't send memos to people who don't want to receive them. */
			if (FlagSet(ni->flags, NI_NOCHANMEMO))
				continue;

			send_memo(callerUser, accessName, ni, message, ci->name, level, FALSE);
		}
	}
}

/*********************************************************/

/* Send a memo to a nick. */
static void do_send(const char *source, User *callerUser, ServiceCommandData *data) {

	NickInfo *ni;
	char *name, *message;
	size_t len;


	TRACE_MAIN_FCLT(FACILITY_MEMOSERV_HANDLE_SEND);

	if (CONF_SET_READONLY)
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SEND_ERROR_READONLY);

	else if (IS_NULL(name = strtok(NULL, " ")) || IS_NULL(message = strtok(NULL, ""))) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SEND_SYNTAX_ERROR);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "SEND");
	}
	else if (name[0] == '#') {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SEND_ERROR_USE_SENDTO);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "SENDTO");
	}
	else if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");	
	}
	else if ((callerUser->lastmemosend + CONF_MEMO_SEND_DELAY) > NOW && !is_services_valid_oper(callerUser)) {

		callerUser->lastmemosend = NOW;
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_MEMO_DELAY, CONF_MEMO_SEND_DELAY, "SEND");
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
	}
	else if (FlagSet(callerUser->ni->flags, NI_AUTH)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SEND_ERROR_MUST_AUTH);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
	}
	else if ((len = str_len(message)) > 400)
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_MEMO_MAX_LENGTH, 400, len);

	else if (str_equals_nocase(source, name))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SEND_ERROR_CANT_MEMO_SELF);

	else if (IS_NULL(ni = findnick(name)))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_NICK_NOT_REG, name);

	else if (FlagSet(ni->flags, NI_FORBIDDEN))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_NICK_FORBIDDEN, ni->nick);

	else if (FlagSet(ni->flags, NI_FROZEN))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_NICK_FROZEN, ni->nick);

	else if (FlagSet(ni->flags, NI_AUTH))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SEND_ERROR_NICK_NOT_AUTH, ni->nick);

	else if (FlagSet(ni->flags, NI_NOMEMO))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_NOMEMO_ON, ni->nick);

	else {

		callerUser->lastmemosend = NOW;

		if (send_memo(callerUser, callerUser->nick, ni, message, NULL, 0, TRUE)) {

			if (CONF_SET_EXTRASNOOP)
				LOG_SNOOP(s_OperServ, "MS S %s -- by %s (%s@%s) [Message: %s ]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, message);

			log_services(LOG_SERVICES_MEMOSERV, "S %s -- by %s (%s@%s) [Message: %s ]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, message);
		}
	}
}

static void do_forward(const char *source, User *callerUser, ServiceCommandData *data) {

	char *nick;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_MEMOSERV_HANDLE_FORWARD);

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_FORWARD_SYNTAX_ERROR);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "FORWARD");	
	}
	else if (IS_NULL(ni = callerUser->ni)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");	
	}
	else if (!user_is_identified_to(callerUser, ni->nick)) {
	
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, ni->nick);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, ni->nick);
	}
	else if (FlagSet(ni->flags, NI_AUTH)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SEND_ERROR_MUST_AUTH);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
	}
	else {

		if (str_equals_nocase(nick, "NONE")) {

			if (IS_NOT_NULL(ni->forward)) {

				if (CONF_SET_EXTRASNOOP)
					LOG_SNOOP(s_OperServ, "MS -F %s -- by %s (%s@%s)", ni->forward, ni->nick, callerUser->username, callerUser->host);

				log_services(LOG_SERVICES_MEMOSERV, "-F %s -- by %s (%s@%s)", ni->forward, ni->nick, callerUser->username, callerUser->host);

				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_FORWARD_OFF, ni->nick);

				if (CONF_SET_READONLY)
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), WARNING_READONLY);

				mem_free(ni->forward);
				ni->forward = NULL;
			}
			else
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_FORWARD_ERROR_FORWARD_OFF, ni->nick);
		}
		else if (str_equals_nocase(nick, callerUser->nick))
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_FORWARD_ERROR_CANT_FORWARD_SELF);

		else if (FlagSet(ni->flags, NI_NOMEMO))
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_FORWARD_ERROR_REJECTED, ni->nick, "No Memo");

		else {

			if (IS_NULL(ni = findnick(nick)))
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_NICK_NOT_REG, nick);

			else if (FlagSet(ni->flags, NI_FORBIDDEN))
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);

			else if (FlagSet(ni->flags, NI_FROZEN))
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FROZEN, ni->nick);

			else if (!user_is_identified_to(callerUser, ni->nick)) {

				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, ni->nick);
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, ni->nick);
			}
			else if (FlagSet(ni->flags, NI_AUTH))
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_FORWARD_ERROR_NOT_AUTH);

			else {

				if (FlagSet(ni->flags, NI_NOMEMO))
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_FORWARD_WARNING_TARGET_NOMEMO_ON, ni->nick, callerUser->ni->nick);
				else if (FlagSet(ni->flags, NI_NOCHANMEMO))
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_FORWARD_WARNING_TARGET_NOCHANMEMO_ON, ni->nick, callerUser->ni->nick);
				else
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_FORWARD_ON, callerUser->ni->nick, ni->nick);

				if (CONF_SET_READONLY)
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), WARNING_READONLY);

				TRACE_MAIN();
				if (callerUser->ni->forward)
					mem_free(callerUser->ni->forward);
				callerUser->ni->forward = str_duplicate(ni->nick);

				if (CONF_SET_EXTRASNOOP)
					LOG_SNOOP(s_OperServ, "MS +F -- by %s (%s@%s) [%s -> %s]", source, callerUser->username, callerUser->host, callerUser->ni->nick, callerUser->ni->forward);

				log_services(LOG_SERVICES_MEMOSERV, "+F -- by %s (%s@%s) [%s -> %s]", source, callerUser->username, callerUser->host, callerUser->ni->nick, callerUser->ni->forward);
			}
		}
	}
}

/*********************************************************/

static void do_unsend(CSTR source, User *callerUser, ServiceCommandData *data) {

	NickInfo *ni;
	MemoList *ml;
	Memo *memo;
	char *target;
	User *user;
	int memoIdx;


	TRACE_MAIN_FCLT(FACILITY_MEMOSERV_HANDLE_UNSEND);

	if (CONF_SET_READONLY)
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNSEND_ERROR_READONLY);

	else if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");	
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
	}
	else if (IS_NULL(target = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNSEND_SYNTAX_ERROR);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "UNSEND");
	}
	else if (*target == '#') {

		ChannelInfo *ci;
		char *list;

		if (IS_NULL(list = strtok(NULL, " "))) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNSEND_SYNTAX_ERROR);
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "UNSEND");
		}
		else if (IS_NULL(ci = cs_findchan(target)))
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, target);

		else if (FlagSet(ci->flags, CI_FORBIDDEN))
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

		else if (FlagSet(ci->flags, CI_FROZEN))
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FROZEN, ci->name);

		else if (FlagSet(ci->flags, CI_CLOSED))
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_CLOSED, ci->name);

		else if (FlagSet(ci->flags, CI_SUSPENDED))
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_SUSPENDED, ci->name);

		else {

			ChanAccess *anAccess;
			char *targetNick;
			int accessIdx, level, deleted = 0;
			int accessLevel;

			str_toupper(list);

			if (str_equals(list, "VOP") || str_equals(list, "ALL")) {

				list = "VOP";
				level = CS_ACCESS_VOP;
			}
			else if (str_equals(list, "HOP"))
				level = CS_ACCESS_HOP;

			else if (str_equals(list, "AOP"))
				level = CS_ACCESS_AOP;

			else if (str_equals(list, "SOP"))
				level = CS_ACCESS_SOP;

			else if (str_equals(list, "CF") || str_equals(list, "COFOUNDER") || str_equals(list, "CFOUNDER")) {

				list = "CF";
				level = CS_ACCESS_COFOUNDER;
			}
			else {

				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNSEND_SYNTAX_ERROR);
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "UNSEND");
				return;
			}

			accessLevel = get_access(callerUser, ci, NULL, NULL, NULL);

			if (accessLevel < CS_ACCESS_VOP) {

				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
				return;
			}

			for (anAccess = ci->access, accessIdx = 0; accessIdx < ci->accesscount; ++anAccess, ++accessIdx) {

				if ((anAccess->status != ACCESS_ENTRY_NICK) || (str_equals_nocase(source, anAccess->name)))
					continue;

				if ((anAccess->level >= level) && IS_NOT_NULL(ni = findnick(anAccess->name))) {

					TRACE_MAIN();

					if (IS_NOT_NULL(ni->forward))
						targetNick = ni->forward;
					else
						targetNick = ni->nick;

					if (IS_NULL(ml = find_memolist(targetNick)) || (ml->n_memos == 0))
						continue;

					/* Go through the list backwards, we want to remove the last memo. */
					for (memoIdx = (ml->n_memos - 1); memoIdx > -1; --memoIdx) {

						memo = ml->memos + memoIdx;

						if (FlagUnset(memo->flags, MF_UNREAD) || (memo->level != level))
							continue;

						if (str_equals_nocase(memo->sender, source) && str_equals_nocase(memo->chan, ci->name))
							break;
					}

					if (memoIdx < 0)
						continue;

					++deleted;

					if (IS_NOT_NULL(user = hash_onlineuser_find(targetNick)) && user_is_identified_to(user, targetNick))
						send_notice_lang_to_user(s_MemoServ, user, FindNickLang(targetNick, user), MS_UNSEND_MEMO_UNSENT_TARGET_CHAN, source, ci->name);

					TRACE_MAIN();
					mem_free(ml->memos[memoIdx].text);

					if (IS_NOT_NULL(ml->memos[memoIdx].chan))
						mem_free(ml->memos[memoIdx].chan);

					/* Decrease user's memo count by one. */
					--(ml->n_memos);

					/* If it wasn't the last one, move the remaining memos down one slot. */
					if (memoIdx < ml->n_memos)
						memmove(ml->memos + memoIdx, (ml->memos + memoIdx + 1), sizeof(Memo) * (ml->n_memos - memoIdx));

					TRACE_MAIN();
					if (ml->n_memos == 0) {

						if (ml->n_ignores == 0)
							del_memolist(ml);

						else {

							if (ml->memos)
								mem_free(ml->memos);
							ml->memos = NULL;
						}
					}
				}
			}

			if (deleted > 0) {

				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNSEND_MEMO_UNSENT_CHAN, list, ci->name);

				if (CONF_SET_EXTRASNOOP)
					LOG_SNOOP(s_OperServ, "MS U %s %s -- by %s (%s@%s)", ci->name, list, callerUser->nick, callerUser->username, callerUser->host);

				log_services(LOG_SERVICES_MEMOSERV, "U %s %s -- by %s (%s@%s)", ci->name, list, callerUser->nick, callerUser->username, callerUser->host);
			}
			else
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNSEND_ERROR_NO_MEMOS_FOR_CHAN, list, ci->name);
		}
	}
	else {

		if (IS_NULL(ni = findnick(target))) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_NICK_NOT_REG, target);
			return;
		}
		else if (FlagSet(ni->flags, NI_FORBIDDEN)) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_NICK_FORBIDDEN, ni->nick);
			return;
		}
		else if (FlagSet(ni->flags, NI_FROZEN)) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_NICK_FROZEN, ni->nick);
			return;
		}

		if (IS_NOT_NULL(ni->forward)) {

			if (IS_NULL(findnick(ni->forward))) {

				mem_free(ni->forward);
				ni->forward = NULL;
			}
			else
				target = ni->forward;
		}

		if (IS_NULL(ml = find_memolist(target)) || (ml->n_memos == 0)) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNSEND_ERROR_NO_MEMOS_FROM_SOURCE, ni->nick);
			return;
		}

		TRACE_MAIN();

		/* Go through the list backwards, we want to remove the last memo. */
		for (memoIdx = (ml->n_memos - 1); memoIdx > -1; --memoIdx) {

			memo = ml->memos + memoIdx;

			if (FlagSet(memo->flags, MF_UNREAD) && IS_NULL(memo->chan) && str_equals_nocase(memo->sender, source))
				break;
		}

		TRACE_MAIN();
		if (memoIdx < 0) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNSEND_ERROR_NO_MEMOS_FROM_SOURCE, ni->nick);
			return;
		}

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNSEND_MEMO_UNSENT_SOURCE_1, ni->nick);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNSEND_MEMO_UNSENT_SOURCE_2, ml->memos[memoIdx].text);

		if (CONF_SET_EXTRASNOOP)
			LOG_SNOOP(s_OperServ, "MS U %s -- by %s (%s@%s) [Message: %s ]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ml->memos[memoIdx].text);

		log_services(LOG_SERVICES_MEMOSERV, "U %s -- by %s (%s@%s) [Message: %s ]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, ml->memos[memoIdx].text);

		if (IS_NOT_NULL(user = hash_onlineuser_find(target)) && user_is_identified_to(user, target))
			send_notice_lang_to_user(s_MemoServ, user, FindNickLang(target, user), MS_UNSEND_MEMO_UNSENT_TARGET, source);

		TRACE_MAIN();
		mem_free(ml->memos[memoIdx].text);	/* Deallocate memo text memory */

		if (IS_NOT_NULL(ml->memos[memoIdx].chan))
			mem_free(ml->memos[memoIdx].chan);

		/* Decrease user's memo count by one. */
		--(ml->n_memos);

		/* If it wasn't the last one, move the remaining memos down one slot. */
		if (memoIdx < ml->n_memos)
			memmove(ml->memos + memoIdx, (ml->memos + memoIdx + 1), sizeof(Memo) * (ml->n_memos - memoIdx));

		TRACE_MAIN();
		if (ml->n_memos == 0) {

			TRACE_MAIN();
			if (ml->n_ignores == 0)
				del_memolist(ml);

			else {

				TRACE_MAIN();
				if (ml->memos)
					mem_free(ml->memos);
				ml->memos = NULL;
			}
		}
	}
}

/*********************************************************/

static void do_list(const char *source, User *callerUser, ServiceCommandData *data) {

	TRACE_MAIN_FCLT(FACILITY_MEMOSERV_HANDLE_LIST);

	if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");	
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
	}
	else {

		const char *param;
		int memoIdx, sent = 0, matchType = FALSE;
		MemoList *ml;
		Memo *memo;

		if (IS_NOT_NULL(param = strtok(NULL, " "))) {

			if (str_equals_nocase(param, "NEW"))
				matchType = MEMO_TYPE_NEW;

			else if (str_equals_nocase(param, "CHANNEL"))
				matchType = MEMO_TYPE_CHANNEL;

			else if  (str_equals_nocase(param, "USER"))
				matchType = MEMO_TYPE_DIRECT;

			else {

				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_LIST_SYNTAX_ERROR);
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "LIST");
				return;
			}
		}

		if (IS_NULL(ml = find_memolist(source)) || (ml->n_memos == 0)) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_NO_MEMOS);
			return;
		}

		TRACE_MAIN();

		switch (matchType) {

			case MEMO_TYPE_NEW:
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_LIST_NEW_MEMOS_LIST, source);
				break;

			case MEMO_TYPE_CHANNEL:
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_LIST_CHANNEL_MEMOS_LIST, source);
				break;

			case MEMO_TYPE_DIRECT:
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_LIST_DIRECT_MEMOS_LIST, source);
				break;

			default:
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_LIST_MEMOS_LIST, source);
				break;
		}

		TRACE_MAIN();
		for (memo = ml->memos, memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx, ++memo)
			sent += read_memo(callerUser, memo, matchType, (memoIdx + 1));

		if (sent == 0)
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_LIST_NO_NEW_MEMOS);
	}
}

/*********************************************************/

static void do_del(const char *source, User *callerUser, ServiceCommandData *data) {

	MemoList	*ml;
	const char	*what;


	TRACE_MAIN_FCLT(FACILITY_MEMOSERV_HANDLE_DEL);

	if (CONF_SET_READONLY)
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_DEL_ERROR_READONLY);

	else if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");	
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
	}
	else if (IS_NULL(what = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_DEL_SYNTAX_ERROR);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "DEL");
	}
	else if (IS_NULL(ml = find_memolist(source)) || (ml->n_memos == 0))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_NO_MEMOS);

	else {

		Memo		*memo;
		char		*err;
		int			memoIdx;
		long int	value;


		TRACE_MAIN();

		value = strtol(what, &err, 10);

		if ((value > 0) && (*err == '\0')) {

			/* Delete a specific memo. */
			for (memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx) {

				if (value == (memoIdx + 1))
					break;
			}

			TRACE_MAIN();
			if (memoIdx < ml->n_memos) {

				memo = ml->memos + memoIdx;

				if (FlagSet(memo->flags, MF_DEL))
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_DEL_ERROR_MEMO_ALREADY_DEL, value);

				else {

					AddFlag(memo->flags, MF_DEL);
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_DEL_MEMO_MARKED_DEL, value);

					if (CONF_SET_EXTRASNOOP)
						LOG_SNOOP(s_OperServ, "MS D %d -- by %s (%s@%s) [Message: %s ]", value, callerUser->nick, callerUser->username, callerUser->host, memo->text);

					log_services(LOG_SERVICES_MEMOSERV, "D %d -- by %s (%s@%s) [Message: %s ]", value, callerUser->nick, callerUser->username, callerUser->host, memo->text);
				}
			}
			else
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_NO_MATCH, value);
		}
		else if (str_equals_nocase(what, "ALL")) {

			char *type;
			int memoType = FALSE;


			if (IS_NOT_NULL(type = strtok(NULL, " "))) {

				if (str_equals_nocase(type, "CHANNEL"))
					memoType = MEMO_TYPE_CHANNEL;

				else if (str_equals_nocase(type, "USER"))
					memoType = MEMO_TYPE_DIRECT;

				else if (str_equals_nocase(type, "NEW"))
					memoType = MEMO_TYPE_NEW;

				else {

					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_DEL_SYNTAX_ERROR);
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "DEL");
					return;
				}
			}

			TRACE_MAIN();
			for (memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx) {

				if ((memoType == MEMO_TYPE_NEW) && FlagUnset(ml->memos[memoIdx].flags, MF_UNREAD))
					continue;

				if ((memoType == MEMO_TYPE_CHANNEL) && IS_NULL(ml->memos[memoIdx].chan))
					continue;

				if ((memoType == MEMO_TYPE_DIRECT) && IS_NOT_NULL(ml->memos[memoIdx].chan))
					continue;

				AddFlag(ml->memos[memoIdx].flags, MF_DEL);
			}

			if (memoType == FALSE) {

				if (CONF_SET_EXTRASNOOP)
					LOG_SNOOP(s_OperServ, "MS D ALL -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);

				log_services(LOG_SERVICES_MEMOSERV, "D ALL -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				if (CONF_SET_EXTRASNOOP)
					LOG_SNOOP(s_OperServ, "MS D ALL [%s] -- by %s (%s@%s)", (memoType == MEMO_TYPE_NEW) ? "NEW" : ((memoType == MEMO_TYPE_CHANNEL) ? "CHAN" : "USER"),
						callerUser->nick, callerUser->username, callerUser->host);

				log_services(LOG_SERVICES_MEMOSERV, "D ALL [%s] -- by %s (%s@%s)", (memoType == MEMO_TYPE_NEW) ? "NEW" : ((memoType == MEMO_TYPE_CHANNEL) ? "CHAN" : "USER"),
					callerUser->nick, callerUser->username, callerUser->host);
			}

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_DEL_ALL_MEMOS_MARKED_DEL);
		}
		else {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_DEL_SYNTAX_ERROR);
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "DEL");
		}
	}
}

/*********************************************************/

static void do_read(const char *source, User *callerUser, ServiceCommandData *data) {

	MemoList	*ml;
	const char	*what;


	TRACE_MAIN_FCLT(FACILITY_MEMOSERV_HANDLE_READ);

	if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");	
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
	}
	else if (IS_NULL(what = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_READ_SYNTAX_ERROR);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "READ");
	}
	else if (IS_NULL(ml = find_memolist(source)) || (ml->n_memos == 0))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_NO_MEMOS);

	else {

		Memo		*memo;
		char		*err, timebuf[64];
		int			memoIdx;
		long int	value;


		value = strtol(what, &err, 10);


		if ((value > 0) && (*err == '\0')) {

			for (memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx) {

				if (value == (memoIdx + 1))
					break;
			}

			TRACE_MAIN();
			if (memoIdx >= ml->n_memos) {

				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_NO_MATCH, value);
				return;
			}
		}
		else if (str_equals_nocase(what, "LAST"))
			memoIdx = (ml->n_memos - 1);

		else {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_READ_SYNTAX_ERROR);
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "READ");
			return;
		}

		TRACE_MAIN();
		memo = ml->memos + memoIdx;

		lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DAYTIME, memo->time);

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_READ_MEMO_HEADER, (memoIdx + 1), memo->sender, (memoIdx + 1));
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_READ_MEMO_DATE_SENT, timebuf);

		if (IS_NOT_NULL(memo->chan))
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_READ_MEMO_CHANNEL_MESSAGE, memo->chan, memo->text);
		else
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_READ_MEMO_MESSAGE, memo->text);

		RemoveFlag(memo->flags, MF_UNREAD);
	}
}

/*********************************************************/

static void do_news(const char *source, User *callerUser, ServiceCommandData *data) {

	TRACE_MAIN_FCLT(FACILITY_MEMOSERV_HANDLE_NEWS);

	if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");	
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
	}
	else {

		if (lang_send_news(callerUser) == FALSE)
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_NEWS_ERROR_NO_NEWS);

		AddFlag(callerUser->ni->flags, NI_READNEWS);

		if (CONF_SET_EXTRASNOOP)
			LOG_SNOOP(s_OperServ, "MS N -- by %s (%s@%s) [Lang: %s]", callerUser->nick, callerUser->username, callerUser->host, lang_get_shortname(GetNickLang(callerUser->ni)));

		log_services(LOG_SERVICES_MEMOSERV, "N -- by %s (%s@%s) [Lang: %s]", callerUser->nick, callerUser->username, callerUser->host, lang_get_shortname(GetNickLang(callerUser->ni)));
	}
}

/*********************************************************/

static void do_undel(const char *source, User *callerUser, ServiceCommandData *data) {

	MemoList	*ml;
	const char	*what;


	TRACE_MAIN_FCLT(FACILITY_MEMOSERV_HANDLE_UNDEL);

	if (CONF_SET_READONLY)
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNDEL_ERROR_READONLY);

	else if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");	
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
	}
	else if (IS_NULL(what = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNDEL_SYNTAX_ERROR);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "UNDEL");
	}
	else if (IS_NULL(ml = find_memolist(source)) || (ml->n_memos == 0))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNDEL_ERROR_NO_MEMOS_TO_UNDEL);
		
	else {

		Memo		*memo;
		int			memoIdx;
		long int	value;
		char		*err;


		value = strtol(what, &err, 10);

		if ((value > 0) && (*err == '\0')) {

			/* Undelete a specific memo. */
			for (memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx) {

				if (value == (memoIdx + 1))
					break;
			}

			TRACE_MAIN();
			if (memoIdx < ml->n_memos) {

				memo = ml->memos + memoIdx;

				if (FlagSet(memo->flags, MF_DEL)) {

					RemoveFlag(memo->flags, MF_DEL);
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNDEL_MEMO_UNMARKED, value);

					if (CONF_SET_EXTRASNOOP)
						LOG_SNOOP(s_OperServ, "MS UD %d -- by %s (%s@%s) [Message: %s ]", value, callerUser->nick, callerUser->username, callerUser->host, memo->text);

					log_services(LOG_SERVICES_MEMOSERV, "UD %d -- by %s (%s@%s) [Message: %s ]", value, callerUser->nick, callerUser->username, callerUser->host, memo->text);
				}
				else
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNDEL_ERROR_MEMO_NOT_MARKED, value);
			}
			else
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_NO_MATCH, value);
		}
		else if (str_equals_nocase(what, "ALL")) {

			TRACE_MAIN();

			/* Undelete all memos. */
			for (memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx) {

				memo = ml->memos + memoIdx;

				if (FlagSet(memo->flags, MF_DEL))
					RemoveFlag(memo->flags, MF_DEL);
			}

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNDEL_ALL_MEMOS_UNMARKED);

			if (CONF_SET_EXTRASNOOP)
				LOG_SNOOP(s_OperServ, "MS UD ALL -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);

			log_services(LOG_SERVICES_MEMOSERV, "UD ALL -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
		}
		else {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_UNDEL_SYNTAX_ERROR);
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "UNDEL");
		}
	}
}

/*********************************************************/

static void do_purge(const char *source, User *callerUser, ServiceCommandData *data) {

	TRACE_MAIN_FCLT(FACILITY_MEMOSERV_HANDLE_PURGE);

	if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");	
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
	}
	else {

		memoserv_delete_flagged_memos(source, FALSE);

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), WARNING_READONLY);

		if (CONF_SET_EXTRASNOOP)
			LOG_SNOOP(s_OperServ, "MS P -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);

		log_services(LOG_SERVICES_MEMOSERV, "P -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
	}
}

/*********************************************************/

static void do_set(const char *source, User *callerUser, ServiceCommandData *data) {

	const char *cmd, *param;

	TRACE_MAIN_FCLT(FACILITY_MEMOSERV_HANDLE_SET);

	if (CONF_SET_READONLY)
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_ERROR_READONLY);

	else if (IS_NULL(cmd = strtok(NULL, " ")) || IS_NULL(param = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_SYNTAX_ERROR);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "SET");
	}
	else if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");	
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
	}
	else if (str_equals_nocase(cmd, "NOTIFY"))
		do_set_notify(callerUser, param);

	else if (str_equals_nocase(cmd, "IGNORETYPE"))
		do_set_ignoretype(callerUser, param);

	else {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_UNKNOWN_SET_COMMAND, str_toupper((char *)cmd));
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "SET");
	}
}

/*********************************************************/

static void do_set_notify(User *callerUser, const char *param) {

	NickInfo *ni = callerUser->ni;


	TRACE_FCLT(FACILITY_MEMOSERV_SET_NOTIFY);

	if (str_equals_nocase(param, "ON")) {

		TRACE();
		if (FlagSet(ni->flags, NI_MEMO_SIGNON) && FlagSet(ni->flags, NI_MEMO_RECEIVE)) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_ERROR_ALREADY_SET, "NOTIFY", "ON");
			return;
		}

		AddFlag(ni->flags, NI_MEMO_SIGNON);
		AddFlag(ni->flags, NI_MEMO_RECEIVE);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_NOTIFY_ON, s_MemoServ, s_NickServ);
	}
	else if (str_equals_nocase(param, "LOGON")) {

		TRACE();
		if (FlagSet(ni->flags, NI_MEMO_SIGNON) && FlagUnset(ni->flags, NI_MEMO_RECEIVE)) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_ERROR_ALREADY_SET, "NOTIFY", "LOGON");
			return;
		}

		AddFlag(ni->flags, NI_MEMO_SIGNON);
		RemoveFlag(ni->flags, NI_MEMO_RECEIVE);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_NOTIFY_LOGON, s_MemoServ, s_NickServ);
	}
	else if (str_equals_nocase(param, "NEW")) {

		TRACE();
		if (FlagUnset(ni->flags, NI_MEMO_SIGNON) && FlagSet(ni->flags, NI_MEMO_RECEIVE)) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_ERROR_ALREADY_SET, "NOTIFY", "NEW");
			return;
		}

		RemoveFlag(ni->flags, NI_MEMO_SIGNON);
		AddFlag(ni->flags, NI_MEMO_RECEIVE);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_NOTIFY_NEW, s_MemoServ);
	}
	else if (str_equals_nocase(param, "OFF")) {

		TRACE();
		if (FlagUnset(ni->flags, NI_MEMO_SIGNON) && FlagUnset(ni->flags, NI_MEMO_RECEIVE)) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_ERROR_ALREADY_SET, "NOTIFY", "OFF");
			return;
		}

		RemoveFlag(ni->flags, NI_MEMO_SIGNON);
		RemoveFlag(ni->flags, NI_MEMO_RECEIVE);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_NOTIFY_OFF, s_MemoServ);
	}
	else {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_NOTIFY_SYNTAX_ERROR);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "SET NOTIFY");
	}
}

/*********************************************************/

static void do_set_ignoretype(User *callerUser, const char *param) {

	NickInfo *ni = callerUser->ni;


	TRACE_FCLT(FACILITY_MEMOSERV_SET_IGNORETYPE);

	if (str_equals_nocase(param, "1")) {

		TRACE();
		if (FlagUnset(ni->flags, NI_REVERSEIGN)) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_ERROR_ALREADY_SET, "IGNORETYPE", "1");
			return;
		}

		RemoveFlag(ni->flags, NI_REVERSEIGN);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_IGNORETYPE_ALL);
	}
	else if (str_equals_nocase(param, "2")) {

		TRACE();
		if (FlagSet(ni->flags, NI_REVERSEIGN)) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_ERROR_ALREADY_SET, "IGNORETYPE", "2");
			return;
		}

		AddFlag(ni->flags, NI_REVERSEIGN);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_IGNORETYPE_ALL_BUT);
	}
	else {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SET_IGNORETYPE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "SET IGNORETYPE");
	}
}

/*********************************************************/

static void do_ignore(const char *source, User *callerUser, ServiceCommandData *data) {

	NickInfo *ni;
	MemoList *ml;
	MemoIgnore *ignore;
	char *cmd;


	TRACE_MAIN_FCLT(FACILITY_MEMOSERV_HANDLE_IGNORE);

	if (IS_NULL(cmd = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "IGNORE");
	}
	else if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
	}
	else if (str_equals_nocase(cmd, "ADD")) {

		char *name;

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_ERROR_READONLY);

		else if (IS_NULL(name = strtok(NULL, " "))) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_SYNTAX_ERROR);
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "IGNORE");
		}
		else if (str_equals_nocase(source, name))
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_SEND_ERROR_CANT_IGNORE_SELF);

		else if (IS_NULL(ni = findnick(name)))
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_NICK_NOT_REG, name);

		else if (FlagSet(ni->flags, NI_FORBIDDEN))
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_ERROR_NICK_FORBIDDEN, ni->nick);

		else if (FlagSet(ni->flags, NI_FROZEN))
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_ERROR_NICK_FROZEN, ni->nick);

		else {

			if (IS_NULL(ml = find_memolist(source)))
				ml = create_memolist(source);

			else {

				ignore = memoserv_find_ignore(ml->ignores, ni->nick);

				if (IS_NOT_NULL(ignore)) {

					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_ERROR_NICK_ALREADY_IGNORED, ni->nick);
					return;
				}

				if (ml->n_ignores >= (MAX_IGNORES - 1)) {

					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_ERROR_IGNORE_LIST_FULL);
					return;
				}
			}

			TRACE_MAIN();

			ignore = (MemoIgnore*) mem_malloc(sizeof(MemoIgnore));

			ignore->creationTime = NOW;
			ignore->ignoredNick = str_duplicate(ni->nick);
			ignore->prev = NULL;
			ignore->next = ml->ignores;

			ml->ignores = ignore;

			if (IS_NOT_NULL(ignore->next))
				ignore->next->prev = ignore;

			++(ml->n_ignores);
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_NICK_IGNORED, ni->nick);

			if (CONF_SET_EXTRASNOOP)
				LOG_SNOOP(s_OperServ, "MS +I %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);

			log_services(LOG_SERVICES_MEMOSERV, "+I %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
		}
	}
	else if (str_equals_nocase(cmd, "DEL")) {

		char *name;

		if (IS_NULL(name = strtok(NULL, " "))) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_SYNTAX_ERROR);
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "IGNORE");
		}
		else if (IS_NULL(ml = find_memolist(source)) || ml->n_ignores == 0)
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_ERROR_LIST_EMPTY);

		else {

			long int numEntry;
			char *err;

			numEntry = strtol(name, &err, 10);

			if (*err == '\0') {

				/* This is a number. */

				if ((numEntry > 0) && (numEntry <= ml->n_ignores)) {

					ignore = ml->ignores;

					/* Decrease first, first entry counts! */
					while (--numEntry > 0) {

						ignore = ignore->next;

						if (IS_NULL(ignore)) {

							send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_ERROR_NICK_NOT_IGNORED, name);
							return;
						}
					}

					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_NICK_UNIGNORED, ignore->ignoredNick);

					if (CONF_SET_READONLY)
						send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), WARNING_READONLY);

					if (CONF_SET_EXTRASNOOP)
						LOG_SNOOP(s_OperServ, "MS -I %s -- by %s (%s@%s)", ignore->ignoredNick, callerUser->nick, callerUser->username, callerUser->host);

					log_services(LOG_SERVICES_MEMOSERV, "-I %s -- by %s (%s@%s)", ignore->ignoredNick, callerUser->nick, callerUser->username, callerUser->host);

					if (IS_NOT_NULL(ignore->next))
						ignore->next->prev = ignore->prev;

					if (IS_NOT_NULL(ignore->prev))
						ignore->prev->next = ignore->next;
					else
						ml->ignores = ignore->next;

					mem_free(ignore->ignoredNick);
					mem_free(ignore);

					--(ml->n_ignores);

					if (ml->n_ignores == 0) {

						if (ml->n_memos == 0)
							del_memolist(ml);

						else {
	
							if (ml->n_ignores == 0) {

								if (ml->ignores)
									mem_free(ml->ignores);
								ml->ignores = NULL;
							}
						}
					}
				}
				else
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_ERROR_NICK_NOT_IGNORED, name);
			}
			else {

				TRACE_MAIN();

				ignore = memoserv_find_ignore(ml->ignores, name);

				if (IS_NULL(ignore))
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_ERROR_NICK_NOT_IGNORED, name);

				else {

					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_NICK_UNIGNORED, ignore->ignoredNick);

					if (CONF_SET_READONLY)
						send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), WARNING_READONLY);

					if (CONF_SET_EXTRASNOOP)
						LOG_SNOOP(s_OperServ, "MS -I %s -- by %s (%s@%s)", ignore->ignoredNick, callerUser->nick, callerUser->username, callerUser->host);

					log_services(LOG_SERVICES_MEMOSERV, "-I %s -- by %s (%s@%s)", ignore->ignoredNick, callerUser->nick, callerUser->username, callerUser->host);

					if (IS_NOT_NULL(ignore->next))
						ignore->next->prev = ignore->prev;

					if (IS_NOT_NULL(ignore->prev))
						ignore->prev->next = ignore->next;
					else
						ml->ignores = ignore->next;

					mem_free(ignore->ignoredNick);
					mem_free(ignore);

					--(ml->n_ignores);

					if (ml->n_ignores == 0) {
					
						if (ml->n_memos == 0)
							del_memolist(ml);

						else {
	
							if (ml->n_ignores == 0) {

								if (ml->ignores)
									mem_free(ml->ignores);
								ml->ignores = NULL;
							}
						}
					}
				}
			}
		}
	}
	else if (str_equals_nocase(cmd, "WIPE")) {

		MemoIgnore *next;

		if (IS_NULL(ml = find_memolist(source)) || (ml->n_ignores == 0)) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_ERROR_LIST_EMPTY);
			return;
		}

		TRACE_MAIN();
		for (ignore = ml->ignores; IS_NOT_NULL(ignore); ) {

			next = ignore->next;

			mem_free(ignore->ignoredNick);
			mem_free(ignore);

			ignore = next;
		}

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_LIST_WIPED, ml->n_ignores);

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), WARNING_READONLY);

		if (CONF_SET_EXTRASNOOP)
			LOG_SNOOP(s_OperServ, "MS I! -- by %s (%s@%s) [Entries: %d ]", callerUser->nick, callerUser->username, callerUser->host, ml->n_ignores);

		log_services(LOG_SERVICES_MEMOSERV, "I! -- by %s (%s@%s) [Entries: %d ]", callerUser->nick, callerUser->username, callerUser->host, ml->n_ignores);

		ml->ignores = NULL;
		ml->n_ignores = 0;

		if (ml->n_memos == 0)
			del_memolist(ml);
	}
	else if (str_equals_nocase(cmd, "LIST")) {

		int count = 0;

		if (IS_NULL(ml = find_memolist(source)) || (ml->n_ignores == 0)) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_ERROR_LIST_EMPTY);
			return;
		}

		TRACE_MAIN();
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_LIST_HEADER, callerUser->ni->nick);

		for (ignore = ml->ignores; IS_NOT_NULL(ignore); ignore = ignore->next) {

			if (IS_NOT_NULL(findnick(ignore->ignoredNick)))
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_LIST_ENTRY, ++count, ignore->ignoredNick);
			else
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_LIST_ENTRY_EXPIRED, ++count, ignore->ignoredNick);
		}

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), END_OF_LIST);
	}
	else {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_IGNORE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_MS, "IGNORE");
	}
}


/*********************************************************
 * MemoServ Operator commands.                           *
 *********************************************************/

static void do_limit(const char *source, User *callerUser, ServiceCommandData *data) {

	char *nick, *value;
	int limit;
	NickInfo *ni;


	TRACE_MAIN_FCLT(FACILITY_MEMOSERV_HANDLE_LIMIT);

	if (IS_NULL(nick = strtok(NULL, " ")) || IS_NULL(value = strtok(NULL, " ")) || (limit = strtol(value, &value, 10), value && *value)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_LIMIT_SYNTAX_ERROR);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_MS, "LIMIT");
	}
	else if (IS_NULL(ni = findnick(nick))) {

		LOG_SNOOP(s_OperServ, "MS *L %s -- by %s (%s@%s) [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_NOT_REG, nick);
	}
	else if (FlagSet(ni->flags, NI_FORBIDDEN))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);

	else if ((limit < 0) || (limit > 250))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_LIMIT_ERROR_VALUE, 250);

	else {

		TRACE_MAIN();
		LOG_SNOOP(s_OperServ, "MS L %s -- by %s (%s@%s) [%d]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, limit);
		log_services(LOG_SERVICES_MEMOSERV, "L %s -- by %s (%s@%s) [%d]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, limit);

		ni->memomax = limit;

		if (limit) {

			TRACE_MAIN();
			send_globops(s_MemoServ, "\2%s\2 set Memo Limit for \2%s\2 to \2%d\2", callerUser->nick, ni->nick, limit);
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_LIMIT_CHANGED, ni->nick, limit);
		}
		else {

			TRACE_MAIN();
			send_globops(s_MemoServ, "\2%s\2 reset Memo Limit for \2%s\2", callerUser->nick, ni->nick);
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_LIMIT_DISABLED, ni->nick);
		}

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_global(const char *source, User *callerUser, ServiceCommandData *data) {

	char *text;
	size_t len;


	TRACE_MAIN_FCLT(FACILITY_MEMOSERV_HANDLE_GLOBAL);

	if (IS_NULL(text = strtok(NULL, ""))) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_GLOBAL_SYNTAX_ERROR);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_MS, "GLOBAL");
	}
	else if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");	
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
	}
	else if ((len = str_len(text)) > 400) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), OPER_MS_ERROR_MEMO_MAX_LENGTH, 400, len);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "MS *G -- by %s (%s@%s) [Too Long]", callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "MS *G -- by %s (%s@%s) through %s [Too Long]", callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else {

		NickInfo *ni, *next;
		char message[512];
		int idx, count = 0;

		TRACE_MAIN();
		snprintf(message, sizeof(message), "GLOBAL MEMO >> %s", text);

		TRACE_MAIN();

		for (idx = 65; idx < 126; ++idx) {

			for (ni = retnick(idx); IS_NOT_NULL(ni); ni = next) {

				/* send_memo() might point ni to another nick. */
				next = ni->next;

				TRACE_MAIN();
				++count;
				send_memo(callerUser, s_GlobalNoticer, ni, message, NULL, 0, FALSE);
			}
		}

		TRACE_MAIN();

		if (data->operMatch) {

			send_globops(s_MemoServ, "\2%s\2 sent a Global Memo [Nicks: \2%d\2]", callerUser->nick, count);

			LOG_SNOOP(s_OperServ, "MS G -- by %s (%s@%s) [%d]", callerUser->nick, callerUser->username, callerUser->host, count);
			log_services(LOG_SERVICES_MEMOSERV, "G -- by %s (%s@%s) [%d]", callerUser->nick, callerUser->username, callerUser->host, count);
		}
		else {

			send_globops(s_MemoServ, "\2%s\2 (through \2%s\2) sent a Global Memo [Nicks: \2%d\2]", callerUser->nick, data->operName, count);

			LOG_SNOOP(s_OperServ, "MS G -- by %s (%s@%s) through %s [%d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, count);
			log_services(LOG_SERVICES_MEMOSERV, "G -- by %s (%s@%s) through %s [%d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, count);
		}

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_GLOBAL_MEMO_SENT);
		callerUser->lastmemosend = NOW;
	}
}

/*********************************************************/

static void do_info(const char *source, User *callerUser, ServiceCommandData *data) {

	NickInfo	*ni;
	MemoList	*ml;
	const char	*nick, *param;
	User		*user;
	long int	value = 0;
	char		buffer[IRCBUFSIZE];


	TRACE_MAIN_FCLT(FACILITY_MEMOSERV_HANDLE_INFO);

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_INFO_SYNTAX_ERROR);
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_MS, "INFO");
		return;
	}

	TRACE_MAIN();
	if (IS_NULL(ni = findnick(nick))) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_NOT_REG, nick);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "MS *M %s -- by %s (%s@%s) [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "MS *M %s -- by %s (%s@%s) through %s [Not Registered]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		return;
	}
	
	if (FlagSet(ni->flags, NI_FORBIDDEN)) {

		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), NS_ERROR_NICK_FORBIDDEN, ni->nick);
		return;
	}

	if (IS_NOT_NULL(param = strtok(NULL, " "))) {

		char *err;

		value = strtol(param, &err, 10);

		if ((value <= 0) || (*err != '\0')) {

			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_INFO_SYNTAX_ERROR);
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_MS, "INFO");
			return;
		}
	}

	if (value > 0) {

		if (data->operMatch) {

			send_globops(s_MemoServ, "\2%s\2 requested Memo Information on nick \2%s\2 [ Reading Memo number \2%d\2 ]", source, ni->nick, value);

			LOG_SNOOP(s_OperServ, "MS M %s -- by %s (%s@%s) [Reading Memo #%d]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, value);
			log_services(LOG_SERVICES_MEMOSERV, "M %s -- by %s (%s@%s) [Reading Memo #%d]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, value);
		}
		else {

			send_globops(s_MemoServ, "\2%s\2 (through \2%s\2) requested Memo Information on nick \2%s\2 [ Reading Memo number \2%d\2 ]", source, data->operName, ni->nick, value);

			LOG_SNOOP(s_OperServ, "MS M %s -- by %s (%s@%s) through %s [Reading Memo #%d]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, value);
			log_services(LOG_SERVICES_MEMOSERV, "M %s -- by %s (%s@%s) through %s [Reading Memo #%d]", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, value);
		}
	}
	else {

		if (data->operMatch) {

			send_globops(s_MemoServ, "\2%s\2 requested Memo Information on nick \2%s\2", source, ni->nick);

			LOG_SNOOP(s_OperServ, "MS M %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_MEMOSERV, "M %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
		}
		else {

			send_globops(s_MemoServ, "\2%s\2 (through \2%s\2) requested Memo Information on nick \2%s\2", source, data->operName, ni->nick);

			LOG_SNOOP(s_OperServ, "MS M %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_MEMOSERV, "M %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
		}
	}

	send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_INFO_HEADER, ni->nick);
	send_notice_to_user(s_MemoServ, callerUser, s_SPACE);

	TRACE_MAIN();
	if (IS_NULL(ml = find_memolist(nick)))
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_INFO_NO_MEMOLIST);

	else {

		Memo	*memo;
		int		memoIdx;
		size_t	len = 0;


		if (value > 0) {

			for (memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx) {

				if (value == (memoIdx + 1))
					break;
			}

			TRACE_MAIN();
			if (memoIdx >= ml->n_memos)
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_ERROR_NO_MATCH, value);

			else {

				TRACE_MAIN();
				memo = ml->memos + memoIdx;

				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_INFO_MEMO_HEADER, (memoIdx + 1), memo->sender);

				if (FlagSet(memo->flags, MF_DEL))
					len += str_copy_checked("Deleted", buffer, sizeof(buffer));

				if (FlagSet(memo->flags, MF_UNREAD)) {

					if (len > 0) {

						*(buffer + len++) = c_COMMA;
						*(buffer + len++) = c_SPACE;
					}

					len += str_copy_checked("Unread", (buffer + len), (sizeof(buffer) - len));
				}

				send_notice_to_user(s_MemoServ, callerUser, "Flags: %s", (len > 0) ? buffer : "None");

				lang_format_localtime(buffer, sizeof(buffer), GetCallerLang(), TIME_FORMAT_DATETIME, memo->time);
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_READ_MEMO_DATE_SENT, buffer);

				if (memo->chan)
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_READ_MEMO_CHANNEL_MESSAGE, memo->chan, memo->text);
				else
					send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_READ_MEMO_MESSAGE, memo->text);
			}

			send_notice_to_user(s_MemoServ, callerUser, s_SPACE);
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), END_OF_INFO);
			return;
		}

		TRACE_MAIN();
		if (ml->n_memos > 0) {

			for (memo = ml->memos, memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx, ++memo)
				read_memo(callerUser, memo, FALSE, (memoIdx + 1));
		}
		else
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_INFO_NO_MEMOS);

		TRACE_MAIN();
		if (ml->n_ignores > 0) {

			MemoIgnore *ignore;


			TRACE_MAIN();

			for (ignore = ml->ignores; IS_NOT_NULL(ignore); ignore = ignore->next) {

				if (IS_NOT_NULL(ignore->ignoredNick)) {

					if (len > 0) {

						*(buffer + len++) = c_COMMA;
						*(buffer + len++) = c_SPACE;
					}

					len += str_copy_checked(ignore->ignoredNick, (buffer + len), (sizeof(buffer) - len));

					if (len > 400) {

						send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_INFO_IGNORED_NICKS, buffer, ml->n_ignores);
						len = 0;
					}
				}
			}

			TRACE_MAIN();
			if (len > 0)
				send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_INFO_IGNORED_NICKS, buffer, ml->n_ignores);
		}
		else
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_INFO_NO_IGNORES);
	}

	TRACE_MAIN();
	if (IS_NOT_NULL(user = hash_onlineuser_find(nick)) && user_is_identified_to(user, nick)) {

		if (user->lastmemosend)
			send_notice_to_user(s_MemoServ, callerUser, "Last Memo Sent: %s ago", convert_time(buffer, sizeof(buffer), (NOW - user->lastmemosend), LANG_DEFAULT));
		else
			send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_INFO_NO_MEMOS_SENT);
	}

	if (ni->memomax == 0)
		send_notice_to_user(s_MemoServ, callerUser, "Memo Max: Unlimited");
	else
		send_notice_to_user(s_MemoServ, callerUser, "Memo Max: \2%d\2%s", ni->memomax, (ni->memomax == CONF_DEF_MAX_MEMOS) ? " Default" : "");

	if (ni->forward)
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_INFO_FORWARD_ON, ni->forward);

	if (FlagSet(ni->flags, NI_EMAILMEMOS) && ni->email)
		send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), MS_INFO_EMAILMEMOS_ON, ni->email);

	send_notice_to_user(s_MemoServ, callerUser, s_SPACE);
	send_notice_lang_to_user(s_MemoServ, callerUser, GetCallerLang(), END_OF_INFO);
}

/*********************************************************/

void memoserv_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	STR		cmd = strtok(request, s_SPACE);
	STR		value = strtok(NULL, s_SPACE);
	BOOL	needSyntax = FALSE;

	if (IS_NOT_NULL(cmd)) {

		if (str_equals_nocase(cmd, "HELP")) {

			/* HELP ! */
		}
		else if (str_equals_nocase(cmd, "NICK")) {

			if (IS_NULL(value))
				needSyntax = TRUE;

			else {

				STR what = strtok(NULL, s_SPACE);
				MemoList *ml = find_memolist(value);

				if (IS_NULL(ml))
					send_notice_to_user(sourceNick, callerUser, "DUMP: MemoList for \2%s\2 is empty.", value);

				else if (str_equals_nocase(what, "MEMOS")) {

					Memo *memo;
					int memoIdx;

					send_notice_to_user(sourceNick, callerUser, "DUMP: memos for \2%s\2", value);

					for (memo = ml->memos, memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx, ++memo) {

						send_notice_to_user(sourceNick, callerUser, "%d) Address 0x%08X, size %d B",			(memoIdx + 1), (unsigned long)memo, sizeof(Memo));
						send_notice_to_user(sourceNick, callerUser, "Unused: %d / Time Sent C-time: %d",		memo->unused, memo->time);
						send_notice_to_user(sourceNick, callerUser, "Sent by: %s / Flags: %d",					memo->sender, memo->flags);
						send_notice_to_user(sourceNick, callerUser, "Channel: 0x%08X \2[\2%s\2]\2",				(unsigned long)memo->chan, str_get_valid_display_value(memo->chan));
						send_notice_to_user(sourceNick, callerUser, "Text: 0x%08X \2[\2%s\2]\2",				(unsigned long)memo->text, str_get_valid_display_value(memo->text));
						send_notice_to_user(sourceNick, callerUser, "Level: %d",								memo->level);
						send_notice_to_user(sourceNick, callerUser, "reserved[3]: %d %d %d",					memo->reserved[0], memo->reserved[1], memo->reserved[2]);
					}
					LOG_DEBUG_SNOOP("Command: DUMP MEMOSERV NICK %s -- by %s (%s@%s) [Memos]", value, callerUser->nick, callerUser->username, callerUser->host);
				}
				else if (str_equals_nocase(what, "IGNORES")) {

					MemoIgnore *ignore;
					int idx = 0;

					send_notice_to_user(sourceNick, callerUser, "DUMP: memo ignores for \2%s\2", value);

					for (ignore = ml->ignores; IS_NOT_NULL(ignore); ignore = ignore->next) {

						++idx;
						send_notice_to_user(sourceNick, callerUser, "%d) Address 0x%08X, size %d B",			idx, (unsigned long)ignore, sizeof(MemoIgnore));
						send_notice_to_user(sourceNick, callerUser, "Ignored Nick: 0x%08X \2[\2%s\2]\2",		(unsigned long)ignore->ignoredNick, str_get_valid_display_value(ignore->ignoredNick));
						send_notice_to_user(sourceNick, callerUser, "Time Added C-time: %d",					ignore->creationTime);
						send_notice_to_user(sourceNick, callerUser, "Next / previous record: 0x%08X / 0x%08X",	(unsigned long)ignore->next, (unsigned long)ignore->prev);
					}

					LOG_DEBUG_SNOOP("Command: DUMP MEMOSERV NICK %s -- by %s (%s@%s) [Ignores]", value, callerUser->nick, callerUser->username, callerUser->host);
				}
				else {

					send_notice_to_user(sourceNick, callerUser, "DUMP: memolist for \2%s\2", value);

					send_notice_to_user(sourceNick, callerUser, "Address 0x%08X, size %d B",					(unsigned long)ml, sizeof(MemoList));
					send_notice_to_user(sourceNick, callerUser, "Name: %s",										ml->nick);
					send_notice_to_user(sourceNick, callerUser, "Memos: 0x%08X",								(unsigned long)ml->memos);
					send_notice_to_user(sourceNick, callerUser, "Number of Memos: %d",							ml->n_memos);
					send_notice_to_user(sourceNick, callerUser, "Ignores: 0x%08X",								(unsigned long)ml->ignores);
					send_notice_to_user(sourceNick, callerUser, "Number of Ignores: %d",						ml->n_ignores);
					send_notice_to_user(sourceNick, callerUser, "reserved[2]: %d %d",							ml->reserved[0], ml->reserved[1]);
					send_notice_to_user(sourceNick, callerUser, "Next / previous record: 0x%08X / 0x%08X",		(unsigned long)ml->next, (unsigned long)ml->prev);

					LOG_DEBUG_SNOOP("Command: DUMP MEMOSERV NICK %s -- by %s (%s@%s)", value, callerUser->nick, callerUser->username, callerUser->host);
				}
			}

		#ifdef FIX_USE_MPOOL
		} else if (str_equals_nocase(cmd, "POOL")) {

		} else if (str_equals_nocase(cmd, "POOLSTAT")) {

			MemoryPoolStats pstats;

			mempool_stats(memodb_mempool, &pstats);
			send_notice_to_user(sourceNick, callerUser, "DUMP: MemoServ memory pool - Address 0x%08X, ID: %d",	(unsigned long)memodb_mempool, pstats.id);
			send_notice_to_user(sourceNick, callerUser, "Memory allocated / free: %d B / %d B",				pstats.memory_allocated, pstats.memory_free);
			send_notice_to_user(sourceNick, callerUser, "Items allocated / free: %d / %d",					pstats.items_allocated, pstats.items_free);
			send_notice_to_user(sourceNick, callerUser, "Items per block / block count: %d / %d",			pstats.items_per_block, pstats.block_count);
			//send_notice_to_user(sourceNick, callerUser, "Average use: %.2f%%",								pstats.block_avg_usage);

		#endif
		} else
			needSyntax = TRUE;
	}
	else
		needSyntax = TRUE;

	if (needSyntax) {

		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 MEMOSERV HELP");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 MEMOSERV NICK nickname [ignores|memos]");
		#ifdef FIX_USE_MPOOL
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 MEMOSERV POOLSTAT");
		#endif
	}
}

/*********************************************************/

unsigned long memoserv_mem_report(CSTR sourceNick, const User *callerUser) {

	MemoList		*ml;
	unsigned long	recordCount = 0, memoCount = 0, mem = 0;
	int				idx, memoIdx;


	TRACE_FCLT(FACILITY_MEMOSERV_GET_STATS);

	send_notice_to_user(sourceNick, callerUser, "\2%s\2:", s_MemoServ);

	/* memo */

	for (idx = 65; idx < 126; ++idx) {

		for (ml = memolists[idx]; IS_NOT_NULL(ml); ml = ml->next) {

			TRACE();

			++recordCount;

			mem += sizeof(*ml);
			mem += (sizeof(Memo) * ml->n_memos);

			for (memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx) {

				++memoCount;

				mem += str_len(ml->memos[memoIdx].text) + 1;

				if (ml->memos[memoIdx].chan)
					mem += str_len(ml->memos[memoIdx].chan) + 1;
			}
		}
	}

	send_notice_to_user(sourceNick, callerUser, "Record / Memos: \2%d\2 / \2%d\2 -> \2%d\2 KB (\2%d\2 B)", recordCount, memoCount, mem / 1024, mem);
	return mem;
}
