/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* seenserv.c - SeenServ service
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/memory.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/logging.h"
#include "../inc/helpserv.h"
#include "../inc/seenserv.h"
#include "../inc/conf.h"
#include "../inc/send.h"
#include "../inc/misc.h"
#include "../inc/main.h"
#include "../inc/regions.h"
#include "../inc/storage.h"
#include "../inc/cidr.h"
#include "../inc/crypt_userhost.h"


/*********************************************************
 * Local and global variables                            *
 *********************************************************/

#ifdef	FIX_USE_MPOOL
MemoryPool			*seen_nickseen_mempool;
#endif

/* Stuff to pass to the command handler. */
static Agent a_SeenServ;


/*********************************************************
 * List hashing support                                  *
 *********************************************************/

#define HASH_DATA_MODIFIER			static
#define HASH_FUNCTIONS_MODIFIER		
#undef  LIST_USE_MY_HASH

#include "../inc/list.h"


#define SEENINFO_HASHSIZE	1024

// SeenInfo *hashtable_seeninfo[SEENINFO_HASHSIZE];
CREATE_HASHTABLE(seeninfo, SeenInfo, SEENINFO_HASHSIZE)

// void hash_seeninfo_add(SeenInfo *node);
static CREATE_HASH_ADD(seeninfo, SeenInfo, nick)

// void hash_seeninfo_add_tail(SeenInfo *node);
static CREATE_HASH_ADD_TAIL(seeninfo, SeenInfo, nick)

// void hash_seeninfo_remove(SeenInfo *node);
static CREATE_HASH_REMOVE(seeninfo, SeenInfo, nick)

// SeenInfo *hash_seeninfo_find(const char *value);
CREATE_HASH_FIND(seeninfo, SeenInfo, nick)


/*********************************************************
 * Prototypes                                            *
 *********************************************************/

static void delete_seen_record(SeenInfo *si);

static void do_seen(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_seennick(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_seenstats(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_unseen(CSTR source, User *callerUser, ServiceCommandData *data);


/*********************************************************
 * Initialization/Cleanup routines                       *
 *********************************************************/

void seenserv_init(const time_t now) {

	int hashIdx;

	HASH_FOREACH_BRANCH(hashIdx, SEENINFO_HASHSIZE) {

		hashtable_seeninfo[hashIdx] = NULL;
		hashtable_seeninfo_tails[hashIdx] = NULL;
	}

	#ifdef FIX_USE_MPOOL
	seen_nickseen_mempool = mempool_create(MEMPOOL_ID_SEEN_SEENDB, sizeof(SeenInfo), MP_IPB_SEEN_SEENDB, MP_IBC_SEEN_SEENDB);
	#endif

	/* Initialize this struct. */
	a_SeenServ.nick = s_SeenServ;
	a_SeenServ.shortNick = s_SS;
	a_SeenServ.agentID = AGENTID_SEENSERV;
	a_SeenServ.logID = logid_from_agentid(AGENTID_SEENSERV);
}

void seenserv_terminate(void) {
	
	#ifdef FIX_USE_MPOOL
	mempool_destroy(seen_nickseen_mempool);
	seen_nickseen_mempool = NULL;
	#endif
}


/*********************************************************
 * Command handlers                                      *
 *********************************************************/

// 'A' (65 / 0)
// 'B' (66 / 1)
// 'C' (67 / 2)
// 'D' (68 / 3)
// 'E' (69 / 4)
// 'F' (70 / 5)
// 'G' (71 / 6)
// 'H' (72 / 7)
static ServiceCommand	seenserv_commands_H[] = {
	{ "HELP",		ULEVEL_USER,	0, handle_help },
	{ NULL,			0,				0, NULL }
};
// 'I' (73 / 8)
// 'J' (74 / 9)
// 'K' (75 / 10)
// 'L' (76 / 11)
// 'M' (77 / 12)
// 'N' (78 / 13)
// 'O' (79 / 14)
static ServiceCommand	seenserv_commands_O[] = {
	{ "OHELP",		ULEVEL_OPER,	0, handle_help },
	{ NULL,			0,				0, NULL }
};
// 'P' (80 / 15)
// 'Q' (81 / 16)
// 'R' (82 / 17)
// 'S' (83 / 18)
static ServiceCommand	seenserv_commands_S[] = {
	{ "SEEN",		ULEVEL_USER,	0, do_seen },
	{ "SEENNICK",	ULEVEL_USER,	0, do_seennick },
	{ "SEENSTATS",	ULEVEL_SA,		0, do_seenstats },
	{ NULL,			0,				0, NULL }
};
// 'T' (84 / 19)
// 'U' (85 / 20)
static ServiceCommand	seenserv_commands_U[] = {
	{ "UNSEEN",		ULEVEL_SA,		0, do_unseen },
	{ NULL,			0,				0, NULL }
};
// 'V' (86 / 21)
// 'W' (87 / 22)
// 'X' (88 / 23)
// 'Y' (89 / 24)
// 'Z' (90 / 25)

ServiceCommand	*seenserv_commands[26] = {
	NULL,					NULL,
	NULL,					NULL,
	NULL,					NULL,
	NULL,					seenserv_commands_H,
	NULL,					NULL,
	NULL,					NULL,
	NULL,					NULL,
	seenserv_commands_O,	NULL,
	NULL,					NULL,
	seenserv_commands_S,	NULL,
	seenserv_commands_U,	NULL,
	NULL,					NULL,
	NULL,					NULL
};


/*********************************************************
 * Main routine                                          *
 *********************************************************/

void seenserv(CSTR source, User *callerUser, char *buf) {

	char *command = strtok(buf, " ");

	TRACE_MAIN_FCLT(FACILITY_SEENSERV);

	if (IS_NULL(command))
		return;

	else if (command[0] == '\001') {

		++command;

		if (IS_EMPTY_STR(command))
			LOG_SNOOP(s_SeenServ, "Invalid CTCP from \2%s\2", source);

		else {

			char *action = strtok(NULL, "");

			if (action) {

				action[str_len(action) - 1] = '\0';
				LOG_SNOOP(s_SeenServ, "CTCP: %s %s from \2%s\2", command, action, source);
			}
			else {

				command[str_len(command) - 1] = '\0';
				LOG_SNOOP(s_SeenServ, "CTCP: %s from \2%s\2", command, source);
			}
		}
	}
	else
		oper_invoke_agent_command(command, seenserv_commands, callerUser, &a_SeenServ);
}


/*********************************************************
 * Database related functions                            *
 *********************************************************/

BOOL seenserv_db_load(void) {

	STGHANDLE	stg = 0;
	STG_RESULT	result;
	int			hashIdx;

	#ifdef FIX_USE_MPOOL
	MEMORYBLOCK_ID	mblock_id;
	#endif


	TRACE_FCLT(FACILITY_SEENSERV_DB_LOAD);

	result = stg_open(SEENSERV_DB, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version;
			BOOL		in_section;
			BOOL		read_done;


			version = stg_data_version(stg);

			switch (version) {

			case SEENSERV_DB_CURRENT_VERSION: {

					SeenInfo_V10	*si;

					HASH_FOREACH_BRANCH(hashIdx, SEENINFO_HASHSIZE) {

						// start-of-section marker
						result = stg_read_record(stg, NULL, 0);

						if (result == stgBeginOfSection) {

							in_section = TRUE;

							while (in_section) {

								#ifdef	FIX_USE_MPOOL
								si = mempool_alloc2(SeenInfo_V10*, seen_nickseen_mempool, FALSE, &mblock_id);
								#else
								si = mem_malloc(sizeof(SeenInfo_V10));
								#endif

								result = stg_read_record(stg, (PBYTE)si, sizeof(SeenInfo_V10));

								switch (result) {

									case stgEndOfSection: // end-of-section
										in_section = FALSE;
										#ifdef	FIX_USE_MPOOL
										mempool_free2(seen_nickseen_mempool, si, mblock_id);
										#else
										mem_free(si);
										#endif

										break;

									case stgSuccess: // a valid region

										#ifdef	FIX_USE_MPOOL
										si->mblock_id = mblock_id;
										#endif

										read_done = TRUE;
										if (IS_NOT_NULL(si->nick))
											read_done &= (result = stg_read_string(stg, &(si->nick), NULL)) == stgSuccess;

										if (read_done && IS_NOT_NULL(si->username))
											read_done &= (result = stg_read_string(stg, &(si->username), NULL)) == stgSuccess;

										if (read_done && IS_NOT_NULL(si->host))
											read_done &= (result = stg_read_string(stg, &(si->host), NULL)) == stgSuccess;

										if (read_done && IS_NOT_NULL(si->realname))
											read_done &= (result = stg_read_string(stg, &(si->realname), NULL)) == stgSuccess;

										if (read_done && IS_NOT_NULL(si->tempnick))
											read_done &= (result = stg_read_string(stg, &(si->tempnick), NULL)) == stgSuccess;

										if (read_done && IS_NOT_NULL(si->quitmsg))
											read_done &= (result = stg_read_string(stg, &(si->quitmsg), NULL)) == stgSuccess;

										if (!read_done)
											fatal_error(FACILITY_SEENSERV_DB_LOAD, __LINE__, "Read error on %s (2) - %s", SEENSERV_DB, stg_result_to_string(result));

										si->next = si->prev = NULL;

										if (!is_seen_exempt(si->nick, si->username, si->host, si->ip))
											hash_seeninfo_add_tail(si);

										break;

									default: // some error
										fatal_error(FACILITY_SEENSERV_DB_LOAD, __LINE__, "Read error on %s - %s", SEENSERV_DB, stg_result_to_string(result));
								}
							}
						}
						else
							fatal_error(FACILITY_SEENSERV_DB_LOAD, __LINE__, "Read error on %s : invalid format", SEENSERV_DB);
					}

					stg_close(stg, SEENSERV_DB);
					return TRUE;
				}

				default:
					fatal_error(FACILITY_SEENSERV_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, SEENSERV_DB);
			}
		}

		case stgNotFound: // no data to load
			return TRUE;

		default: // error!
			stg_close(stg, SEENSERV_DB);
			fatal_error(FACILITY_SEENSERV_DB_LOAD, __LINE__, "Error opening %s - %s", SEENSERV_DB, stg_result_to_string(result));

			return FALSE;
	}
}

/*********************************************************/

BOOL seenserv_db_save(void) {

	STGHANDLE		stg;
	STG_RESULT		result;
	SeenInfo		*si;
	int				hashIdx, error_index;
	char			*strings[6];


	TRACE_FCLT(FACILITY_SEENSERV_DB_SAVE);

	result = stg_create(SEENSERV_DB, SF_NOFLAGS, SEENSERV_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_SEENSERV_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"seenserv_db_save(): Could not create database file %s: %s [Error %d: %s]", SEENSERV_DB, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	HASH_FOREACH_BRANCH(hashIdx, SEENINFO_HASHSIZE) {

		result = stg_start_section(stg);

		if (result != stgSuccess)
			fatal_error(FACILITY_SEENSERV_DB_SAVE, __LINE__, "Write error on %s - %s", SEENSERV_DB, stg_result_to_string(result));

		for (si = hashtable_seeninfo[hashIdx]; si; si = si->next) {

			result = stg_write_record(stg, (PBYTE)si, sizeof(SeenInfo));

			if (result != stgSuccess)
				fatal_error(FACILITY_SEENSERV_DB_SAVE, __LINE__, "Write error on %s - %s", SEENSERV_DB, stg_result_to_string(result));

			strings[0] = si->nick;
			strings[1] = si->username;
			strings[2] = si->host;
			strings[3] = si->realname;
			strings[4] = si->tempnick;
			strings[5] = si->quitmsg;

			error_index = -1;

			result = stg_write_strings(stg, strings, sizeof(strings) / sizeof(char*), &error_index);

			if (result != stgSuccess)
				fatal_error(FACILITY_SEENSERV_DB_SAVE, __LINE__, "Write error on %s for string n. %d - %s", SEENSERV_DB, error_index, stg_result_to_string(result));
		}

		result = stg_end_section(stg);

		if (result != stgSuccess)
			fatal_error(FACILITY_SEENSERV_DB_SAVE, __LINE__, "Write error on %s - %s", SEENSERV_DB, stg_result_to_string(result));
	}

	stg_close(stg, SEENSERV_DB);

	return TRUE;
}


/*********************************************************
 * Expiration routines                                   *
 *********************************************************/

void seenserv_expire_records() {

	SeenInfo *si, *next = NULL;
	int hashIdx;
	const time_t expire_time = (NOW - (CONF_SEEN_EXPIRE * ONE_DAY));
	long int count = 0, xcount = 0;
	User *user;


	TRACE_FCLT(FACILITY_SEENSERV_EXPIRE_RECORDS);

	if (CONF_SET_NOEXPIRE)
		return;

	HASH_FOREACH_BRANCH(hashIdx, SEENINFO_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM_SAFE(seeninfo, hashIdx, si, next) {

			TRACE();
			++count;

			TRACE();

			if ((expire_time >= si->last_seen) && (IS_NULL(user = hash_onlineuser_find(si->nick)))) {

				TRACE();
				++xcount;

				delete_seen_record(si);
			}
		}
	}

	if (CONF_DISPLAY_UPDATES)
		send_globops(NULL, "Completed Seen Records Expire (%d/%d)", xcount, count);
}


void seenserv_weekly_expire() {

	#ifdef	FIX_USE_MPOOL
	unsigned int	count;

	count = mempool_garbage_collect(seen_nickseen_mempool);

	LOG_DEBUG_SNOOP("\2MPGC\2 Seens:\2 %d\2 blocks collected", count);
	#endif

	if (CONF_DISPLAY_UPDATES)
		send_globops(NULL, "Completed Weekly Seen Expire");
}


/*********************************************************
 * SeenServ private routines                             *
 *********************************************************/

/* Remove a nick from the SeenServ database. Return 1 on success, 0 otherwise. */

static void delete_seen_record(SeenInfo *si) {

	TRACE_FCLT(FACILITY_SEENSERV_DELETE_RECORD);

	hash_seeninfo_remove(si);

	TRACE();
	if (IS_NOT_NULL(si->nick))
		mem_free(si->nick);

	TRACE();
	if (IS_NOT_NULL(si->username))
		mem_free(si->username);

	TRACE();
	if (IS_NOT_NULL(si->host))
		mem_free(si->host);

	TRACE();
	if (IS_NOT_NULL(si->realname))
		mem_free(si->realname);

	TRACE();
	if (IS_NOT_NULL(si->tempnick))
		mem_free(si->tempnick);

	TRACE();
	if (IS_NOT_NULL(si->quitmsg))
		mem_free(si->quitmsg);

	TRACE();

	#ifdef	FIX_USE_MPOOL
	mempool_free2(seen_nickseen_mempool, si, si->mblock_id);
	#else
	mem_free(si);
	#endif
}

/*********************************************************/

SeenInfo *seenserv_create_record(const User *user) {

	SeenInfo *si;

	#ifdef	FIX_USE_MPOOL
	MEMORYBLOCK_ID	mblock_id;
	#endif


	TRACE_FCLT(FACILITY_SEENSERV_CREATE_RECORD);

	if (IS_NULL(user)) {

		log_error(FACILITY_SEENSERV_CREATE_RECORD, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "seenserv_CREATE_record()", s_LOG_NULL, "user");

		return NULL;
	}

	#ifdef	FIX_USE_MPOOL
	si = mempool_alloc2(SeenInfo*, seen_nickseen_mempool, TRUE, &mblock_id);
	si->mblock_id = mblock_id;
	#else
	si = mem_calloc(1, sizeof(SeenInfo));
	#endif

	si->nick = str_duplicate(user->nick);
	si->username = str_duplicate(user->username);
	si->host = str_duplicate(user->host);
	si->realname = str_duplicate(user->realname);
	si->ip = user->ip;
	si->last_seen = NOW;

	hash_seeninfo_add(si);

	LOG_DEBUG("seen: Added record for %s (%s@%s [%s]) [%s]", si->nick, si->username, si->host, user->maskedHost, si->realname);

	return si;
}

/*********************************************************/

BOOL is_seen_exempt(CSTR nick, CSTR username, CSTR host, const unsigned long int ip) {

	if ((ip == SERVICES_IP_NETWORK_ORDER) ||							/* Services' clients and enforcers. */
		(ip == 591065044UL) ||											/* picard.azzurra.org */
		((ip == 4213038297UL) && str_equals_partial(nick, "ircd", 4)))	/* golia.caltanet.it */
		return TRUE;

	return FALSE;
}

/*********************************************************/

static time_t match_insert(SeenInfo **matches, SeenInfo *si, int limit) {

	if (IS_NULL(matches[0])) {

		matches[0] = si;
		return si->last_seen;
	}
	else {

		int i, j;
		time_t lowest_TS = 0;

		/* Loop through our matches till we get to the one with lower TS than the new one. */
		for (i = 0; (i < limit) && IS_NOT_NULL(matches[i]); ++i) {

			if (matches[i]->last_seen < si->last_seen) {

				/* Got it. Replace it with the new one, and move the rest down one slot. */
				for (j = limit - 1; j > i; --j) {

					matches[j] = matches[j - 1];

					if (lowest_TS == 0 && matches[j])
						lowest_TS = matches[j]->last_seen;
				}

				matches[i] = si;

				/* We're done. */
				return (lowest_TS ? lowest_TS : si->last_seen);
			}
		}

		/* We didn't find it? There must be at least one empty slot then. */
		for (i = 0; i < limit; ++i) {

			if (IS_NULL(matches[i])) {

				matches[i] = si;
				return si->last_seen;
			}
		}

		/* No empty slots? Something's wrong... */
		LOG_DEBUG_SNOOP("Couldn't add %s (%ld) to matches", si->nick, si->last_seen);
		LOG_DEBUG_SNOOP("Status: %s (%ld), %s (%ld), %s (%ld), %s (%ld), %s (%ld)", matches[0] ? matches[0]->nick : NULL, matches[0] ? matches[0]->last_seen : 0, matches[1] ? matches[1]->nick : NULL, matches[1] ? matches[1]->last_seen : 0, matches[2] ? matches[2]->nick : NULL, matches[2] ? matches[2]->last_seen : 0, matches[3] ? matches[3]->nick : NULL, matches[3] ? matches[3]->last_seen : 0, matches[4] ? matches[4]->nick : NULL, matches[4] ? matches[4]->last_seen : 0);
		return NOW;
	}
}

static void send_seen_info(SeenInfo *si, const User *callerUser) {

	char seenbuf[64];
	BOOL isOper = user_is_ircop(callerUser);

	switch (si->type) {

		case SEEN_TYPE_NICK:
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_TYPE_NICK, si->nick, convert_time(seenbuf, sizeof(seenbuf), (NOW - si->last_seen), GetCallerLang()));
			break;

		case SEEN_TYPE_QUIT:
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_TYPE_QUIT, si->nick, convert_time(seenbuf, sizeof(seenbuf), (NOW - si->last_seen), GetCallerLang()), si->quitmsg);
			break;

		case SEEN_TYPE_NCTO:
			if (isOper)
				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_TYPE_NCTO_OPER, si->nick, si->tempnick, convert_time(seenbuf, sizeof(seenbuf), (NOW - si->last_seen), GetCallerLang()));
			else
				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_TYPE_NCTO, si->nick, convert_time(seenbuf, sizeof(seenbuf), (NOW - si->last_seen), GetCallerLang()));

			break;

		case SEEN_TYPE_NCFR:
			if (isOper)
				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_TYPE_NCFR_OPER, si->nick, si->tempnick, convert_time(seenbuf, sizeof(seenbuf), (NOW - si->last_seen), GetCallerLang()));
			else
				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_TYPE_NCFR, si->nick, convert_time(seenbuf, sizeof(seenbuf), (NOW - si->last_seen), GetCallerLang()));

			break;

		case SEEN_TYPE_KILL:
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_TYPE_KILL, si->tempnick, si->nick, convert_time(seenbuf, sizeof(seenbuf), (NOW - si->last_seen), GetCallerLang()));
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_TYPE_REASON, si->quitmsg);
			break;

		case SEEN_TYPE_SPLIT:
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_TYPE_SPLIT, si->nick, convert_time(seenbuf, sizeof(seenbuf), (NOW - si->last_seen), GetCallerLang()));
			break;

		case SEEN_TYPE_KLINE:
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_TYPE_KLINE, si->nick, convert_time(seenbuf, sizeof(seenbuf), (NOW - si->last_seen), GetCallerLang()));
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_TYPE_REASON, si->quitmsg);
			break;

		case SEEN_TYPE_AKILL:
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_TYPE_AKILL, si->nick, convert_time(seenbuf, sizeof(seenbuf), (NOW - si->last_seen), GetCallerLang()));
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_TYPE_REASON, si->quitmsg);
			break;

		case SEEN_TYPE_NOSEEN:
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_TYPE_NOSEEN, si->nick, convert_time(seenbuf, sizeof(seenbuf), (NOW - si->last_seen), GetCallerLang()));
			break;

		default:
			LOG_SNOOP(s_SeenServ, "si->type for %s unknown! (%d)", si->nick, si->type);
			break;
	}
}


/*********************************************************
 * SeenServ Command Routines                             *
 *********************************************************/

static void do_unseen(CSTR source, User *callerUser, ServiceCommandData *data) {
	
	const char *nick;
	SeenInfo *si;
	User *user;


	TRACE_MAIN_FCLT(FACILITY_SEENSERV_HANDLE_UNSEEN);

	if (CONF_SET_READONLY) {

		send_notice_to_user(s_SeenServ, callerUser, "Services is in read-only mode, nickname deletion is temporarily disabled.");
		return;
	}

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_to_user(s_SeenServ, callerUser, "Syntax: \2UNSEEN\2 nickname");
		send_notice_to_user(s_SeenServ, callerUser, "Type \2/ss OHELP UNSEEN\2 for more information.");
		return;
	}

	if (IS_NOT_NULL(user = hash_onlineuser_find(nick))) {

		LOG_SNOOP(s_SeenServ, "SS *U %s -- by %s (%s@%s) [User Online]", user->nick, source, callerUser->username, callerUser->host);
		send_notice_to_user(s_SeenServ, callerUser, "\2%s\2 is online, cannot delete seen information.", user->nick);
		return;
	}

	TRACE_MAIN();

	if (IS_NULL(si = hash_seeninfo_find(nick))) {

		LOG_SNOOP(s_SeenServ, "SS *U %s -- by %s (%s@%s) [Not Found]", nick, source, callerUser->username, callerUser->host);
		send_notice_to_user(s_SeenServ, callerUser, "No seen record found for \2%s\2.", nick);
		return;
	}

	if (data->operMatch) {

		LOG_SNOOP(s_SeenServ, "SS U %s -- by %s (%s@%s)", si->nick, source, callerUser->username, callerUser->host);
		log_services(LOG_SERVICES_SEENSERV, "U %s -- by %s (%s@%s)", si->nick, source, callerUser->username, callerUser->host);

		send_globops(s_SeenServ, "\2%s\2 deleted seen record for \2%s\2", source, si->nick);
	}
	else {

		LOG_SNOOP(s_SeenServ, "SS U %s -- by %s (%s@%s) through %s", si->nick, source, callerUser->username, callerUser->host, data->operName);
		log_services(LOG_SERVICES_SEENSERV, "U %s -- by %s (%s@%s) through %s", si->nick, source, callerUser->username, callerUser->host, data->operName);

		send_globops(s_SeenServ, "\2%s\2 (through \2%s\2) deleted seen record for \2%s\2", source, data->operName, si->nick);
	}

	send_notice_to_user(s_SeenServ, callerUser, "Seen record deleted for \2%s\2.", si->nick);

	TRACE_MAIN();
	delete_seen_record(si);
	TRACE_MAIN();
}

/*********************************************************/

static void do_seennick(CSTR source, User *callerUser, ServiceCommandData *data) {
	
	const char *nick;
	SeenInfo *si;
	User *user;
	BOOL isOper;


	TRACE_MAIN_FCLT(FACILITY_SEENSERV_HANDLE_SEENNICK);

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEENNICK_SYNTAX_ERROR);
		send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_SS, "SEENNICK");
		return;
	}

	isOper = user_is_ircop(callerUser);

	TRACE_MAIN();
	if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), ERROR_NICK_MAX_LENGTH, NICKMAX);

	else if (!validate_nick(nick, FALSE))
		send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), ERROR_INVALID_NICK, nick);

	else if (IS_NOT_NULL(user = hash_onlineuser_find(nick)) && !isOper)
		send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_NICK_IS_ONLINE, user->nick, user->nick);

	else if (IS_NULL(si = hash_seeninfo_find(nick))) {

		if (IS_NOT_NULL(user))
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_NICK_IS_ONLINE, user->nick, user->nick);
		else
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_NO_SEEN, nick);
	}
	else {

		char timebuf[64];

		TRACE_MAIN();

		send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEENNICK_HEADER, si->nick);
		send_notice_to_user(s_SeenServ, callerUser, s_SPACE);

		send_seen_info(si, callerUser);

		TRACE_MAIN();
		if (IS_NOT_NULL(si->realname))
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEENNICK_REPLY_REALNAME, si->realname);

		if (FlagSet(si->mode, UMODE_x)) {

			HOST_TYPE	htype;
			short int	dotsCount;

			htype = host_type(si->host, &dotsCount);

			if (!isOper)
				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEENNICK_REPLY_ADDRESS, si->username, crypt_userhost(si->host, htype, dotsCount));
			else
				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEENNICK_REPLY_ADDRESS_OPER, si->username, crypt_userhost(si->host, htype, dotsCount), si->host);
		}
		else
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEENNICK_REPLY_ADDRESS, si->username, si->host);

		if (FlagSet(si->mode, UMODE_r)) {

			if (IS_NOT_NULL(user))
				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEENNICK_REPLY_IDENTIFIED_ONLINE);
			else
				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEENNICK_REPLY_IDENTIFIED_OFFLINE);
		}
		else {

			if (IS_NOT_NULL(user))
				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEENNICK_REPLY_NOTID_ONLINE);
			else
				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEENNICK_REPLY_NOTID_OFFLINE);
		}

		lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, NOW);

		send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), INFO_CURRENT_TIME, timebuf);

		TRACE_MAIN();
		if (!isOper) {

			send_notice_to_user(s_SeenServ, callerUser, s_SPACE);
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), END_OF_SEEN);
			return;
		}

		send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEENNICK_REPLY_USERMODE, get_user_modes(si->mode, 0));
		send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), END_OF_SEEN);
	}
}

/*********************************************************/

static void do_seenstats(CSTR source, User *callerUser, ServiceCommandData *data) {

	SeenInfo *si;
	int hashIdx;
	unsigned long int nicks = 0, quits = 0, nc = 0, kills = 0, splits = 0, noseen = 0, akill = 0, kline = 0;


	TRACE_MAIN_FCLT(FACILITY_SEENSERV_HANDLE_SEENSTATS);

	HASH_FOREACH_BRANCH(hashIdx, SEENINFO_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM(seeninfo, hashIdx, si) {

			TRACE_MAIN();
			switch (si->type) {

				case SEEN_TYPE_NICK:
					++nicks;
					break;

				case SEEN_TYPE_QUIT:
					++quits;
					break;

				case SEEN_TYPE_NCTO:
				case SEEN_TYPE_NCFR:
					++nc;
					break;

				case SEEN_TYPE_KILL:
					++kills;
					break;

				case SEEN_TYPE_SPLIT:
					++splits;
					break;

				case SEEN_TYPE_NOSEEN:
					++noseen;
					break;

				case SEEN_TYPE_KLINE:
					++kline;
					break;

				case SEEN_TYPE_AKILL:
					++akill;
					break;

				default:
					LOG_SNOOP(s_SeenServ, "si->type for si->nick %s is %d", si->nick, si->type);
					break;
			}
		}
	}

	TRACE_MAIN();
	send_notice_to_user(s_SeenServ, callerUser, "\2*** SeenServ Records Status ***\2");
	send_notice_to_user(s_SeenServ, callerUser, s_SPACE);
	send_notice_to_user(s_SeenServ, callerUser, "Currently tracking %ld seen records.", nicks + quits + nc + kills + splits + noseen);
	send_notice_to_user(s_SeenServ, callerUser, s_SPACE);
	send_notice_to_user(s_SeenServ, callerUser, "Nicks: \2%d\2", nicks);
	send_notice_to_user(s_SeenServ, callerUser, "Quits: \2%d\2", quits);
	send_notice_to_user(s_SeenServ, callerUser, "Nick Changes: \2%d\2", nc);
	send_notice_to_user(s_SeenServ, callerUser, "Kills: \2%d\2", kills);
	send_notice_to_user(s_SeenServ, callerUser, "Splits: \2%d\2", splits);
	send_notice_to_user(s_SeenServ, callerUser, "No Seen: \2%d\2", noseen);
	send_notice_to_user(s_SeenServ, callerUser, "Autokills: \2%d\2", akill);
	send_notice_to_user(s_SeenServ, callerUser, "K-Lines: \2%d\2", kline);
	send_notice_to_user(s_SeenServ, callerUser, s_SPACE);
	send_notice_to_user(s_SeenServ, callerUser, "\2*** End of Seen Stats***\2");
}

/*********************************************************/

static void do_seen(CSTR source, User *callerUser, ServiceCommandData *data) {

	char	*mask, *options, *token;
	char	c;
	int		max_hits = WILDSEEN, wantType = 0;
	BOOL	isOper, add = FALSE, wantQuit = FALSE, wantTS = FALSE, wantID = FALSE, wantIDSet = FALSE;
	BOOL	wantNick = FALSE, wantUsername = FALSE, wantRealname = FALSE, wantHost = FALSE, wantCrypt = FALSE;
	char	*strQuit = NULL, *strRealname = NULL, *strHost = NULL, *strUsername = NULL, *strNick = NULL;
	time_t	requestedTS = 0;


	TRACE_MAIN_FCLT(FACILITY_SEENSERV_HANDLE_SEEN);

	isOper = user_is_ircop(callerUser);

	if (IS_NULL(options = strtok(NULL, " ")))
		goto error;

	if (!isOper || ((options[0] != '+') && (options[0] != '-'))) {

		mask = options;
		goto proceed;
	}

	while (*options) {

		switch (c = *options++) {

			case '+':
				add = TRUE;
				break;

			case '-':
				add = FALSE;
				break;


			case 'c':
				if (add)
					wantCrypt = TRUE;
				break;


			case 'h':
				if (IS_NULL(token = strtok(NULL, " ")))
					goto error;

				if (strHost)
					mem_free(strHost);
				strHost = str_duplicate(token);

				wantHost = add;
				break;


			case 'l':
				if (IS_NULL(token = strtok(NULL, " ")))
					goto error;

				requestedTS = (NOW - convert_amount(token));

				if (requestedTS == NOW)
					goto error;

				wantTS = add;
				break;


			case 'm': {

				long int hits;
				char *err;

				if (IS_NULL(token = strtok(NULL, " ")))
					goto error;

				hits = strtol(token, &err, 10);

				if ((hits <= 0) || (*err != '\0'))
					goto error;

				max_hits = (hits > 32) ? 32 : hits;
				break;
			}


			case 'n':
				if (IS_NULL(token = strtok(NULL, " ")))
					goto error;

				if (strNick)
					mem_free(strNick);
				strNick = str_duplicate(token);

				wantNick = add;
				break;


			case 'q':
				if (IS_NULL(token = strtok(NULL, " ")))
					goto error;

				if (strQuit)
					mem_free(strQuit);
				strQuit = str_duplicate(token);

				wantQuit = add;
				break;


			case 'r':
				if (IS_NULL(token = strtok(NULL, " ")))
					goto error;

				if (strRealname)
					mem_free(strRealname);
				strRealname = str_duplicate(token);

				wantRealname = add;
				break;


			case 'R':
				wantID = TRUE;
				wantIDSet = add;
				break;


			case 't':
				if (IS_NULL(token = strtok(NULL, " ")))
					goto error;

				if (str_equals_nocase(token, "NICK"))
					wantType = SEEN_TYPE_NICK;
				else if (str_equals_nocase(token, "QUIT"))
					wantType = SEEN_TYPE_QUIT;
				else if (str_equals_nocase(token, "NCFR"))
					wantType = SEEN_TYPE_NCFR;
				else if (str_equals_nocase(token, "NCTO"))
					wantType = SEEN_TYPE_NCTO;
				else if (str_equals_nocase(token, "KILL"))
					wantType = SEEN_TYPE_KILL;
				else if (str_equals_nocase(token, "SPLIT"))
					wantType = SEEN_TYPE_SPLIT;
				else if (str_equals_nocase(token, "NOSEEN"))
					wantType = SEEN_TYPE_NOSEEN;
				else if (str_equals_nocase(token, "AKILL"))
					wantType = SEEN_TYPE_AKILL;
				else if (str_equals_nocase(token, "KLINE"))
					wantType = SEEN_TYPE_KLINE;
				else
					goto error;

				break;


			case 'u':
				if (IS_NULL(token = strtok(NULL, " ")))
					goto error;

				if (strUsername)
					mem_free(strUsername);
				strUsername = str_duplicate(token);

				wantUsername = add;
				break;


			default:
				goto error;
		}
	}

	if (IS_NULL(mask = strtok(NULL, " ")))
		goto error;

proceed:

	if (str_len(mask) > MASKMAX) {

		send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), ERROR_MASK_MAX_LENGTH, MASKMAX);
		goto done;
	}
	else {

		char nick[NICKSIZE], username[USERSIZE], host[HOSTSIZE], buffer[IRCBUFSIZE];
		char *ptr;
		int hashIdx, matchIdx, count = 0;
		SeenInfo *si, *matches[32];
		time_t lowest_TS = NOW;
		CIDR_IP cidr;
		BOOL matchCIDR = FALSE;

		/* recupero parametri di ricerca */

		TRACE_MAIN();

		memset(nick, 0, sizeof(nick));
		memset(username, 0, sizeof(username));
		memset(host, 0, sizeof(host));

		if (strchr(mask, '!')) {

			ptr = str_tokenize(mask, buffer, sizeof(buffer), '!');

			if (IS_NULL(ptr) || IS_EMPTY_STR(buffer)) {

				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_NO_SEEN, buffer);
				goto done;
			}

			if (str_len(buffer) > NICKMAX) {

				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), ERROR_NICK_MAX_LENGTH, NICKMAX);
				goto done;
			}

			if (!validate_nick(buffer, TRUE)) {

				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), ERROR_INVALID_NICK, buffer);
				goto done;
			}

			TRACE_MAIN();

			if (!strchr(buffer, '*') && !strchr(buffer, '?')) {

				if (IS_NOT_NULL(si = hash_seeninfo_find(buffer))) {

					User *user;

					if (!isOper && IS_NOT_NULL(user = hash_onlineuser_find(buffer))) {

						send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_NICK_IS_ONLINE, user->nick, user->nick);
						goto done;
					}

					TRACE_MAIN();
					send_seen_info(si, callerUser);
				}
				else
					send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_NO_SEEN, buffer);

				TRACE_MAIN();
				goto done;
			}
			else if (!isOper)
				goto error;

			str_copy_checked(buffer, nick, NICKSIZE);

			if (IS_NOT_NULL(ptr = str_tokenize(ptr, buffer, sizeof(buffer), c_AT))) {

				if (str_len(buffer) > USERMAX) {

					send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), ERROR_USER_MAX_LENGTH, USERMAX);
					goto done;
				}

				str_copy_checked(buffer, username, USERSIZE);
			}

			if (IS_NOT_NULL(ptr = str_tokenize(ptr, buffer, sizeof(buffer), c_NULL))) {

				if (cidr_ip_fill(buffer, &cidr, FALSE) == cidrSuccess)
					matchCIDR = TRUE;

				else if (strchr(buffer, '/')) {

					send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEEN_SYNTAX_ERROR_OPER);
					goto done;
				}
				else if (str_len(buffer) > HOSTMAX) {

					send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), ERROR_HOST_MAX_LENGTH, HOSTMAX);
					goto done;
				}
				else
					str_copy_checked(buffer, host, HOSTSIZE);
			}
		}
		else if (strchr(mask, c_AT)) {

			if (!isOper)
				goto error;

			TRACE_MAIN();

			if (IS_NOT_NULL(ptr = str_tokenize(mask, buffer, sizeof(buffer), c_AT))) {

				if (str_len(buffer) > USERMAX) {

					send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), ERROR_USER_MAX_LENGTH, USERMAX);
					goto done;
				}

				str_copy_checked(buffer, username, USERSIZE);
			}

			if (IS_NOT_NULL(ptr = str_tokenize(ptr, buffer, sizeof(buffer), c_NULL))) {

				if (cidr_ip_fill(buffer, &cidr, FALSE) == cidrSuccess)
					matchCIDR = TRUE;

				else if (strchr(buffer, '/')) {

					send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEEN_SYNTAX_ERROR_OPER);
					goto done;
				}
				else if (str_len(buffer) > HOSTMAX) {

					send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), ERROR_HOST_MAX_LENGTH, HOSTMAX);
					goto done;
				}
				else
					str_copy_checked(buffer, host, HOSTSIZE);
			}
		}
		else {

			TRACE_MAIN();

			if (str_len(mask) > NICKMAX) {

				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), ERROR_NICK_MAX_LENGTH, NICKMAX);
				goto done;
			}

			if (!validate_nick(mask, TRUE)) {

				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), ERROR_INVALID_NICK, mask);
				goto done;
			}

			if (!strchr(mask, '*') && !strchr(mask, '?')) {

				User *user;

				if (IS_NOT_NULL(user = hash_onlineuser_find(mask)) && !isOper) {

					send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_NICK_IS_ONLINE, user->nick, user->nick);
					goto done;
				}

				TRACE_MAIN();

				if (IS_NOT_NULL(si = hash_seeninfo_find(mask)))
					send_seen_info(si, callerUser);
				else if (IS_NOT_NULL(user))
					send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_NICK_IS_ONLINE, user->nick, user->nick);
				else
					send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_NO_SEEN, mask);

				TRACE_MAIN();
				goto done;
			}
			else if (!isOper)
				goto error;

			TRACE_MAIN();
			str_copy_checked(mask, nick, NICKSIZE);
		}

		if ((*username && !*host && !matchCIDR) || (!*username && (*host || matchCIDR))
			|| (!*nick && !*username && !*host && !matchCIDR)) {

			TRACE_MAIN();
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), ERROR_NO_NICK_OR_USER_AT_HOST_MASK);
			goto done;
		}

		/* Inizio ricerca. */

		TRACE_MAIN();

		for (matchIdx = 0; matchIdx < 32; ++matchIdx)
			matches[matchIdx] = NULL;

		HASH_FOREACH_BRANCH(hashIdx, SEENINFO_HASHSIZE) {

			HASH_FOREACH_BRANCH_ITEM(seeninfo, hashIdx, si) {

				TRACE_MAIN();

				if (requestedTS && (wantTS ? (si->last_seen >= requestedTS) : (si->last_seen <= requestedTS)))
					continue;

				if (wantType && (si->type != wantType))
					continue;

				if (wantID && (wantIDSet != FlagSet(si->mode, UMODE_r)))
					continue;

				if (matchCIDR) {

					if (!cidr_match(&cidr, si->ip))
						continue;
				}
				else {

					if (*host) {

						if (!wantCrypt) {

							 if (!str_match_wild_nocase(host, si->host))
								continue;
						}
						else {

							HOST_TYPE htype;
							short int dotsCount;

							htype = host_type(si->host, &dotsCount);

							if ((htype == htIPv4) || (htype == htHostname)) {

								if (!str_match_wild_nocase(host, crypt_userhost(si->host, htype, dotsCount)))
									continue;
							}
							else {

								 if (!str_match_wild_nocase(host, si->host))
									continue;
							}
						}
					}
				}

				if (*nick && !str_match_wild_nocase(nick, si->nick))
					continue;

				if (*username && !str_match_wild_nocase(username, si->username))
					continue;

				/* Skip entries whose nick matches 'strNick'. */
				if (IS_NOT_NULL(strNick) && (wantNick != str_match_wild_nocase(strNick, si->nick)))
					continue;

				/* Skip entries whose username matches 'strUsername'. */
				if (IS_NOT_NULL(strUsername) && (wantUsername != str_match_wild_nocase(strUsername, si->username)))
					continue;

				/* Skip entries whose host matches 'strHost'. */
				if (IS_NOT_NULL(strHost) && (wantHost != str_match_wild_nocase(strHost, si->host)))
					continue;

				if (IS_NOT_NULL(strQuit) && (IS_NULL(si->quitmsg) ||
					(wantQuit != str_match_wild_nocase(strQuit, si->quitmsg))))
					continue;

				if (IS_NOT_NULL(strRealname) && (wantRealname != str_match_wild_nocase(strRealname, si->realname)))
					continue;

				/* Only add it if it's newer, or if we're below the limit. */
				if ((si->last_seen > lowest_TS) || (count < max_hits))
					lowest_TS = match_insert(matches, si, max_hits);

				++count;
			}
		}

		TRACE_MAIN();

		if (count == 0)
			send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEEN_REPLY_NOMATCH);

		else {

			User	*user;
			char	reply[IRCBUFSIZE];
			size_t	len;


			TRACE_MAIN();

			if (count > max_hits)
				snprintf(reply, sizeof(reply), lang_msg(GetCallerLang(), SS_SEEN_REPLY_MANY), count, max_hits);

			else if (count == 1)
				snprintf(reply, sizeof(reply), lang_msg(GetCallerLang(), SS_SEEN_REPLY_ONE));

			else
				snprintf(reply, sizeof(reply), lang_msg(GetCallerLang(), SS_SEEN_REPLY_SOME), count);

			len = str_len(reply);

			TRACE_MAIN();
			for (matchIdx = 0; (matchIdx < max_hits) && (matchIdx < count); ++matchIdx) {

				TRACE_MAIN();
				if (matchIdx > 0) {

					*(reply + len++) = c_COMMA;
					*(reply + len++) = c_SPACE;
				}

				len += str_copy_checked(matches[matchIdx]->nick, (reply + len), (sizeof(reply) - len));
			}

			*(reply + len++) = c_DOT;
			*(reply + len) = c_NULL;

			TRACE_MAIN();
			send_notice_to_user(s_SeenServ, callerUser, reply);

			if (!isOper && IS_NOT_NULL(user = hash_onlineuser_find(matches[0]->nick))) {

				send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), REPLY_NICK_IS_ONLINE, user->nick, user->nick);
				goto done;
			}

			TRACE_MAIN();

			send_seen_info(matches[0], callerUser);
		}

		goto done;
	}

error:
	if (!isOper)
		send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEEN_SYNTAX_ERROR);
	else
		send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), SS_SEEN_SYNTAX_ERROR_OPER);

	send_notice_lang_to_user(s_SeenServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_SS, "SEEN");

done:
	if (strQuit)
		mem_free(strQuit);
	if (strNick)
		mem_free(strNick);
	if (strRealname)
		mem_free(strRealname);
	if (strUsername)
		mem_free(strUsername);
	if (strHost)
		mem_free(strHost);
}


/*********************************************************
 * DebugServ dump support                                *
 *********************************************************/

void seenserv_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	/*
	DS DUMP SEENSERV HELP
	DS DUMP SEENSERV NICK nickname
	DS DUMP SEENSERV HASHTABLE index start end
	DS DUMP SEENSERV POOLSTAT
	*/

	STR			command;
	BOOL		needSyntax = FALSE;


	if (IS_NULL(command = strtok(request, s_SPACE)))
		needSyntax = TRUE;

	else if (str_equals_nocase(command, "NICK")) {

		SeenInfo	*si;
		char		*nick;

		if (IS_NOT_NULL(nick = strtok(NULL, s_SPACE))) {

			if (IS_NOT_NULL(si = hash_seeninfo_find(nick))) {

				send_notice_to_user(sourceNick, callerUser, "DUMP: Seen record for \2%s\2:", nick);

				send_notice_to_user(sourceNick, callerUser, "Address 0x%08X, size %d B",						(unsigned long)si, sizeof(SeenInfo) + str_len(si->nick) + str_len(si->username) + str_len(si->host) + str_len(si->realname) + str_len(si->tempnick) + str_len(si->quitmsg) + 6);
				send_notice_to_user(sourceNick, callerUser, "Name: 0x%08X \2[\2%s\2]\2",						(unsigned long)si->nick, str_get_valid_display_value(si->nick));
				send_notice_to_user(sourceNick, callerUser, "Username: 0x%08X \2[\2%s\2]\2",					(unsigned long)si->username, str_get_valid_display_value(si->username));
				send_notice_to_user(sourceNick, callerUser, "Realname: 0x%08X \2[\2%s\2]\2",					(unsigned long)si->realname, str_get_valid_display_value(si->realname));
				send_notice_to_user(sourceNick, callerUser, "Host: 0x%08X \2[\2%s\2]\2",						(unsigned long)si->host, str_get_valid_display_value(si->host));

				#ifdef ENABLE_CAPAB_NICKIP
				send_notice_to_user(sourceNick, callerUser, "IP from NICKIP: 0x%08X \2[\2%lu\2]\2",				si->ip, si->ip);
				#endif

				send_notice_to_user(sourceNick, callerUser, "User Modes: %d",									si->mode);
				send_notice_to_user(sourceNick, callerUser, "Type: %d",											(int)si->type);
				send_notice_to_user(sourceNick, callerUser, "Temp Nick: 0x%08X \2[\2%s\2]\2",					(unsigned long)si->tempnick, str_get_valid_display_value(si->tempnick));
				send_notice_to_user(sourceNick, callerUser, "Quit Message: 0x%08X \2[\2%s\2]\2",				(unsigned long)si->quitmsg, str_get_valid_display_value(si->quitmsg));
				send_notice_to_user(sourceNick, callerUser, "Last seen C-time: %d",								si->last_seen);
				send_notice_to_user(sourceNick, callerUser, "Next / previous record: 0x%08X / 0x%08X",			(unsigned long)si->next, (unsigned long)si->prev);

				LOG_DEBUG_SNOOP("Command: DUMP SEENSERV NICK %s -- by %s (%s@%s)", nick, callerUser->nick, callerUser->username, callerUser->host);
			}
			else
				send_notice_to_user(sourceNick, callerUser, "DUMP: Seen record for \2%s\2 not found.", nick);
		}
		else
			needSyntax = TRUE;
	}
	else if (str_equals_nocase(command, "HASHTABLE")) {

		long int	hashIdx = -1, startIdx = 0, endIdx = 50, idx;
		char		*ptr;
		SeenInfo	*si;


		if (IS_NOT_NULL(ptr = strtok(NULL, s_SPACE))) {

			char *err;
			long int value;

			value = strtol(ptr, &err, 10);

			if ((value >= 0) && (value < SEENINFO_HASHSIZE) && (*err == '\0')) {

				hashIdx = value;

				if (IS_NOT_NULL(ptr = strtok(NULL, " "))) {

					value = strtol(ptr, &err, 10);

					if ((value >= 0) && (*err == '\0')) {

						startIdx = value;

						if (IS_NOT_NULL(ptr = strtok(NULL, " "))) {

							value = strtol(ptr, &err, 10);

							if ((value >= 0) && (*err == '\0'))
								endIdx = value;
						}
					}
				}
			}
		}

		if (hashIdx >= 0) {

			if (endIdx < startIdx)
				endIdx = (startIdx + 50);

			for (idx = 0, si = hashtable_seeninfo[hashIdx]; IS_NOT_NULL(si) && (idx <= endIdx); ++idx, si = si->next) {

				if (idx >= startIdx)
					send_notice_to_user(sourceNick, callerUser, "%05d) ADR\2 0x%08X\2 - NXT\2 0x%08X\2 - PRV\2 0x%08X\2 - KEY \2%s\2", idx, (unsigned long)si, (unsigned long)si->next, (unsigned long)si->prev, str_get_valid_display_value(si->nick));
			}

			LOG_DEBUG_SNOOP("Command: DUMP SEENSERV HASHTABLE %d %d %d -- by %s (%s@%s)", hashIdx, startIdx, endIdx, callerUser->nick, callerUser->username, callerUser->host);
		}
		else
			needSyntax = TRUE;
	}

	#ifdef FIX_USE_MPOOL
	else if (str_equals_nocase(command, "POOLSTAT")) {

		MemoryPoolStats pstats;

		mempool_stats(seen_nickseen_mempool, &pstats);
		send_notice_to_user(sourceNick, callerUser, "DUMP: SeenServ nickseen memory pool - Address 0x%08X, ID: %d",	(unsigned long)seen_nickseen_mempool, pstats.id);
		send_notice_to_user(sourceNick, callerUser, "Memory allocated / free: %d B / %d B",				pstats.memory_allocated, pstats.memory_free);
		send_notice_to_user(sourceNick, callerUser, "Items allocated / free: %d / %d",					pstats.items_allocated, pstats.items_free);
		send_notice_to_user(sourceNick, callerUser, "Items per block / block count: %d / %d",			pstats.items_per_block, pstats.block_count);
		//send_notice_to_user(sourceNick, callerUser, "Average use: %.2f%%",							pstats.block_avg_usage);

		LOG_DEBUG_SNOOP("Command: DUMP SEENSERV POOLSTAT -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
	}
	#endif
	else
		needSyntax = TRUE;

	if (needSyntax) {

		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 SEENSERV NICK nickname");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 SEENSERV HASHTABLE index [start [end]]");
		#ifdef FIX_USE_MPOOL
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 SEENSERV POOLSTAT");
		#endif
	}
}


/*********************************************************
 * DebugServ memory support                              *
 *********************************************************/

unsigned long seenserv_mem_report(CSTR sourceNick, const User *callerUser) {

	SeenInfo			*si;
	unsigned long int	count = 0, mem = 0, mem_total;
	int					hashIdx;


	TRACE_FCLT(FACILITY_SEENSERV_MEM_REPORT);

	send_notice_to_user(sourceNick, callerUser, "\2SEENSERV\2:");

	HASH_FOREACH_BRANCH(hashIdx, SEENINFO_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM(seeninfo, hashIdx, si) {

			++count;
			mem += sizeof(SeenInfo);

			TRACE();

			if (IS_NOT_NULL(si->nick))
				mem += str_len(si->nick) + 1;

			if (IS_NOT_NULL(si->username))
				mem += str_len(si->username) + 1;

			if (IS_NOT_NULL(si->host))
				mem += str_len(si->host) + 1;

			if (IS_NOT_NULL(si->realname))
				mem += str_len(si->realname) + 1;

			if (IS_NOT_NULL(si->tempnick))
				mem += str_len(si->tempnick) + 1;

			if (IS_NOT_NULL(si->quitmsg))
				mem += str_len(si->quitmsg) + 1;
		}
	}

	TRACE();
	mem_total = mem;

	send_notice_to_user(sourceNick, callerUser, "Seen records: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", count, mem / 1024, mem);

	return mem_total;
}

