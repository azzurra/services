/*
*
* Azzurra IRC Services
*
* akill.c - Gestione AutoKills
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
#include "../inc/conf.h"
#include "../inc/misc.h"
#include "../inc/main.h"
#include "../inc/users.h"
#include "../inc/akill.h"
#include "../inc/storage.h"
#include "../inc/list.h"

#ifdef USE_SOCKSMONITOR
#include "../inc/cybcop.h"
#endif


#if defined(USE_SERVICES) || defined(USE_SOCKSMONITOR)

static AutoKill *AutoKillList;
BOOL AutoKillListLoadComplete;


BOOL akill_db_save(void) {

	STGHANDLE		stg;
	STG_RESULT		result;
	AutoKill		*akill;
	char			*strings[5];
	int				error_index;


	TRACE_FCLT(FACILITY_AKILL_DB_SAVE);

	result = stg_create(AKILL_DB, SF_NOFLAGS, AKILL_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_AKILL_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"akill_db_save(): Could not create database file %s: %s [Error %d: %s]", AKILL_DB, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	result = stg_start_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_AKILL_DB_SAVE, __LINE__, "Write error on %s - %s", AKILL_DB, stg_result_to_string(result));

	akill = AutoKillList;

	while (IS_NOT_NULL(akill)) {

		result = stg_write_record(stg, (PBYTE)akill, sizeof(AutoKill));

		if (result != stgSuccess)
			fatal_error(FACILITY_AKILL_DB_SAVE, __LINE__, "Write error on %s - %s", AKILL_DB, stg_result_to_string(result));

		strings[0] = akill->username;
		strings[1] = akill->host;
		strings[2] = akill->reason;
		strings[3] = akill->desc;
		strings[4] = akill->creator.name;

		error_index = -1;

		result = stg_write_strings(stg, strings, sizeof(strings) / sizeof(char*), &error_index);

		if (result != stgSuccess)
			fatal_error(FACILITY_AKILL_DB_SAVE, __LINE__, "Write error on %s for string n. %d - %s", AKILL_DB, error_index, stg_result_to_string(result));

		akill = akill->next;
	}

	result = stg_end_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_AKILL_DB_SAVE, __LINE__, "Write error on %s - %s", AKILL_DB, stg_result_to_string(result));

	stg_close(stg, AKILL_DB);
	return TRUE;
}

/*********************************************************/

BOOL akill_db_load(void) {

	STGHANDLE	stg = 0;
	STG_RESULT	result;


	TRACE_FCLT(FACILITY_AKILL_DB_LOAD);

	result = stg_open(AKILL_DB, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version;
			BOOL		in_section;
			BOOL		read_done;


			version = stg_data_version(stg);

			switch (version) {

				case AKILL_DB_CURRENT_VERSION: {

					AutoKill_V10 *akill;

					// start-of-section marker
					result = stg_read_record(stg, NULL, 0);

					if (result == stgBeginOfSection) {

						in_section = TRUE;

						while (in_section) {

							akill = mem_malloc(sizeof(AutoKill_V10));

							result = stg_read_record(stg, (PBYTE)akill, sizeof(AutoKill_V10));

							switch (result) {

								case stgEndOfSection: // end-of-section
									in_section = FALSE;
									mem_free(akill);
									break;

								case stgSuccess: // a valid record

									read_done = TRUE;

									if (akill->username)
										read_done &= (result = stg_read_string(stg, &(akill->username), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(akill->host))
										read_done &= (result = stg_read_string(stg, &(akill->host), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(akill->reason))
										read_done &= (result = stg_read_string(stg, &(akill->reason), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(akill->desc))
										read_done &= (result = stg_read_string(stg, &(akill->desc), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(akill->creator.name))
										read_done &= (result = stg_read_string(stg, &(akill->creator.name), NULL)) == stgSuccess;

									if (!read_done)
										fatal_error(FACILITY_AKILL_DB_LOAD, __LINE__, "Read error on %s (2) - %s", AKILL_DB, stg_result_to_string(result));

									akill->next = AutoKillList;
									akill->prev = NULL;

									if (AutoKillList)
										AutoKillList->prev = akill;

									AutoKillList = akill;
									break;

								default: // some error
									fatal_error(FACILITY_AKILL_DB_LOAD, __LINE__, "Read error on %s - %s", AKILL_DB, stg_result_to_string(result));
							}
						}
					}
					else
						fatal_error(FACILITY_AKILL_DB_LOAD, __LINE__, "Read error on %s : invalid format", AKILL_DB);

					stg_close(stg, AKILL_DB);
					return TRUE;
				}

				default:
					fatal_error(FACILITY_AKILL_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, AKILL_DB);
			}
		}

		case stgNotFound: // no data to load
			return TRUE;

		default: // error!
			stg_close(stg, AKILL_DB);

			fatal_error(FACILITY_AKILL_DB_LOAD, __LINE__, "Error opening %s - %s", AKILL_DB, stg_result_to_string(result));
			return FALSE;
	}
}

/*********************************************************/

static char *get_akill_type_short(flags_t type) {

	static char buffer[33];
	char *ptr = buffer;

	memset(buffer, 0, sizeof(buffer));

	if (FlagSet(type, AKILL_TYPE_BY_APM))
		*ptr++ = 'A';

	if (FlagSet(type, AKILL_TYPE_BY_DNSBL))
		*ptr++ = 'D';

	if (FlagSet(type, AKILL_TYPE_MANUAL))
		*ptr++ = 'M';

	if (FlagSet(type, AKILL_TYPE_FLOODER))
		*ptr++ = 'F';

	if (FlagSet(type, AKILL_TYPE_SOCKS4) || FlagSet(type, AKILL_TYPE_SOCKS5))
		*ptr++ = 'S';

	if (FlagSet(type, AKILL_TYPE_PROXY))
		*ptr++ = 'X';

	if (FlagSet(type, AKILL_TYPE_CLONES))
		*ptr++ = 'C';

	if (FlagSet(type, AKILL_TYPE_IDENT))
		*ptr++ = 'I';

	if (FlagSet(type, AKILL_TYPE_BOTTLER))
		*ptr++ = 'B';

	if (FlagSet(type, AKILL_TYPE_TROJAN))
		*ptr++ = 'J';

	if (FlagSet(type, AKILL_TYPE_MIRCWORM))
		*ptr++ = 'W';

	if (FlagSet(type, AKILL_TYPE_TEMPORARY))
		*ptr++ = 'T';

	if (FlagSet(type, AKILL_TYPE_PERMANENT))
		*ptr++ = 'P';

	/* Something's wrong... */
	if (ptr == buffer)
		*ptr++ = 'M';

	*ptr = 0;

	return buffer;
}

/*********************************************************/

static char *get_akill_type_long(flags_t type) {

	static char buffer[IRCBUFSIZE];
	size_t		len = 0;


	APPEND_FLAG(type, AKILL_TYPE_WINGATE, "Wingate")
	APPEND_FLAG(type, AKILL_TYPE_FLOODER, "Flooder")
	APPEND_FLAG(type, AKILL_TYPE_BOTTLER, "Bottler")
	APPEND_FLAG(type, AKILL_TYPE_IDENT, "Ident")
	APPEND_FLAG(type, AKILL_TYPE_TROJAN, "Trojan")
	APPEND_FLAG(type, AKILL_TYPE_MIRCWORM, "mIRC Worm")
	APPEND_FLAG(type, AKILL_TYPE_CLONES, "Clones")
	APPEND_FLAG(type, AKILL_TYPE_SOCKS4, "Socks 4")
	APPEND_FLAG(type, AKILL_TYPE_SOCKS5, "Socks 5")
	APPEND_FLAG(type, AKILL_TYPE_PROXY80, "Proxy (80)")
	APPEND_FLAG(type, AKILL_TYPE_PROXY3128, "Proxy (3128)")
	APPEND_FLAG(type, AKILL_TYPE_PROXY6588, "Proxy (6588)")
	APPEND_FLAG(type, AKILL_TYPE_PROXY3128, "Proxy (8080)")
	APPEND_FLAG(type, AKILL_TYPE_PROXY3128, "Proxy")
	APPEND_FLAG(type, AKILL_TYPE_MANUAL, "Manual")
	APPEND_FLAG(type, AKILL_TYPE_BY_APM, "By APM")
	APPEND_FLAG(type, AKILL_TYPE_BY_DNSBL, "By DNSBL")

	if (len == 0)
		return "Error";

	return buffer;
}


/*********************************************************/

static void akill_delete(AutoKill *akill) {

	if (akill->next)
		akill->next->prev = akill->prev;

	if (akill->prev)
		akill->prev->next = akill->next;
	else
		AutoKillList = akill->next;

	mem_free(akill->username);
	mem_free(akill->host);
	mem_free(akill->reason);

	if (akill->desc)
		mem_free(akill->desc);

	str_creator_free(&(akill->creator));

	mem_free(akill);
}

/*********************************************************/

/* Does the user match any AKILLs? */
BOOL akill_match(CSTR nick, CSTR username, CSTR host, unsigned long ip) {

	AutoKill *akill = AutoKillList;


	TRACE_FCLT(FACILITY_AKILL_MATCH);

	while (IS_NOT_NULL(akill)) {

		TRACE();
		if (FlagUnset(akill->type, AKILL_TYPE_DISABLED) && str_match_wild_nocase(akill->username, username) &&
			((FlagSet(akill->type, AKILL_TYPE_WITHCIDR) && (ip != 0)) ?
			cidr_match(&(akill->cidr), ip) : str_match_wild_nocase(akill->host, host))) {

			TRACE();
			send_AKILL(akill->username, akill->host, akill->creator.name, akill->reason, akill->id, get_akill_type_short(akill->type));

			TRACE();
			akill->lastUsed = NOW;
			return TRUE;
		}

		akill = akill->next;
	}

	return FALSE;
}

/*********************************************************/

/* Delete any expired autokills. */
void akill_expire() {

	AutoKill *akill, *next;


	TRACE_FCLT(FACILITY_AKILL_EXPIRE);

	if (CONF_SET_NOEXPIRE)
		return;

	akill = AutoKillList;

	while (IS_NOT_NULL(akill)) {

		if ((akill->expireTime != 0) && (akill->expireTime < NOW)) {

			next = akill->next;

			send_RAKILL(akill->username, akill->host);

			akill_delete(akill);

			akill = next;
		}
		else
			akill = akill->next;
	}
}

/*********************************************************/

BOOL is_already_akilled(CSTR username, CSTR host, const time_t expireTime, CSTR agent, const User *callerUser) {

	AutoKill *akill = AutoKillList;


	TRACE_FCLT(FACILITY_AKILL_IS_ALREADY_AKILLED);

	while (IS_NOT_NULL(akill)) {

		if (str_equals_nocase(username, akill->username) && str_equals_nocase(host, akill->host)) {

			if ((expireTime == 0) || (akill->expireTime >= (NOW + expireTime)) || (akill->expireTime == 0)) {

				if (agent && callerUser)
					send_notice_to_user(agent, callerUser, "\2%s@%s\2 already exists on the AKILL list.", username, host);
			}
			else {

				if (agent && callerUser)
					send_notice_to_user(agent, callerUser, "Expiry time of \2%s@%s\2 changed.", username, host);

				akill->expireTime = NOW + expireTime;
			}

			return TRUE;
		}

		akill = akill->next;
	}

	return FALSE;
}

/*********************************************************/

void akill_add(CSTR source, CSTR username, CSTR host, CSTR reason, const BOOL manual, const BOOL withCIDR, CIDR_IP *cidr,
			   const unsigned int type, const unsigned int expireTime, const unsigned long int akillID, const LANG_ID lang) {

	AutoKill *akill;


	/* Allocate it. */
	akill = (AutoKill *) mem_calloc(1, sizeof(AutoKill));

	/* Link it. */
	akill->next = AutoKillList;
	akill->prev = NULL;

	if (AutoKillList)
		AutoKillList->prev = akill;

	AutoKillList = akill;

	/* Fill it. */
	str_creator_set(&(akill->creator), source, NOW);
	akill->lastUsed = NOW;

	akill->username = str_duplicate(username);
	akill->host = str_duplicate(host);

	if (withCIDR == TRUE) {

		AddFlag(akill->type, AKILL_TYPE_WITHCIDR);
		akill->cidr = *cidr;
	}

	if (manual == TRUE)
		AddFlag(akill->type, AKILL_TYPE_MANUAL);

	if (expireTime == 0) {

		akill->expireTime = 0;
		AddFlag(akill->type, AKILL_TYPE_PERMANENT);
	}
	else {

		akill->expireTime = (NOW + expireTime);
		AddFlag(akill->type, AKILL_TYPE_TEMPORARY);
	}

	#ifdef USE_SOCKSMONITOR
	if (akillID == 0) {
	#endif

		srand(randomseed());
		akill->id = (unsigned long)getrandom(1934374832UL, 3974848322UL);

		switch (type) {

			#ifdef USE_SOCKSMONITOR
			case AKILL_TYPE_PROXY:
				AddFlag(akill->type, AKILL_TYPE_PROXY);

				if (IS_NOT_NULL(reason)) {

					snprintf(misc_buffer, MISC_BUFFER_SIZE, lang_msg(lang, PROXY_AKILL_REASON_SPECIFIC), atoi(reason));
					akill->reason = str_duplicate(misc_buffer);
				}
				else
					akill->reason = str_duplicate(lang_msg(lang, PROXY_AKILL_REASON_GENERAL));

				break;

			case AKILL_TYPE_SOCKS4:
				AddFlag(akill->type, AKILL_TYPE_SOCKS4);

				snprintf(misc_buffer, MISC_BUFFER_SIZE, lang_msg(lang, SOCKS_AKILL_REASON), 4);
				akill->reason = str_duplicate(misc_buffer);
				break;

			case AKILL_TYPE_SOCKS5:
				AddFlag(akill->type, AKILL_TYPE_SOCKS5);

				snprintf(misc_buffer, MISC_BUFFER_SIZE, lang_msg(lang, SOCKS_AKILL_REASON), 5);
				akill->reason = str_duplicate(misc_buffer);
				break;

			case AKILL_TYPE_WINGATE:
				AddFlag(akill->type, AKILL_TYPE_WINGATE);
				akill->reason = str_duplicate(lang_msg(lang, WINGATE_AKILL_REASON));
				break;

			case AKILL_TYPE_FLOODER:
				AddFlag(akill->type, AKILL_TYPE_FLOODER);
				akill->reason = str_duplicate(lang_msg(lang, FLOODER_AKILL_REASON));
				break;

			case AKILL_TYPE_BOTTLER:
				AddFlag(akill->type, AKILL_TYPE_BOTTLER);
				akill->reason = str_duplicate(lang_msg(lang, BOTTLER_AKILL_REASON));
				break;

			case AKILL_TYPE_TROJAN:
				AddFlag(akill->type, AKILL_TYPE_TROJAN);
				akill->reason = str_duplicate(lang_msg(lang, TROJAN_AKILL_REASON));
				break;

			case AKILL_TYPE_MIRCWORM:
				AddFlag(akill->type, AKILL_TYPE_MIRCWORM);
				akill->reason = str_duplicate(lang_msg(lang, MIRCWORM_AKILL_REASON));
				break;

			case AKILL_TYPE_IDENT:
				AddFlag(akill->type, AKILL_TYPE_IDENT);
				akill->reason = str_duplicate(lang_msg(lang, IDENT_AKILL_REASON));
				break;
			#endif

			#ifdef USE_SERVICES
			case AKILL_TYPE_RESERVED:
				AddFlag(akill->type, AKILL_TYPE_RESERVED);
				akill->reason = str_duplicate(lang_msg(lang, RESERVED_AKILL_REASON));
				break;

			case AKILL_TYPE_CLONES:
				AddFlag(akill->type, AKILL_TYPE_CLONES);

				snprintf(misc_buffer, MISC_BUFFER_SIZE, lang_msg(lang, CLONES_AKILL_REASON), (CONF_DEFAULT_CLONEKILL_EXPIRY / 60));
				akill->reason = str_duplicate(misc_buffer);
				break;
			#endif

			default:
				#ifdef USE_SOCKSMONITOR
				akill->reason = str_duplicate(lang_msg(lang, PROXY_AKILL_REASON_GENERAL));
				#else
				akill->reason = str_duplicate(reason);
				#endif

				break;
		}
	#ifdef USE_SOCKSMONITOR
	}
	else {

		akill->id = akillID;

		AddFlag(akill->type, AKILL_TYPE_BY_APM);
		AddFlag(akill->type, type);

		/* 'reason' holds the port number here. */
		if (IS_NOT_NULL(reason)) {

			snprintf(misc_buffer, MISC_BUFFER_SIZE, lang_msg(lang, PROXY_AKILL_REASON_SPECIFIC), atoi(reason));
			akill->reason = str_duplicate(misc_buffer);
		}
		else {

			AddFlag(akill->type, AKILL_TYPE_BY_DNSBL);
			akill->reason = str_duplicate(lang_msg(lang, PROXY_AKILL_REASON_GENERAL));
		}
	}
	#endif

	/* Send it. */
	send_AKILL(username, host, source, akill->reason, akill->id, get_akill_type_short(akill->type));
}

/*********************************************************/

void akill_remove(CSTR username, CSTR host) {

	AutoKill *akill = AutoKillList;

	send_RAKILL(username, host);

	while (IS_NOT_NULL(akill)) {

		if ((akill->expireTime > 0) && str_equals_nocase(akill->username, username)
			&& str_equals_nocase(akill->host, host)) {

			akill_delete(akill);
			return;
		}

		akill = akill->next;
	}
}

/*********************************************************/

/* AKILL list modification. */
void handle_akill(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *command;


	TRACE_MAIN_FCLT(FACILITY_AKILL_HANDLE_AKILL);

	if (IS_NULL(command = strtok(NULL, " "))) {

		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2AKILL\2 [ADD|DEL|ID|LIST|PERM|TIME] [time] mask reason");
		send_notice_to_user(data->agent->nick, callerUser, "Type \2/%s OHELP AKILL\2 for more information.", data->agent->shortNick);
	}
	else if (str_equals_nocase(command, "LIST")) {

		AutoKill	*akill;
		int			startIdx = 0, endIdx = 30, akillIdx = 0, sentIdx = 0, type = AKILL_TYPE_NONE;
		char		username[IRCBUFSIZE], host[IRCBUFSIZE], *pattern, *ptr;
		char 		timebuf[64], expirebuf[64];


		if (IS_NOT_NULL(pattern = strtok(NULL, " "))) {

			char *err;
			long int value;

			value = strtol(pattern, &err, 10);

			if ((value >= 0) && (*err == '\0')) {

				startIdx = value;

				if (IS_NOT_NULL(pattern = strtok(NULL, " "))) {

					value = strtol(pattern, &err, 10);

					if ((value >= 0) && (*err == '\0')) {

						endIdx = value;

						pattern = strtok(NULL, " ");
					}
				}
			}

			if (IS_NOT_NULL(pattern)) {

				if (str_equals_nocase(pattern, "MANUAL"))
					type = AKILL_TYPE_MANUAL;

				else if (str_equals_nocase(pattern, "PERM"))
					type = AKILL_TYPE_PERMANENT;

				else if (str_equals_nocase(pattern, "TEMP"))
					type = AKILL_TYPE_TEMPORARY;

#ifdef USE_SERVICES
				else if (str_equals_nocase(pattern, "RESERVED"))
					type = AKILL_TYPE_RESERVED;

				else if (str_equals_nocase(pattern, "CLONES"))
					type = AKILL_TYPE_CLONES;
#endif

#ifdef USE_SOCKSMONITOR
				else if (str_equals_nocase(pattern, "TROJAN"))
					type = AKILL_TYPE_TROJAN;

				else if (str_equals_nocase(pattern, "MIRCWORM"))
					type = AKILL_TYPE_MIRCWORM;

				else if (str_equals_nocase(pattern, "IDENT"))
					type = AKILL_TYPE_IDENT;

				else if (str_equals_nocase(pattern, "BOTTLER"))
					type = AKILL_TYPE_BOTTLER;

				else if (str_equals_nocase(pattern, "SOCKS4"))
					type = AKILL_TYPE_SOCKS4;

				else if (str_equals_nocase(pattern, "SOCKS5"))
					type = AKILL_TYPE_SOCKS5;

				else if (str_equals_nocase(pattern, "SOCKS"))
					type = (AKILL_TYPE_SOCKS4 | AKILL_TYPE_SOCKS5);

				else if (str_equals_nocase(pattern, "FLOODER"))
					type = AKILL_TYPE_FLOODER;

				else if (str_equals_nocase(pattern, "PROXY"))
					type = AKILL_TYPE_PROXY;
#endif

				else {

					/* user@host mask... hopefully. */

					memset(host, 0, sizeof(host));

					ptr = str_tokenize(pattern, username, sizeof(username), c_AT);

					if (IS_NOT_NULL(ptr))
						ptr = str_tokenize(ptr, host, sizeof(host), c_NULL);

					if (IS_EMPTY_STR(username) || IS_EMPTY_STR(host) ||
						(str_len(username) > USERSIZE) || (str_len(host) > HOSTSIZE) ||
						!validate_username(username, TRUE) || !validate_host(host, TRUE, FALSE, FALSE)) {

						send_notice_to_user(data->agent->nick, callerUser, "Pattern must be in \2user@host\2 format.");
						return;
					}
				}

				/* Clear 'pattern' if it is not a mask. */
				if (type != AKILL_TYPE_NONE)
					pattern = NULL;
			}
		}

		if (endIdx < startIdx)
			endIdx = (startIdx + 30);

		if (IS_NULL(pattern))
			send_notice_to_user(data->agent->nick, callerUser, "Current \2AutoKill\2 List (showing entries %d-%d):", startIdx, endIdx);
		else
			send_notice_to_user(data->agent->nick, callerUser, "Current \2AutoKill\2 List (showing entries %d-%d matching %s@%s):", startIdx, endIdx, username, host);

		akill = AutoKillList;

		while (IS_NOT_NULL(akill)) {

			++akillIdx;

			if (((type != AKILL_TYPE_NONE) && FlagUnset(akill->type, type)) ||
				(IS_NOT_NULL(pattern) && (!str_match_wild_nocase(host, akill->host)
				|| !str_match_wild_nocase(username, akill->username)))) {

				/* Doesn't match our search criteria, skip it. */
				akill = akill->next;
				continue;
			}

			++sentIdx;

			if (sentIdx < startIdx) {

				akill = akill->next;
				continue;
			}

			lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, akill->creator.time);
			expire_left(expirebuf, sizeof(expirebuf), akill->expireTime);

			send_notice_to_user(data->agent->nick, callerUser, "%d) %lu-%s - \2%s@%s\2 [Type: %s]", akillIdx, akill->id, get_akill_type_short(akill->type), akill->username, akill->host, get_akill_type_long(akill->type));
			send_notice_to_user(data->agent->nick, callerUser, "Reason: %s", akill->reason);

			if (IS_NOT_NULL(akill->desc))
				send_notice_to_user(data->agent->nick, callerUser, "Description: %s", akill->desc);

			send_notice_to_user(data->agent->nick, callerUser, "Set by %s on %s; %s", akill->creator.name, timebuf, expirebuf);

			convert_time(timebuf, sizeof(timebuf), (NOW - akill->lastUsed), LANG_DEFAULT);
			send_notice_to_user(data->agent->nick, callerUser, "Last used %s ago.", timebuf);

			if (sentIdx >= endIdx)
				break;

			akill = akill->next;
		}

		send_notice_to_user(data->agent->nick, callerUser, "*** \2End of List\2 ***");
	}
	else if (str_equals_nocase(command, "ID")) {

		char *idName;
		char *type;
		unsigned long int id;


		if (IS_NOT_NULL(idName = strtok(NULL, " ")) && IS_NOT_NULL(type = strchr(idName, '-'))) {

			if (str_len(idName) > (size_t)(type - idName + 1)) {

				*type++ = 0;

				id = strtoul(idName, NULL, 10);

				if (id > 0) {

					AutoKill *akill = AutoKillList;

					while (IS_NOT_NULL(akill)) {

						if (akill->id == id) {

							char timebuf[64];

							lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, akill->creator.time);

							send_notice_to_user(data->agent->nick, callerUser, "AKill ID %s-%s: %s@%s", idName, get_akill_type_short(akill->type), akill->username, akill->host);
							send_notice_to_user(data->agent->nick, callerUser, "Set by \2%s\2: %s", akill->creator.name, IS_NOT_NULL(akill->reason) ? akill->reason : "<No reason given>");

							if (IS_NOT_NULL(akill->desc))
								send_notice_to_user(data->agent->nick, callerUser, "Description: %s", akill->desc);

							send_notice_to_user(data->agent->nick, callerUser, "Set on %s - \2%s\2", timebuf, akill->expireTime == 0 ? "Permanent" : "Temporary");

							convert_time(timebuf, sizeof(timebuf), (NOW - akill->lastUsed), LANG_DEFAULT);
							send_notice_to_user(data->agent->nick, callerUser, "Last used %s ago.", timebuf);

							if (akill->expireTime != 0)
								send_notice_to_user(data->agent->nick, callerUser, "Expires in %s", convert_time(timebuf, sizeof(timebuf), (akill->expireTime - NOW), LANG_DEFAULT));

							return;
						}

						akill = akill->next;
					}

					send_notice_to_user(data->agent->nick, callerUser, "AKill ID %s-%s not found.", idName, type);
				}
				else
					send_notice_to_user(data->agent->nick, callerUser, "Invalid ID supplied: %s", idName);
			}
		}
		else {

			send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2AKILL ID\2 id");
			send_notice_to_user(data->agent->nick, callerUser, "Type \2/%s OHELP AKILL\2 for more information.", data->agent->shortNick);
		}
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SOP))
		send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), OPER_ERROR_ACCESS_DENIED);

	else if (str_equals_nocase(command, "ADD") || str_equals_nocase(command, "PERM")
		|| str_equals_nocase(command, "TIME") || str_equals_nocase(command, "OVERRIDE")) {

		char			akill_nicks[IRCBUFSIZE];
		char			*expiry = NULL, *username, *host, *reason, *ptr;
		BOOL			too_many_akill_nicks = FALSE, more_nicks = FALSE, have_CIDR = FALSE;
		size_t			user_len, host_len;
		User			*user;
		int				akillIdx, usercount = 0, valid = 0, expireTime = CONF_DEFAULT_AKILL_EXPIRY;
		int				akill_nicks_freespace = 400;
		float			percent;
		CIDR_IP			cidr;

		#ifndef USE_SOCKSMONITOR
		size_t			len;
		#endif


		switch (command[0]) {

			case 'O':
			case 'o':
				valid += 4;
				/* Fall... */

			case 'T':
			case 't':
				expiry = strtok(NULL, " ");
				username = strtok(NULL, "@");
				host = strtok(NULL, " ");

				#ifdef USE_SOCKSMONITOR
				reason = "Proxy";
				#else
				reason = strtok(NULL, "");
				#endif

				if (IS_NULL(expiry) || IS_NULL(username) || IS_NULL(host) || IS_NULL(reason)) {

					send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2AKILL TIME\2 time user@host reason");
					send_notice_to_user(data->agent->nick, callerUser, "Type \2/%s OHELP AKILL\2 for more information.", data->agent->shortNick);
					return;
				}

				expireTime = convert_amount(expiry);

				if (expireTime == -1) {

					send_notice_to_user(data->agent->nick, callerUser, "Invalid expiry time supplied.");
					send_notice_to_user(data->agent->nick, callerUser, "Type \2/%s OHELP AKILL\2 for more information.", data->agent->shortNick);
					return;
				}

				break;

			case 'P':
			case 'p':
				expireTime = 0;
				/* Fall... */

			default:
				username = strtok(NULL, "@");
				host = strtok(NULL, " ");

				#ifdef USE_SOCKSMONITOR
				reason = "Proxy";
				#else
				reason = strtok(NULL, "");
				#endif

				if (IS_NULL(username) || IS_NULL(host) || IS_NULL(reason)) {

					send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2AKILL ADD\2 user@host reason");
					send_notice_to_user(data->agent->nick, callerUser, "Type \2/%s OHELP AKILL\2 for more information.", data->agent->shortNick);
					return;
				}

				break;
		}

		#ifndef USE_SOCKSMONITOR
		if ((len = str_len(reason)) > 220) {

			send_notice_to_user(data->agent->nick, callerUser, "Reason cannot be longer than 220 characters (yours has: %d).", len);
			return;
		}

		if (!validate_string(reason)) {

			send_notice_to_user(data->agent->nick, callerUser, "Invalid reason supplied.");
			return;
		}
		#endif

		if ((user_len = str_len(username)) > USERMAX) {

			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), ERROR_USER_MAX_LENGTH, USERMAX);
			return;
		}

		if ((host_len = str_len(host)) > HOSTMAX) {

			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), ERROR_HOST_MAX_LENGTH, HOSTMAX);
			return;
		}

		if (!validate_username(username, TRUE) || !validate_host(host, TRUE, TRUE, FALSE)) {

			if (data->operMatch)
				LOG_SNOOP(data->agent->nick, "%s +A* %s@%s -- by %s (%s@%s) [Invalid Mask]", data->agent->shortNick, username, host, callerUser->nick, callerUser->username, callerUser->host);
			else
				LOG_SNOOP(data->agent->nick, "%s +A* %s@%s -- by %s (%s@%s) through %s [Invalid Mask]", data->agent->shortNick, username, host, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_notice_to_user(data->agent->nick, callerUser, "Mask must be in \2user\2@\2host\2 format.");
			return;
		}

		str_compact(username);
		str_compact(host);

		/* Skip this if in OVERRIDE. */
		if (valid == 0) {

			unsigned int ptrIdx;

			for (ptrIdx = 0; ptrIdx < user_len; ++ptrIdx) {

				if (!strchr("*?~", host[ptrIdx]))
					++valid;
			}

			for (ptrIdx = 0; ptrIdx < host_len; ++ptrIdx) {

				if (!strchr("*?.-:/", host[ptrIdx]))
					++valid;
			}

			if (valid < 4) {

				if (data->operMatch) {

					send_globops(data->agent->nick, "\2%s\2 tried to AKILL \2%s@%s\2", source, username, host);

					LOG_SNOOP(data->agent->nick, "%s +A* %s@%s -- by %s (%s@%s) [Lamer]", data->agent->shortNick, username, host, callerUser->nick, callerUser->username, callerUser->host);
					log_services(LOG_SERVICES_GENERAL, "+A* %s@%s -- by %s (%s@%s) [Lamer]", username, host, callerUser->nick, callerUser->username, callerUser->host);
				}
				else {

					send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) tried to AKILL \2%s@%s\2", source, data->operName, username, host);

					LOG_SNOOP(data->agent->nick, "%s +A* %s@%s -- by %s (%s@%s) through %s [Lamer]", data->agent->shortNick, username, host, callerUser->nick, callerUser->username, callerUser->host, data->operName);
					log_services(LOG_SERVICES_GENERAL, "+A* %s@%s -- by %s (%s@%s) through %s [Lamer]", username, host, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				}

				send_notice_to_user(data->agent->nick, callerUser, "Hrmmm, what would your admin think of that?");
				return;
			}
		}

		if (is_already_akilled(username, host, expireTime, data->agent->nick, callerUser))
			return;

		memset(akill_nicks, 0, sizeof(akill_nicks));

		ptr = akill_nicks;

		if (cidr_ip_fill(host, &cidr, FALSE) == cidrSuccess)
			have_CIDR = TRUE;

		else if (convert_host_to_cidr(host) == cidrSuccess)
			send_notice_to_user(data->agent->nick, callerUser, "CIDR IP detected, please add it as CIDR for better results.");

		HASH_FOREACH_BRANCH(akillIdx, ONLINEUSER_HASHSIZE) {

			HASH_FOREACH_BRANCH_ITEM(onlineuser, akillIdx, user) {

				if (str_match_wild_nocase(username, user->username) &&
					(have_CIDR ? cidr_match(&cidr, user->ip) : str_match_wild_nocase(host, user->host))) {

					if (user_is_ircop(user) || user_is_services_agent(user) || user_is_services_client(user)) {

						if (data->operMatch) {

							send_globops(data->agent->nick, "\2%s\2 tried to AKILL \2%s\2", source, user->nick);

							LOG_SNOOP(data->agent->nick, "%s +A* %s@%s -- by %s (%s@%s) [Matches %s]", data->agent->shortNick, username, host, callerUser->nick, callerUser->username, callerUser->host, user->nick);
							log_services(LOG_SERVICES_GENERAL, "+A* %s@%s -- by %s (%s@%s) [Matches %s]", username, host, callerUser->nick, callerUser->username, callerUser->host, user->nick);
						}
						else {

							send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) tried to AKILL \2%s\2", source, data->operName, user->nick);

							LOG_SNOOP(data->agent->nick, "%s +A* %s@%s -- by %s (%s@%s) through %s [Matches %s]", data->agent->shortNick, username, host, callerUser->nick, callerUser->username, callerUser->host, data->operName, user->nick);
							log_services(LOG_SERVICES_GENERAL, "+A* %s@%s -- by %s (%s@%s) through %s [Matches %s]", username, host, callerUser->nick, callerUser->username, callerUser->host, data->operName, user->nick);
						}

						send_notice_to_user(data->agent->nick, callerUser, "Permission denied.");
						return;
					}

					++usercount;

					if (!too_many_akill_nicks) {

						if (IS_NOT_EMPTY_STR(akill_nicks)) {

							*ptr++ = c_COMMA;
							*ptr++ = c_SPACE;

							akill_nicks_freespace -= 2;
						}

						for (user_len = 0; user->nick[user_len]; ++user_len) {

							*ptr++ = user->nick[user_len];
							--akill_nicks_freespace;
						}

						*ptr = c_NULL;

						if (akill_nicks_freespace <= 0)
							too_many_akill_nicks = TRUE;
					}
					else
						more_nicks = TRUE;
				}
			}
		}

		percent = ((usercount + .0) * 100.0) / user_online_user_count;

		if (percent > CONF_AKILL_PERCENT) {

			if (data->operMatch) {

				send_globops(data->agent->nick, "\2%s\2 tried to AKILL \2%.3f%s\2 of the network! (Limit: %.3f%s)", source, percent, "%", CONF_AKILL_PERCENT, "%");

				LOG_SNOOP(data->agent->nick, "%s +A* %s@%s -- by %s (%s@%s) [%.3f%s > %.3f%s]", data->agent->shortNick, username, host, callerUser->nick, callerUser->username, callerUser->host, percent, "%", CONF_AKILL_PERCENT, "%");
				log_services(LOG_SERVICES_GENERAL, "+A* %s@%s -- by %s (%s@%s) [%.3f%s > %.3f%s]", username, host, callerUser->nick, callerUser->username, callerUser->host, percent, "%", CONF_AKILL_PERCENT, "%");
			}
			else {

				send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) tried to AKILL \2%.3f%s\2 of the network! (Limit: %.3f%s)", source, data->operName, percent, "%", CONF_AKILL_PERCENT, "%");

				LOG_SNOOP(data->agent->nick, "%s +A* %s@%s -- by %s (%s@%s) through %s [%.3f%s > %.3f%s]", data->agent->shortNick, username, host, callerUser->nick, callerUser->username, callerUser->host, data->operName, percent, "%", CONF_AKILL_PERCENT, "%");
				log_services(LOG_SERVICES_GENERAL, "+A* %s@%s -- by %s (%s@%s) through %s [%.3f%s > %.3f%s]", username, host, callerUser->nick, callerUser->username, callerUser->host, data->operName, percent, "%", CONF_AKILL_PERCENT, "%");
			}

			send_notice_to_user(data->agent->nick, callerUser, "AKILL rejected. Affected users would be greater than %.3f%s", CONF_AKILL_PERCENT, "%");
			return;
		}

		if (more_nicks == TRUE) {

			*ptr++ = c_COMMA;
			*ptr++ = c_SPACE;
			*ptr++ = c_DOT;
			*ptr++ = c_DOT;
			*ptr++ = c_DOT;
			*ptr = c_NULL;
		}

		#ifndef USE_SOCKSMONITOR
		/* Terminate all control codes to avoid crap in globops. */
		terminate_string_ccodes(reason);
		#endif

		if (expireTime == 0) {

			if (data->operMatch)
				send_globops(s_Snooper, "\2%s\2 added a permanent AKILL for \2%s@%s\2 [Reason: %s]",
					source, username, host, reason);
			else
				send_globops(s_Snooper, "\2%s\2 (through \2%s\2) added a permanent AKILL for \2%s@%s\2 [Reason: %s]",
					source, data->operName, username, host, reason);
		}
		else {

			if (expireTime < ONE_MINUTE)
				expireTime = ONE_MINUTE;

			if (data->operMatch)
				send_globops(s_Snooper, "\2%s\2 added an AKILL for \2%s@%s\2 [Reason: %s] [Expires in %s]",
					source, username, host, reason, convert_time(misc_buffer, MISC_BUFFER_SIZE, expireTime, LANG_DEFAULT));
			else
				send_globops(s_Snooper, "\2%s\2 (through \2%s\2) added an AKILL for \2%s@%s\2 [Reason: %s] [Expires in %s]",
					source, data->operName, username, host, reason, convert_time(misc_buffer, MISC_BUFFER_SIZE, expireTime, LANG_DEFAULT));
		}

		if (usercount > 0)
			send_globops(s_Snooper, "Affects \2%d\2 user%s (%.3f%s): %s",
				usercount, (usercount == 1) ? "" : "s", percent, "%", akill_nicks);

		if (data->operMatch) {

			LOG_SNOOP(data->agent->nick, "%s +A %s@%s -- by %s (%s@%s) [Reason: %s]", data->agent->shortNick, username, host, callerUser->nick, callerUser->username, callerUser->host, reason);
			log_services(LOG_SERVICES_GENERAL, "+A %s@%s -- by %s (%s@%s) [Reason: %s]", username, host, callerUser->nick, callerUser->username, callerUser->host, reason);
		}
		else {

			LOG_SNOOP(data->agent->nick, "%s +A %s@%s -- by %s (%s@%s) through %s [Reason: %s]", data->agent->shortNick, username, host, callerUser->nick, callerUser->username, callerUser->host, data->operName, reason);
			log_services(LOG_SERVICES_GENERAL, "+A %s@%s -- by %s (%s@%s) through %s [Reason: %s]", username, host, callerUser->nick, callerUser->username, callerUser->host, data->operName, reason);
		}

		send_notice_to_user(data->agent->nick, callerUser, "\2%s@%s\2 added to AKILL list.", username, host);

		if (CONF_SET_READONLY)
			send_notice_to_user(data->agent->nick, callerUser, "\2Notice:\2 Services is in read-only mode. Changes will not be saved!");

		akill_add(data->operName, username, host, reason, TRUE, have_CIDR, &cidr, AKILL_TYPE_NONE, expireTime, 0, LANG_DEFAULT);
	}
	else if (str_equals_nocase(command, "DEL")) {

		AutoKill *akill;
		char *mask, *err;
		long int akillIdx;


		if (IS_NULL(mask = strtok(NULL, " "))) {

			send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2AKILL DEL\2 mask");
			send_notice_to_user(data->agent->nick, callerUser, "Type \2/%s OHELP AKILL\2 for more information.", data->agent->shortNick);
			return;
		}

		akill = AutoKillList;

		akillIdx = strtol(mask, &err, 10);

		if ((akillIdx > 0) && (*err == '\0')) {

			while (IS_NOT_NULL(akill) && (akillIdx > 1)) {

				akill = akill->next;
				--akillIdx;
			}

			if (IS_NULL(akill)) {

				send_notice_to_user(data->agent->nick, callerUser, "Entry \2%s\2 not found on AKILL list.", mask);
				return;
			}

			send_RAKILL(akill->username, akill->host);
		}
		else {

			char username[IRCBUFSIZE], host[IRCBUFSIZE];
			char *ptr;


			memset(host, 0, sizeof(host));

			ptr = str_tokenize(mask, username, sizeof(username), c_AT);

			if (IS_NOT_NULL(ptr))
				ptr = str_tokenize(ptr, host, sizeof(host), c_NULL);

			if (IS_EMPTY_STR(username) || IS_EMPTY_STR(host) ||
				(str_len(username) > USERMAX) || (str_len(host) > HOSTMAX) ||
				!validate_username(username, TRUE) || !validate_host(host, TRUE, TRUE, FALSE)) {

				send_notice_to_user(data->agent->nick, callerUser, "Mask must be in \2user@host\2 format.");
				return;
			}

			send_RAKILL(username, host);

			while (IS_NOT_NULL(akill)) {

				if (str_equals_nocase(akill->username, username) && str_equals_nocase(akill->host, host))
					break;

				akill = akill->next;
			}

			if (IS_NULL(akill)) {

				send_notice_to_user(data->agent->nick, callerUser, "Mask \2%s\2 not found on AKILL list.", mask);

				if (data->operMatch)
					LOG_SNOOP(data->agent->nick, "%s -A* %s -- by %s (%s@%s) [Not AKilled]", data->agent->shortNick, mask, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(data->agent->nick, "%s -A* %s -- by %s (%s@%s) through %s [Not AKilled]", data->agent->shortNick, mask, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				return;
			}
		}

		if (data->operMatch) {

			send_globops(data->agent->nick, "\2%s\2 removed \2%s@%s\2 from the AKILL list", source, akill->username, akill->host);

			LOG_SNOOP(data->agent->nick, "%s -A %s@%s -- by %s (%s@%s)", data->agent->shortNick, akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_GENERAL, "-A %s@%s -- by %s (%s@%s)", akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host);
		}
		else {

			send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) removed \2%s@%s\2 from the AKILL list", source, data->operName, akill->username, akill->host);

			LOG_SNOOP(data->agent->nick, "%s -A %s@%s -- by %s (%s@%s) through %s", data->agent->shortNick, akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_GENERAL, "-A %s@%s -- by %s (%s@%s) through %s", akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, data->operName);
		}

		send_notice_to_user(data->agent->nick, callerUser, "\2%s@%s\2 removed from AKILL list.", akill->username, akill->host);

		if (CONF_SET_READONLY)
			send_notice_to_user(data->agent->nick, callerUser, "\2Notice:\2 Services is in read-only mode. Changes will not be saved!");

		#ifdef USE_SOCKSMONITOR
		clear_from_cache(akill->host);
		#endif

		akill_delete(akill);
	}
	else if (str_equals_nocase(command, "DESC")) {

		AutoKill *akill;
		char *username, *host, *desc;


		if (IS_NULL(username = strtok(NULL, "@")) || IS_NULL(host = strtok(NULL, " ")) || IS_NULL(desc = strtok(NULL, ""))) {

			send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2AKILL DESC\2 user@host description");
			send_notice_to_user(data->agent->nick, callerUser, "Type \2/%s OHELP AKILL\2 for more information.", data->agent->shortNick);
			return;
		}

		if (!validate_string(desc)) {

			send_notice_to_user(data->agent->nick, callerUser, "Invalid description supplied.");
			return;
		}

		akill = AutoKillList;

		while (IS_NOT_NULL(akill)) {

			if (str_equals_nocase(akill->username, username) && str_equals_nocase(akill->host, host)) {

				terminate_string_ccodes(desc);

				if (IS_NULL(akill->desc)) {

					if (data->operMatch) {

						LOG_SNOOP(data->agent->nick, "%s AD %s@%s -- by %s (%s@%s) [Set to: %s]", data->agent->shortNick, akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, desc);
						log_services(LOG_SERVICES_GENERAL, "AD %s@%s -- by %s (%s@%s) [Set to: %s]", akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, desc);
					}
					else {

						LOG_SNOOP(data->agent->nick, "%s AD %s@%s -- by %s (%s@%s) through %s [Set to: %s]", data->agent->shortNick, akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, data->operName, desc);
						log_services(LOG_SERVICES_GENERAL, "AD %s@%s -- by %s (%s@%s) through %s [Set to: %s]", akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, data->operName, desc);
					}

					send_notice_to_user(data->agent->nick, callerUser, "AKILL description for \2%s@%s\2 set to: %s", akill->username, akill->host, desc);
				}
				else {

					if (data->operMatch) {

						send_globops(data->agent->nick, "\2%s\2 changed AKILL description for \2%s@%s\2 to: %s", source, akill->username, akill->host, desc);

						LOG_SNOOP(data->agent->nick, "%s AD %s@%s -- by %s (%s@%s) [ -> %s]", data->agent->shortNick, akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, desc);
						log_services(LOG_SERVICES_GENERAL, "AD %s@%s -- by %s (%s@%s) [ -> %s]", akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, desc);
					}
					else {

						send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) changed AKILL description for \2%s@%s\2 to: %s", source, data->operName, akill->username, akill->host, desc);

						LOG_SNOOP(data->agent->nick, "%s AD %s@%s -- by %s (%s@%s) through %s [ -> %s]", data->agent->shortNick, akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, data->operName, desc);
						log_services(LOG_SERVICES_GENERAL, "AD %s@%s -- by %s (%s@%s) through %s [ -> %s]", akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, data->operName, desc);
					}

					send_notice_to_user(data->agent->nick, callerUser, "AKILL description for \2%s@%s\2 changed to: %s", akill->username, akill->host, desc);
					mem_free(akill->desc);
				}

				akill->desc = str_duplicate(desc);
				return;
			}

			akill = akill->next;
		}

		send_notice_to_user(data->agent->nick, callerUser, "AKill for \2%s@%s\2 not found.", username, host);
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SA))
		send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), OPER_ERROR_ACCESS_DENIED);

	else if (str_equals_nocase(command, "ENABLE") || str_equals_nocase(command, "DISABLE")) {

		BOOL enable = ((command[0] == 'E') || (command[0] == 'e'));
		char *username, *host;
		AutoKill *akill;


		if (IS_NULL(username = strtok(NULL, "@")) || IS_NULL(host = strtok(NULL, " "))) {

			send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2AKILL %s\2 user@host", enable ? "ENABLE" : "DISABLE");
			send_notice_to_user(data->agent->nick, callerUser, "Type \2/%s OHELP AKILL\2 for more information.", data->agent->shortNick);
			return;
		}

		akill = AutoKillList;

		while (IS_NOT_NULL(akill)) {

			if (str_equals_nocase(akill->username, username) && str_equals_nocase(akill->host, host)) {

				if (enable ? FlagUnset(akill->type, AKILL_TYPE_DISABLED) : FlagSet(akill->type, AKILL_TYPE_DISABLED)) {

					send_notice_to_user(data->agent->nick, callerUser, "AKill on \2%s@%s\2 is already %s.", akill->username, akill->host, enable ? "enabled" : "disabled");
					return;
				}

				if (data->operMatch) {

					send_globops(data->agent->nick, "\2%s\2 %s AKill on \2%s@%s\2", source, enable ? "enabled" : "disabled", akill->username, akill->host);

					LOG_SNOOP(data->agent->nick, "%s A! %s@%s -- by %s (%s@%s) [%s]", data->agent->shortNick, akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, enable ? "Enabled" : "Disabled");
					log_services(LOG_SERVICES_GENERAL, "A! %s@%s -- by %s (%s@%s) [%s]", akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, enable ? "Enabled" : "Disabled");
				}
				else {

					send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) %s AKill on \2%s@%s\2", source, data->operName, enable ? "enabled" : "disabled", akill->username, akill->host);

					LOG_SNOOP(data->agent->nick, "%s A! %s@%s -- by %s (%s@%s) through %s [%s]", data->agent->shortNick, akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, data->operName, enable ? "Enabled" : "Disabled");
					log_services(LOG_SERVICES_GENERAL, "A! %s@%s -- by %s (%s@%s) through %s [%s]", akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, data->operName, enable ? "Enabled" : "Disabled");
				}

				send_notice_to_user(data->agent->nick, callerUser, "AKILL on \2%s@%s\2 has been %s.", akill->username, akill->host, enable ? "enabled" : "disabled");

				if (enable) {

					RemoveFlag(akill->type, AKILL_TYPE_DISABLED);
					send_AKILL(akill->username, akill->host, akill->creator.name, akill->reason, akill->id, get_akill_type_short(akill->type));
				}
				else {

					AddFlag(akill->type, AKILL_TYPE_DISABLED);
					send_RAKILL(akill->username, akill->host);
				}

				return;
			}

			akill = akill->next;
		}

		send_notice_to_user(data->agent->nick, callerUser, "AKill on \2%s@%s\2 not found.", username, host);
	}
	else if (str_equals_nocase(command, "REASON")) {

		AutoKill *akill;
		char *username, *host, *reason;


		if (IS_NULL(username = strtok(NULL, "@")) || IS_NULL(host = strtok(NULL, " ")) || IS_NULL(reason = strtok(NULL, ""))) {

			send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2AKILL REASON\2 user@host new-reason");
			send_notice_to_user(data->agent->nick, callerUser, "Type \2/%s OHELP AKILL\2 for more information.", data->agent->shortNick);
			return;
		}

		if (!validate_string(reason)) {

			send_notice_to_user(data->agent->nick, callerUser, "Invalid reason supplied.");
			return;
		}

		akill = AutoKillList;

		while (IS_NOT_NULL(akill)) {

			if (str_equals_nocase(akill->username, username) && str_equals_nocase(akill->host, host)) {

				terminate_string_ccodes(reason);

				if (data->operMatch) {

					send_globops(data->agent->nick, "\2%s\2 changed AKILL reason for \2%s@%s\2 to: %s", source, akill->username, akill->host, reason);

					LOG_SNOOP(data->agent->nick, "%s AR %s@%s -- by %s (%s@%s) [ -> %s]", data->agent->shortNick, akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, reason);
					log_services(LOG_SERVICES_GENERAL, "AR %s@%s -- by %s (%s@%s) [ -> %s]", akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, reason);
				}
				else {

					send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) changed AKILL reason for \2%s@%s\2 to: %s", source, data->operName, akill->username, akill->host, reason);

					LOG_SNOOP(data->agent->nick, "%s AR %s@%s -- by %s (%s@%s) through %s [ -> %s]", data->agent->shortNick, akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, data->operName, reason);
					log_services(LOG_SERVICES_GENERAL, "AR %s@%s -- by %s (%s@%s) through %s [ -> %s]", akill->username, akill->host, callerUser->nick, callerUser->username, callerUser->host, data->operName, reason);
				}

				send_notice_to_user(data->agent->nick, callerUser, "AKILL reason for \2%s@%s\2 changed to: %s", akill->username, akill->host, reason);

				mem_free(akill->reason);
				akill->reason = str_duplicate(reason);

				send_RAKILL(akill->username, akill->host);
				send_AKILL(akill->username, akill->host, akill->creator.name, akill->reason, akill->id, get_akill_type_short(akill->type));
				return;
			}

			akill = akill->next;
		}

		send_notice_to_user(data->agent->nick, callerUser, "AKill for \2%s@%s\2 not found.", username, host);
	}
	else {

		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2AKILL\2 [ADD|DEL|DESC|ID|LIST|PERM|REASON|TIME] [time] mask reason");
		send_notice_to_user(data->agent->nick, callerUser, "Type \2/%s OHELP AKILL\2 for more information.", data->agent->shortNick);
	}
}

/*********************************************************/

void akill_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	STR		command = strtok(request, s_SPACE);
	BOOL	needSyntax = FALSE;

	if (IS_NOT_NULL(command)) {

		if (str_equals_nocase(command, "HELP")) {

			/* HELP ! */
		}
		else if (str_equals_nocase(command, "HOST")) {

			char *user = strtok(NULL, "@");
			char *host = strtok(NULL, " ");

			if (IS_NULL(user) || IS_NULL(host))
				needSyntax = TRUE;

			else {

				AutoKill *akill = AutoKillList;
				int akillIdx = 0;

				send_notice_to_user(sourceNick, callerUser, "DUMP: AutoKill(s)");

				while (IS_NOT_NULL(akill)) {

					++akillIdx;

					if (str_match_wild_nocase(user, akill->username) &&
						str_match_wild_nocase(host, akill->host)) {

						send_notice_to_user(sourceNick, callerUser, "%d) Address 0x%08X, size %d B",		akillIdx, (unsigned long)akill, sizeof(AutoKill) + str_len(akill->username) + str_len(akill->host) + str_len(akill->creator.name) + str_len(akill->reason));
						send_notice_to_user(sourceNick, callerUser, "User: 0x%08X \2[\2%s\2]\2",			(unsigned long)akill->username, str_get_valid_display_value(akill->username));
						send_notice_to_user(sourceNick, callerUser, "Host: 0x%08X \2[\2%s\2]\2",			(unsigned long)akill->host, str_get_valid_display_value(akill->host));
						send_notice_to_user(sourceNick, callerUser, "CIDR: %u/%u",							akill->cidr.ip, akill->cidr.mask);
						send_notice_to_user(sourceNick, callerUser, "Set by: 0x%08X \2[\2%s\2]\2",			(unsigned long)akill->creator.name, str_get_valid_display_value(akill->creator.name));
						send_notice_to_user(sourceNick, callerUser, "Time Set C-time: %lu",					akill->creator.time);
						send_notice_to_user(sourceNick, callerUser, "Expiry C-time: %lu",					akill->expireTime);
						send_notice_to_user(sourceNick, callerUser, "Last Used C-time: %lu",				akill->lastUsed);
						send_notice_to_user(sourceNick, callerUser, "Reason: 0x%08X \2[\2%s\2]\2",			(unsigned long)akill->reason, str_get_valid_display_value(akill->reason));
						send_notice_to_user(sourceNick, callerUser, "Description: 0x%08X \2[\2%s\2]\2",		(unsigned long)akill->desc, str_get_valid_display_value(akill->desc));
						send_notice_to_user(sourceNick, callerUser, "Type: 0x%08X \2[\2%s\2]\2",			(unsigned long)akill->type, get_akill_type_long(akill->type));
						send_notice_to_user(sourceNick, callerUser, "ID: %lu-%s",							akill->id, get_akill_type_short(akill->type));
						send_notice_to_user(sourceNick, callerUser, "Next/Prev records: 0x%08X / 0x%08X",	(unsigned long)akill->next, (unsigned long)akill->prev);
					}

					akill = akill->next;
				}

				LOG_DEBUG_SNOOP("Command: DUMP AKILL HOST %s@%s -- by %s", user, host, callerUser->nick);
			}
		}
		else if (str_equals_nocase(command, "ID")) {

			char *id = strtok(NULL, " ");
			char *type;
			unsigned long t;
			int akillIdx = 0;

			if (id && (type = strchr(id, '-')) ) {

				if (str_len(id) > (size_t)(type - id + 1)) {

					*type++ = 0;
					t = strtoul(id, NULL, 10);

					if (t > 0) {

						AutoKill *akill = AutoKillList;

						while (IS_NOT_NULL(akill)) {

							if (akill->id == t) {

								++akillIdx;

								send_notice_to_user(sourceNick, callerUser, "%d) Address 0x%08X, size %d B",		akillIdx, (unsigned long)akill, sizeof(AutoKill) + str_len(akill->username) + str_len(akill->host) + str_len(akill->creator.name) + str_len(akill->reason) + 4);
								send_notice_to_user(sourceNick, callerUser, "User: 0x%08X \2[\2%s\2]\2",			(unsigned long)akill->username, str_get_valid_display_value(akill->username));
								send_notice_to_user(sourceNick, callerUser, "Host: 0x%08X \2[\2%s\2]\2",			(unsigned long)akill->host, str_get_valid_display_value(akill->host));
								send_notice_to_user(sourceNick, callerUser, "CIDR: %u/%u",							akill->cidr.ip, akill->cidr.mask);
								send_notice_to_user(sourceNick, callerUser, "Set by: 0x%08X \2[\2%s\2]\2",			(unsigned long)akill->creator.name, str_get_valid_display_value(akill->creator.name));
								send_notice_to_user(sourceNick, callerUser, "Time Set C-time: %lu",					akill->creator.time);
								send_notice_to_user(sourceNick, callerUser, "Expiry C-time: %lu",					akill->expireTime);
								send_notice_to_user(sourceNick, callerUser, "Last Used C-time: %lu",				akill->lastUsed);
								send_notice_to_user(sourceNick, callerUser, "Reason: 0x%08X \2[\2%s\2]\2",			(unsigned long)akill->reason, str_get_valid_display_value(akill->reason));
								send_notice_to_user(sourceNick, callerUser, "Description: 0x%08X \2[\2%s\2]\2",		(unsigned long)akill->desc, str_get_valid_display_value(akill->desc));
								send_notice_to_user(sourceNick, callerUser, "Type: 0x%08X \2[\2%s\2]\2",			(unsigned long)akill->type, get_akill_type_long(akill->type));
								send_notice_to_user(sourceNick, callerUser, "ID: %lu-%s",							akill->id, get_akill_type_short(akill->type));
								send_notice_to_user(sourceNick, callerUser, "Next/Prev records: 0x%08X / 0x%08X",	(unsigned long)akill->next, (unsigned long)akill->prev);
							}

							akill = akill->next;
						}

						LOG_DEBUG_SNOOP("Command: DUMP AKILL ID %lu-%s -- by %s", id, type, callerUser->nick);
					}
					else
						needSyntax = TRUE;
				}
				else
					needSyntax = TRUE;
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

		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 AKILL HELP");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 AKILL [HOST|ID] host|ID");
	}
}

/*********************************************************/

unsigned long akill_mem_report(CSTR sourceNick, const User *callerUser) {

	unsigned long int mem = 0;
	int count = 0;
	AutoKill *akill = AutoKillList;


	TRACE_FCLT(FACILITY_AKILL_MEM_REPORT);

	send_notice_to_user(sourceNick, callerUser, "\2AKILLS\2:");

	while (IS_NOT_NULL(akill)) {

		++count;

		mem += sizeof(AutoKill);

		mem += str_len(akill->username) + 1;
		mem += str_len(akill->host) + 1;
		mem += str_len(akill->reason) + 1;

		if (akill->desc)
			mem += str_len(akill->desc) + 1;

		mem += str_len(akill->creator.name) + 1;

		akill = akill->next;
	}

	send_notice_to_user(sourceNick, callerUser, "AKILL list: \2%d\2 -> \2%lu\2 KB (\2%lu\2 B)", count, mem / 1024, mem);

	return mem;
}

#endif /* #if defined(USE_SERVICES) || defined(USE_SOCKSMONITOR) */
