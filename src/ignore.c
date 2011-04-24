/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* ignore.c - Services ignores
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
#include "../inc/main.h"
#include "../inc/send.h"
#include "../inc/storage.h"
#include "../inc/cidr.h"
#include "../inc/conf.h"
#include "../inc/misc.h"
#include "../inc/list.h"
#include "../inc/ignore.h"


/*********************************************************
 * Local variables                                       *
 *********************************************************/

/* List of Ignores. */
static Ignore *IgnoreList;


/*********************************************************
 * Private code                                          *
 *********************************************************/

static void ignore_remove_record(Ignore *anIgnore) {

	TRACE_FCLT(FACILITY_IGNORE_REMOVE_RECORD);

	/* Link around it. */
	if (IS_NOT_NULL(anIgnore->next))
		anIgnore->next->prev = anIgnore->prev;

	if (IS_NOT_NULL(anIgnore->prev))
		anIgnore->prev->next = anIgnore->next;
	else
		IgnoreList = anIgnore->next;

	/* Free it. */
	if (anIgnore->nick)
		mem_free(anIgnore->nick);

	if (anIgnore->username)
		mem_free(anIgnore->username);

	if (anIgnore->host)
		mem_free(anIgnore->host);

	str_creationinfo_free(&(anIgnore->info));

	mem_free(anIgnore);
}


/*********************************************************
 * Public code                                           *
 *********************************************************/

BOOL ignore_db_save(void) {

	STGHANDLE		stg;
	STG_RESULT		result;
	Ignore			*anIgnore;
	char			*strings[5];
	int				error_index;


	TRACE_FCLT(FACILITY_IGNORE_DB_SAVE);

	result = stg_create(IGNORE_DB, SF_NOFLAGS, IGNORE_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_IGNORE_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"ignore_db_save(): Could not create database file %s: %s [Error %d: %s]", IGNORE_DB, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	result = stg_start_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_IGNORE_DB_SAVE, __LINE__, "Write error on %s - %s", IGNORE_DB, stg_result_to_string(result));

	anIgnore = IgnoreList;

	while (IS_NOT_NULL(anIgnore)) {

		result = stg_write_record(stg, (PBYTE)anIgnore, sizeof(Ignore));

		if (result != stgSuccess)
			fatal_error(FACILITY_IGNORE_DB_SAVE, __LINE__, "Write error on %s - %s", IGNORE_DB, stg_result_to_string(result));

		strings[0] = anIgnore->nick;
		strings[1] = anIgnore->username;
		strings[2] = anIgnore->host;
		strings[3] = anIgnore->info.creator.name;
		strings[4] = anIgnore->info.reason;

		error_index = -1;

		result = stg_write_strings(stg, strings, sizeof(strings) / sizeof(char *), &error_index);

		if (result != stgSuccess)
			fatal_error(FACILITY_IGNORE_DB_SAVE, __LINE__, "Write error on %s for string n. %d - %s", IGNORE_DB, error_index, stg_result_to_string(result));

		anIgnore = anIgnore->next;
	}

	result = stg_end_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_IGNORE_DB_SAVE, __LINE__, "Write error on %s - %s", IGNORE_DB, stg_result_to_string(result));

	stg_close(stg, IGNORE_DB);

	return TRUE;
}


BOOL ignore_db_load(void) {

	STGHANDLE	stg = 0;
	STG_RESULT	result;


	TRACE_FCLT(FACILITY_IGNORE_DB_LOAD);

	result = stg_open(IGNORE_DB, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version;
			BOOL		in_section;
			BOOL		read_done;


			version = stg_data_version(stg);

			switch (version) {

				case IGNORE_DB_CURRENT_VERSION: {

					Ignore_V10 *anIgnore;

					// start-of-section marker
					result = stg_read_record(stg, NULL, 0);

					if (result == stgBeginOfSection) {

						in_section = TRUE;

						while (in_section) {

							anIgnore = mem_malloc(sizeof(Ignore_V10));

							result = stg_read_record(stg, (PBYTE)anIgnore, sizeof(Ignore_V10));

							switch (result) {

								case stgEndOfSection: // end-of-section
									in_section = FALSE;
									mem_free(anIgnore);
									break;

								case stgSuccess: // a valid record

									read_done = TRUE;

									if (anIgnore->nick)
										read_done &= (result = stg_read_string(stg, &(anIgnore->nick), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anIgnore->username))
										read_done &= (result = stg_read_string(stg, &(anIgnore->username), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anIgnore->host))
										read_done &= (result = stg_read_string(stg, &(anIgnore->host), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anIgnore->info.creator.name))
										read_done &= (result = stg_read_string(stg, &(anIgnore->info.creator.name), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anIgnore->info.reason))
										read_done &= (result = stg_read_string(stg, &(anIgnore->info.reason), NULL)) == stgSuccess;

									if (!read_done)
										fatal_error(FACILITY_IGNORE_DB_LOAD, __LINE__, "Read error on %s (2) - %s", IGNORE_DB, stg_result_to_string(result));

									anIgnore->next = IgnoreList;
									anIgnore->prev = NULL;

									if (IgnoreList)
										IgnoreList->prev = anIgnore;

									IgnoreList = anIgnore;
									break;

								default: // some error
									fatal_error(FACILITY_IGNORE_DB_LOAD, __LINE__, "Read error on %s - %s", IGNORE_DB, stg_result_to_string(result));
							}
						}
					}
					else
						fatal_error(FACILITY_IGNORE_DB_LOAD, __LINE__, "Read error on %s : invalid format", IGNORE_DB);

					stg_close(stg, IGNORE_DB);
					return TRUE;
				}

				default:
					fatal_error(FACILITY_IGNORE_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, IGNORE_DB);
			}
		}

		case stgNotFound: // no data to load
			return TRUE;

		default: // error!
			stg_close(stg, IGNORE_DB);

			fatal_error(FACILITY_IGNORE_DB_LOAD, __LINE__, "Error opening %s - %s", IGNORE_DB, stg_result_to_string(result));
			return FALSE;
	}
}


void ignore_create_record(CSTR source, STR nick, STR username, STR host, CSTR reason,
	BOOL manual, const time_t expire_t, BOOL have_CIDR, CIDR_IP cidr) {

	Ignore *ignore;


	TRACE_FCLT(FACILITY_IGNORE_CREATE_RECORD);

	/* Allocate it. */
	ignore = (Ignore *) mem_calloc(1, sizeof(Ignore));

	/* Link it. */
	ignore->next = IgnoreList;
	ignore->prev = NULL;

	if (IgnoreList)
		IgnoreList->prev = ignore;

	IgnoreList = ignore;

	/* Fill it. */

	str_creationinfo_init(&(ignore->info));
	str_creationinfo_set(&(ignore->info), source, reason, NOW);

	ignore->lastUsed = NOW;

	ignore->nick = nick;
	ignore->username = username;
	ignore->host = host;

	if (have_CIDR) {

		AddFlag(ignore->flags, IGNORE_FLAG_WITHCIDR);
		ignore->cidr = cidr;
	}

	if (manual == TRUE)
		AddFlag(ignore->flags, IGNORE_FLAG_MANUAL);

	if (expire_t == 0) {

		ignore->expireTime = 0;
		AddFlag(ignore->flags, IGNORE_FLAG_PERMANENT);
	}
	else {

		ignore->expireTime = (NOW + expire_t);
		AddFlag(ignore->flags, IGNORE_FLAG_TEMPORARY);
	}
}


BOOL ignore_match(const User *user) {

	Ignore *ignore = IgnoreList;


	TRACE_FCLT(FACILITY_IGNORE_MATCH);

	while (IS_NOT_NULL(ignore)) {

		if ((IS_NULL(ignore->nick) || str_match_wild_nocase(ignore->nick, user->nick)) &&
			(IS_NULL(ignore->username) || str_match_wild_nocase(ignore->username, user->username)) &&
			((FlagSet(ignore->flags, IGNORE_FLAG_WITHCIDR) && (user->ip != 0)) ?
			cidr_match(&ignore->cidr, user->ip) : (IS_NULL(ignore->host) ? TRUE : str_match_wild_nocase(ignore->host, user->host)))) {

			ignore->lastUsed = NOW;
			return TRUE;
		}

		ignore = ignore->next;
	}

	return FALSE;
}


BOOL is_already_ignored(CSTR nick, CSTR username, CSTR host, const time_t expire_t, const User *callerUser) {

	Ignore *ignore = IgnoreList;


	TRACE_FCLT(FACILITY_IGNORE_IS_ALREADY_IGNORED);

	while (IS_NOT_NULL(ignore)) {

		if ((IS_NULL(ignore->nick) ? str_equals(nick, "*") : str_equals_nocase(nick, ignore->nick)) &&
			(IS_NULL(ignore->username) ? str_equals(username, "*") : str_equals_nocase(username, ignore->username)) &&
			(IS_NULL(ignore->host) ? str_equals(host, "*") : str_equals_nocase(ignore->host, host))) {

			if ((ignore->expireTime >= (NOW + expire_t)) || (ignore->expireTime == 0))
				send_notice_to_user(s_OperServ, callerUser, "\2%s!%s@%s\2 already exists on the Ignore List.", nick, username, host);

			else {

				send_notice_to_user(s_OperServ, callerUser, "Expiry time of \2%s!%s@%s\2 changed.", nick, username, host);
				ignore->expireTime = NOW + expire_t;
			}

			return TRUE;
		}

		ignore = ignore->next;
	}

	return FALSE;
}


void ignore_expire(void) {

	Ignore *ignore, *next;


	TRACE_FCLT(FACILITY_IGNORE_EXPIRE);

	if (CONF_SET_NOEXPIRE)
		return;

	ignore = IgnoreList;

	while (IS_NOT_NULL(ignore)) {

		if ((ignore->expireTime != 0) && (ignore->expireTime <= NOW)) {

			next = ignore->next;

			ignore_remove_record(ignore);

			ignore = next;
		}
		else
			ignore = ignore->next;
	}
}


void handle_ignore(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *cmd = strtok(NULL, " ");


	TRACE_MAIN_FCLT(FACILITY_IGNORE_HANDLE_IGNORE);

	if (IS_NULL(cmd)) {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2IGNORE\2 [ADD|DEL|LIST|PERM|TIME] [expiry] mask reason");
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP IGNORE\2 for more information.");
	}
	else if (str_equals_nocase(cmd, "LIST")) {

		Ignore *anIgnore;
		int idx = 0;
		char timebuf[64], expirebuf[64];


		if (IS_NULL(IgnoreList)) {

			send_notice_to_user(s_OperServ, callerUser, "The Ignore List is empty.");
			return;
		}

		send_notice_to_user(s_OperServ, callerUser, "Current \2IGNORE\2 list:");

		anIgnore = IgnoreList;

		while (IS_NOT_NULL(anIgnore)) {

			++idx;

			lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, anIgnore->info.creator.time);
			expire_left(expirebuf, sizeof(expirebuf), anIgnore->expireTime);

			send_notice_to_user(s_OperServ, callerUser, "%d) %s!%s@%s [Reason: %s]", idx, IS_NULL(anIgnore->nick) ? "*" : anIgnore->nick, IS_NULL(anIgnore->username) ? "*" : anIgnore->username, IS_NULL(anIgnore->host) ? "*" : anIgnore->host, anIgnore->info.reason);
			send_notice_to_user(s_OperServ, callerUser, "Set by \2%s\2 on %s; %s", anIgnore->info.creator.name, timebuf, expirebuf);

			anIgnore = anIgnore->next;
		}

		send_notice_to_user(s_OperServ, callerUser, "*** \2End of List\2 ***");
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SOP))
		send_notice_lang_to_user(s_OperServ, callerUser, GetCallerLang(), OPER_ERROR_ACCESS_DENIED);

	else if (str_equals_nocase(cmd, "ADD") || str_equals_nocase(cmd, "PERM")
		|| str_equals_nocase(cmd, "TIME") || str_equals_nocase(cmd, "OVERRIDE")) {

		char	ignored_nicks[IRCBUFSIZE];
		char	*reason, *mask, *nick, *username, *host, *expiry = NULL, *ptr = ignored_nicks;
		User	*user;
		int		ignorecount = 0, valid = 0, expire_t = CONF_DEFAULT_IGNORE_EXPIRY;
		int		ignored_nicks_freespace = 400;
		float	percent;
		size_t	nick_len, user_len, host_len;
		BOOL	too_many_ignored_nicks = FALSE, more_nicks = FALSE, have_CIDR = FALSE;
		CIDR_IP	cidr;
		unsigned int idx;


		switch (cmd[0]) {

			case 'O':
			case 'o':
				valid += 4;
				/* Fall... */

			case 'T':
			case 't':
				expiry = strtok(NULL, " ");
				mask = strtok(NULL, " ");
				reason = strtok(NULL, "");

				if (IS_NULL(mask) || IS_NULL(reason) || IS_NULL(expiry)) {

					send_notice_to_user(s_OperServ, callerUser, "Syntax: \2IGNORE TIME\2 time [nick!]user@host reason");
					send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP IGNORE\2 for more information.");
					return;
				}

				expire_t = convert_amount(expiry);

				if (expire_t == -1) {

					send_notice_to_user(s_OperServ, callerUser, "Invalid expiry time supplied.");
					send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP IGNORE\2 for more information.");
					return;
				}

				break;

			case 'P':
			case 'p':
				expire_t = 0;
				/* Fall... */

			default:
				mask = strtok(NULL, " ");
				reason = strtok(NULL, "");

				if (IS_NULL(mask) || IS_NULL(reason)) {

					send_notice_to_user(s_OperServ, callerUser, "Syntax: \2IGNORE ADD\2 [nick!]user@host reason");
					send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP IGNORE\2 for more information.");
					return;
				}

				break;
		}

		TRACE_MAIN();

		if (!validate_mask(mask, TRUE, FALSE, FALSE)) {

			send_notice_to_user(s_OperServ, callerUser, "Hostmask must be in [nick!]user@host format.");

			if (data->operMatch)
				LOG_SNOOP(s_OperServ, "OS +I* %s -- by %s (%s@%s) [Invalid Mask]", mask, callerUser->nick, callerUser->username, callerUser->host);
			else
				LOG_SNOOP(s_OperServ, "OS +I* %s -- by %s (%s@%s) through %s [Invalid Mask]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			return;
		}

		TRACE_MAIN();

		if ((idx = str_len(reason)) > 220) {

			send_notice_to_user(s_OperServ, callerUser, "Reason cannot be longer than 220 characters (yours has: %d).", idx);
			return;
		}

		if (!validate_string(reason)) {

			send_notice_to_user(s_OperServ, callerUser, "Invalid reason supplied.");
			return;
		}

		user_usermask_split(mask, &nick, &username, &host);

		if ((nick_len = str_len(nick)) > NICKMAX) {

			send_notice_lang_to_user(s_OperServ, callerUser, GetCallerLang(), ERROR_NICK_MAX_LENGTH, NICKMAX);
			goto clear;
		}

		if ((user_len = str_len(username)) > USERMAX) {

			send_notice_lang_to_user(s_OperServ, callerUser, GetCallerLang(), ERROR_USER_MAX_LENGTH, USERMAX);
			goto clear;
		}

		if ((host_len = str_len(host)) > HOSTMAX) {

			send_notice_lang_to_user(s_OperServ, callerUser, GetCallerLang(), ERROR_HOST_MAX_LENGTH, HOSTMAX);
			goto clear;
		}

		str_compact(nick);
		str_compact(username);
		str_compact(host);

		if (valid == 0) {

			for (idx = 0; idx < nick_len; ++idx) {

				if (nick[idx] != '*' && nick[idx] != '?')
					++valid;
			}

			for (idx = 0; idx < user_len; ++idx) {

				if (username[idx] != '*' && username[idx] != '?' && username[idx] != '~')
					++valid;
			}

			for (idx = 0; idx < host_len; ++idx) {

				if (host[idx] != '*' && host[idx] != '?' && host[idx] != '.' && host[idx] != '-' && host[idx] != ':')
					++valid;
			}

			if (valid < 4) {

				if (data->operMatch) {

					send_globops(s_OperServ, "\2%s\2 tried to IGNORE \2%s\2", source, mask);

					LOG_SNOOP(s_OperServ, "OS +I* %s -- by %s (%s@%s) [Lamer]", mask, callerUser->nick, callerUser->username, callerUser->host);
					log_services(LOG_SERVICES_OPERSERV, "+I* %s -- by %s (%s@%s) [Lamer]", mask, callerUser->nick, callerUser->username, callerUser->host);
				}
				else {

					send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried to IGNORE \2%s\2", source, data->operName, mask);

					LOG_SNOOP(s_OperServ, "OS +I* %s -- by %s (%s@%s) through %s [Lamer]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName);
					log_services(LOG_SERVICES_OPERSERV, "+I* %s -- by %s (%s@%s) through %s [Lamer]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				}

				send_notice_to_user(s_OperServ, callerUser, "Hrmmm, what would your admin think of that?");
				goto clear;
			}
		}

		if (is_already_ignored(nick, username, host, expire_t, callerUser))
			goto clear;

		if (str_equals(nick, "*")) {

			mem_free(nick);
			nick = NULL;
		}

		if (str_equals(username, "*")) {

			mem_free(username);
			username = NULL;
		}

		if (str_equals(host, "*")) {

			mem_free(host);
			host = NULL;
		}

		memset(ignored_nicks, 0, sizeof(ignored_nicks));

		if (IS_NOT_NULL(host)) {

			if (cidr_ip_fill(host, &cidr, FALSE) == cidrSuccess)
				have_CIDR = TRUE;

			else if (convert_host_to_cidr(host) == cidrSuccess)
				send_notice_to_user(data->agent->nick, callerUser, "CIDR IP detected, please add it as CIDR for better results.");
		}

		HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

			HASH_FOREACH_BRANCH_ITEM(onlineuser, idx, user) {

				if (((IS_NULL(nick)) ? TRUE : str_match_wild_nocase(nick, user->nick)) &&
					((IS_NULL(username)) ? TRUE : str_match_wild_nocase(username, user->username)) &&
					((have_CIDR) ? cidr_match(&cidr, user->ip) :
					((IS_NULL(host)) ? TRUE : str_match_wild_nocase(host, user->host)))) {

					if (user_is_ircop(user) || user_is_services_agent(user) || user_is_services_client(user)) {

						if (data->operMatch) {

							send_globops(s_OperServ, "\2%s\2 tried to IGNORE \2%s\2", source, user->nick);

							LOG_SNOOP(s_OperServ, "OS +I* %s -- by %s (%s@%s) [Matches %s]", mask, callerUser->nick, callerUser->username, callerUser->host, user->nick);
							log_services(LOG_SERVICES_OPERSERV, "+I* %s -- by %s (%s@%s) [Matches %s]", mask, callerUser->nick, callerUser->username, callerUser->host, user->nick);
						}
						else {

							send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried to IGNORE \2%s\2", source, data->operName, user->nick);

							LOG_SNOOP(s_OperServ, "OS +I* %s -- by %s (%s@%s) through %s [Matches %s]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName, user->nick);
							log_services(LOG_SERVICES_OPERSERV, "+I* %s -- by %s (%s@%s) through %s [Matches %s]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName, user->nick);
						}

						send_notice_to_user(s_OperServ, callerUser, "Permission denied.");
						goto clear;
					}

					++ignorecount;

					if (!too_many_ignored_nicks) {

						const char *nickPtr = user->nick;

						if (IS_NOT_EMPTY_STR(ignored_nicks)) {

							*ptr++ = c_COMMA;
							*ptr++ = c_SPACE;

							ignored_nicks_freespace -= 2;
						}

						while (*nickPtr != c_NULL) {

							*ptr++ = *nickPtr++;
							--ignored_nicks_freespace;
						}

						*ptr = c_NULL;

						if (ignored_nicks_freespace <= 0)
							too_many_ignored_nicks = TRUE;
					}
					else
						more_nicks = TRUE;
				}
			}
		}

		percent = ((ignorecount + .0) * 100.0) / user_online_user_count;

		TRACE_MAIN();
		if (percent > CONF_AKILL_PERCENT) {

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 tried to IGNORE \2%.3f%s\2 of the network! (Limit: %.3f%s)", source, percent, "%", CONF_AKILL_PERCENT, "%");

				LOG_SNOOP(s_OperServ, "OS +I* %s -- by %s (%s@%s) [%.3f%s > %.3f%s]", mask, callerUser->nick, callerUser->username, callerUser->host, percent, "%", CONF_AKILL_PERCENT, "%");
				log_services(LOG_SERVICES_OPERSERV, "+I* %s -- by %s (%s@%s) [%.3f%s > %.3f%s]", mask, callerUser->nick, callerUser->username, callerUser->host, percent, "%", CONF_AKILL_PERCENT, "%");
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried to IGNORE \2%.3f%s\2 of the network! (Limit: %.3f%s)", source, data->operName, percent, "%", CONF_AKILL_PERCENT, "%");

				LOG_SNOOP(s_OperServ, "OS +I* %s -- by %s (%s@%s) through %s [%.3f%s > %.3f%s]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName, percent, "%", CONF_AKILL_PERCENT, "%");
				log_services(LOG_SERVICES_OPERSERV, "+I* %s -- by %s (%s@%s) through %s [%.3f%s > %.3f%s]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName, percent, "%", CONF_AKILL_PERCENT, "%");
			}

			send_notice_to_user(s_OperServ, callerUser, "IGNORE rejected. Affected users would be greater than %.3f%s", CONF_AKILL_PERCENT, "%");
			goto clear;
		}

		if (more_nicks == TRUE) {

			*ptr++ = c_COMMA;
			*ptr++ = c_SPACE;
			*ptr++ = c_DOT;
			*ptr++ = c_DOT;
			*ptr++ = c_DOT;
			*ptr = c_NULL;
		}

		TRACE_MAIN();

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "OS +I %s -- by %s (%s@%s) [Reason: %s]", mask, callerUser->nick, callerUser->username, callerUser->host, reason);
			log_services(LOG_SERVICES_OPERSERV, "+I %s -- by %s (%s@%s) [Reason: %s]", mask, callerUser->nick, callerUser->username, callerUser->host, reason);
		}
		else {

			LOG_SNOOP(s_OperServ, "OS +I %s -- by %s (%s@%s) through %s [Reason: %s]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName, reason);
			log_services(LOG_SERVICES_OPERSERV, "+I %s -- by %s (%s@%s) through %s [Reason: %s]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName, reason);
		}

		/* Adding entry. */
		if (expire_t == 0) {

			if (data->operMatch)
				send_globops(s_OperServ, "\2%s\2 added a permanent IGNORE for \2%s\2. [Reason: %s]",
					source, mask, reason);
			else
				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) added a permanent IGNORE for \2%s\2. [Reason: %s]",
					source, data->operName, mask, reason);
		}
		else {

			if (expire_t < ONE_MINUTE)
				expire_t = ONE_MINUTE;

			if (data->operMatch)
				send_globops(s_OperServ, "\2%s\2 added an IGNORE for \2%s\2 [Reason: %s] [Expires in %s]",
					source, mask, reason, convert_time(misc_buffer, MISC_BUFFER_SIZE, expire_t, LANG_DEFAULT));
			else
				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) added an IGNORE for \2%s\2 [Reason: %s] [Expires in %s]",
					source, data->operName, mask, reason, convert_time(misc_buffer, MISC_BUFFER_SIZE, expire_t, LANG_DEFAULT));
		}

		if (ignorecount > 0)
			send_globops(s_OperServ, "Affects \2%d\2 user%s (%.3f%s): %s",
				ignorecount, (ignorecount == 1) ? "" : "s", percent, "%", ignored_nicks);

		send_notice_to_user(s_OperServ, callerUser, "\2%s\2 added to IGNORE list.", mask);

		if (CONF_SET_READONLY)
			send_notice_to_user(s_OperServ, callerUser, "\2Notice:\2 Services is in read-only mode. Changes will not be saved!");

		terminate_string_ccodes(reason);

		ignore_create_record(data->operName, nick, username, host, reason, TRUE, expire_t, have_CIDR, cidr);
		return;

clear:
		if (nick)
			mem_free(nick);
		if (username)
			mem_free(username);
		if (host)
			mem_free(host);
	}
	else if (str_equals_nocase(cmd, "DEL")) {

		char *mask, *err;
		Ignore *ignore;
		unsigned long int ignoreIdx;


		if (IS_NULL(mask = strtok(NULL, " "))) {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2IGNORE DEL\2 mask");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP IGNORE\2 for more information.");
			return;
		}

		ignore = IgnoreList;

		ignoreIdx = strtoul(mask, &err, 10);

		if ((ignoreIdx > 0) && (*err == '\0')) {

			while (IS_NOT_NULL(ignore) && (ignoreIdx > 1)) {

				ignore = ignore->next;
				--ignoreIdx;
			}

			if (IS_NULL(ignore)) {

				send_notice_to_user(s_OperServ, callerUser, "Entry \2%s\2 not found on the IGNORE list.", mask);
				return;
			}
		}
		else {

			char *nick, *username, *host;


			user_usermask_split(mask, &nick, &username, &host);

			while (IS_NOT_NULL(ignore)) {

				if ((IS_NULL(ignore->nick) ? str_equals(nick, "*") : str_equals_nocase(nick, ignore->nick)) &&
					(IS_NULL(ignore->username) ? str_equals(username, "*") : str_equals_nocase(username, ignore->username)) &&
					(IS_NULL(ignore->host) ? str_equals(host, "*") : str_equals_nocase(ignore->host, host)))
					break;

				ignore = ignore->next;
			}

			if (IS_NULL(ignore)) {

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "OS -I* %s -- by %s (%s@%s) [Not Ignored]", mask, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(s_OperServ, "OS -I* %s -- by %s (%s@%s) through %s [Not Ignored]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_notice_to_user(s_OperServ, callerUser, "Mask \2%s\2 not found on IGNORE list.", mask);
				return;
			}
		}

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 removed \2%s!%s@%s\2 from the IGNORE list.", source, IS_NULL(ignore->nick) ? "*" : ignore->nick, IS_NULL(ignore->username) ? "*" : ignore->username, IS_NULL(ignore->host) ? "*" : ignore->host);

			LOG_SNOOP(s_OperServ, "OS -I %s!%s@%s -- by %s (%s@%s)", IS_NULL(ignore->nick) ? "*" : ignore->nick, IS_NULL(ignore->username) ? "*" : ignore->username, IS_NULL(ignore->host) ? "*" : ignore->host, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_OPERSERV, "-I %s!%s@%s -- by %s (%s@%s)", IS_NULL(ignore->nick) ? "*" : ignore->nick, IS_NULL(ignore->username) ? "*" : ignore->username, IS_NULL(ignore->host) ? "*" : ignore->host, callerUser->nick, callerUser->username, callerUser->host);
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) removed \2%s!%s@%s\2 from the IGNORE list.", source, data->operName, IS_NULL(ignore->nick) ? "*" : ignore->nick, IS_NULL(ignore->username) ? "*" : ignore->username, IS_NULL(ignore->host) ? "*" : ignore->host);

			LOG_SNOOP(s_OperServ, "OS -I %s!%s@%s -- by %s (%s@%s) through %s", IS_NULL(ignore->nick) ? "*" : ignore->nick, IS_NULL(ignore->username) ? "*" : ignore->username, IS_NULL(ignore->host) ? "*" : ignore->host, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_OPERSERV, "-I %s!%s@%s -- by %s (%s@%s) through %s", IS_NULL(ignore->nick) ? "*" : ignore->nick, IS_NULL(ignore->username) ? "*" : ignore->username, IS_NULL(ignore->host) ? "*" : ignore->host, callerUser->nick, callerUser->username, callerUser->host, data->operName);
		}

		send_notice_to_user(s_OperServ, callerUser, "\2%s!%s@%s\2 removed from IGNORE list.", IS_NULL(ignore->nick) ? "*" : ignore->nick, IS_NULL(ignore->username) ? "*" : ignore->username, IS_NULL(ignore->host) ? "*" : ignore->host);

		if (CONF_SET_READONLY)
			send_notice_to_user(s_OperServ, callerUser, "\2Notice:\2 Services is in read-only mode. Changes will not be saved!");

		ignore_remove_record(ignore);
	}
	else {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2IGNORE\2 [ADD|DEL|LIST|PERM|TIME] [expiry] mask reason");
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP IGNORE\2 for more information.");
	}
}


void ignore_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	Ignore	*anIgnore;
	int		startIdx = 0, endIdx = 5, ignoreIdx = 0;


	TRACE_FCLT(FACILITY_IGNORE_DS_DUMP);

	if (IS_NULL(IgnoreList)) {

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2Ignore\2 List is empty.");
		return;
	}

	if (IS_NOT_NULL(request)) {

		char *err;
		long int value;

		value = strtol(request, &err, 10);

		if ((value >= 0) && (*err == '\0')) {

			startIdx = value;

			if (IS_NOT_NULL(request = strtok(NULL, " "))) {

				value = strtol(request, &err, 10);

				if ((value >= 0) && (*err == '\0'))
					endIdx = value;
			}
		}
	}

	if (endIdx < startIdx)
		endIdx = (startIdx + 5);

	send_notice_to_user(sourceNick, callerUser, "DUMP: \2Ignore\2 List (showing entries %d-%d):", startIdx, endIdx);
	LOG_DEBUG_SNOOP("Command: DUMP IGNORES %d-%d -- by %s (%s@%s)", startIdx, endIdx, callerUser->nick, callerUser->username, callerUser->host);

	anIgnore = IgnoreList;

	while (IS_NOT_NULL(anIgnore)) {

		++ignoreIdx;

		if (ignoreIdx < startIdx) {

			anIgnore = anIgnore->next;
			continue;
		}

		send_notice_to_user(sourceNick, callerUser, "%d) Address 0x%08X, size %d B",		ignoreIdx, (unsigned long)anIgnore, sizeof(Ignore));
		send_notice_to_user(sourceNick, callerUser, "Nick: 0x%08X \2[\2%s\2]\2",			(unsigned long)anIgnore->nick, str_get_valid_display_value(anIgnore->nick));
		send_notice_to_user(sourceNick, callerUser, "Username: 0x%08X \2[\2%s\2]\2",		(unsigned long)anIgnore->username, str_get_valid_display_value(anIgnore->username));
		send_notice_to_user(sourceNick, callerUser, "Host: 0x%08X \2[\2%s\2]\2",			(unsigned long)anIgnore->host, str_get_valid_display_value(anIgnore->host));
		send_notice_to_user(sourceNick, callerUser, "Creator: 0x%08X \2[\2%s\2]\2",			(unsigned long)anIgnore->info.creator.name, str_get_valid_display_value(anIgnore->info.creator.name));
		send_notice_to_user(sourceNick, callerUser, "Reason: 0x%08X \2[\2%s\2]\2",			(unsigned long)anIgnore->info.reason, str_get_valid_display_value(anIgnore->info.reason));
		send_notice_to_user(sourceNick, callerUser, "Time Set C-time: %d",					anIgnore->info.creator.time);
		send_notice_to_user(sourceNick, callerUser, "Expire C-time: %d",					anIgnore->expireTime);
		send_notice_to_user(sourceNick, callerUser, "Last Used C-time: %d",					anIgnore->lastUsed);
		send_notice_to_user(sourceNick, callerUser, "Flags: %d",							anIgnore->flags);
		send_notice_to_user(sourceNick, callerUser, "Next/Prev records: 0x%08X / 0x%08X",	(unsigned long)anIgnore->next, (unsigned long)anIgnore->prev);

		if (ignoreIdx >= endIdx)
			break;

		anIgnore = anIgnore->next;
	}
}


unsigned long int ignore_mem_report(CSTR sourceNick, const User *callerUser) {

	unsigned long int count = 0, mem = 0;
	Ignore *anIgnore;


	TRACE_FCLT(FACILITY_IGNORE_MEM_REPORT);

	send_notice_to_user(sourceNick, callerUser, "\2IGNORES\2:");

	anIgnore = IgnoreList;

	while (IS_NOT_NULL(anIgnore)) {

		++count;

		mem += sizeof(Ignore);

		if (IS_NOT_NULL(anIgnore->nick))
			mem += str_len(anIgnore->nick) + 1;

		if (IS_NOT_NULL(anIgnore->username))
			mem += str_len(anIgnore->username) + 1;

		if (IS_NOT_NULL(anIgnore->host))
			mem += str_len(anIgnore->host) + 1;

		mem += str_len(anIgnore->info.creator.name) + 1;
		mem += str_len(anIgnore->info.reason) + 1;

		anIgnore = anIgnore->next;
	}

	send_notice_to_user(sourceNick, callerUser, "Ignore List: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", count, mem / 1024, mem);
	return mem;
}
