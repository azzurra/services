/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* sxline.c - Services G:/Q:/Z:Lines
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
#include "../inc/main.h"
#include "../inc/send.h"
#include "../inc/storage.h"
#include "../inc/conf.h"
#include "../inc/misc.h"
#include "../inc/list.h"
#include "../inc/sxline.h"


/*********************************************************
 * Local variables                                       *
 *********************************************************/

/* List of SQLines. */
static SXLine *SQLineList;

/* List of SGLines. */
static SXLine *SGLineList;


/*********************************************************
 * Private code                                          *
 *********************************************************/

/*********************************************************
 * Public code                                           *
 *********************************************************/

BOOL sxline_db_load(const int type) {

	STGHANDLE	stg = 0;
	STG_RESULT	result;
	char		*database;
	SXLine		**SXLineList;


	TRACE_FCLT(FACILITY_SXLINE_DB_LOAD);

	switch (type) {

		default:
		case SXLINE_TYPE_GLINE:
			database = GLINE_DB;
			SXLineList = &SGLineList;
			break;

		case SXLINE_TYPE_QLINE:
			database = QLINE_DB;
			SXLineList = &SQLineList;
			break;
	}

	result = stg_open(database, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version;
			BOOL		in_section;
			BOOL		read_done;


			version = stg_data_version(stg);

			switch (version) {

				case SXLINE_DB_CURRENT_VERSION: {

					SXLine_V10 *aSXLine;


					// start-of-section marker
					result = stg_read_record(stg, NULL, 0);

					if (result == stgBeginOfSection) {

						in_section = TRUE;

						while (in_section) {

							aSXLine = mem_malloc(sizeof(SXLine_V10));

							result = stg_read_record(stg, (PBYTE)aSXLine, sizeof(SXLine_V10));

							switch (result) {

								case stgEndOfSection: // end-of-section
									in_section = FALSE;
									mem_free(aSXLine);
									break;

								case stgSuccess: // a valid record

									read_done = TRUE;

									read_done &= (result = stg_read_string(stg, &(aSXLine->name), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(aSXLine->info.creator.name))
										read_done &= (result = stg_read_string(stg, &(aSXLine->info.creator.name), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(aSXLine->info.reason))
										read_done &= (result = stg_read_string(stg, &(aSXLine->info.reason), NULL)) == stgSuccess;

									if (!read_done)
										fatal_error(FACILITY_SXLINE_DB_LOAD, __LINE__, "Read error on %s (2) - %s", database, stg_result_to_string(result));

									aSXLine->next = *SXLineList;
									aSXLine->prev = NULL;

									if (IS_NOT_NULL(*SXLineList))
										(*SXLineList)->prev = aSXLine;

									*SXLineList = aSXLine;
									break;

								default: // some error
									fatal_error(FACILITY_SXLINE_DB_LOAD, __LINE__, "Read error on %s - %s", database, stg_result_to_string(result));
							}
						}
					}
					else
						fatal_error(FACILITY_SXLINE_DB_LOAD, __LINE__, "Read error on %s : invalid format", database);

					stg_close(stg, database);
					return TRUE;
				}

				default:
					fatal_error(FACILITY_SXLINE_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, database);
			}
		}

		case stgNotFound: // no data to load
			return TRUE;

		default: // error!
			stg_close(stg, database);

			fatal_error(FACILITY_SXLINE_DB_LOAD, __LINE__, "Error opening %s - %s", database, stg_result_to_string(result));
			return FALSE;
	}
}


BOOL sxline_db_save(const int type) {

	STGHANDLE		stg;
	STG_RESULT		result;
	SXLine			*aSXLine;
	char			*database, *strings[3];
	int				error_index;


	TRACE_FCLT(FACILITY_SXLINE_DB_SAVE);

	switch (type) {

		default:
		case SXLINE_TYPE_GLINE:
			database = GLINE_DB;
			aSXLine = SGLineList;
			break;

		case SXLINE_TYPE_QLINE:
			database = QLINE_DB;
			aSXLine = SQLineList;
			break;
	}

	result = stg_create(database, SF_NOFLAGS, SXLINE_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_SXLINE_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"sxline_db_save(): Could not create database file %s: %s [Error %d: %s]", database, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	result = stg_start_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_SXLINE_DB_SAVE, __LINE__, "Write error on %s - %s", database, stg_result_to_string(result));

	while (IS_NOT_NULL(aSXLine)) {

		result = stg_write_record(stg, (PBYTE)aSXLine, sizeof(SXLine));

		if (result != stgSuccess)
			fatal_error(FACILITY_SXLINE_DB_SAVE, __LINE__, "Write error on %s - %s", database, stg_result_to_string(result));

		strings[0] = aSXLine->name;
		strings[1] = aSXLine->info.creator.name;
		strings[2] = aSXLine->info.reason;

		error_index = -1;

		result = stg_write_strings(stg, strings, sizeof(strings) / sizeof(char *), &error_index);

		if (result != stgSuccess)
			fatal_error(FACILITY_SXLINE_DB_SAVE, __LINE__, "Write error on %s for string n. %d - %s", database, error_index, stg_result_to_string(result));

		aSXLine = aSXLine->next;
	}

	result = stg_end_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_SXLINE_DB_SAVE, __LINE__, "Write error on %s - %s", database, stg_result_to_string(result));

	stg_close(stg, database);

	return TRUE;
}


void sxline_burst_send(void) {

	SXLine *aSXLine;


	TRACE_FCLT(FACILITY_SXLINE_BURST_SEND);

	/* Send SQLines first. */
	aSXLine = SQLineList;

	while (IS_NOT_NULL(aSXLine)) {

		send_cmd("SQLINE %s :%s", aSXLine->name, aSXLine->info.reason);
		aSXLine = aSXLine->next;
	}

	/* Send SGLines next. */
	aSXLine = SGLineList;

	while (IS_NOT_NULL(aSXLine)) {

		send_cmd("SGLINE %d :%s:%s", str_len(aSXLine->name), aSXLine->name, aSXLine->info.reason);
		aSXLine = aSXLine->next;
	}
}


int sxline_get_count(const int type) {

	SXLine	*aSXLine;
	int		count = 0;


	TRACE_FCLT(FACILITY_SXLINE_GET_COUNT);

	switch (type) {

		default:
		case SXLINE_TYPE_GLINE:
			aSXLine = SGLineList;
			break;

		case SXLINE_TYPE_QLINE:
			aSXLine = SQLineList;
			break;
	}

	while (IS_NOT_NULL(aSXLine)) {

		++count;

		aSXLine = aSXLine->next;
	}

	return count;
}


void handle_sxline(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *command;
	BOOL isQLine = (data->commandName[1] == 'Q');


	TRACE_MAIN_FCLT(FACILITY_SXLINE_HANDLE_SXLINE);

	if (IS_NULL(command = strtok(NULL, " "))) {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2S%cLINE\2 [ADD|DEL|LIST] field reason", data->commandName[1]);
		send_notice_to_user(s_OperServ, callerUser,	"Type \2/os OHELP S%cLINE\2 for more information.", data->commandName[1]);
	}
	else if (str_equals_nocase(command, "LIST")) {

		char	timebuf[64];
		char	*pattern;
		int		idx = 0, startIdx = 0, endIdx = 30, sentIdx = 0;
		SXLine	*aSXLine;


		aSXLine = (isQLine ? SQLineList : SGLineList);

		if (IS_NULL(aSXLine)) {

			send_notice_to_user(s_OperServ, callerUser, "The S%c:Line List is empty.", data->commandName[1]);
			return;
		}

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
		}

		if (endIdx < startIdx)
			endIdx = (startIdx + 30);

		if (IS_NULL(pattern))
			send_notice_to_user(s_OperServ, callerUser, "Current \2S%cLine\2 List (showing entries %d-%d):", data->commandName[1], startIdx, endIdx);
		else
			send_notice_to_user(s_OperServ, callerUser, "Current \2S%cLine\2 List (showing entries %d-%d matching %s):", data->commandName[1], startIdx, endIdx, pattern);

		while (IS_NOT_NULL(aSXLine)) {

			++idx;

			if (IS_NOT_NULL(pattern) && !str_match_wild_nocase(pattern, aSXLine->name)) {

				/* Doesn't match our search criteria, skip it. */
				aSXLine = aSXLine->next;
				continue;
			}

			++sentIdx;

			if (sentIdx < startIdx) {

				aSXLine = aSXLine->next;
				continue;
			}

			lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, aSXLine->info.creator.time);

			send_notice_to_user(s_OperServ, callerUser, "%d) %s [Reason: %s]", idx, aSXLine->name, aSXLine->info.reason);
			send_notice_to_user(s_OperServ, callerUser, "Set by \2%s\2 on %s", aSXLine->info.creator.name, timebuf);

			if (sentIdx >= endIdx)
				break;

			aSXLine = aSXLine->next;
		}

		send_notice_to_user(s_OperServ, callerUser, "*** \2End of List\2 ***");
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SA))
		send_notice_to_user(s_OperServ, callerUser, "Permission denied.");

	else if (str_equals_nocase(command, "ADD") || str_equals_nocase(command, "OVERRIDE")) {

		char 			*name, *reason, *ptr, affected_nicks[IRCBUFSIZE];
		int 			usercount = 0, valid = 0, wild = 0, affected_nicks_freespace = 400;
		unsigned int	idx;
		User 			*user;
		float			percent;
		BOOL			too_many_affected_nicks = FALSE, more_nicks = FALSE;
		size_t			user_len;
		SXLine			*aSXLine, **SXLineList;

		if (IS_NULL(name = strtok(NULL, " ")) || IS_NULL(reason = strtok(NULL, ""))) {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2S%cLINE\2 [ADD|DEL|LIST] field reason", data->commandName[1]);
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP S%cLINE\2 for more information.", data->commandName[1]);
			return;
		}

		/* Skip the sanity check if we're overriding. */
		if (str_char_toupper(command[0]) == 'A') {

			ptr = name;

			while (*ptr) {

				switch (*ptr++) {

					case '*':
					case '?':
						wild = TRUE;
						break;

					case '#':
						if (isQLine)
							break;
						/* Fall... */

					default:
						++valid;
				}
			}

			if (wild && (valid < 4)) {

				if (data->operMatch) {

					send_globops(s_OperServ, "\2%s\2 tried to S%c:Line \2%s\2", source, data->commandName[1], name);

					LOG_SNOOP(s_OperServ, "OS +S%c* %s -- by %s (%s@%s) [Lamer]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host);
					log_services(LOG_SERVICES_OPERSERV, "+S%c* %s -- by %s (%s@%s) [Lamer]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host);
				}
				else {

					send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried to S%c:Line \2%s\2", source, data->operName, data->commandName[1], name);

					LOG_SNOOP(s_OperServ, "OS +S%c* %s -- by %s (%s@%s) through %s [Lamer]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
					log_services(LOG_SERVICES_OPERSERV, "+S%c* %s -- by %s (%s@%s) through %s [Lamer]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				}

				send_notice_to_user(s_OperServ, callerUser, "Hrmmm, what would your admin think of that?");
				return;
			}
		}

		str_compact(name);

		TRACE_MAIN();
		/* Check that it's not already on our list. */
		aSXLine = (isQLine ? SQLineList : SGLineList);

		while (IS_NOT_NULL(aSXLine)) {

			if (str_equals_nocase(name, aSXLine->name)) {

				send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is already S%c:Lined", aSXLine->name, data->commandName[1]);

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "OS +S%c* %s -- by %s (%s@%s) [Already present]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(s_OperServ, "OS +S%c* %s -- by %s (%s@%s) through %s [Already present]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				return;
			}

			aSXLine = aSXLine->next;
		}

		/* Check that it doesn't affects too many users. */
		memset(affected_nicks, 0, sizeof(affected_nicks));

		ptr = affected_nicks;

		HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

			HASH_FOREACH_BRANCH_ITEM(onlineuser, idx, user) {

				if (isQLine ? str_match_wild_nocase(name, user->nick) : str_match_wild_nocase(name, user->realname)) {

					if (user_is_ircop(user) || user_is_services_agent(user) || user_is_services_client(user)) {

						if (data->operMatch) {

							send_globops(s_OperServ, "\2%s\2 tried to S%c:Line \2%s\2", source, data->commandName[1], user->nick);

							LOG_SNOOP(s_OperServ, "OS +S%c* %s -- by %s (%s@%s) [Matches %s]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, user->nick);
							log_services(LOG_SERVICES_OPERSERV, "+S%c* %s -- by %s (%s@%s) [Matches %s]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, user->nick);
						}
						else {

							send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried to S%c:Line \2%s\2", source, data->operName, data->commandName[1], user->nick);

							LOG_SNOOP(s_OperServ, "OS +S%c* %s -- by %s (%s@%s) through %s [Matches %s]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, data->operName, user->nick);
							log_services(LOG_SERVICES_OPERSERV, "+S%c* %s -- by %s (%s@%s) through %s [Matches %s]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, data->operName, user->nick);
						}

						send_notice_to_user(s_OperServ, callerUser, "Permission denied.");
						return;
					}

					++usercount;

					if (!too_many_affected_nicks) {

						if (IS_NOT_EMPTY_STR(affected_nicks)) {

							*ptr++ = c_COMMA;
							*ptr++ = c_SPACE;

							affected_nicks_freespace -= 2;
						}

						for (user_len = 0; user->nick[user_len]; ++user_len) {

							*ptr++ = user->nick[user_len];
							--affected_nicks_freespace;
						}

						*ptr = c_NULL;

						if (affected_nicks_freespace <= 0)
							too_many_affected_nicks = TRUE;
					}
					else
						more_nicks = TRUE;
				}
			}
		}

		percent = (((usercount + .0) * 100.0) / user_online_user_count);

		TRACE_MAIN();
		if (percent > CONF_AKILL_PERCENT) {

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 tried to S%c:Line \2%.3f%s\2 of the network! (Limit: %.3f%s)", source, data->commandName[1], percent, "%", CONF_AKILL_PERCENT, "%");

				LOG_SNOOP(s_OperServ, "OS +S%c* %s -- by %s (%s@%s) [%.3f%s > %.3f%s]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, percent, "%", CONF_AKILL_PERCENT, "%");
				log_services(LOG_SERVICES_OPERSERV, "+S%c* %s -- by %s (%s@%s) [%.3f%s > %.3f%s]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, percent, "%", CONF_AKILL_PERCENT, "%");
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried to S%c:Line \2%.3f%s\2 of the network! (Limit: %.3f%s)", source, data->commandName[1], data->operName, percent, "%", CONF_AKILL_PERCENT, "%");

				LOG_SNOOP(s_OperServ, "OS +S%c* %s -- by %s (%s@%s) through %s [%.3f%s > %.3f%s]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, data->operName, percent, "%", CONF_AKILL_PERCENT, "%");
				log_services(LOG_SERVICES_OPERSERV, "+S%c* %s -- by %s (%s@%s) through %s [%.3f%s > %.3f%s]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, data->operName, percent, "%", CONF_AKILL_PERCENT, "%");
			}

			send_notice_to_user(s_OperServ, callerUser, "Permission denied. Affected users would be greater than %.3f%s", CONF_AKILL_PERCENT, "%");
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

		TRACE_MAIN();

		/* Allocate the new entry. */
		aSXLine = mem_malloc(sizeof(SXLine));

		/* Fill it. */
		aSXLine->name = str_duplicate(name);

		str_creationinfo_init(&(aSXLine->info));
		str_creationinfo_set(&(aSXLine->info), data->operName, reason, NOW);

		/* Link it. */
		SXLineList = (isQLine ? &SQLineList : &SGLineList);

		aSXLine->next = *SXLineList;
		aSXLine->prev = NULL;

		if (IS_NOT_NULL(*SXLineList))
			(*SXLineList)->prev = aSXLine;

		*SXLineList = aSXLine;

		/* Send it. */
		if (isQLine)
			send_cmd("SQLINE %s :%s", name, reason);
		else
			send_cmd("SGLINE %d :%s:%s", str_len(name), name, reason);

		TRACE_MAIN();

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 S%c:Lined \2%s\2 because: %s", source, data->commandName[1], name, reason);

			LOG_SNOOP(s_OperServ, "OS +S%c %s -- by %s (%s@%s) [%s]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, reason);
			log_services(LOG_SERVICES_OPERSERV, "+S%c %s -- by %s (%s@%s) [%s]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, reason);
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) S%c:Lined \2%s\2 because: %s", source, data->operName, data->commandName[1], name, reason);

			LOG_SNOOP(s_OperServ, "OS +S%c %s -- by %s (%s@%s) through %s [%s]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, data->operName, reason);
			log_services(LOG_SERVICES_OPERSERV, "+S%c %s -- by %s (%s@%s) through %s [%s]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, data->operName, reason);
		}

		if (usercount > 0)
			send_globops(s_OperServ, "Affects \2%d\2 user%s (%.3f%s): %s",
				usercount, (usercount == 1) ? "" : "s", percent, "%", affected_nicks);

		send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is now S%c:Lined because: %s", name, data->commandName[1], reason);

		if (CONF_SET_READONLY)
			send_notice_to_user(s_OperServ, callerUser, "\2Notice:\2 Services is in read-only mode. Changes will not be saved!");
	}
	else if (str_equals_nocase(command, "DEL")) {

		char		*err, *name;
		long int 	position;
		SXLine		*aSXLine = NULL, **SXLineList;


		if (IS_NULL(name = strtok(NULL, " "))) {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2S%cLINE\2 DEL field", data->commandName[1]);
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP S%cLINE\2 for more information.", data->commandName[1]);
			return;
		}

		SXLineList = (isQLine ? &SQLineList : &SGLineList);

		position = strtol(name, &err, 10);

		if ((position > 0) && (*err == '\0')) {

			aSXLine = *SXLineList;

			while (--position > 0) {

				aSXLine = aSXLine->next;

				if (IS_NULL(aSXLine)) {

					send_notice_to_user(s_OperServ, callerUser, "S%c:Line entry \2%s\2 not found.", data->commandName[1], name);
					return;
				}

				send_cmd("UNS%cLINE %s", data->commandName[1], aSXLine->name);
			}
		}
		else {

			/* Remove it first, in case it's an old one left on some server. */
			send_cmd("UNS%cLINE %s", data->commandName[1], name);

			aSXLine = *SXLineList;

			while (IS_NOT_NULL(aSXLine)) {

				if (str_equals_nocase(name, aSXLine->name))
					break;

				aSXLine = aSXLine->next;
			}

			if (IS_NULL(aSXLine)) {

				send_notice_to_user(s_OperServ, callerUser, "S%c:Line for \2%s\2 not found.", data->commandName[1], name);

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "OS -S%c* %s -- by %s (%s@%s) [Not S%c:Lined]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, data->commandName[1]);
				else
					LOG_SNOOP(s_OperServ, "OS -S%c* %s -- by %s (%s@%s) through %s [Not S%c:Lined]", data->commandName[1], name, callerUser->nick, callerUser->username, callerUser->host, data->operName, data->commandName[1]);

				return;
			}
		}

		if (IS_NULL(aSXLine)) {

			log_error(FACILITY_SXLINE_HANDLE_SXLINE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
				"handle_sxline() returned NULL value (source: %s, name: %s, position: %ld, isQLine: %s)", source, name, position, (isQLine ? "Yes" : "No"));

			return;
		}

		TRACE_MAIN();

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 removed S%c:Line on \2%s\2", source, data->commandName[1], aSXLine->name);

			LOG_SNOOP(s_OperServ, "OS -S%c %s -- by %s (%s@%s)", data->commandName[1], aSXLine->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_OPERSERV, "-S%c %s -- by %s (%s@%s)", data->commandName[1], aSXLine->name, callerUser->nick, callerUser->username, callerUser->host);
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) removed S%c:Line \2%s\2", source, data->operName, data->commandName[1], aSXLine->name);

			LOG_SNOOP(s_OperServ, "OS -S%c %s -- by %s (%s@%s) through %s", data->commandName[1], aSXLine->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_OPERSERV, "-S%c %s -- by %s (%s@%s) through %s", data->commandName[1], aSXLine->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
		}

		send_notice_to_user(s_OperServ, callerUser, "\2%s\2 removed from the S%c:Line List.", aSXLine->name, data->commandName[1]);

		if (CONF_SET_READONLY)
			send_notice_to_user(s_OperServ, callerUser, "\2Notice:\2 Services is in readonly mode. Changes will not be saved!");

		TRACE_MAIN();
		/* Link around it. */
		if (aSXLine->next)
			aSXLine->next->prev = aSXLine->prev;

		if (aSXLine->prev)
			aSXLine->prev->next = aSXLine->next;
		else
			*SXLineList = aSXLine->next;

		/* Free it. */
		mem_free(aSXLine->name);

		str_creationinfo_free(&(aSXLine->info));

		mem_free(aSXLine);
	}
	else {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2S%cLINE\2 [ADD|DEL|LIST] field reason", data->commandName[1]);
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP S%cLINE\2 for more information.", data->commandName[1]);
	}
}


void sxline_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	BOOL	isQLine = (str_char_toupper(request[1]) == 'Q');
	SXLine	*aSXLine = (isQLine ? SQLineList : SGLineList);
	int		startIdx = 0, endIdx = 5, lineIdx = 0, sentIdx = 0;


	TRACE_FCLT(FACILITY_SXLINE_DS_DUMP);

	if (IS_NULL(aSXLine)) {

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2S%c:Line\2 List is empty.", str_char_toupper(request[1]));
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

				if ((value >= 0) && (*err == '\0')) {

					endIdx = value;

					request = strtok(NULL, " ");
				}
			}
		}
	}

	if (endIdx < startIdx)
		endIdx = (startIdx + 5);

	if (IS_NULL(request)) {

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2S%c:Line\2 List (showing entries %d-%d):", str_char_toupper(request[1]), startIdx, endIdx);
		LOG_DEBUG_SNOOP("Command: DUMP S%cLINE %d-%d -- by %s (%s@%s)", str_char_toupper(request[1]), startIdx, endIdx, callerUser->nick, callerUser->username, callerUser->host);
	}
	else {

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2S%c:Line\2 List (showing entries %d-%d matching %s):", str_char_toupper(request[1]), startIdx, endIdx, request);
		LOG_DEBUG_SNOOP("Command: DUMP S%cLINE %d-%d -- by %s (%s@%s) [Pattern: %s]", str_char_toupper(request[1]), startIdx, endIdx, callerUser->nick, callerUser->username, callerUser->host, request);
	}

	while (IS_NOT_NULL(aSXLine)) {

		++lineIdx;

		if (IS_NOT_NULL(request) && !str_match_wild_nocase(request, aSXLine->name)) {

			/* Doesn't match our search criteria, skip it. */
			aSXLine = aSXLine->next;
			continue;
		}

		++sentIdx;

		if (sentIdx < startIdx) {

			aSXLine = aSXLine->next;
			continue;
		}

		send_notice_to_user(sourceNick, callerUser, "%d) Address 0x%08X, size %d B",		lineIdx, (unsigned long)aSXLine, sizeof(SXLine));
		send_notice_to_user(sourceNick, callerUser, "Name: 0x%08X \2[\2%s\2]\2",			(unsigned long)aSXLine->name, str_get_valid_display_value(aSXLine->name));
		send_notice_to_user(sourceNick, callerUser, "Creator: 0x%08X \2[\2%s\2]\2",			(unsigned long)aSXLine->info.creator.name, str_get_valid_display_value(aSXLine->info.creator.name));
		send_notice_to_user(sourceNick, callerUser, "Reason: 0x%08X \2[\2%s\2]\2",			(unsigned long)aSXLine->info.reason, str_get_valid_display_value(aSXLine->info.reason));
		send_notice_to_user(sourceNick, callerUser, "Time Set C-time: %d",					aSXLine->info.creator.time);
		send_notice_to_user(sourceNick, callerUser, "Last Used C-time: %d",					aSXLine->lastUsed);
		send_notice_to_user(sourceNick, callerUser, "Next/Prev records: 0x%08X / 0x%08X",	(unsigned long)aSXLine->next, (unsigned long)aSXLine->prev);

		if (sentIdx >= endIdx)
			break;

		aSXLine = aSXLine->next;
	}
}


unsigned long int sxline_mem_report(CSTR sourceNick, const User *callerUser) {

	unsigned long int count = 0, mem = 0, total_mem = 0;
	SXLine *aSXLine;


	TRACE_FCLT(FACILITY_SXLINE_MEM_REPORT);

	send_notice_to_user(sourceNick, callerUser, "\2SXLINES\2:");

	/* SQLines. */
	aSXLine = SQLineList;

	while (IS_NOT_NULL(aSXLine)) {

		++count;

		mem += sizeof(SXLine);

		mem += str_len(aSXLine->name) + 1;
		mem += str_len(aSXLine->info.creator.name) + 1;
		mem += str_len(aSXLine->info.reason) + 1;

		aSXLine = aSXLine->next;
	}

	send_notice_to_user(sourceNick, callerUser, "SQLine List: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", count, mem / 1024, mem);
	total_mem += mem;


	/* SGLines. */
	count = 0;
	aSXLine = SGLineList;

	while (IS_NOT_NULL(aSXLine)) {

		++count;

		mem += sizeof(SXLine);

		mem += str_len(aSXLine->name) + 1;
		mem += str_len(aSXLine->info.creator.name) + 1;
		mem += str_len(aSXLine->info.reason) + 1;

		aSXLine = aSXLine->next;
	}

	send_notice_to_user(sourceNick, callerUser, "SGLine List: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", count, mem / 1024, mem);
	total_mem += mem;

	return total_mem;
}

#endif
