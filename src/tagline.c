/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* tagline.c - Taglines
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
#include "../inc/tagline.h"


/*********************************************************
 * Global variables                                      *
 *********************************************************/

/* Number of Tag lines in the database. */
int TaglineCount;


/*********************************************************
 * Local variables                                       *
 *********************************************************/

/* List of Tag lines. */
static Tagline *TaglineList;


/*********************************************************
 * Public code                                           *
 *********************************************************/

BOOL tagline_db_load(void) {

	STGHANDLE	stg = 0;
	STG_RESULT	result;


	TRACE_FCLT(FACILITY_TAGLINE_DB_LOAD);

	result = stg_open(TAGLINE_DB, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version;
			BOOL		in_section;
			BOOL		read_done;


			version = stg_data_version(stg);

			switch (version) {

				case TAGLINE_DB_CURRENT_VERSION: {

					Tagline_V10		*aTagline;


					// start-of-section marker
					result = stg_read_record(stg, NULL, 0);

					if (result == stgBeginOfSection) {

						in_section = TRUE;

						while (in_section) {

							aTagline = mem_malloc(sizeof(Tagline_V10));

							result = stg_read_record(stg, (PBYTE)aTagline, sizeof(Tagline_V10));

							switch (result) {

								case stgEndOfSection: // end-of-section
									in_section = FALSE;
									mem_free(aTagline);
									break;

								case stgSuccess: // a valid record

									read_done = TRUE;

									read_done &= (result = stg_read_string(stg, &(aTagline->text), NULL)) == stgSuccess;

									if (read_done)
										read_done &= (result = stg_read_string(stg, &(aTagline->creator.name), NULL)) == stgSuccess;

									if (!read_done)
										fatal_error(FACILITY_TAGLINE_DB_LOAD, __LINE__, "Read error on %s (2) - %s", TAGLINE_DB, stg_result_to_string(result));

									aTagline->next = TaglineList;
									aTagline->prev = NULL;

									if (IS_NOT_NULL(TaglineList))
										TaglineList->prev = aTagline;

									TaglineList = aTagline;

									++TaglineCount;
									break;

								default: // some error
									fatal_error(FACILITY_TAGLINE_DB_LOAD, __LINE__, "Read error on %s - %s", TAGLINE_DB, stg_result_to_string(result));
							}
						}
					}
					else
						fatal_error(FACILITY_TAGLINE_DB_LOAD, __LINE__, "Read error on %s : invalid format", TAGLINE_DB);

					stg_close(stg, TAGLINE_DB);
					return TRUE;
				}

				default:
					fatal_error(FACILITY_TAGLINE_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, TAGLINE_DB);
			}
		}

		case stgNotFound: // no data to load
			return TRUE;

		default: // error!
			stg_close(stg, TAGLINE_DB);

			fatal_error(FACILITY_TAGLINE_DB_LOAD, __LINE__, "Error opening %s - %s", TAGLINE_DB, stg_result_to_string(result));
			return FALSE;
	}
}


BOOL tagline_db_save(void) {

	STGHANDLE		stg;
	STG_RESULT		result;
	Tagline			*aTagline;
	char			*strings[2];
	int				error_index;


	TRACE_FCLT(FACILITY_TAGLINE_DB_SAVE);

	result = stg_create(TAGLINE_DB, SF_NOFLAGS, TAGLINE_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_TAGLINE_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"operserv_tagline_db_save(): Could not create database file %s: %s [Error %d: %s]", TAGLINE_DB, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	result = stg_start_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_TAGLINE_DB_SAVE, __LINE__, "Write error on %s - %s", TAGLINE_DB, stg_result_to_string(result));

	aTagline = TaglineList;

	while (IS_NOT_NULL(aTagline)) {

		result = stg_write_record(stg, (PBYTE)aTagline, sizeof(Tagline));

		if (result != stgSuccess)
			fatal_error(FACILITY_TAGLINE_DB_SAVE, __LINE__, "Write error on %s - %s", TAGLINE_DB, stg_result_to_string(result));

		strings[0] = aTagline->text;
		strings[1] = aTagline->creator.name;

		error_index = -1;

		result = stg_write_strings(stg, strings, sizeof(strings) / sizeof(char *), &error_index);

		if (result != stgSuccess)
			fatal_error(FACILITY_TAGLINE_DB_SAVE, __LINE__, "Write error on %s for string n. %d - %s", TAGLINE_DB, error_index, stg_result_to_string(result));

		aTagline = aTagline->next;
	}

	result = stg_end_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_TAGLINE_DB_SAVE, __LINE__, "Write error on %s - %s", TAGLINE_DB, stg_result_to_string(result));

	stg_close(stg, TAGLINE_DB);
	return TRUE;
}


void handle_tagline(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *command;


	TRACE_MAIN_FCLT(FACILITY_TAGLINE_HANDLE_TAGLINE);

	if (IS_NULL(command = strtok(NULL, " "))) {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2TAGLINE\2 [ADD|DEL|LIST] text");
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP TAGLINE\2 for more information.");
	}
	else if (str_equals_nocase(command, "LIST")) {

		char	timebuf[64];
		int 	taglineIdx = 0, startIdx = 0, endIdx = 30, sentIdx = 0;
		char	*pattern;
		Tagline	*aTagline;


		if (IS_NULL(TaglineList)) {

			send_notice_to_user(s_OperServ, callerUser, "The Tagline List is empty.");
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
			send_notice_to_user(s_OperServ, callerUser, "Current \2Tagline\2 List (showing entries %d-%d):", startIdx, endIdx);
		else
			send_notice_to_user(s_OperServ, callerUser, "Current \2Tagline\2 List (showing entries %d-%d matching %s):", startIdx, endIdx, pattern);

		aTagline = TaglineList;

		while (IS_NOT_NULL(aTagline)) {

			++taglineIdx;

			if (IS_NOT_NULL(pattern) && !str_match_wild_nocase(pattern, aTagline->text)) {

				/* Doesn't match our search criteria, skip it. */
				aTagline = aTagline->next;
				continue;
			}

			++sentIdx;

			if (sentIdx < startIdx) {

				aTagline = aTagline->next;
				continue;
			}

			lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, aTagline->creator.time);

			send_notice_to_user(s_OperServ, callerUser, "%d) %s", taglineIdx, aTagline->text);
			send_notice_to_user(s_OperServ, callerUser, "Set by \2%s\2 on %s", aTagline->creator.name, timebuf);

			if (sentIdx >= endIdx)
				break;

			aTagline = aTagline->next;
		}

		send_notice_to_user(s_OperServ, callerUser, "*** \2End of List\2 ***");
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SOP))
		send_notice_lang_to_user(s_OperServ, callerUser, GetCallerLang(), OPER_ERROR_ACCESS_DENIED);

	else if (str_equals_nocase(command, "ADD")) {

		char		*text;
		size_t		len;
		Tagline		*aTagline;


		if (IS_NULL(text = strtok(NULL, ""))) {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2TAGLINE ADD\2 text");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP SGLINE\2 for more information.");
			return;
		}

		if ((len = str_len(text)) > 260) {

			send_notice_to_user(s_OperServ, callerUser, "The maximum length for a tagline is 260 characters. Your tagline has %d.", len);
			return;
		}

		if (!validate_string(text)) {

			send_notice_to_user(s_OperServ, callerUser, "Invalid text supplied.");
			return;
		}

		terminate_string_ccodes(text);

		aTagline = TaglineList;

		while (IS_NOT_NULL(aTagline)) {

			if (str_equals_nocase(text, aTagline->text)) {

				send_notice_to_user(s_OperServ, callerUser, "This text is already taglined!");

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "OS +TG* -- by %s (%s@%s) [Already Taglined]", callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(s_OperServ, "OS +TG* -- by %s (%s@%s) through %s [Already Taglined]", callerUser->nick, callerUser->username, callerUser->host, data->operName);

				return;
			}

			aTagline = aTagline->next;
		}

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 added the following tagline: %s", source, text);

			LOG_SNOOP(s_OperServ, "OS +TG -- by %s (%s@%s) [%s]", callerUser->nick, callerUser->username, callerUser->host, text);
			log_services(LOG_SERVICES_OPERSERV, "+TG -- by %s (%s@%s) [%s]", callerUser->nick, callerUser->username, callerUser->host, text);
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) added the following tagline: %s", source, data->operName, text);

			LOG_SNOOP(s_OperServ, "OS +TG -- by %s (%s@%s) through %s [%s]", callerUser->nick, callerUser->username, callerUser->host, data->operName, text);
			log_services(LOG_SERVICES_OPERSERV, "+TG -- by %s (%s@%s) through %s [%s]", callerUser->nick, callerUser->username, callerUser->host, data->operName, text);
		}

		send_notice_to_user(s_OperServ, callerUser, "Your tagline has been added successfully.");

		if (CONF_SET_READONLY)
			send_notice_to_user(s_OperServ, callerUser, "\2Notice:\2 Services is in readonly mode. Changes will not be saved!");

		TRACE_MAIN();

		/* Allocate the new entry. */
		aTagline = mem_malloc(sizeof(Tagline));

		/* Fill it. */
		aTagline->text = str_duplicate(text);

		str_creator_init(&(aTagline->creator));
		str_creator_set(&(aTagline->creator), data->operName, NOW);

		/* Link it. */
		aTagline->next = TaglineList;
		aTagline->prev = NULL;

		if (IS_NOT_NULL(TaglineList))
			TaglineList->prev = aTagline;

		TaglineList = aTagline;

		/* Increase tagline counter. */
		++TaglineCount;
	}
	else if (str_equals_nocase(command, "DEL")) {

		char		*text, *err;
		long int	taglineIdx;
		Tagline		*aTagline;


		if (IS_NULL(text = strtok(NULL, ""))) {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2TAGLINE DEL\2 [text|number]");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP SGLINE\2 for more information.");
			return;
		}

		if (str_len(text) > 260) {

			send_notice_to_user(s_OperServ, callerUser, "Tagline not found.");
			return;
		}

		aTagline = TaglineList;

		taglineIdx = strtol(text, &err, 10);

		if ((taglineIdx > 0) && (*err == '\0')) {

			while (--taglineIdx > 0) {

				aTagline = aTagline->next;

				if (IS_NULL(aTagline)) {

					send_notice_to_user(s_OperServ, callerUser, "Tagline entry %s not found.", text);
					return;
				}
			}
		}
		else {

			while (IS_NOT_NULL(aTagline)) {

				if (str_equals_nocase(text, aTagline->text))
					break;

				aTagline = aTagline->next;
			}

			if (IS_NULL(aTagline)) {

				send_notice_to_user(s_OperServ, callerUser, "Tagline not found.");

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "OS -TG* -- by %s (%s@%s) [Not Found: %s]", callerUser->nick, callerUser->username, callerUser->host, text);
				else
					LOG_SNOOP(s_OperServ, "OS -TG* -- by %s (%s@%s) through %s [Not Found: %s]", callerUser->nick, callerUser->username, callerUser->host, data->operName, text);

				return;
			}
		}

		TRACE_MAIN();

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 removed the following tagline: %s", source, aTagline->text);

			LOG_SNOOP(s_OperServ, "OS -TG -- by %s (%s@%s) [%s]", callerUser->nick, callerUser->username, callerUser->host, aTagline->text);
			log_services(LOG_SERVICES_OPERSERV, "-TG -- by %s (%s@%s) [%s]", callerUser->nick, callerUser->username, callerUser->host, aTagline->text);
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) removed the following tagline: %s", source, data->operName, aTagline->text);

			LOG_SNOOP(s_OperServ, "OS -TG -- by %s (%s@%s) through %s [%s]", callerUser->nick, callerUser->username, callerUser->host, data->operName, aTagline->text);
			log_services(LOG_SERVICES_OPERSERV, "-TG -- by %s (%s@%s) through %s [%s]", callerUser->nick, callerUser->username, callerUser->host, data->operName, aTagline->text);
		}

		send_notice_to_user(s_OperServ, callerUser, "Tagline removed successfully.");

		if (CONF_SET_READONLY)
			send_notice_to_user(s_OperServ, callerUser, "\2Notice:\2 Services is in readonly mode. Changes will not be saved!");

		TRACE_MAIN();

		/* Link around it. */
		if (IS_NOT_NULL(aTagline->next))
			aTagline->next->prev = aTagline->prev;

		if (IS_NOT_NULL(aTagline->prev))
			aTagline->prev->next = aTagline->next;
		else
			TaglineList = aTagline->next;

		/* Decrease the tagline counter. */
		--TaglineCount;

		/* Free data. */
		mem_free(aTagline->text);
		str_creator_free(&(aTagline->creator));
		mem_free(aTagline);
	}
	else {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2TAGLINE\2 [ADD|DEL|LIST] text");
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP TAGLINE\2 for more information.");
	}
}


void tagline_show(const time_t now) {

	int		tagIdx;
	Tagline	*aTagline;


	TRACE_FCLT(FACILITY_TAGLINE_SHOW);

	if (!CONF_SHOW_TAGLINES || IS_NULL(TaglineList)) {

		send_globops(NULL, "Completed database write (%d secs)", time(NULL) - now);
		return;
	}

	srand(randomseed());
	tagIdx = getrandom(1, TaglineCount);

	aTagline = TaglineList;

	while (--tagIdx > 0) {

		aTagline = aTagline->next;

		if (IS_NULL(aTagline)) {

			log_error(FACILITY_TAGLINE_SHOW, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
				"tagline_show() returned NULL value (tagIdx: %d)", tagIdx);

			send_globops(NULL, "Completed database write (%d secs)", time(NULL) - now);
			return;
		}
	}

	send_globops(NULL, "Completed database write (%d secs) -> %s", (time(NULL) - now), aTagline->text);
}


void tagline_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	Tagline *aTagline;
	int		startIdx = 0, endIdx = 5, taglineIdx = 0, sentIdx = 0;


	TRACE_FCLT(FACILITY_TAGLINE_DS_DUMP);

	if (IS_NULL(TaglineList)) {

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2Tagline\2 List is empty.");
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

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2Tagline\2 List (showing entries %d-%d):", startIdx, endIdx);
		LOG_DEBUG_SNOOP("Command: DUMP TAGLINES %d-%d -- by %s (%s@%s)", startIdx, endIdx, callerUser->nick, callerUser->username, callerUser->host);
	}
	else {

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2Tagline\2 List (showing entries %d-%d matching %s):", startIdx, endIdx, request);
		LOG_DEBUG_SNOOP("Command: DUMP TAGLINES %d-%d -- by %s (%s@%s) [Pattern: %s]", startIdx, endIdx, callerUser->nick, callerUser->username, callerUser->host, request);
	}

	aTagline = TaglineList;

	while (IS_NOT_NULL(aTagline)) {

		++taglineIdx;

		if (IS_NOT_NULL(request) && !str_match_wild_nocase(request, aTagline->text)) {

			/* Doesn't match our search criteria, skip it. */
			aTagline = aTagline->next;
			continue;
		}

		++sentIdx;

		if (sentIdx < startIdx) {

			aTagline = aTagline->next;
			continue;
		}

		send_notice_to_user(sourceNick, callerUser, "%d) Address 0x%08X, size %d B",		taglineIdx, (unsigned long)aTagline, sizeof(Tagline));
		send_notice_to_user(sourceNick, callerUser, "Text: 0x%08X \2[\2%s\2]\2",			(unsigned long)aTagline->text, str_get_valid_display_value(aTagline->text));
		send_notice_to_user(sourceNick, callerUser, "Creator: 0x%08X \2[\2%s\2]\2",			(unsigned long)aTagline->creator.name, str_get_valid_display_value(aTagline->creator.name));
		send_notice_to_user(sourceNick, callerUser, "Time Set C-time: %d",					aTagline->creator.time);
		send_notice_to_user(sourceNick, callerUser, "Next/Prev records: 0x%08X / 0x%08X",	(unsigned long)aTagline->next, (unsigned long)aTagline->prev);

		if (sentIdx >= endIdx)
			break;

		aTagline = aTagline->next;
	}
}


unsigned long int tagline_mem_report(CSTR sourceNick, const User *callerUser) {

	unsigned long int count = 0, mem = 0;
	Tagline *aTagline;


	TRACE_FCLT(FACILITY_TAGLINE_MEM_REPORT);

	send_notice_to_user(sourceNick, callerUser, "\2TAGLINES\2:");

	aTagline = TaglineList;

	while (IS_NOT_NULL(aTagline)) {

		++count;

		mem += sizeof(Tagline);

		mem += str_len(aTagline->text) + 1;
		mem += str_len(aTagline->creator.name) + 1;

		aTagline = aTagline->next;
	}

	send_notice_to_user(sourceNick, callerUser, "Tagline List: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", count, mem / 1024, mem);
	return mem;
}

#endif
