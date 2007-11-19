/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* trigger.c - Clone triggers
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
#include "../inc/cidr.h"
#include "../inc/conf.h"
#include "../inc/misc.h"
#include "../inc/trigger.h"


/*********************************************************
 * Local variables                                       *
 *********************************************************/

/* List of Triggers. */
static Trigger *TriggerList;

/* List of Exempts. */
static Exempt *ExemptList;


/*********************************************************
 * Private code                                          *
 *********************************************************/

/*********************************************************
 * This function removes an entry from the Trigger list, *
 * logging the action and notifying the network.         *
 *********************************************************/

static void remove_trigger(Trigger *aTrigger, const User *callerUser, BOOL operMatch, CSTR operName) {

	if (operMatch) {

		send_globops(s_OperServ, "\2%s\2 reset Trigger for \2%s@%s\2", callerUser->nick, aTrigger->username ?: "*", aTrigger->host);

		LOG_SNOOP(s_OperServ, "OS -T %s@%s -- by %s (%s@%s)", aTrigger->username ?: "*", aTrigger->host, callerUser->nick, callerUser->username, callerUser->host);
		log_services(LOG_SERVICES_OPERSERV, "-T %s@%s -- by %s (%s@%s)", aTrigger->username ?: "*", aTrigger->host, callerUser->nick, callerUser->username, callerUser->host);
	}
	else {

		send_globops(s_OperServ, "\2%s\2 (through \2%s\2) reset Trigger for \2%s@%s\2", callerUser->nick, operName, aTrigger->username ?: "*", aTrigger->host);

		LOG_SNOOP(s_OperServ, "OS -T %s@%s -- by %s (%s@%s) through %s", aTrigger->username ?: "*", aTrigger->host, callerUser->nick, callerUser->username, callerUser->host, operName);
		log_services(LOG_SERVICES_OPERSERV, "-T %s@%s -- by %s (%s@%s) through %s", aTrigger->username ?: "*", aTrigger->host, callerUser->nick, callerUser->username, callerUser->host, operName);
	}

	TRACE_MAIN();
	send_notice_to_user(s_OperServ, callerUser, "Trigger for \2%s@%s\2 has been reset.", aTrigger->username ?: "*", aTrigger->host);

	/* Link around it. */
	if (IS_NOT_NULL(aTrigger->next))
		aTrigger->next->prev = aTrigger->prev;

	if (IS_NOT_NULL(aTrigger->prev))
		aTrigger->prev->next = aTrigger->next;
	else
		TriggerList = aTrigger->next;

	/* Free it. */
	if (IS_NOT_NULL(aTrigger->username))
		mem_free(aTrigger->username);

	mem_free(aTrigger->host);

	str_creationinfo_free(&(aTrigger->info));

	mem_free(aTrigger);
}


/*********************************************************
 * Public code                                           *
 *********************************************************/

BOOL trigger_db_load(void) {

	STGHANDLE	stg = 0;
	STG_RESULT	result;


	TRACE_FCLT(FACILITY_TRIGGER_DB_LOAD);

	result = stg_open(TRIGGER_DB, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version;
			BOOL		in_section;
			BOOL		read_done;


			version = stg_data_version(stg);

			switch (version) {

				case TRIGGER_DB_CURRENT_VERSION: {

					Trigger_V10		*aTrigger;


					// start-of-section marker
					result = stg_read_record(stg, NULL, 0);

					if (result == stgBeginOfSection) {

						in_section = TRUE;

						while (in_section) {

							aTrigger = mem_malloc(sizeof(Trigger_V10));

							result = stg_read_record(stg, (PBYTE)aTrigger, sizeof(Trigger_V10));

							switch (result) {

								case stgEndOfSection: // end-of-section
									in_section = FALSE;
									mem_free(aTrigger);
									break;

								case stgSuccess: // a valid record

									read_done = TRUE;

									if (IS_NOT_NULL(aTrigger->username))
										read_done &= (result = stg_read_string(stg, &(aTrigger->username), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(aTrigger->host))
										read_done &= (result = stg_read_string(stg, &(aTrigger->host), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(aTrigger->info.creator.name))
										read_done &= (result = stg_read_string(stg, &(aTrigger->info.creator.name), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(aTrigger->info.reason))
										read_done &= (result = stg_read_string(stg, &(aTrigger->info.reason), NULL)) == stgSuccess;

									if (!read_done)
										fatal_error(FACILITY_TRIGGER_DB_LOAD, __LINE__, "Read error on %s (2) - %s", TRIGGER_DB, stg_result_to_string(result));

									aTrigger->next = TriggerList;
									aTrigger->prev = NULL;

									if (IS_NOT_NULL(TriggerList))
										TriggerList->prev = aTrigger;

									TriggerList = aTrigger;
									break;

								default: // some error
									fatal_error(FACILITY_TRIGGER_DB_LOAD, __LINE__, "Read error on %s - %s", TRIGGER_DB, stg_result_to_string(result));
							}
						}
					}
					else
						fatal_error(FACILITY_TRIGGER_DB_LOAD, __LINE__, "Read error on %s : invalid format", TRIGGER_DB);

					stg_close(stg, TRIGGER_DB);
					return TRUE;
				}

				default:
					fatal_error(FACILITY_TRIGGER_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, TRIGGER_DB);
			}
		}

		case stgNotFound: // no data to load
			return TRUE;

		default: // error!
			stg_close(stg, TRIGGER_DB);

			fatal_error(FACILITY_TRIGGER_DB_LOAD, __LINE__, "Error opening %s - %s", TRIGGER_DB, stg_result_to_string(result));
			return FALSE;
	}
}


BOOL trigger_db_save(void) {

	STGHANDLE		stg;
	STG_RESULT		result;
	Trigger			*aTrigger;
	char			*strings[4];
	int				error_index;


	TRACE_FCLT(FACILITY_TRIGGER_DB_SAVE);

	result = stg_create(TRIGGER_DB, SF_NOFLAGS, TRIGGER_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_TRIGGER_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"trigger_db_save(): Could not create database file %s: %s [Error %d: %s]", TRIGGER_DB, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	result = stg_start_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_TRIGGER_DB_SAVE, __LINE__, "Write error on %s - %s", TRIGGER_DB, stg_result_to_string(result));

	aTrigger = TriggerList;

	while (IS_NOT_NULL(aTrigger)) {

		result = stg_write_record(stg, (PBYTE)aTrigger, sizeof(Trigger));

		if (result != stgSuccess)
			fatal_error(FACILITY_TRIGGER_DB_SAVE, __LINE__, "Write error on %s - %s", TRIGGER_DB, stg_result_to_string(result));

		strings[0] = aTrigger->username;
		strings[1] = aTrigger->host;
		strings[2] = aTrigger->info.creator.name;
		strings[3] = aTrigger->info.reason;

		error_index = -1;

		result = stg_write_strings(stg, strings, sizeof(strings) / sizeof(char *), &error_index);

		if (result != stgSuccess)
			fatal_error(FACILITY_TRIGGER_DB_SAVE, __LINE__, "Write error on %s for string n. %d - %s", TRIGGER_DB, error_index, stg_result_to_string(result));

		aTrigger = aTrigger->next;
	}

	result = stg_end_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_TRIGGER_DB_SAVE, __LINE__, "Write error on %s - %s", TRIGGER_DB, stg_result_to_string(result));

	stg_close(stg, TRIGGER_DB);
	return TRUE;
}


BOOL exempt_db_load(void) {

	STGHANDLE	stg = 0;
	STG_RESULT	result;


	TRACE_FCLT(FACILITY_TRIGGER_EXEMPT_DB_LOAD);

	result = stg_open(EXEMPT_DB, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version;
			BOOL		in_section;
			BOOL		read_done;


			version = stg_data_version(stg);

			switch (version) {

				case EXEMPT_DB_CURRENT_VERSION: {

					Exempt_V10		*anExempt;


					// start-of-section marker
					result = stg_read_record(stg, NULL, 0);

					if (result == stgBeginOfSection) {

						in_section = TRUE;

						while (in_section) {

							anExempt = mem_malloc(sizeof(Exempt_V10));

							result = stg_read_record(stg, (PBYTE)anExempt, sizeof(Exempt_V10));

							switch (result) {

								case stgEndOfSection: // end-of-section
									in_section = FALSE;
									mem_free(anExempt);
									break;

								case stgSuccess: // a valid record

									read_done = TRUE;

									if (IS_NOT_NULL(anExempt->realname))
										read_done &= (result = stg_read_string(stg, &(anExempt->realname), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anExempt->info.creator.name))
										read_done &= (result = stg_read_string(stg, &(anExempt->info.creator.name), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anExempt->info.reason))
										read_done &= (result = stg_read_string(stg, &(anExempt->info.reason), NULL)) == stgSuccess;

									if (!read_done)
										fatal_error(FACILITY_TRIGGER_EXEMPT_DB_LOAD, __LINE__, "Read error on %s (2) - %s", EXEMPT_DB, stg_result_to_string(result));

									anExempt->next = ExemptList;
									anExempt->prev = NULL;

									if (IS_NOT_NULL(ExemptList))
										ExemptList->prev = anExempt;

									ExemptList = anExempt;
									break;

								default: // some error
									fatal_error(FACILITY_TRIGGER_EXEMPT_DB_LOAD, __LINE__, "Read error on %s - %s", EXEMPT_DB, stg_result_to_string(result));
							}
						}
					}
					else
						fatal_error(FACILITY_TRIGGER_EXEMPT_DB_LOAD, __LINE__, "Read error on %s : invalid format", EXEMPT_DB);

					stg_close(stg, EXEMPT_DB);
					return TRUE;
				}

				default:
					fatal_error(FACILITY_TRIGGER_EXEMPT_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, EXEMPT_DB);
			}
		}

		case stgNotFound: // no data to load
			return TRUE;

		default: // error!
			stg_close(stg, EXEMPT_DB);

			fatal_error(FACILITY_TRIGGER_EXEMPT_DB_LOAD, __LINE__, "Error opening %s - %s", EXEMPT_DB, stg_result_to_string(result));
			return FALSE;
	}
}


BOOL exempt_db_save(void) {

	STGHANDLE		stg;
	STG_RESULT		result;
	Exempt			*anExempt;
	char			*strings[3];
	int				error_index;


	TRACE_FCLT(FACILITY_TRIGGER_EXEMPT_DB_SAVE);

	result = stg_create(EXEMPT_DB, SF_NOFLAGS, EXEMPT_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_TRIGGER_EXEMPT_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"exempt_db_save(): Could not create database file %s: %s [Error %d: %s]", EXEMPT_DB, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	result = stg_start_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_TRIGGER_EXEMPT_DB_SAVE, __LINE__, "Write error on %s - %s", EXEMPT_DB, stg_result_to_string(result));

	anExempt = ExemptList;

	while (IS_NOT_NULL(anExempt)) {

		result = stg_write_record(stg, (PBYTE)anExempt, sizeof(Exempt));

		if (result != stgSuccess)
			fatal_error(FACILITY_TRIGGER_EXEMPT_DB_SAVE, __LINE__, "Write error on %s - %s", EXEMPT_DB, stg_result_to_string(result));

		strings[0] = anExempt->realname;
		strings[1] = anExempt->info.creator.name;
		strings[2] = anExempt->info.reason;

		error_index = -1;

		result = stg_write_strings(stg, strings, sizeof(strings) / sizeof(char *), &error_index);

		if (result != stgSuccess)
			fatal_error(FACILITY_TRIGGER_EXEMPT_DB_SAVE, __LINE__, "Write error on %s for string n. %d - %s", EXEMPT_DB, error_index, stg_result_to_string(result));

		anExempt = anExempt->next;
	}

	result = stg_end_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_TRIGGER_EXEMPT_DB_SAVE, __LINE__, "Write error on %s - %s", EXEMPT_DB, stg_result_to_string(result));

	stg_close(stg, EXEMPT_DB);
	return TRUE;
}


TRIGGER_RESULT trigger_match(CSTR username, CSTR host, const unsigned long int ip, const int cloneCount, char **reason, int *position) {

	Trigger *aTrigger;
	int idx = 0;


	TRACE_FCLT(FACILITY_TRIGGER_MATCH);

	aTrigger = TriggerList;

	while (IS_NOT_NULL(aTrigger)) {

		++idx;

		if (IS_NULL(aTrigger->username) || str_match_wild_nocase(aTrigger->username, username)) {

			if (FlagSet(aTrigger->flags, TRIGGER_FLAG_HOST) ?
				(str_match_wild_nocase(aTrigger->host, host)) :
				(cidr_match(&(aTrigger->cidr), ip))) {

				if (cloneCount <= 0)
					return triggerFound;

				/* We've used this trigger, update it. */
				aTrigger->lastUsed = NOW;

				if (cloneCount < aTrigger->value)
					return triggerExempt;

				/* Point 'reason' to the trigger's reason. */
				if (IS_NOT_NULL(reason))
					*reason = aTrigger->info.reason;

				/* Point 'position' to the trigger's position in the array. */
				if (IS_NOT_NULL(position))
					*position = idx;

				return triggerFound;
			}
		}

		aTrigger = aTrigger->next;
	}

	return triggerNotFound;
}


BOOL exempt_match(CSTR realname, int *position) {

	Exempt *anExempt;
	int idx = 0;


	TRACE_FCLT(FACILITY_TRIGGER_EXEMPT_MATCH);

	anExempt = ExemptList;

	while (IS_NOT_NULL(anExempt)) {

		++idx;

		if (str_match_wild_nocase(anExempt->realname, realname)) {

			*position = idx;
			return TRUE;
		}

		anExempt = anExempt->next;
	}

	return FALSE;
}


void handle_trigger(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *command;


	TRACE_MAIN_FCLT(FACILITY_TRIGGER_HANDLE_TRIGGER);

	if (IS_NULL(command = strtok(NULL, " "))) {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2TRIGGER\2 ADD|DEL|CHECK|EXEMPT|LIST user@host [value] [reason]");
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP TRIGGER\2 for more information.");
	}
	else if (str_equals_nocase(command, "EXEMPT")) {

		char *action;

		if (IS_NULL(action = strtok(NULL, " "))) {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2TRIGGER\2 EXEMPT ADD|DEL|LIST");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP TRIGGER\2 for more information.");
		}
		else if (str_equals_nocase(action, "LIST")) {

			char		timebuf[64], usedbuf[64];
			char		*pattern;
			int 		exemptIdx = 0, startIdx = 0, endIdx = 30, sentIdx = 0;
			Exempt		*anExempt;


			if (IS_NULL(ExemptList)) {

				send_notice_to_user(s_OperServ, callerUser, "The Trigger List is empty.");
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
				send_notice_to_user(s_OperServ, callerUser, "Current \2Trigger Exempt\2 list (showing entries %d-%d):", startIdx, endIdx);
			else
				send_notice_to_user(s_OperServ, callerUser, "Current \2Trigger Exempt\2 list (showing entries %d-%d matching %s):", startIdx, endIdx, pattern);

			anExempt = ExemptList;

			while (IS_NOT_NULL(anExempt)) {

				++exemptIdx;

				if (IS_NOT_NULL(pattern) && !str_match_wild_nocase(pattern, anExempt->realname)) {

					/* Doesn't match our search criteria, skip it. */
					anExempt = anExempt->next;
					continue;
				}

				++sentIdx;

				if (sentIdx < startIdx) {

					anExempt = anExempt->next;
					continue;
				}

				lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, anExempt->info.creator.time);

				send_notice_to_user(s_OperServ, callerUser, "%d) \2%s\2 [Reason: %s]", exemptIdx, anExempt->realname, anExempt->info.reason);
				send_notice_to_user(s_OperServ, callerUser, "Set by \2%s\2 on %s [Last used: %s]", anExempt->info.creator.name, timebuf, (anExempt->lastUsed == 0) ? "Never" : convert_time(usedbuf, sizeof(usedbuf), (NOW - anExempt->lastUsed), LANG_DEFAULT));

				if (sentIdx >= endIdx)
					break;

				anExempt = anExempt->next;
			}

			send_notice_to_user(s_OperServ, callerUser, "\2*** End of List ***\2");
		}
		else if (str_equals_nocase(command, "ADD")) {

			char *realname, *reason;
			Exempt *anExempt;


			if (IS_NULL(realname = strtok(NULL, " ")) || IS_NULL(reason = strtok(NULL, " "))) {

				send_notice_to_user(s_OperServ, callerUser, "Syntax: TRIGGER EXEMPT ADD realname reason");
				return;
			}

			if (str_len(realname) > REALMAX) {

				send_notice_to_user(s_OperServ, callerUser, "Maximum length for a realname is \2%d\2 characters.", REALMAX);
				return;
			}

			if (str_len(reason) > 80) {

				send_notice_to_user(s_OperServ, callerUser, "Maximum length for a reason is \2%d\2 characters.", 80);
				return;
			}

			str_compact(realname);
			terminate_string_ccodes(realname);

			anExempt = ExemptList;

			while (IS_NOT_NULL(anExempt)) {

				if (str_equals_nocase(anExempt->realname, realname)) {

					send_notice_to_user(s_OperServ, callerUser, "Realname \2%s\2 is already exempt.", realname);

					if (data->operMatch)
						LOG_SNOOP(s_OperServ, "OS +TE* %s -- by %s (%s@%s) [Already Exempt]", realname, callerUser->nick, callerUser->username, callerUser->host);
					else
						LOG_SNOOP(s_OperServ, "OS +TE* %s -- by %s (%s@%s) through %s [Already Exempt]", realname, callerUser->nick, callerUser->username, callerUser->host, data->operName);

					return;
				}

				anExempt = anExempt->next;
			}

			terminate_string_ccodes(reason);

			/* Allocate the new exempt. */
			anExempt = mem_calloc(1, sizeof(Exempt));

			/* Link it. */
			anExempt->next = ExemptList;
			anExempt->prev = NULL;

			if (IS_NOT_NULL(ExemptList))
				ExemptList->prev = anExempt;

			ExemptList = anExempt;

			/* Fill it. */
			anExempt->realname = str_duplicate(realname);

			str_creationinfo_init(&(anExempt->info));
			str_creationinfo_set(&(anExempt->info), data->operName, reason, NOW);

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 added a trigger exempt on realname \2%s\2 [Reason: %s]", source, realname, reason);

				LOG_SNOOP(s_OperServ, "OS +TE %s -- by %s (%s@%s)", realname, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "+TE %s -- by %s (%s@%s) [Reason: %s]", realname, callerUser->nick, callerUser->username, callerUser->host, reason);
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) added a trigger exempt on realname \2%s\2 [Reason: %s]", source, data->operName, realname, reason);

				LOG_SNOOP(s_OperServ, "OS +TE %s -- by %s (%s@%s) through %s", realname, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "+TE %s -- by %s (%s@%s) through %s [Reason: %s]", realname, callerUser->nick, callerUser->username, callerUser->host, data->operName, reason);
			}

			send_notice_to_user(s_OperServ, callerUser, "Exempt for \2%s\2 added successfully.", realname);
		}
		else if (str_equals_nocase(action, "DEL")) {

			char *realname;
			Exempt *anExempt;


			if (IS_NULL(realname = strtok(NULL, " "))) {

				send_notice_to_user(s_OperServ, callerUser, "Syntax: TRIGGER EXEMPT DEL realname");
				return;
			}

			str_compact(realname);
			terminate_string_ccodes(realname);

			anExempt = ExemptList;

			while (IS_NOT_NULL(anExempt)) {

				if (str_equals_nocase(anExempt->realname, realname)) {

					if (data->operMatch) {

						send_globops(s_OperServ, "\2%s\2 removed trigger exempt for \2%s\2", callerUser->nick, anExempt->realname);

						LOG_SNOOP(s_OperServ, "OS -TE %s -- by %s (%s@%s)", anExempt->realname, callerUser->nick, callerUser->username, callerUser->host);
						log_services(LOG_SERVICES_OPERSERV, "-TE %s -- by %s (%s@%s)", anExempt->realname, callerUser->nick, callerUser->username, callerUser->host);
					}
					else {

						send_globops(s_OperServ, "\2%s\2 (through \2%s\2) removed trigger exempt for \2%s\2", callerUser->nick, data->operName, anExempt->realname);

						LOG_SNOOP(s_OperServ, "OS -TE %s -- by %s (%s@%s) through %s", anExempt->realname, callerUser->nick, callerUser->username, callerUser->host, data->operName);
						log_services(LOG_SERVICES_OPERSERV, "-TE %s -- by %s (%s@%s) through %s", anExempt->realname, callerUser->nick, callerUser->username, callerUser->host, data->operName);
					}

					TRACE_MAIN();
					send_notice_to_user(s_OperServ, callerUser, "Exempt for \2%s\2 has been removed.", anExempt->realname);

					/* Link around it. */
					if (IS_NOT_NULL(anExempt->next))
						anExempt->next->prev = anExempt->prev;

					if (IS_NOT_NULL(anExempt->prev))
						anExempt->prev->next = anExempt->next;
					else
						ExemptList = anExempt->next;

					/* Free it. */
					mem_free(anExempt->realname);

					str_creationinfo_free(&(anExempt->info));

					mem_free(anExempt);
					return;
				}

				anExempt = anExempt->next;
			}

			send_notice_to_user(s_OperServ, callerUser, "Exempt for \2%s\2 not found.", realname);
		}
		else {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2TRIGGER\2 EXEMPT ADD|DEL|LIST");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP TRIGGER\2 for more information.");
		}
	}
	else if (str_equals_nocase(command, "LIST")) {

		char		timebuf[64], usedbuf[64];
		char		*pattern, *ptr = NULL;
		int 		triggerIdx = 0, startIdx = 0, endIdx = 30, sentIdx = 0;
		Trigger		*aTrigger;


		if (IS_NULL(TriggerList)) {

			send_notice_to_user(s_OperServ, callerUser, "The Trigger List is empty.");
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

			if (IS_NOT_NULL(pattern)) {

				/* Skip anything before a '!', if any. */
				if (IS_NOT_NULL(ptr = strchr(pattern, '!')))
					pattern = ptr + 1;

				/* Split mask in username (in 'pattern') and host (in 'ptr'). */
				if (IS_NOT_NULL(ptr = strchr(pattern, '@')))
					*ptr++ = '\0';

				if (IS_NULL(pattern) || IS_EMPTY_STR(pattern) || IS_NULL(ptr)) {

					send_notice_to_user(s_OperServ, callerUser, "Invalid pattern supplied.");
					return;
				}

				str_compact(pattern);
				str_compact(ptr);
			}
		}

		if (endIdx < startIdx)
			endIdx = (startIdx + 30);

		if (IS_NULL(pattern))
			send_notice_to_user(s_OperServ, callerUser, "Current \2Trigger\2 list (showing entries %d-%d):", startIdx, endIdx);
		else
			send_notice_to_user(s_OperServ, callerUser, "Current \2Trigger\2 list (showing entries %d-%d matching %s@%s):", startIdx, endIdx, pattern, ptr);

		aTrigger = TriggerList;

		while (IS_NOT_NULL(aTrigger)) {

			++triggerIdx;

			if (IS_NOT_NULL(pattern) && (!str_match_wild_nocase(ptr, aTrigger->host) ||
				(IS_NULL(aTrigger->username) ? str_not_equals(pattern, "*") : !str_match_wild_nocase(pattern, aTrigger->username)))) {

				/* Doesn't match our search criteria, skip it. */
				aTrigger = aTrigger->next;
				continue;
			}

			++sentIdx;

			if (sentIdx < startIdx) {

				aTrigger = aTrigger->next;
				continue;
			}

			lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, aTrigger->info.creator.time);

			send_notice_to_user(s_OperServ, callerUser, "%d) \2%s@%s\2 (%d) [Reason: %s]", triggerIdx, IS_NULL(aTrigger->username) ? "*" : aTrigger->username, aTrigger->host, aTrigger->value, aTrigger->info.reason);
			send_notice_to_user(s_OperServ, callerUser, "Set by \2%s\2 on %s [Last used: %s]", aTrigger->info.creator.name, timebuf, (aTrigger->lastUsed == 0) ? "Never" : convert_time(usedbuf, sizeof(usedbuf), (NOW - aTrigger->lastUsed), LANG_DEFAULT));

			if (sentIdx >= endIdx)
				break;

			aTrigger = aTrigger->next;
		}

		send_notice_to_user(s_OperServ, callerUser, "\2*** End of List ***\2");
	}
	else if (str_equals_nocase(command, "CHECK")) {

		char				*username, *host;
		unsigned long int	ip;
		Trigger				*aTrigger;


		if (IS_NULL(username = strtok(NULL, s_AT)) || IS_NULL(host = strtok(NULL, s_SPACE))) {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: TRIGGER CHECK user@host");
			return;
		}

		if ((str_len(username) > USERMAX) || !validate_username(username, TRUE)) {

			send_notice_to_user(s_OperServ, callerUser, "Invalid username.");
			return;
		}

		ip = aton(host);

		if (ip == INADDR_NONE) {

			/* Not an IPv4. */
			if ((str_len(host) > HOSTMAX) || !validate_host(host, TRUE, FALSE, FALSE)) {

				send_notice_to_user(s_OperServ, callerUser, "Invalid host.");
				return;
			}

			ip = INADDR_NONE;
		}

		/* See if it's triggered. */
		aTrigger = TriggerList;

		while (IS_NOT_NULL(aTrigger)) {

			if (IS_NULL(aTrigger->username) || str_match_wild_nocase(aTrigger->username, username)) {

				if (FlagSet(aTrigger->flags, TRIGGER_FLAG_HOST) ?
					((ip == INADDR_NONE) && str_match_wild_nocase(aTrigger->host, host)) :
					((ip != INADDR_NONE) && cidr_match(&(aTrigger->cidr), ip))) {

					send_notice_to_user(s_OperServ, callerUser, "Mask \2%s@%s\2 is covered by trigger on \2%s@%s\2 [%s]", username, host, aTrigger->username ?: "*", aTrigger->host, FlagSet(aTrigger->flags, TRIGGER_FLAG_HOST) ? "Host" : "CIDR");
					return;
				}
			}

			aTrigger = aTrigger->next;
		}

		send_notice_to_user(s_OperServ, callerUser, "Mask \2%s@%s\2 is not triggered.", username, host);
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SOP))
		send_notice_lang_to_user(s_OperServ, callerUser, GetCallerLang(), OPER_ERROR_ACCESS_DENIED);

	else if (str_equals_nocase(command, "ADD") || str_equals_nocase(command, "DEL")) {

		char			*mask;
		char			*value = NULL, *reason = NULL;
		char			*ptr, username[USERSIZE], host[HOSTSIZE], token[IRCBUFSIZE];
		int				flag, tval = CONF_CLONE_MIN_USERS;
		CIDR_IP			cidr;
		HOST_TYPE		htype = htInvalid;
		BOOL			found = FALSE, isADD = FALSE;
		Trigger			*aTrigger;


		mask = strtok(NULL, " ");

		if (toupper(command[0]) == 'A') {

			value = strtok(NULL, " ");
			reason = strtok(NULL, "");

			if (IS_NOT_NULL(reason) && (str_len(reason) > 80)) {

				send_notice_to_user(s_OperServ, callerUser, "Maximum length for a reason is 80 characters.");
				return;
			}

			isADD = TRUE;
		}

		if (IS_NULL(mask) || (isADD && IS_NULL(value))) {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2TRIGGER\2 ADD|DEL user@host [value] [reason]");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP TRIGGER\2 for more information.");
			return;
		}

		if (isADD == FALSE) {

			long int triggerIdx;
			char *err;


			if (IS_NULL(TriggerList)) {

				send_notice_to_user(s_OperServ, callerUser, "Trigger List is empty.");
				return;
			}

			triggerIdx = strtol(mask, &err, 10);

			if ((*err == '\0') && (triggerIdx > 0)) {

				aTrigger = TriggerList;

				while (--triggerIdx > 0) {

					aTrigger = aTrigger->next;

					if (IS_NULL(aTrigger)) {

						send_notice_to_user(s_OperServ, callerUser, "Entry %s not found on the Tagline List is empty.", mask);
						return;
					}
				}

				remove_trigger(aTrigger, callerUser, data->operMatch, data->operName);
				return;
			}
		}

		memset(username, 0, sizeof(username));
		memset(host, 0, sizeof(host));

		if (!strchr(mask, '!')) {

			if (IS_NOT_NULL(ptr = str_tokenize(mask, token, sizeof(token), c_AT)))
				str_copy_checked(token, username, USERSIZE);

			if (IS_NOT_NULL(ptr = str_tokenize(ptr, token, sizeof(token), c_NULL)))
				str_copy_checked(token, host, HOSTSIZE);
		}

		if (IS_NOT_EMPTY_STR(host)) {

			str_compact(host);

			if (cidr_ip_fill(host, &cidr, FALSE) == cidrSuccess)
				htype = htIPv4;

			else {

				if (convert_host_to_cidr(host) == cidrSuccess)
					send_notice_to_user(data->agent->nick, callerUser, "CIDR IP detected, please add it as CIDR for better results.");

				if (strchr(host, ':'))
					htype = htIPv6;
				else
					htype = htHostname;
			}
		}

		if ((htype == htInvalid) || IS_EMPTY_STR(username) || (str_len(username) > USERMAX) || IS_EMPTY_STR(host) ||
			(str_len(host) > HOSTMAX) || !validate_username(username, TRUE) || !validate_host(host, TRUE, TRUE, FALSE)) {

			send_notice_to_user(s_OperServ, callerUser, "Hostmask must be in \2user\2@\2host\2 format.");

			if (data->operMatch)
				LOG_SNOOP(s_OperServ, "OS %cT* %s -- by %s (%s@%s) [Invalid Mask]", isADD ? '+' : '-', mask, callerUser->nick, callerUser->username, callerUser->host);
			else
				LOG_SNOOP(s_OperServ, "OS %cT* %s -- by %s (%s@%s) through %s [Invalid Mask]", isADD ? '+' : '-', mask, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			return;
		}

		if (isADD) {

			tval = strtol(value, &ptr, 10);

			if ((*ptr != '\0') || (tval <= 0) || (tval > 250)) {

				send_notice_to_user(s_OperServ, callerUser, "Value must be an integer between 1 and 250.");

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "OS +T* %s -- by %s (%s@%s) [Invalid Value: %s]", mask, callerUser->nick, callerUser->username, callerUser->host, value);
				else
					LOG_SNOOP(s_OperServ, "OS +T* %s -- by %s (%s@%s) through %s [Invalid Value: %s]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName, value);

				return;
			}

			/* Maybe add these to DEL too? */
			str_compact(username);
		}

		/* If username is '*' then clear it, and it will be set to NULL in the trigger. */
		if (username[0] == c_STAR && username[1] == c_NULL)
			username[0]	= c_NULL;

		aTrigger = TriggerList;

		flag = (((htype == htHostname) || (htype == htIPv6)) ? TRIGGER_FLAG_HOST : TRIGGER_FLAG_CIDR);

		while (IS_NOT_NULL(aTrigger)) {

			if (FlagUnset(aTrigger->flags, flag)) {

				aTrigger = aTrigger->next;
				continue;
			}

			if (IS_NULL(aTrigger->username) ? IS_NOT_EMPTY_STR(username) : str_not_equals_nocase(aTrigger->username, username)) {

				aTrigger = aTrigger->next;
				continue;
			}

			if ((flag == TRIGGER_FLAG_HOST) ? str_equals_nocase(aTrigger->host, host) : ((aTrigger->cidr.ip == cidr.ip) && (aTrigger->cidr.mask == cidr.mask))) {

				found = TRUE;
				break;
			}

			aTrigger = aTrigger->next;
		}

		if (found == TRUE) {

			if ((isADD == FALSE) || (tval == CONF_CLONE_MIN_USERS)) {

				/* Remove the entry. */
				remove_trigger(aTrigger, callerUser, data->operMatch, data->operName);
			}
			else {

				/* An existent trigger is being modified. */

				if (tval == aTrigger->value) {

					send_notice_to_user(s_OperServ, callerUser, "Mask \2%s\2 is already triggered to \2%d\2.", mask, tval);

					if (data->operMatch)
						LOG_SNOOP(s_OperServ, "OS +T* %s -- by %s (%s@%s) [Same Value: %d]", mask, callerUser->nick, callerUser->username, callerUser->host, tval);
					else
						LOG_SNOOP(s_OperServ, "OS +T* %s -- by %s (%s@%s) through %s [Same Value: %d]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName, tval);
				}
				else {

					if (data->operMatch) {

						send_globops(s_OperServ, "\2%s\2 re-triggered \2%s\2 to \2%d\2 [was \2%d\2]", source, mask, tval, aTrigger->value);

						LOG_SNOOP(s_OperServ, "OS +T %s -- by %s (%s@%s) [%d -> %d]", mask, callerUser->nick, callerUser->username, callerUser->host, aTrigger->value, tval);
						log_services(LOG_SERVICES_OPERSERV, "+T %s -- by %s (%s@%s) [%d -> %d]", mask, callerUser->nick, callerUser->username, callerUser->host, aTrigger->value, tval);
					}
					else {

						send_globops(s_OperServ, "\2%s\2 (through \2%s\2) re-triggered \2%s\2 to \2%d\2 [was \2%d\2]", source, data->operName, mask, tval, aTrigger->value);

						LOG_SNOOP(s_OperServ, "OS +T %s -- by %s (%s@%s) through %s [%d -> %d]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName, aTrigger->value, tval);
						log_services(LOG_SERVICES_OPERSERV, "+T %s -- by %s (%s@%s) through %s [%d -> %d]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName, aTrigger->value, tval);
					}

					TRACE_MAIN();
					send_notice_to_user(s_OperServ, callerUser, "Re-triggered \2%s\2 to \2%d\2 [was \2%d\2].", mask, tval, aTrigger->value);
					aTrigger->value = tval;
				}
			}
		}
		else {

			/* The requested mask is not already triggered. */
			if (isADD == FALSE) {

				send_notice_to_user(s_OperServ, callerUser, "Mask \2%s\2 is not triggered.", mask, tval);

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "OS -T* %s -- by %s (%s@%s) [Not Found]", mask, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(s_OperServ, "OS -T* %s -- by %s (%s@%s) through %s [Not Found]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}
			else {

				if (IS_NULL(reason)) {

					send_notice_to_user(s_OperServ, callerUser, "Syntax: \2TRIGGER ADD\2 user@host value reason");
					send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP TRIGGER\2 for more information.");
				}
				else if (tval == CONF_CLONE_MIN_USERS) {

					TRACE_MAIN();
					send_notice_to_user(s_OperServ, callerUser, "Trigger is \2%d\2 by default", tval);

					if (data->operMatch)
						LOG_SNOOP(s_OperServ, "OS +T* %s -- by %s (%s@%s) [Default]", mask, callerUser->nick, callerUser->username, callerUser->host);
					else
						LOG_SNOOP(s_OperServ, "OS +T* %s -- by %s (%s@%s) through %s [Default]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				}
				else {

					/* Allocate the new trigger. */
					aTrigger = mem_calloc(1, sizeof(Trigger));

					/* Link it. */
					aTrigger->next = TriggerList;
					aTrigger->prev = NULL;

					if (IS_NOT_NULL(TriggerList))
						TriggerList->prev = aTrigger;

					TriggerList = aTrigger;

					/* Fill it. */
					if (IS_NOT_EMPTY_STR(username))
						aTrigger->username = str_duplicate(username);

					aTrigger->value = tval;
					aTrigger->host = str_duplicate(host);

					str_creationinfo_init(&(aTrigger->info));
					str_creationinfo_set(&(aTrigger->info), data->operName, reason, NOW);

					if (htype == htIPv4) {

						aTrigger->flags = TRIGGER_FLAG_CIDR;
						aTrigger->cidr = cidr;
					}
					else
						aTrigger->flags = TRIGGER_FLAG_HOST;

					if (data->operMatch) {

						send_globops(s_OperServ, "\2%s\2 triggered \2%s\2 to \2%d\2 [Reason: %s]", source, mask, tval, reason);

						LOG_SNOOP(s_OperServ, "OS +T %s -- by %s (%s@%s) [%d]", mask, callerUser->nick, callerUser->username, callerUser->host, tval);
						log_services(LOG_SERVICES_OPERSERV, "+T %s -- by %s (%s@%s) [%d] [Reason: %s]", mask, callerUser->nick, callerUser->username, callerUser->host, tval, reason);
					}
					else {

						send_globops(s_OperServ, "\2%s\2 (through \2%s\2) triggered \2%s\2 to \2%d\2 [Reason: %s]", source, data->operName, mask, tval, reason);

						LOG_SNOOP(s_OperServ, "OS +T %s -- by %s (%s@%s) through %s [%d]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName, tval);
						log_services(LOG_SERVICES_OPERSERV, "+T %s -- by %s (%s@%s) through %s [%d] [Reason: %s]", mask, callerUser->nick, callerUser->username, callerUser->host, data->operName, tval, reason);
					}

					send_notice_to_user(s_OperServ, callerUser, "Trigger for \2%s\2 set to \2%d\2 [Reason: %s].", mask, tval, reason);
				}
			}
		}
	}
	else {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2TRIGGER\2 ADD|DEL|CHECK|LIST user@host [value] [reason]");
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP TRIGGER\2 for more information.");
	}
}


void trigger_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	char		*ptr = NULL;
	int 		triggerIdx = 0, startIdx = 0, endIdx = 5, sentIdx = 0;
	Trigger		*aTrigger;


	TRACE_FCLT(FACILITY_TRIGGER_DS_DUMP);

	if (IS_NULL(TriggerList)) {

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2Trigger\2 List is empty.");
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

		if (IS_NOT_NULL(request)) {

			/* Skip anything before a '!', if any. */
			if (IS_NOT_NULL(ptr = strchr(request, '!')))
				request = ptr + 1;

			/* Split mask in username (in 'request') and host (in 'ptr'). */
			if (IS_NOT_NULL(ptr = strchr(request, '@')))
				*ptr++ = '\0';

			if (IS_NULL(request) || IS_EMPTY_STR(request) || IS_NULL(ptr)) {

				send_notice_to_user(sourceNick, callerUser, "DUMP: Invalid pattern supplied.");
				return;
			}

			str_compact(request);
			str_compact(ptr);
		}
	}

	if (endIdx < startIdx)
		endIdx = (startIdx + 5);

	if (IS_NULL(request)) {

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2Trigger\2 list (showing entries %d-%d):", startIdx, endIdx);
		LOG_DEBUG_SNOOP("Command: DUMP TRIGGERS %d-%d -- by %s (%s@%s)", startIdx, endIdx, callerUser->nick, callerUser->username, callerUser->host);
	}
	else {

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2Trigger\2 list (showing entries %d-%d matching %s@%s):", startIdx, endIdx, request, ptr);
		LOG_DEBUG_SNOOP("Command: DUMP TRIGGERS %d-%d -- by %s (%s@%s) [Pattern: %s@%s]", startIdx, endIdx, callerUser->nick, callerUser->username, callerUser->host, request, ptr);
	}

	aTrigger = TriggerList;

	while (IS_NOT_NULL(aTrigger)) {

		++triggerIdx;

		if (IS_NOT_NULL(request) && (!str_match_wild_nocase(ptr, aTrigger->host) ||
			(IS_NULL(aTrigger->username) ? str_not_equals(request, "*") : !str_match_wild_nocase(request, aTrigger->username)))) {

			/* Doesn't match our search criteria, skip it. */
			aTrigger = aTrigger->next;
			continue;
		}

		++sentIdx;

		if (sentIdx < startIdx) {

			aTrigger = aTrigger->next;
			continue;
		}

		send_notice_to_user(sourceNick, callerUser, "%d) Address 0x%08X, size %d B",		triggerIdx, (unsigned long)aTrigger, sizeof(Trigger));
		send_notice_to_user(sourceNick, callerUser, "Username: 0x%08X \2[\2%s\2]\2",		(unsigned long)aTrigger->username, str_get_valid_display_value(aTrigger->username));
		send_notice_to_user(sourceNick, callerUser, "Host: 0x%08X \2[\2%s\2]\2",			(unsigned long)aTrigger->host, str_get_valid_display_value(aTrigger->host));
		send_notice_to_user(sourceNick, callerUser, "Reason: 0x%08X \2[\2%s\2]\2",			(unsigned long)aTrigger->info.reason, str_get_valid_display_value(aTrigger->info.reason));
		send_notice_to_user(sourceNick, callerUser, "Set by: 0x%08X \2[\2%s\2]\2",			(unsigned long)aTrigger->info.creator.name, str_get_valid_display_value(aTrigger->info.creator.name));
		send_notice_to_user(sourceNick, callerUser, "Time Set C-time: %ld",					aTrigger->info.creator.time);
		send_notice_to_user(sourceNick, callerUser, "Last Used C-time: %ld",				aTrigger->lastUsed);
		send_notice_to_user(sourceNick, callerUser, "Expire C-time: %ld",					aTrigger->expireTime);
		send_notice_to_user(sourceNick, callerUser, "Flags: %d",							aTrigger->flags);
		send_notice_to_user(sourceNick, callerUser, "Value: %d",							aTrigger->value);
		send_notice_to_user(sourceNick, callerUser, "Next/Prev records: 0x%08X / 0x%08X",	(unsigned long)aTrigger->next, (unsigned long)aTrigger->prev);

		if (sentIdx >= endIdx)
			break;

		aTrigger = aTrigger->next;
	}
}

unsigned long int trigger_mem_report(CSTR sourceNick, const User *callerUser) {

	unsigned long int count = 0, mem = 0, total_mem = 0;
	Trigger *aTrigger;
	Exempt *anExempt;


	TRACE_FCLT(FACILITY_TRIGGER_MEM_REPORT);

	send_notice_to_user(sourceNick, callerUser, "\2TRIGGER\2:");

	/* Trigger List */
	aTrigger = TriggerList;

	while (IS_NOT_NULL(aTrigger)) {

		++count;

		mem += sizeof(Trigger);

		if (IS_NOT_NULL(aTrigger->username))
			mem += str_len(aTrigger->username) + 1;

		mem += str_len(aTrigger->host) + 1;
		mem += str_len(aTrigger->info.creator.name) + 1;
		mem += str_len(aTrigger->info.reason) + 1;

		aTrigger = aTrigger->next;
	}

	send_notice_to_user(sourceNick, callerUser, "Trigger List: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", count, mem / 1024, mem);
	total_mem += mem;

	/* Exempt List */
	count = 0;
	anExempt = ExemptList;

	while (IS_NOT_NULL(anExempt)) {

		++count;

		mem += sizeof(Exempt);

		mem += str_len(anExempt->realname) + 1;
		mem += str_len(anExempt->info.creator.name) + 1;
		mem += str_len(anExempt->info.reason) + 1;

		anExempt = anExempt->next;
	}

	send_notice_to_user(sourceNick, callerUser, "Exempt List: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", count, mem / 1024, mem);
	total_mem += mem;

	return total_mem;
}

#endif
