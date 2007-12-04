/*
*
* Azzurra IRC Services
* 
* blacklist.c - Blacklisted E-Mail addresses
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
#include "../inc/akill.h"
#include "../inc/blacklist.h"


/*********************************************************
 * Local variables                                       *
 *********************************************************/

/* List of BlackLists. */
static BlackList *BlackListList;


/*********************************************************
 * Private code                                          *
 *********************************************************/

static char *get_blacklist_flags(tiny_flags_t flags) {

	if (FlagSet(flags, BLACKLIST_FLAG_NOTIFY)) {

		if (FlagSet(flags, BLACKLIST_FLAG_DENY))
			return "Block";

		return "Notify";
	}

	if (FlagSet(flags, BLACKLIST_FLAG_DENY))
		return "Deny";

	return "None";
}


/*********************************************************
 * Public code                                           *
 *********************************************************/

BOOL blacklist_db_load(void) {

	STGHANDLE	stg = 0;
	STG_RESULT	result;


	TRACE_FCLT(FACILITY_BLACKLIST_DB_LOAD);

	result = stg_open(BLACKLIST_DB, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version;
			BOOL		in_section;
			BOOL		read_done;


			version = stg_data_version(stg);

			switch (version) {

				case BLACKLIST_DB_CURRENT_VERSION: {

					BlackList_V10	*anAddress;


					// start-of-section marker
					result = stg_read_record(stg, NULL, 0);

					if (result == stgBeginOfSection) {

						in_section = TRUE;

						while (in_section) {

							anAddress = mem_malloc(sizeof(BlackList_V10));

							result = stg_read_record(stg, (PBYTE)anAddress, sizeof(BlackList_V10));

							switch (result) {

								case stgEndOfSection: // end-of-section
									in_section = FALSE;
									mem_free(anAddress);
									break;

								case stgSuccess: // a valid record

									read_done = TRUE;

									read_done &= (result = stg_read_string(stg, &(anAddress->address), NULL)) == stgSuccess;

									if (read_done)
										read_done &= (result = stg_read_string(stg, &(anAddress->info.creator.name), NULL)) == stgSuccess;

									if (read_done)
										read_done &= (result = stg_read_string(stg, &(anAddress->info.reason), NULL)) == stgSuccess;

									if (!read_done)
										fatal_error(FACILITY_BLACKLIST_DB_LOAD, __LINE__, "Read error on %s (2) - %s", BLACKLIST_DB, stg_result_to_string(result));

									anAddress->next = BlackListList;
									anAddress->prev = NULL;

									if (IS_NOT_NULL(BlackListList))
										BlackListList->prev = anAddress;

									BlackListList = anAddress;
									break;

								default: // some error
									fatal_error(FACILITY_BLACKLIST_DB_LOAD, __LINE__, "Read error on %s - %s", BLACKLIST_DB, stg_result_to_string(result));
							}
						}
					}
					else
						fatal_error(FACILITY_BLACKLIST_DB_LOAD, __LINE__, "Read error on %s : invalid format", BLACKLIST_DB);

					stg_close(stg, BLACKLIST_DB);
					return TRUE;
				}

				default:
					fatal_error(FACILITY_BLACKLIST_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, BLACKLIST_DB);
			}
		}

		case stgNotFound: // no data to load
			return TRUE;

		default: // error!
			stg_close(stg, BLACKLIST_DB);

			fatal_error(FACILITY_BLACKLIST_DB_LOAD, __LINE__, "Error opening %s - %s", BLACKLIST_DB, stg_result_to_string(result));
			return FALSE;
	}
}


BOOL blacklist_db_save(void) {

	STGHANDLE		stg;
	STG_RESULT		result;
	BlackList		*anAddress;
	char			*strings[3];
	int				error_index;


	TRACE_FCLT(FACILITY_BLACKLIST_DB_SAVE);

	result = stg_create(BLACKLIST_DB, SF_NOFLAGS, BLACKLIST_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_BLACKLIST_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"operserv_blacklist_db_save(): Could not create database file %s: %s [Error %d: %s]", BLACKLIST_DB, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	result = stg_start_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_BLACKLIST_DB_SAVE, __LINE__, "Write error on %s - %s", BLACKLIST_DB, stg_result_to_string(result));

	anAddress = BlackListList;

	while (IS_NOT_NULL(anAddress)) {

		result = stg_write_record(stg, (PBYTE)anAddress, sizeof(BlackList));

		if (result != stgSuccess)
			fatal_error(FACILITY_BLACKLIST_DB_SAVE, __LINE__, "Write error on %s - %s", BLACKLIST_DB, stg_result_to_string(result));

		strings[0] = anAddress->address;
		strings[1] = anAddress->info.creator.name;
		strings[2] = anAddress->info.reason;

		error_index = -1;

		result = stg_write_strings(stg, strings, sizeof(strings) / sizeof(char *), &error_index);

		if (result != stgSuccess)
			fatal_error(FACILITY_BLACKLIST_DB_SAVE, __LINE__, "Write error on %s for string n. %d - %s", BLACKLIST_DB, error_index, stg_result_to_string(result));

		anAddress = anAddress->next;
	}

	result = stg_end_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_BLACKLIST_DB_SAVE, __LINE__, "Write error on %s - %s", BLACKLIST_DB, stg_result_to_string(result));

	stg_close(stg, BLACKLIST_DB);
	return TRUE;
}


void handle_blacklist(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *command;


	TRACE_MAIN_FCLT(FACILITY_BLACKLIST_HANDLE_BLACKLIST);

	if (IS_NULL(command = strtok(NULL, " "))) {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2BLACKLIST\2 [ADD|DEL|LIST] text");
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP BLACKLIST\2 for more information.");
	}
	else if (str_equals_nocase(command, "LIST")) {

		char 		*pattern, timebuf[64], usedbuf[64];
		int			blackIdx = 0, startIdx = 0, endIdx = 30, sentIdx = 0;
		BlackList	*anAddress;


		if (IS_NULL(BlackListList)) {

			send_notice_to_user(s_OperServ, callerUser, "The Blacklisted address list is empty.");
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
			send_notice_to_user(s_OperServ, callerUser, "Current blacklisted addresses (showing entries %d-%d):", startIdx, endIdx);
		else
			send_notice_to_user(s_OperServ, callerUser, "Current blacklisted addresses (showing entries %d-%d matching %s):", startIdx, endIdx, pattern);

		anAddress = BlackListList;

		while (IS_NOT_NULL(anAddress)) {

			++blackIdx;

			if (IS_NOT_NULL(pattern) && !str_match_wild_nocase(pattern, anAddress->address)) {

				anAddress = anAddress->next;
				continue;
			}

			++sentIdx;

			if (sentIdx < startIdx) {

				anAddress = anAddress->next;
				continue;
			}

			lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, anAddress->info.creator.time);

			send_notice_to_user(s_OperServ, callerUser, "%d) \2%s\2 [Reason: %s]", blackIdx, anAddress->address, anAddress->info.reason);
			send_notice_to_user(s_OperServ, callerUser, "Set by \2%s\2 on %s [Last used: %s ago]", anAddress->info.creator.name, timebuf, (anAddress->lastUsed == 0) ? "Never" : convert_time(usedbuf, sizeof(usedbuf), (NOW - anAddress->lastUsed), LANG_DEFAULT));

			if (sentIdx >= endIdx)
				break;

			anAddress = anAddress->next;
		}

		send_notice_to_user(s_OperServ, callerUser, "*** \2End of List\2 ***");
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SOP))
		send_notice_lang_to_user(s_OperServ, callerUser, GetCallerLang(), OPER_ERROR_ACCESS_DENIED);

	else if (str_equals_nocase(command, "ADD")) {
		
		char			*address, *type, *reason;
		tiny_flags_t	flags;
		size_t			len;
		BlackList		*anAddress;


		if (IS_NULL(address = strtok(NULL, " ")) || IS_NULL(type = strtok(NULL, " ")) || IS_NULL(reason = strtok(NULL, ""))) {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2BLACKLIST\2 [ADD|DEL|LIST] address [type] [reason]");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP BLACKLIST\2 for more information.");
			return;
		}

		/* Let them register, but notify opers. */
		if (str_equals_nocase(type, "NOTIFY"))
			flags = BLACKLIST_FLAG_NOTIFY;

		/* Don't let them register, and don't notify. */
		else if (str_equals_nocase(type, "DENY"))
			flags = BLACKLIST_FLAG_DENY;

		/* Don't let them register, and notify opers. */
		else if (str_equals_nocase(type, "BLOCK"))
			flags = BLACKLIST_FLAG_NOTIFY | BLACKLIST_FLAG_DENY;

		else {

			send_notice_to_user(s_OperServ, callerUser, "Invalid type specified.");
			return;
		}

		if ((len = str_len(reason)) > 220) {

			send_notice_to_user(s_OperServ, callerUser, "Reason cannot be longer than 220 characters (yours has: %d).", len);
			return;
		}

		if (str_len(address) > MAILMAX) {

			send_notice_lang_to_user(s_OperServ, callerUser, GetCallerLang(), CSNS_ERROR_MAIL_MAX_LENGTH, MAILMAX);
			return;
		}

		if (!validate_email(address, TRUE)) {
			send_notice_to_user(s_OperServ, callerUser, "E-Mail address \2%s\2 is not valid.", address);
			return;
		}

		str_compact(address);

		anAddress = BlackListList;

		while (IS_NOT_NULL(anAddress)) {

			if (str_equals_nocase(address, anAddress->address)) {

				if (anAddress->flags != flags) {

					char *oldtype = get_blacklist_flags(anAddress->flags);
					char *newtype = get_blacklist_flags(flags);

					send_notice_to_user(s_OperServ, callerUser, "Blacklist type for \2%s\2 changed from %s to %s", address, oldtype, newtype);

					if (data->operMatch)
						LOG_SNOOP(s_OperServ, "OS BL %s -- by %s (%s@%s) [Type: %s -> %s]", address, callerUser->nick, callerUser->username, callerUser->host, oldtype, newtype);
					else
						LOG_SNOOP(s_OperServ, "OS BL %s -- by %s (%s@%s) through %s [Type: %s -> %s]", address, callerUser->nick, callerUser->username, callerUser->host, data->operName, oldtype, newtype);

					anAddress->flags = flags;
				}
				else {

					send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is already blacklisted", address);

					if (data->operMatch)
						LOG_SNOOP(s_OperServ, "OS +BL* %s -- by %s (%s@%s) [Already blacklisted]", address, callerUser->nick, callerUser->username, callerUser->host);
					else
						LOG_SNOOP(s_OperServ, "OS +BL* %s -- by %s (%s@%s) through %s [Already blacklisted]", address, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				}

				return;
			}

			anAddress = anAddress->next;
		}

		TRACE_MAIN();

		type = get_blacklist_flags(flags);

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 blacklisted E-Mail address \2%s\2 [Type: %s] [Reason: %s]", source, address, type, reason);

			LOG_SNOOP(s_OperServ, "OS +BL %s -- by %s (%s@%s) [T: %s] [R: %s]", address, callerUser->nick, callerUser->username, callerUser->host, type, reason);
			log_services(LOG_SERVICES_OPERSERV, "+BL %s -- by %s (%s@%s) [T: %s] [R: %s]", address, callerUser->nick, callerUser->username, callerUser->host, type, reason);
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) blacklisted E-Mail address \2%s\2 [Type: %s] [Reason: %s]", source, data->operName, address, type, reason);

			LOG_SNOOP(s_OperServ, "OS +BL %s -- by %s (%s@%s) through %s [T: %s] [R: %s]", address, callerUser->nick, callerUser->username, callerUser->host, data->operName, type, reason);
			log_services(LOG_SERVICES_OPERSERV, "+BL %s -- by %s (%s@%s) through %s [T: %s] [R: %s]", address, callerUser->nick, callerUser->username, callerUser->host, data->operName, type, reason);
		}

		send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is now blacklisted because: %s", address, reason);

		if (CONF_SET_READONLY)
			send_notice_to_user(s_OperServ, callerUser, "\2Notice:\2 Services is in read-only mode. Changes will not be saved!");

		/* Allocate the new entry. */
		anAddress = mem_calloc(1, sizeof(BlackList));

		/* Fill it. */
		anAddress->address = str_duplicate(address);
		anAddress->flags = flags;

		str_creationinfo_init(&(anAddress->info));
		str_creationinfo_set(&(anAddress->info), data->operName, reason, NOW);

		/* Link it. */
		anAddress->next = BlackListList;
		anAddress->prev = NULL;

		if (IS_NOT_NULL(BlackListList))
			BlackListList->prev = anAddress;

		BlackListList = anAddress;
	}
	else if (str_equals_nocase(command, "DEL")) {

		char 		*address, *err;
		long int	listIdx;
		BlackList	*anAddress;


		if (IS_NULL(address = strtok(NULL, " "))) {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2BLACKLIST\2 DEL address");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP BLACKLIST\2 for more information.");
			return;
		}

		anAddress = BlackListList;

		listIdx = strtol(address, &err, 10);

		if ((listIdx > 0) && (*err == '\0')) {

			while (--listIdx > 0) {

				anAddress = anAddress->next;

				if (IS_NULL(anAddress)) {

					send_notice_to_user(s_OperServ, callerUser, "Blacklist entry \2%s\2 not found.", address);
					return;
				}
			}
		}
		else {

			while (IS_NOT_NULL(anAddress)) {

				if (str_equals_nocase(address, anAddress->address))
					break;

				anAddress = anAddress->next;
			}

			if (IS_NULL(anAddress)) {

				send_notice_to_user(s_OperServ, callerUser, "Blacklist for \2%s\2 not found.", address);

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "OS -BL* %s -- by %s (%s@%s) [Not Blacklisted]", address, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(s_OperServ, "OS -BL* %s -- by %s (%s@%s) through %s [Not Blacklisted]", address, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				return;
			}
		}

		TRACE_MAIN();

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 removed blacklist on \2%s\2", source, anAddress->address);

			LOG_SNOOP(s_OperServ, "OS -BL %s -- by %s (%s@%s)", anAddress->address, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_OPERSERV, "-BL %s -- by %s (%s@%s)", anAddress->address, callerUser->nick, callerUser->username, callerUser->host);
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) removed blacklist \2%s\2", source, data->operName, anAddress->address);

			LOG_SNOOP(s_OperServ, "OS -BL %s -- by %s (%s@%s) through %s", anAddress->address, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_OPERSERV, "-BL %s -- by %s (%s@%s) through %s", anAddress->address, callerUser->nick, callerUser->username, callerUser->host, data->operName);
		}

		send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is no longer blacklisted.", anAddress->address);

		if (CONF_SET_READONLY)
			send_notice_to_user(s_OperServ, callerUser, "\2Notice:\2 Services is in readonly mode. Changes will not be saved!");

		TRACE_MAIN();

		/* Link around it. */
		if (IS_NOT_NULL(anAddress->next))
			anAddress->next->prev = anAddress->prev;

		if (IS_NOT_NULL(anAddress->prev))
			anAddress->prev->next = anAddress->next;
		else
			BlackListList = anAddress->next;

		/* Free it. */
		mem_free(anAddress->address);
		str_creationinfo_free(&(anAddress->info));
		mem_free(anAddress);
	}
	else {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2BLACKLIST\2 [ADD|DEL|LIST] address [type] [reason]");
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP BLACKLIST\2 for more information.");
	}
}

/*********************************************************/

BOOL blacklist_match(const User *user, CSTR address, const char type) {

	BlackList *anAddress;


	TRACE_FCLT(FACILITY_BLACKLIST_MATCH);

	if (IS_NULL(address) || IS_EMPTY_STR(address)) {

		log_error(FACILITY_BLACKLIST_MATCH, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, s_LOG_ERR_PARAMETER, "is_blacklisted()", s_LOG_NULL, "address");
		return FALSE;
	}

	anAddress = BlackListList;

	while (IS_NOT_NULL(anAddress)) {

		if (str_match_wild_nocase(anAddress->address, address)) {

			if (FlagSet(anAddress->flags, BLACKLIST_FLAG_NOTIFY)) {

				if (FlagSet(anAddress->flags, BLACKLIST_FLAG_DENY)) {

					if (type == 'c')
						send_globops(s_OperServ, "\2%s\2 tried changing E-Mail to blacklisted address \2%s\2", user->nick, address);
					else
						send_globops(s_OperServ, "\2%s\2 tried registering a nickname using blacklisted E-Mail address \2%s\2", user->nick, address);
				}
				else {

					if (type == 'c')
						send_globops(s_OperServ, "\2%s\2 changed E-Mail to blacklisted address \2%s\2", user->nick, address);
					else
						send_globops(s_OperServ, "\2%s\2 registered a nickname using blacklisted E-Mail address \2%s\2", user->nick, address);
				}
			}

			anAddress->lastUsed = NOW;

			/* FIX: return true ONLY if we should block this mail address */
			if (FlagSet(anAddress->flags, BLACKLIST_FLAG_DENY))
				return TRUE;
			else
				return FALSE;
		}

		anAddress = anAddress->next;
	}

	return FALSE;
}

void blacklist_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	BlackList	*anAddress;
	int			startIdx = 0, endIdx = 5, addressIdx = 0, sentIdx = 0;


	TRACE_FCLT(FACILITY_BLACKLIST_DS_DUMP);

	if (IS_NULL(BlackListList)) {

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2BlackList\2 List is empty.");
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

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2BlackList\2 List (showing entries %d-%d):", startIdx, endIdx);
		LOG_DEBUG_SNOOP("Command: DUMP BLACKLIST %d-%d -- by %s (%s@%s)", startIdx, endIdx, callerUser->nick, callerUser->username, callerUser->host);
	}
	else {

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2BlackList\2 List (showing entries %d-%d matching %s):", startIdx, endIdx, request);
		LOG_DEBUG_SNOOP("Command: DUMP BLACKLIST %d-%d -- by %s (%s@%s) [Pattern: %s]", startIdx, endIdx, callerUser->nick, callerUser->username, callerUser->host, request);
	}

	anAddress = BlackListList;

	while (IS_NOT_NULL(anAddress)) {

		++addressIdx;

		if (IS_NOT_NULL(request) && !str_match_wild_nocase(request, anAddress->address)) {

			/* Doesn't match our search criteria, skip it. */
			anAddress = anAddress->next;
			continue;
		}

		++sentIdx;

		if (sentIdx < startIdx) {

			anAddress = anAddress->next;
			continue;
		}

		send_notice_to_user(sourceNick, callerUser, "%d) Address 0x%08X, size %d B",		addressIdx, (unsigned long)anAddress, sizeof(BlackList));
		send_notice_to_user(sourceNick, callerUser, "Value: 0x%08X \2[\2%s\2]\2",			(unsigned long)anAddress->address, str_get_valid_display_value(anAddress->address));
		send_notice_to_user(sourceNick, callerUser, "Reason: 0x%08X \2[\2%s\2]\2",			(unsigned long)anAddress->info.reason, str_get_valid_display_value(anAddress->info.reason));
		send_notice_to_user(sourceNick, callerUser, "Set by: 0x%08X \2[\2%s\2]\2",			(unsigned long)anAddress->info.creator.name, str_get_valid_display_value(anAddress->info.creator.name));
		send_notice_to_user(sourceNick, callerUser, "Time Set C-time: %ld",					anAddress->info.creator.time);
		send_notice_to_user(sourceNick, callerUser, "Last Used C-time: %ld",				anAddress->lastUsed);
		send_notice_to_user(sourceNick, callerUser, "Flags: %d",							anAddress->flags);
		send_notice_to_user(sourceNick, callerUser, "Next/Prev records: 0x%08X / 0x%08X",	(unsigned long)anAddress->next, (unsigned long)anAddress->prev);

		if (sentIdx >= endIdx)
			break;

		anAddress = anAddress->next;
	}
}


unsigned long int blacklist_mem_report(CSTR sourceNick, const User *callerUser) {

	unsigned long int count = 0, mem = 0;
	BlackList *anAddress;


	TRACE_FCLT(FACILITY_BLACKLIST_MEM_REPORT);

	send_notice_to_user(sourceNick, callerUser, "\2BLACKLIST\2:");

	anAddress = BlackListList;

	while (IS_NOT_NULL(anAddress)) {

		++count;

		mem += sizeof(BlackList);

		mem += str_len(anAddress->address) + 1;
		mem += str_len(anAddress->info.creator.name) + 1;
		mem += str_len(anAddress->info.reason) + 1;

		anAddress = anAddress->next;
	}

	send_notice_to_user(sourceNick, callerUser, "BlackListed addresses: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", count, mem / 1024, mem);
	return mem;
}

#endif
