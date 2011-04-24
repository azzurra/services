/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* reserved.c - Reserved names
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
#include "../inc/conf.h"
#include "../inc/misc.h"
#include "../inc/list.h"
#include "../inc/akill.h"
#include "../inc/reserved.h"


/*********************************************************
 * Local variables                                       *
 *********************************************************/

/* List of Reserved Names. */
static reservedName *reservedNameList;

/* Has the list been loaded successfully? */
static BOOL reservedNameListLoadComplete; 

/* Is the reserved names control active? */
static BOOL reservedNameActive;


/*********************************************************
 * Private code                                          *
 *********************************************************/

static char *reserved_flagsToString(reservedName *aName) {

	static char string[10];
	long int flags;


	TRACE_FCLT(FACILITY_RESERVED_FLAGSTOSTRING);

	if (IS_NULL(aName)) {

		log_error(FACILITY_RESERVED_FLAGSTOSTRING, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "reserved_flagsToString()", s_LOG_NULL, "name");

		return "Error";
	}

	flags = aName->flags;

	snprintf(string, sizeof(string), "%s%s%s%s%s%s%s%s%s",
		FlagSet(flags, RESERVED_ACTIVE) ? "E" : s_NULL,
		FlagSet(flags, RESERVED_NICK)	? "N" : s_NULL,
		FlagSet(flags, RESERVED_CHAN)	? "C" : s_NULL,
		FlagSet(flags, RESERVED_NOUSE)	? "U" : s_NULL,
		FlagSet(flags, RESERVED_NOREG)	? "R" : s_NULL,
		FlagSet(flags, RESERVED_ALERT)	? "W" : s_NULL,
		FlagSet(flags, RESERVED_KILL)	? "K" : s_NULL,
		FlagSet(flags, RESERVED_AKILL)	? "A" : s_NULL,
		FlagSet(flags, RESERVED_LOG)	? "L" : s_NULL);

	if (string[0] == '\0')
		return "None";

	return string;
}


static reservedName *reserved_find(CSTR value, const long type) {

	reservedName *aName = reservedNameList;


	TRACE_FCLT(FACILITY_RESERVED_FIND);

	if (IS_NOT_NULL(value)) {

		while (IS_NOT_NULL(aName)) {

			if ((type == 0 ? TRUE : FlagSet(aName->flags, type)) && str_match_wild_nocase(aName->name, value))
				return aName;

			TRACE();
			aName = aName->next;
		}
	}

	return NULL;
}


/*********************************************************
 * Public code                                           *
 *********************************************************/

BOOL reserved_db_load(void) {

	STGHANDLE	stg = 0;
	STG_RESULT	result;


	TRACE_FCLT(FACILITY_RESERVED_DB_LOAD);

	reservedNameActive = TRUE;
	reservedNameListLoadComplete = TRUE;

	result = stg_open(RESERVED_DB, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version;
			BOOL		in_section;
			BOOL		read_done;


			version = stg_data_version(stg);

			switch (version) {

				case RESERVED_DB_CURRENT_VERSION: {

					reservedName_V10 *aName;


					// start-of-section marker
					result = stg_read_record(stg, NULL, 0);

					if (result == stgBeginOfSection) {

						in_section = TRUE;

						while (in_section) {

							aName = mem_malloc(sizeof(reservedName_V10));

							result = stg_read_record(stg, (PBYTE)aName, sizeof(reservedName_V10));

							switch (result) {

								case stgEndOfSection: // end-of-section
									in_section = FALSE;
									mem_free(aName);
									break;

								case stgSuccess: // a valid record

									read_done = TRUE;

									read_done &= (result = stg_read_string(stg, &(aName->name), NULL)) == stgSuccess;

									if (read_done)
										read_done &= (result = stg_read_string(stg, &(aName->info.creator.name), NULL)) == stgSuccess;

									if (read_done)
										read_done &= (result = stg_read_string(stg, &(aName->info.reason), NULL)) == stgSuccess;

									if (!read_done)
										fatal_error(FACILITY_RESERVED_DB_LOAD, __LINE__, "Read error on %s (2) - %s", TAGLINE_DB, stg_result_to_string(result));

									aName->next = reservedNameList;
									reservedNameList = aName;
									break;

								default: // some error
									fatal_error(FACILITY_RESERVED_DB_LOAD, __LINE__, "Read error on %s - %s", RESERVED_DB, stg_result_to_string(result));
							}
						}
					}
					else
						fatal_error(FACILITY_RESERVED_DB_LOAD, __LINE__, "Read error on %s : invalid format", RESERVED_DB);

					stg_close(stg, RESERVED_DB);
					return TRUE;
				}

				default:
					fatal_error(FACILITY_RESERVED_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, RESERVED_DB);
			}
		}

		case stgNotFound: // no data to load
			return TRUE;

		default: // error!
			stg_close(stg, RESERVED_DB);

			fatal_error(FACILITY_RESERVED_DB_LOAD, __LINE__, "Error opening %s - %s", RESERVED_DB, stg_result_to_string(result));
			return FALSE;
	}
}


BOOL reserved_db_save(void) {

	STGHANDLE		stg;
	STG_RESULT		result;
	reservedName	*aName;
	char			*strings[3];
	int				error_index;


	TRACE_FCLT(FACILITY_RESERVED_DB_SAVE);

	if (reservedNameListLoadComplete != TRUE)
		return FALSE;

	result = stg_create(RESERVED_DB, SF_NOFLAGS, RESERVED_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_RESERVED_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"reserved_db_save(): Could not create database file %s: %s [Error %d: %s]", RESERVED_DB, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	result = stg_start_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_RESERVED_DB_SAVE, __LINE__, "Write error on %s - %s", RESERVED_DB, stg_result_to_string(result));

	aName = reservedNameList;

	while (IS_NOT_NULL(aName)) {

		result = stg_write_record(stg, (PBYTE)aName, sizeof(reservedName));

		if (result != stgSuccess)
			fatal_error(FACILITY_RESERVED_DB_SAVE, __LINE__, "Write error on %s - %s", RESERVED_DB, stg_result_to_string(result));

		strings[0] = aName->name;
		strings[1] = aName->info.creator.name;
		strings[2] = aName->info.reason;

		error_index = -1;

		result = stg_write_strings(stg, strings, sizeof(strings) / sizeof(char *), &error_index);

		if (result != stgSuccess)
			fatal_error(FACILITY_RESERVED_DB_SAVE, __LINE__, "Write error on %s for string n. %d - %s", RESERVED_DB, error_index, stg_result_to_string(result));

		aName = aName->next;
	}

	result = stg_end_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_RESERVED_DB_SAVE, __LINE__, "Write error on %s - %s", RESERVED_DB, stg_result_to_string(result));

	stg_close(stg, RESERVED_DB);
	return TRUE;
}


void reserved_terminate(void) {
	
	reservedName *aName, *prev;

	
	TRACE_FCLT(FACILITY_RESERVED_TERMINATE);

	aName = reservedNameList;

	while (IS_NOT_NULL(aName)) {

		TRACE();
		mem_free(aName->name);
		str_creationinfo_free(&(aName->info));

		TRACE();
		prev = aName;
		aName = aName->next;
		mem_free(prev);
	}

	TRACE();
	reservedNameList = NULL;
	reservedNameListLoadComplete = FALSE;
}


RESERVED_RESULT reserved_match(CSTR value, const long int type, const BOOL isReg, CSTR service,
	CSTR nick, CSTR ident, CSTR host, const unsigned long int ip, const BOOL isExempt,
	const LANG_ID lang) {

	reservedName *aName;


	TRACE_FCLT(FACILITY_RESERVED_MATCH);

	if (!reservedNameActive)
		return reservedValid;

	TRACE();

	aName = reserved_find(value, type);

	if (IS_NOT_NULL(aName) && FlagSet(aName->flags, RESERVED_ACTIVE)) {

		// il valore indicato e' un nome riservato -> verificare l'operazione

		TRACE();
		if (FlagSet(aName->flags, (isReg ? RESERVED_NOREG : RESERVED_NOUSE))) {

			// non e' possibile usare o registrare il nome

			RESERVED_RESULT result = reservedBlock;

			if (FlagSet(aName->flags, RESERVED_ALERT))
				send_globops(service, "\2%s\2 tried %s reserved %s \2%s%s\2 (Matches: %s)", nick, (isReg ? "registering" : "using"), (type == RESERVED_CHAN) ? "channel" : "nickname", (type == RESERVED_CHAN) ? "#" : "", value, aName->name);

			TRACE();

			if ((isExempt == FALSE) && FlagSet(aName->flags, RESERVED_AKILL)) {

				CIDR_IP cidr;


				cidr_ip_fill_direct(ip, 32, &cidr);

				TRACE();
				akill_add(service, "*", host, NULL, FALSE, TRUE, &cidr, AKILL_TYPE_RESERVED, CONF_DEFAULT_CLONEKILL_EXPIRY, 0, lang);

				if (FlagSet(aName->flags, RESERVED_LOG)) {

					LOG_SNOOP(s_OperServ, "OS R! %s -- by %s (%s@%s) [Matches %s - AKilled]", value, nick, ident, host, aName->name);
					log_services(LOG_SERVICES_OPERSERV, "R! %s -- by %s (%s@%s) [Matches %s - AKilled]", value, nick, ident, host, aName->name);
				}

				TRACE();
				result = reservedAutoKill;
			}
			else if ((isExempt == FALSE) && FlagSet(aName->flags, RESERVED_KILL)) {

				TRACE();
				if (FlagSet(aName->flags, RESERVED_LOG)) {

					LOG_SNOOP(s_OperServ, "OS R! %s -- by %s (%s@%s) [Matches %s - Killed]", value, nick, ident, host, aName->name);
					log_services(LOG_SERVICES_OPERSERV, "R! %s -- by %s (%s@%s) [Matches %s - Killed]", value, nick, ident, host, aName->name);
				}

				result = reservedKill;
			}

			if (FlagSet(aName->flags, RESERVED_LOG)) {

				LOG_SNOOP(s_OperServ, "OS R! %s -- by %s (%s@%s) [Matches %s]", value, nick, ident, host, aName->name);
				log_services(LOG_SERVICES_OPERSERV, "R! %s -- by %s (%s@%s) [Matches %s]", value, nick, ident, host, aName->name);
			}

			return result;
		}
	}

	return reservedValid;
}


void handle_reserved(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *command;


	TRACE_MAIN_FCLT(FACILITY_RESERVED_HANDLE_RESERVED);

	if (IS_NULL(command = strtok(NULL, " "))) {

		send_notice_to_user(s_OperServ, callerUser, "Sintassi: \2RESERVED\2 [ADD|DEL|SET|LIST|INFO|ENABLE|DISABLE]");
		send_notice_to_user(s_OperServ, callerUser,	"Type \2/os OHELP RESERVED\2 for more information.");
	}
	else if (str_equals_nocase(command, "LIST")) {

		reservedName *aName;
		int idx = 0, startIdx = 0, endIdx = 30, sentIdx = 0;
		char *pattern, timebuf[64];


		if (IS_NULL(reservedNameList)) {

			send_notice_to_user(s_OperServ, callerUser, "The Reserved Names List is empty.");
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
			send_notice_to_user(s_OperServ, callerUser, "Current \2Reserved\2 names (showing entries %d-%d):", startIdx, endIdx);
		else
			send_notice_to_user(s_OperServ, callerUser, "Current \2Reserved\2 names (showing entries %d-%d matching %s):", startIdx, endIdx, pattern);

		aName = reservedNameList;

		while (IS_NOT_NULL(aName)) {

			++idx;

			if (IS_NOT_NULL(pattern) && !str_match_wild_nocase(pattern, aName->name)) {

				/* Doesn't match our search criteria, skip it. */
				aName = aName->next;
				continue;
			}

			++sentIdx;

			if (sentIdx < startIdx) {

				aName = aName->next;
				continue;
			}

			lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, aName->info.creator.time);

			send_notice_to_user(s_OperServ, callerUser, "%d) \2%s\2 [Flags: %s] [Reason: %s]", idx, aName->name, reserved_flagsToString(aName), aName->info.reason);
			send_notice_to_user(s_OperServ, callerUser, "Set by \2%s\2 on %s", aName->info.creator.name, timebuf);

			if (sentIdx >= endIdx)
				break;

			aName = aName->next;
		}

		TRACE_MAIN();
		send_notice_to_user(s_OperServ, callerUser, "End of list. Entries found: %d", idx);
		send_notice_to_user(s_OperServ, callerUser, "Reserved names control is %s.", reservedNameActive ? "ON" : "OFF");
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SA))
		send_notice_to_user(s_OperServ, callerUser, "Permission denied.");

	else if (str_equals_nocase(command, "ENABLE")) {

		TRACE_MAIN();
		reservedNameActive = TRUE;
		send_notice_to_user(s_OperServ, callerUser, "Reserved names check is Enabled.");

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "OS R Enable -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_OPERSERV, "R Enable -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
		}
		else {

			LOG_SNOOP(s_OperServ, "OS R Enable -- by %s (%s@%s) through %s", callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_OPERSERV, "R Enable -- by %s (%s@%s) through %s", callerUser->nick, callerUser->username, callerUser->host, data->operName);
		}
	}
	else if (str_equals_nocase(command, "DISABLE")) {

		TRACE_MAIN();
		reservedNameActive = FALSE;
		send_notice_to_user(s_OperServ, callerUser, "Reserved names check is Disabled.");

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "OS R Disable -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_OPERSERV, "R Disable -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
		}
		else {

			LOG_SNOOP(s_OperServ, "OS R Disable -- by %s (%s@%s) through %s", callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_OPERSERV, "R Disable -- by %s (%s@%s) through %s", callerUser->nick, callerUser->username, callerUser->host, data->operName);
		}
	}
	else if (str_equals_nocase(command, "ADD")) {

		char *value, *reason;


		if (IS_NOT_NULL(value = strtok(NULL, " ")) && IS_NOT_NULL(reason = strtok(NULL, ""))) {

			reservedName *aName;


			if (!validate_string(reason)) {

				send_notice_to_user(s_OperServ, callerUser, "Invalid reason supplied.");
				return;
			}

			if (str_spn(value, "*?.-@")) {

				if (data->operMatch) {

					send_globops(s_OperServ, "\2%s\2 tried adding \2%s\2 to the Reserved list", source, value);

					LOG_SNOOP(s_OperServ, "OS +R* %s -- by %s (%s@%s) [Lamer]", value, callerUser->nick, callerUser->username, callerUser->host);
					log_services(LOG_SERVICES_OPERSERV, "+R* %s -- by %s (%s@%s) [Lamer]", value, callerUser->nick, callerUser->username, callerUser->host);
				}
				else {

					send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried adding \2%s\2 to the Reserved list", source, data->operName, value);

					LOG_SNOOP(s_OperServ, "OS +R* %s -- by %s (%s@%s) through %s [Lamer]", value, callerUser->nick, callerUser->username, callerUser->host, data->operName);
					log_services(LOG_SERVICES_OPERSERV, "+R* %s -- by %s (%s@%s) through %s [Lamer]", value, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				}

				send_notice_to_user(s_OperServ, callerUser, "Hrmm, what would your admin think of that?");
				return;
			}
			
			str_compact(value);

			aName = reserved_find(value, FALSE);

			if (IS_NOT_NULL(aName)) {

				TRACE_MAIN();
				send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is already present in the Reserved list.", value);

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "OS +R* %s -- by %s (%s@%s) [Already Reserved]", value, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(s_OperServ, "OS +R* %s -- by %s (%s@%s) through %s [Already Reserved]", value, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				return;
			}

			terminate_string_ccodes(reason);

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 added \2%s\2 to the Reserved list", source, value);

				LOG_SNOOP(s_OperServ, "OS +R %s -- by %s (%s@%s)", value, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "+R %s -- by %s (%s@%s)", value, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) added \2%s\2 to the Reserved list", source, data->operName, value);

				LOG_SNOOP(s_OperServ, "OS +R %s -- by %s (%s@%s) through %s", value, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "+R %s -- by %s (%s@%s) through %s", value, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}

			send_notice_to_user(s_OperServ, callerUser, "\2%s\2 has been added successfully, but is currently disabled.", value);

			TRACE_MAIN();
			/* Allocate the new entry. */
			aName = (reservedName *) mem_calloc(1, sizeof(reservedName));

			/* Fill it. */
			aName->name = str_duplicate(value);

			str_creationinfo_init(&(aName->info));
			str_creationinfo_set(&(aName->info), data->operName, reason, NOW);

			/* Link it. */
			aName->next = reservedNameList;
			reservedNameList = aName;
		}
		else {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2RESERVED\2 ADD name reason");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP RESERVED\2 for more information.");
		}
	}
	else if (str_equals_nocase(command, "DEL")) {

		char *value;


		if (IS_NOT_NULL(value = strtok(NULL, " "))) {

			reservedName *aName, *namePrev;


			TRACE_MAIN();
			namePrev = NULL;
			aName = reservedNameList;

			while (IS_NOT_NULL(aName)) {

				if (str_equals_nocase(value, aName->name)) {

					if (IS_NOT_NULL(namePrev))
						namePrev->next = aName->next;
					else
						reservedNameList = aName->next;

					TRACE_MAIN();

					if (data->operMatch) {

						send_globops(s_OperServ, "\2%s\2 removed \2%s\2 from the Reserved list", source, aName->name);

						LOG_SNOOP(s_OperServ, "OS -R %s -- by %s (%s@%s)", aName->name, callerUser->nick, callerUser->username, callerUser->host);
						log_services(LOG_SERVICES_OPERSERV, "-R %s -- by %s (%s@%s)", aName->name, callerUser->nick, callerUser->username, callerUser->host);
					}
					else {

						send_globops(s_OperServ, "\2%s\2 (through \2%s\2) removed \2%s\2 from the Reserved list", source, data->operName, aName->name);

						LOG_SNOOP(s_OperServ, "OS -R %s -- by %s (%s@%s) through %s", aName->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
						log_services(LOG_SERVICES_OPERSERV, "-R %s -- by %s (%s@%s) through %s", aName->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
					}

					send_notice_to_user(s_OperServ, callerUser, "\2%s\2 has been removed from the Reserved list.", aName->name);

					// cancellazione
					mem_free(aName->name);
					str_creationinfo_free(&(aName->info));
					mem_free(aName);
					break;
				}

				TRACE_MAIN();
				namePrev = aName;
				aName = aName->next;
			}
		}
		else {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2RESERVED\2 DEL name");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP RESERVED\2 for more information.");
		}
	}
	else if (str_equals_nocase(command, "SET")) {

		char *value, *flags;


		if (IS_NOT_NULL(value = strtok(NULL, " ")) && IS_NOT_NULL(flags = strtok(NULL, " "))) {

			reservedName *aName;


			if (IS_NOT_NULL(aName = reserved_find(value, FALSE))) {

				char c;
				BOOL add = FALSE;

				TRACE_MAIN();
				while ((c = *flags++)) {

					switch (str_char_toupper(c)) {

						case '+':
							add = TRUE;
							break;

						case '-':
							add = FALSE;
							break;

						case 'N':
							if (add)
								AddFlag(aName->flags, RESERVED_NICK);
							else
								RemoveFlag(aName->flags, RESERVED_NICK);
							break;

						case 'C':
							if (add)
								AddFlag(aName->flags, RESERVED_CHAN);
							else
								RemoveFlag(aName->flags, RESERVED_CHAN);
							break;

						case 'U':
							if (add)
								AddFlag(aName->flags, RESERVED_NOUSE);
							else
								RemoveFlag(aName->flags, RESERVED_NOUSE);
							break;

						case 'R':
							if (add)
								AddFlag(aName->flags, RESERVED_NOREG);
							else
								RemoveFlag(aName->flags, RESERVED_NOREG);
							break;

						case 'W':
							if (add)
								AddFlag(aName->flags, RESERVED_ALERT);
							else
								RemoveFlag(aName->flags, RESERVED_ALERT);
							break;

						case 'K':
							if (add)
								AddFlag(aName->flags, RESERVED_KILL);
							else
								RemoveFlag(aName->flags, RESERVED_KILL);
							break;

						case 'A':
							if (add)
								AddFlag(aName->flags, RESERVED_AKILL);
							else
								RemoveFlag(aName->flags, RESERVED_AKILL);
							break;

						case 'L':
							if (add)
								AddFlag(aName->flags, RESERVED_LOG);
							else
								RemoveFlag(aName->flags, RESERVED_LOG);
							break;

						case 'E':
							if (add)
								AddFlag(aName->flags, RESERVED_ACTIVE);
							else
								RemoveFlag(aName->flags, RESERVED_ACTIVE);
							break;
					}
				}

				TRACE_MAIN();
				send_notice_to_user(s_OperServ, callerUser, "All changes have been applied successfully.");
				send_notice_to_user(s_OperServ, callerUser, "Current settings: %s", reserved_flagsToString(aName));
				send_notice_to_user(s_OperServ, callerUser, "Reserved names control is %s.", reservedNameActive ? "ON" : "OFF");
			}
			else {

				send_notice_to_user(s_OperServ, callerUser, "Name \2%s\2 is not in the reserved list.", value);

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "OS *R %s -- by %s (%s@%s) [Not Reserved]", value, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(s_OperServ, "OS *R %s -- by %s (%s@%s) through %s [Not Reserved]", value, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}
		}
		else {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2RESERVED SET\2 name [+|-]flags");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP RESERVED\2 for more information.");
		}
	}
	else if (str_equals_nocase(command, "INFO")) {

		reservedName *aName;
		char *value;


		if (IS_NOT_NULL(value = strtok(NULL, " "))) {

			if (IS_NOT_NULL(aName = reserved_find(value, FALSE))) {

				char timebuf[64];


				TRACE_MAIN();
				send_notice_to_user(s_OperServ, callerUser, "Informazioni sul nome riservato \2%s\2:", value);
				send_notice_to_user(s_OperServ, callerUser, "Flags: %s", reserved_flagsToString(aName));

				lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, aName->info.creator.time);
				send_notice_to_user(s_OperServ, callerUser, "Added by %s on %s", aName->info.creator.name, timebuf);
				send_notice_to_user(s_OperServ, callerUser, "Reason: %s", aName->info.reason);

				lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, aName->lastUpdate);

				send_notice_to_user(s_OperServ, callerUser, "Last Updated on %s", timebuf);
				send_notice_to_user(s_OperServ, callerUser, "Il controllo dei nomi riservati e' %s", reservedNameActive ? "attivo" : "disattivo");
			}
			else
				send_notice_to_user(s_OperServ, callerUser, "Il nome \2%s\2 non e' un nome riservato.", value);
		}
		else {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2RESERVED INFO\2 name");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP RESERVED\2 for more information.");
		}
	}
	else
		send_notice_to_user(s_OperServ, callerUser, "Sintassi: \2RESERVED\2 [ADD|DEL|SET|LIST|INFO|ENABLE|DISABLE]");

	TRACE_MAIN();
	if (!reservedNameListLoadComplete)
		send_notice_to_user(s_OperServ, callerUser, "\2Attenzione\2: non tutte le registrazioni sono state caricate allo startup. I cambiamenti \2NON\2 verranno salvati.");
}


void reserved_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	reservedName	*aName;
	int				startIdx = 0, endIdx = 5, reservedIdx = 0, sentIdx = 0;


	TRACE_FCLT(FACILITY_RESERVED_DS_DUMP);

	if (IS_NULL(reservedNameList)) {

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2Reserved Names\2 List is empty.");
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

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2Reserved Names\2 List (showing entries %d-%d):", startIdx, endIdx);
		LOG_DEBUG_SNOOP("Command: DUMP RESERVED %d-%d -- by %s (%s@%s)", startIdx, endIdx, callerUser->nick, callerUser->username, callerUser->host);
	}
	else {

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2Reserved Names\2 List (showing entries %d-%d matching %s):", startIdx, endIdx, request);
		LOG_DEBUG_SNOOP("Command: DUMP RESERVED %d-%d -- by %s (%s@%s) [Pattern: %s]", startIdx, endIdx, callerUser->nick, callerUser->username, callerUser->host, request);
	}

	aName = reservedNameList;

	while (IS_NOT_NULL(aName)) {

		++reservedIdx;

		if (IS_NOT_NULL(request) && !str_match_wild_nocase(request, aName->name)) {

			/* Doesn't match our search criteria, skip it. */
			aName = aName->next;
			continue;
		}

		++sentIdx;

		if (sentIdx < startIdx) {

			aName = aName->next;
			continue;
		}

		send_notice_to_user(sourceNick, callerUser, "%d) Address 0x%08X, size %d B",	reservedIdx, (unsigned long)aName, sizeof(reservedName));
		send_notice_to_user(sourceNick, callerUser, "Name: 0x%08X \2[\2%s\2]\2",		(unsigned long)aName->name, str_get_valid_display_value(aName->name));
		send_notice_to_user(sourceNick, callerUser, "Creator: 0x%08X \2[\2%s\2]\2",		(unsigned long)aName->info.creator.name, str_get_valid_display_value(aName->info.creator.name));
		send_notice_to_user(sourceNick, callerUser, "Reason: 0x%08X \2[\2%s\2]\2",		(unsigned long)aName->info.reason, str_get_valid_display_value(aName->info.reason));
		send_notice_to_user(sourceNick, callerUser, "Time Added C-time: %ld",			aName->info.creator.time);
		send_notice_to_user(sourceNick, callerUser, "Flags: %d",						aName->flags);
		send_notice_to_user(sourceNick, callerUser, "Last Update: %ld",					aName->lastUpdate);
		send_notice_to_user(sourceNick, callerUser, "Next record: 0x%08X",				(unsigned long)aName->next);

		if (sentIdx >= endIdx)
			break;

		aName = aName->next;
	}
}


unsigned long int reserved_mem_report(CSTR sourceNick, const User *callerUser) {

	unsigned long int count = 0, mem = 0;
	reservedName *aName;


	TRACE_FCLT(FACILITY_RESERVED_MEM_REPORT);

	send_notice_to_user(sourceNick, callerUser, "\2RESERVED NAMES\2:");

	/* Reserved names. */
	aName = reservedNameList;

	while (IS_NOT_NULL(aName)) {

		++count;

		mem += sizeof(reservedName);

		mem += str_len(aName->name) + 1;
		mem += str_len(aName->info.creator.name) + 1;
		mem += str_len(aName->info.reason) + 1;

		aName = aName->next;
	}

	send_notice_to_user(sourceNick, callerUser, "Reserved Name List: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", count, mem / 1024, mem);
	return mem;
}
