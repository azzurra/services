/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* access.c - Eggdrop-like access routines
*
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/cidr.h"
#include "../inc/logging.h"
#include "../inc/memory.h"
#include "../inc/storage.h"
#include "../inc/send.h"
#include "../inc/main.h"
#include "../inc/conf.h"
#include "../inc/users.h"
#include "../inc/access.h"

#if defined(USE_SERVICES) || defined(USE_SOCKSMONITOR)

/*********************************************************/

BOOL access_db_load(Access **accessList, CSTR database, BOOL *ListLoadComplete) {

	STGHANDLE	stg = 0;
	STG_RESULT	result;


	TRACE_MAIN_FCLT(FACILITY_ACCESS_DB_LOAD);

	*accessList = NULL;
	*ListLoadComplete = TRUE;

	result = stg_open(database, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version;
			BOOL		in_section;
			BOOL		read_done;
			int			recordIdx = 0;


			version = stg_data_version(stg);

			switch (version) {

				case ACCESS_DB_CURRENT_VERSION: {

					Access *anAccess;


					// start-of-section marker
					result = stg_read_record(stg, NULL, 0);

					if (result == stgBeginOfSection) {

						in_section = TRUE;

						while (in_section) {

							anAccess = mem_malloc(sizeof(Access));

							++recordIdx;

							result = stg_read_record(stg, (PBYTE)anAccess, sizeof(Access));

							switch (result) {

								case stgEndOfSection: // end-of-section
									in_section = FALSE;
									mem_free(anAccess);
									break;

								case stgSuccess: // a valid region

									read_done = TRUE;

									read_done &= (result = stg_read_string(stg, &(anAccess->nick), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anAccess->user))
										read_done &= (result = stg_read_string(stg, &(anAccess->user), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anAccess->user2))
										read_done &= (result = stg_read_string(stg, &(anAccess->user2), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anAccess->user3))
										read_done &= (result = stg_read_string(stg, &(anAccess->user3), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anAccess->host))
										read_done &= (result = stg_read_string(stg, &(anAccess->host), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anAccess->host2))
										read_done &= (result = stg_read_string(stg, &(anAccess->host2), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anAccess->host3))
										read_done &= (result = stg_read_string(stg, &(anAccess->host3), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anAccess->server))
										read_done &= (result = stg_read_string(stg, &(anAccess->server), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anAccess->server2))
										read_done &= (result = stg_read_string(stg, &(anAccess->server2), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anAccess->server3))
										read_done &= (result = stg_read_string(stg, &(anAccess->server3), NULL)) == stgSuccess;

									if (read_done && IS_NOT_NULL(anAccess->creator.name))
										read_done &= (result = stg_read_string(stg, &(anAccess->creator.name), NULL)) == stgSuccess;

									if (!read_done)
										fatal_error(FACILITY_ACCESS_DB_LOAD, __LINE__, "Read error on %s (2) - %s", database, stg_result_to_string(result));

									/* Link it. */
									anAccess->next = *accessList;
									*accessList = anAccess;
									break;

								default: // some error
									fatal_error(FACILITY_ACCESS_DB_LOAD, __LINE__, "Read error on %s [Record #%d] - %s", database, recordIdx, stg_result_to_string(result));
							}
						}
					}
					else
						fatal_error(FACILITY_ACCESS_DB_LOAD, __LINE__, "Read error on %s : invalid format", database);

					stg_close(stg, database);
					return TRUE;
				}

				default:
					fatal_error(FACILITY_ACCESS_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, database);
			}
		}

		case stgNotFound: // no data to load
			return TRUE;

		default: // error!
			stg_close(stg, database);

			fatal_error(FACILITY_ACCESS_DB_LOAD, __LINE__, "Error opening %s - %s", database, stg_result_to_string(result));
			return FALSE;
	}
}

/*********************************************************/

BOOL access_db_save(Access *accessList, CSTR database, BOOL ListLoadComplete) {

	STGHANDLE	stg;
	STG_RESULT	result;
	Access		*anAccess;
	int			error_index, idx = 0;
	char		*strings[11];


	TRACE_MAIN_FCLT(FACILITY_ACCESS_DB_SAVE);

	if (ListLoadComplete != TRUE) {

		log_error(FACILITY_ACCESS_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"access_db_save(): List is not fully loaded, not saving to %s", database);

		return FALSE;
	}

	result = stg_create(database, SF_NOFLAGS, ACCESS_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_ACCESS_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"access_db_save(): Could not create database file %s: %s [Error %d: %s]", database, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	result = stg_start_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_ACCESS_DB_SAVE, __LINE__, "Write error on %s - %s", database, stg_result_to_string(result));

	anAccess = accessList;

	TRACE_MAIN();
	while (IS_NOT_NULL(anAccess)) {

		++idx;

		result = stg_write_record(stg, (PBYTE)anAccess, sizeof(Access));

		if (result != stgSuccess)
			fatal_error(FACILITY_ACCESS_DB_SAVE, __LINE__, "Write error on %s - %s", database, stg_result_to_string(result));

		strings[0] = anAccess->nick;
		strings[1] = anAccess->user;
		strings[2] = anAccess->user2;
		strings[3] = anAccess->user3;
		strings[4] = anAccess->host;
		strings[5] = anAccess->host2;
		strings[6] = anAccess->host3;
		strings[7] = anAccess->server;
		strings[8] = anAccess->server2;
		strings[9] = anAccess->server3;
		strings[10] = anAccess->creator.name;

		error_index = -1;

		result = stg_write_strings(stg, strings, sizeof(strings) / sizeof(char *), &error_index);

		if (result != stgSuccess)
			fatal_error(FACILITY_ACCESS_DB_SAVE, __LINE__, "Write error on %s for string n. %d - %s", database, error_index, stg_result_to_string(result));

		TRACE_MAIN();
		anAccess = anAccess->next;
	}

	result = stg_end_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_ACCESS_DB_SAVE, __LINE__, "Write error on %s - %s", database, stg_result_to_string(result));

	stg_close(stg, database);
	return TRUE;
}

/*********************************************************/

void free_access_list(Access *accessList, int *ListLoadComplete) {

	Access *anAccess, *clear;

	TRACE_FCLT(FACILITY_ACCESS_FREE_ACCESS_LIST);

	anAccess = accessList;

	TRACE();
	while (IS_NOT_NULL(anAccess)) {

		TRACE();
		if (anAccess->nick)
			mem_free(anAccess->nick);
		if (anAccess->user)
			mem_free(anAccess->user);
		if (anAccess->user2)
			mem_free(anAccess->user2);
		if (anAccess->user3)
			mem_free(anAccess->user3);
		if (anAccess->host)
			mem_free(anAccess->host);
		if (anAccess->host2)
			mem_free(anAccess->host2);
		if (anAccess->host3)
			mem_free(anAccess->host3);
		if (anAccess->server)
			mem_free(anAccess->server);
		if (anAccess->server2)
			mem_free(anAccess->server2);
		if (anAccess->server3)
			mem_free(anAccess->server3);

		str_creator_free(&(anAccess->creator));

		TRACE();
		clear = anAccess;
		anAccess = anAccess->next;
		mem_free(clear);
	}

	TRACE();
	accessList = NULL;
	*ListLoadComplete = 0;
}

/*********************************************************/

Access *find_access(Access *accessList, const char *nick) {

	Access *anAccess = accessList;

	TRACE_FCLT(FACILITY_ACCESS_FIND_ACCESS);

	if (nick) {

		while (IS_NOT_NULL(anAccess)) {

			TRACE();
			if (str_equals_nocase(nick, anAccess->nick))
				return anAccess;

			anAccess = anAccess->next;
		}
	}

	return NULL;
}

/*********************************************************/

int match_access(Access *anAccess, CSTR user, CSTR host, CSTR server) {

	TRACE_FCLT(FACILITY_ACCESS_CHECK_ACCESS);

	if (anAccess && FlagSet(anAccess->flags, AC_FLAG_ENABLED)) {

		TRACE();
		if (((anAccess->user && str_match_wild_nocase(anAccess->user, user)) ||
			(anAccess->user2 && str_match_wild_nocase(anAccess->user2, user)) ||
			(anAccess->user3 && str_match_wild_nocase(anAccess->user3, user))) &&
			((anAccess->host && str_match_wild_nocase(anAccess->host, host)) ||
			(anAccess->host2 && str_match_wild_nocase(anAccess->host2, host)) ||
			(anAccess->host3 && str_match_wild_nocase(anAccess->host3, host))) &&
			((anAccess->server && str_match_wild_nocase(anAccess->server, server)) ||
			(anAccess->server2 && str_match_wild_nocase(anAccess->server2, server)) ||
			(anAccess->server3 && str_match_wild_nocase(anAccess->server3, server)))) {

			return GRANTED;
		}
	}

	return DENIED;
}

/*********************************************************/

int check_access(Access *accessList, CSTR nick, CSTR user, CSTR host, CSTR server, time_t tsinfo, Access **userAccess) {

	Access *anAccess = find_access(accessList, nick);

	TRACE_FCLT(FACILITY_ACCESS_CHECK_ACCESS);

	if (IS_NOT_NULL(userAccess))
		*userAccess = NULL;

	if (IS_NULL(anAccess))
		return AC_RESULT_NOTFOUND;

	if (match_access(anAccess, user, host, server)) {

		if (IS_NOT_NULL(userAccess))
			*userAccess = anAccess;

		#ifdef USE_SERVICES
		if ((anAccess->modes_on != 0) || (anAccess->modes_off != 0))
			send_user_SVSMODE(s_RootServ, nick, get_user_modes(anAccess->modes_on, anAccess->modes_off), tsinfo);
		#endif

		return AC_RESULT_GRANTED;
	}

	return AC_RESULT_DENIED;
}

/*********************************************************/

Access *access_add(Access **accessList, CSTR nick, CSTR creator) {

	Access *anAccess;

	anAccess = (Access *) mem_calloc(1, sizeof(Access));

	if (IS_NULL(anAccess))
		return NULL;

	anAccess->nick = str_duplicate(nick);
	str_creator_set(&anAccess->creator, creator, NOW);
	anAccess->lastUpdate = NOW;

	anAccess->next = *accessList;
	*accessList = anAccess;

	return anAccess;
}

/*********************************************************/

int access_remove(Access **accessList, CSTR nick, char *removed) {

	Access *anAccess, *accessPrev = NULL;

	anAccess = *accessList;

	TRACE_MAIN();
	while (IS_NOT_NULL(anAccess)) {

		if (str_equals_nocase(nick, anAccess->nick)) {

			#ifdef USE_SERVICES
			User *user;
			#endif

			if (IS_NOT_NULL(accessPrev))
				accessPrev->next = anAccess->next;
			else
				*accessList = anAccess->next;

			#ifdef USE_SERVICES
			TRACE_MAIN();

			if (IS_NOT_NULL(user = hash_onlineuser_find(nick)) && FlagSet(user->flags, UMODE_z)) {

				send_user_SVSMODE(s_RootServ, nick, "-z", user->tsinfo);
				RemoveFlag(user->flags, UMODE_z);
			}
			#endif

			if (IS_NOT_NULL(removed))
				str_copy_checked(anAccess->nick, removed, NICKSIZE);

			TRACE_MAIN();
			if (anAccess->nick)
				mem_free(anAccess->nick);
			TRACE_MAIN();
			if (anAccess->user)
				mem_free(anAccess->user);
			TRACE_MAIN();
			if (anAccess->user2)
				mem_free(anAccess->user2);
			TRACE_MAIN();
			if (anAccess->user3)
				mem_free(anAccess->user3);
			TRACE_MAIN();
			if (anAccess->host)
				mem_free(anAccess->host);
			TRACE_MAIN();
			if (anAccess->host2)
				mem_free(anAccess->host2);
			TRACE_MAIN();
			if (anAccess->host3)
				mem_free(anAccess->host3);
			TRACE_MAIN();
			if (anAccess->server)
				mem_free(anAccess->server);
			TRACE_MAIN();
			if (anAccess->server2)
				mem_free(anAccess->server2);
			TRACE_MAIN();
			if (anAccess->server3)
				mem_free(anAccess->server3);
			TRACE_MAIN();
			str_creator_free(&(anAccess->creator));

			TRACE_MAIN();
			mem_free(anAccess);

			return TRUE;
		}

		accessPrev = anAccess;
		anAccess = anAccess->next;
	}

	return FALSE;
}

/*********************************************************/

void send_access_list(Access *accessList, const char *sourceNick, const User *target) {

	int n = 0;
	Access *anAccess = accessList;

	while (IS_NOT_NULL(anAccess)) {

		send_notice_to_user(sourceNick, target, "%d) %s", ++n, anAccess->nick);
		anAccess = anAccess->next;
	}

	send_notice_to_user(sourceNick, target, "*** End of List ***");
}

/*********************************************************/

BOOL send_access_info(Access *accessList, CSTR nick, CSTR sourceNick, const User *target) {

	Access *anAccess = find_access(accessList, nick);

	if (anAccess) {

		char timebuf[64];
		struct tm tm;

		TRACE_MAIN();
		send_notice_to_user(sourceNick, target, "Info on \2%s\2:", anAccess->nick);
		send_notice_to_user(sourceNick, target, "User: %s", anAccess->user ? anAccess->user : "<?>");

		if (anAccess->user2)
			send_notice_to_user(sourceNick, target, "User 2: %s", anAccess->user2);
		if (anAccess->user3)
			send_notice_to_user(sourceNick, target, "User 3: %s", anAccess->user3);

		send_notice_to_user(sourceNick, target, "Host: %s", anAccess->host ? anAccess->host : "<?>");

		if (anAccess->host2)
			send_notice_to_user(sourceNick, target, "Host 2: %s", anAccess->host2);
		if (anAccess->host3)
			send_notice_to_user(sourceNick, target, "Host 3: %s", anAccess->host3);

		send_notice_to_user(sourceNick, target, "Server: %s", anAccess->server ? anAccess->server : "<?>");

		if (anAccess->server2)
			send_notice_to_user(sourceNick, target, "Server 2: %s", anAccess->server2);
		if (anAccess->server3)
			send_notice_to_user(sourceNick, target, "Server 3: %s", anAccess->server3);

		#ifdef USE_SERVICES
		send_notice_to_user(sourceNick, target, "Modes On/Off: %s", get_user_modes(anAccess->modes_on, anAccess->modes_off));
		#endif

		send_notice_to_user(sourceNick, target, "Enabled: %s", FlagSet(anAccess->flags, AC_FLAG_ENABLED) ? "Yes" : "No");

		tm = *localtime(&(anAccess->creator.time));
		strftime(timebuf, sizeof(timebuf), "%d/%m/%Y %H:%M:%S (%Z)", &tm);

		send_notice_to_user(sourceNick, target, "Registered by %s on %s", anAccess->creator.name, timebuf);

		TRACE_MAIN();
		tm = *localtime(&(anAccess->lastUpdate));
		strftime(timebuf, sizeof(timebuf), "%d/%m/%Y %H:%M:%S (%Z)", &tm);
		send_notice_to_user(sourceNick, target, "Last Update: %s", timebuf);

		return TRUE;
	}

	return FALSE;
}

/*********************************************************/

void access_send_dump(Access *anAccess, CSTR sourceNick, const User *callerUser) {

	send_notice_to_user(sourceNick, callerUser, "Address 0x%08X, size %d B",		(unsigned long)anAccess, sizeof(Access));
	send_notice_to_user(sourceNick, callerUser, "Nick: 0x%08X \2[\2%s\2]\2",		(unsigned long)anAccess->nick, str_get_valid_display_value(anAccess->nick));
	send_notice_to_user(sourceNick, callerUser, "User: 0x%08X \2[\2%s\2]\2",		(unsigned long)anAccess->user, str_get_valid_display_value(anAccess->user));
	send_notice_to_user(sourceNick, callerUser, "User2: 0x%08X \2[\2%s\2]\2",		(unsigned long)anAccess->user2, str_get_valid_display_value(anAccess->user2));
	send_notice_to_user(sourceNick, callerUser, "User3: 0x%08X \2[\2%s\2]\2",		(unsigned long)anAccess->user3, str_get_valid_display_value(anAccess->user3));
	send_notice_to_user(sourceNick, callerUser, "Host: 0x%08X \2[\2%s\2]\2",		(unsigned long)anAccess->host, str_get_valid_display_value(anAccess->host));
	send_notice_to_user(sourceNick, callerUser, "Host2: 0x%08X \2[\2%s\2]\2",		(unsigned long)anAccess->host2, str_get_valid_display_value(anAccess->host2));
	send_notice_to_user(sourceNick, callerUser, "Host3: 0x%08X \2[\2%s\2]\2",		(unsigned long)anAccess->host3, str_get_valid_display_value(anAccess->host3));
	send_notice_to_user(sourceNick, callerUser, "Server: 0x%08X \2[\2%s\2]\2",		(unsigned long)anAccess->server, str_get_valid_display_value(anAccess->server));
	send_notice_to_user(sourceNick, callerUser, "Server2: 0x%08X \2[\2%s\2]\2",		(unsigned long)anAccess->server2, str_get_valid_display_value(anAccess->server2));
	send_notice_to_user(sourceNick, callerUser, "Server3: 0x%08X \2[\2%s\2]\2",		(unsigned long)anAccess->server3, str_get_valid_display_value(anAccess->server3));
	send_notice_to_user(sourceNick, callerUser, "Flags: %ld",						anAccess->flags);

	#ifdef USE_SERVICES
	send_notice_to_user(sourceNick, callerUser, "Modes ON: %ld \2[\2%s\2]\2",		anAccess->modes_on, get_user_modes(anAccess->modes_on, 0));
	send_notice_to_user(sourceNick, callerUser, "Modes OFF: %ld \2[\2%s\2]\2",		anAccess->modes_off, get_user_modes(0, anAccess->modes_off));
	#endif

	send_notice_to_user(sourceNick, callerUser, "Created by: 0x%08X \2[\2%s\2]\2",	(unsigned long)anAccess->creator.name, str_get_valid_display_value(anAccess->creator.name));
	send_notice_to_user(sourceNick, callerUser, "Time Added C-time: %ld",			anAccess->creator.time);
	send_notice_to_user(sourceNick, callerUser, "Last Update C-time: %ld",			anAccess->lastUpdate);
	send_notice_to_user(sourceNick, callerUser, "Next record: 0x%08X",				(unsigned long)anAccess->next);
}

/*********************************************************/

void access_ds_dump(Access *accessList, CSTR sourceNick, const User *callerUser, BOOL listOnly) {

	Access	*anAccess = accessList;
	int		count = 0;


	if (listOnly == TRUE) {

		while (IS_NOT_NULL(anAccess)) {

			send_notice_to_user(sourceNick, callerUser, "%d) \2%s\2 [Added by %s]", ++count, anAccess->nick, anAccess->creator.name);

			anAccess = anAccess->next;
		}
	}
	else {

		while (IS_NOT_NULL(anAccess)) {

			send_notice_to_user(sourceNick, callerUser, "Entry #%d:", ++count);

			access_send_dump(anAccess, sourceNick, callerUser);

			anAccess = anAccess->next;
		}
	}
}

/*********************************************************/

unsigned long access_mem_report(Access *accessList, int *count) {

	Access *anAccess = accessList;
	unsigned long mem = 0;

	*count = 0;

	while (IS_NOT_NULL(anAccess)) {

		++(*count);

		mem += sizeof(Access);
		mem += str_len(anAccess->nick) + 1;

		if (anAccess->user)
			mem += str_len(anAccess->user) + 1;
		if (anAccess->user2)
			mem += str_len(anAccess->user2) + 1;
		if (anAccess->user3)
			mem += str_len(anAccess->user3) + 1;
		if (anAccess->host)
			mem += str_len(anAccess->host) + 1;
		if (anAccess->host2)
			mem += str_len(anAccess->host2) + 1;
		if (anAccess->host3)
			mem += str_len(anAccess->host3) + 1;
		if (anAccess->server)
			mem += str_len(anAccess->server) + 1;
		if (anAccess->server2)
			mem += str_len(anAccess->server2) + 1;
		if (anAccess->server3)
			mem += str_len(anAccess->server3) + 1;

		mem += str_len(anAccess->creator.name) + 1;

		anAccess = anAccess->next;
	}

	return mem;
}

#endif /* defined(USE_SERVICES) || defined(USE_SOCKSMONITOR) */
