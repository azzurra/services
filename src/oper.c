/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* oper.c - Services Operator Access Control
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
#include "../inc/main.h"
#include "../inc/misc.h"
#include "../inc/oper.h"
#include "../inc/users.h"
#include "../inc/storage.h"
#include "../inc/list.h"


/*********************************************************
 * Local variables                                       *
 *********************************************************/

static Oper *opers[256];


/*********************************************************
 * Forward definitions                                   *
 *********************************************************/

static void database_insert_oper(Oper *item);
static char *get_access_name(int accessLevel, BOOL isShort);
static Oper *oper_add(CSTR nick, CSTR creator, int accessLevel);
static Oper *findoper(CSTR nick);


/*********************************************************/

/* Load/save data files. */
BOOL oper_db_load(void) {

	STGHANDLE	stg = 0;
	STG_RESULT	result;
	BOOL		masterFound = FALSE;
	Oper		*currentMaster = NULL, *confMaster = NULL;


	TRACE_FCLT(FACILITY_OPER_DB_LOAD);

	result = stg_open(OPER_DB, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version;
			BOOL		in_section;
			BOOL		read_done;


			version = stg_data_version(stg);

			switch (version) {

				case OPER_DB_CURRENT_VERSION: {

					Oper	*anOper;
					int		operIdx;


					for (operIdx = FIRST_VALID_NICK_CHAR; operIdx <= LAST_VALID_NICK_CHAR; ++operIdx) {

						// start-of-section marker
						result = stg_read_record(stg, NULL, 0);

						if (result == stgBeginOfSection) {

							in_section = TRUE;

							while (in_section) {

								anOper = mem_malloc(sizeof(Oper));

								result = stg_read_record(stg, (PBYTE)anOper, sizeof(Oper));

								switch (result) {

									case stgEndOfSection: // end-of-section
										in_section = FALSE;
										mem_free(anOper);
										break;

									case stgSuccess: // a valid region

										read_done = TRUE;

										read_done &= (result = stg_read_string(stg, &(anOper->nick), NULL)) == stgSuccess;

										if (read_done)
											read_done &= (result = stg_read_string(stg, &(anOper->creator.name), NULL)) == stgSuccess;

										#ifndef USE_SERVICES
										if (read_done && IS_NOT_NULL(anOper->password))
											read_done &= (result = stg_read_string(stg, &(anOper->password), NULL)) == stgSuccess;
										#endif

										if (!read_done)
											fatal_error(FACILITY_OPER_DB_LOAD, __LINE__, "Read error on %s (2) - %s", OPER_DB, stg_result_to_string(result));

										database_insert_oper(anOper);

										if (anOper->level == ULEVEL_MASTER) {

											masterFound = TRUE;
											currentMaster = anOper;
										}

										if (str_equals_nocase(anOper->nick, CONF_SERVICES_MASTER))
											confMaster = anOper;

										break;

									default: // some error
										fatal_error(FACILITY_OPER_DB_LOAD, __LINE__, "Read error on %s - %s", OPER_DB, stg_result_to_string(result));
								}
							}
						}
						else
							fatal_error(FACILITY_OPER_DB_LOAD, __LINE__, "Read error on %s : invalid format", OPER_DB);
					}

					stg_close(stg, OPER_DB);
					break;
				}

				case 10: {

					Oper_V10		anOper_V10;
					Oper_V11		*anOper_V11;
					OperAccess_V10	*anAccess;
					int				operIdx, accessIdx;


					for (operIdx = FIRST_VALID_NICK_CHAR; operIdx <= LAST_VALID_NICK_CHAR; ++operIdx) {

						// start-of-section marker
						result = stg_read_record(stg, NULL, 0);

						if (result == stgBeginOfSection) {

							in_section = TRUE;

							while (in_section) {

								anOper_V11 = mem_malloc(sizeof(Oper_V11));

								result = stg_read_record(stg, (PBYTE)&anOper_V10, sizeof(Oper_V10));

								switch (result) {

									case stgEndOfSection: // end-of-section
										in_section = FALSE;
										mem_free(anOper_V11);
										break;

									case stgSuccess: // a valid region

										read_done = TRUE;

										read_done &= (result = stg_read_string(stg, &(anOper_V11->nick), NULL)) == stgSuccess;

										if (read_done)
											read_done &= (result = stg_read_string(stg, &(anOper_V11->creator.name), NULL)) == stgSuccess;

										if (!read_done)
											fatal_error(FACILITY_OPER_DB_LOAD, __LINE__, "Read error on %s (2) - %s", OPER_DB, stg_result_to_string(result));

										#ifndef USE_SERVICES
										anOper_V11->password = IS_EMPTY_STR(anOper_V10.password) ? NULL : str_duplicate(anOper_V10.password);
										#endif

										anOper_V11->creator.time = anOper_V10.creator.time;
										anOper_V11->lastUpdate = anOper_V10.lastUpdate;
										anOper_V11->flags = anOper_V10.flags;
										anOper_V11->level = anOper_V10.level;

										database_insert_oper(anOper_V11);

										/* Read the userlist. */
										for (accessIdx = 0; accessIdx < anOper_V10.userCount; ++accessIdx) {

											anAccess = mem_malloc(sizeof(OperAccess));

											result = stg_read_record(stg, (PBYTE)anAccess, sizeof(OperAccess_V10));

											if (result != stgSuccess)
												fatal_error(FACILITY_OPER_DB_LOAD, __LINE__, "Read error on %s - %s", OPER_DB, stg_result_to_string(result));

											read_done = TRUE;

											read_done &= (result = stg_read_string(stg, &(anAccess->name), NULL)) == stgSuccess;

											if (read_done)
												read_done &= (result = stg_read_string(stg, &(anAccess->creator.name), NULL)) == stgSuccess;

											if (!read_done)
												fatal_error(FACILITY_OPER_DB_LOAD, __LINE__, "Read error on %s (2) - %s", OPER_DB, stg_result_to_string(result));

											mem_free(anAccess->name);
											mem_free(anAccess->creator.name);
											mem_free(anAccess);
										}

										/* Read the hostlist. */
										for (accessIdx = 0; accessIdx < anOper_V10.hostCount; ++accessIdx) {

											anAccess = mem_malloc(sizeof(OperAccess));

											result = stg_read_record(stg, (PBYTE)anAccess, sizeof(OperAccess_V10));

											if (result != stgSuccess)
												fatal_error(FACILITY_OPER_DB_LOAD, __LINE__, "Read error on %s - %s", OPER_DB, stg_result_to_string(result));

											read_done = TRUE;

											read_done &= (result = stg_read_string(stg, &(anAccess->name), NULL)) == stgSuccess;

											if (read_done)
												read_done &= (result = stg_read_string(stg, &(anAccess->creator.name), NULL)) == stgSuccess;

											if (!read_done)
												fatal_error(FACILITY_OPER_DB_LOAD, __LINE__, "Read error on %s (2) - %s", OPER_DB, stg_result_to_string(result));

											mem_free(anAccess->name);
											mem_free(anAccess->creator.name);
											mem_free(anAccess);
										}

										if (anOper_V11->level == ULEVEL_MASTER) {

											masterFound = TRUE;
											currentMaster = anOper_V11;
										}

										if (str_equals_nocase(anOper_V11->nick, CONF_SERVICES_MASTER))
											confMaster = anOper_V11;

										break;

									default: // some error
										fatal_error(FACILITY_OPER_DB_LOAD, __LINE__, "Read error on %s - %s", OPER_DB, stg_result_to_string(result));
								}
							}
						}
						else
							fatal_error(FACILITY_OPER_DB_LOAD, __LINE__, "Read error on %s : invalid format", OPER_DB);
					}

					stg_close(stg, OPER_DB);
					break;
				}

				default:
					fatal_error(FACILITY_OPER_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, OPER_DB);
			}

			break;
		}

		case stgNotFound: // no data to load
			break;

		default: // error!
			stg_close(stg, OPER_DB);

			fatal_error(FACILITY_OPER_DB_LOAD, __LINE__, "Error opening %s - %s", OPER_DB, stg_result_to_string(result));
			return FALSE;
	}

	TRACE();
	if (currentMaster != confMaster) {
		// il Services Master attuale non e' quello specificato nel .conf

		if (currentMaster) {

			/* Rimuovere il Master attuale. */
			currentMaster->level = ULEVEL_HOP;
			RemoveFlag(currentMaster->flags, OPER_FLAG_ENABLED);

 			/* Forzare la creazione dell'entry per il nuovo Master. */
			masterFound = FALSE;
		}

		if (confMaster) {

			/* Promuovere a Master. */
			confMaster->level = ULEVEL_MASTER;
			AddFlag(confMaster->flags, OPER_FLAG_ENABLED);
			masterFound = TRUE;
		}
	}

	if (!masterFound) {

		Oper *anOper;

		if (IS_NULL(anOper = findoper(CONF_SERVICES_MASTER))) {

			/* Create an entry for the new Master. */
			anOper = oper_add(CONF_SERVICES_MASTER, "Services", ULEVEL_MASTER);

			#ifndef USE_SERVICES
			/* Set their password. */
			anOper->password = str_duplicate(CONF_SERVICES_MASTER_PASS);
			#endif
		}
		else
			anOper->level = ULEVEL_MASTER;

		/* Enable the entry. */
		AddFlag(anOper->flags, OPER_FLAG_ENABLED);
	}

	return TRUE;
}

/*********************************************************/

BOOL oper_db_save(void) {

	STGHANDLE	stg;
	STG_RESULT	result;
	Oper		*anOper;
	int			operIdx, error_index;
	char		*strings[3];


	TRACE_FCLT(FACILITY_OPER_DB_SAVE);

	result = stg_create(OPER_DB, SF_NOFLAGS, OPER_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_OPER_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"oper_db_save(): Could not create database file %s: %s [Error %d: %s]", OPER_DB, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	TRACE();

	for (operIdx = FIRST_VALID_NICK_CHAR; operIdx <= LAST_VALID_NICK_CHAR; ++operIdx) {

		result = stg_start_section(stg);

		if (result != stgSuccess)
			fatal_error(FACILITY_OPER_DB_SAVE, __LINE__, "Write error on %s - %s", OPER_DB, stg_result_to_string(result));

		for (anOper = opers[operIdx]; IS_NOT_NULL(anOper); anOper = anOper->next) {

			result = stg_write_record(stg, (PBYTE)anOper, sizeof(Oper));

			if (result != stgSuccess)
				fatal_error(FACILITY_OPER_DB_SAVE, __LINE__, "Write error on %s - %s", OPER_DB, stg_result_to_string(result));

			strings[0] = anOper->nick;
			strings[1] = anOper->creator.name;

			#ifdef USE_SERVICES
			strings[2] = NULL;
			#else
			strings[2] = anOper->password;
			#endif

			error_index = -1;

			result = stg_write_strings(stg, strings, sizeof(strings) / sizeof(char *), &error_index);

			if (result != stgSuccess)
				fatal_error(FACILITY_OPER_DB_SAVE, __LINE__, "Write error on %s for string n. %d - %s", OPER_DB, error_index, stg_result_to_string(result));
		}

		result = stg_end_section(stg);

		if (result != stgSuccess)
			fatal_error(FACILITY_OPER_DB_SAVE, __LINE__, "Write error on %s - %s", OPER_DB, stg_result_to_string(result));
	}

	stg_close(stg, OPER_DB);
	return TRUE;
}

/*********************************************************/

/* Insert a nick into the database. */
static void database_insert_oper(Oper *item) {

	Oper		*branch_head;
	int			branch_name;

	TRACE_FCLT(FACILITY_OPER_DATABASE_INSERT_OPER);

	if (IS_NULL(item)) {

		log_error(FACILITY_OPER_DATABASE_INSERT_OPER, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, s_LOG_ERR_PARAMETER, "database_insert_oper()", s_LOG_NULL, "item");
		return;
	}

	branch_name = str_char_tolower(item->nick[0]);

	TRACE();
	branch_head = opers[branch_name];
	opers[branch_name] = item;

	TRACE();
	item->next = branch_head;
	item->prev = NULL;

	if (IS_NOT_NULL(branch_head))
		branch_head->prev = item;
}

/*********************************************************/

static Oper *findoper(CSTR nick) {

	Oper *oper;

	TRACE_FCLT(FACILITY_OPER_FINDOPER);

	if (IS_NOT_NULL(nick) && IS_NOT_EMPTY_STR(nick)) {

		for (oper = opers[str_char_tolower(*nick)]; IS_NOT_NULL(oper); oper = oper->next) {

			TRACE();
			if (str_equals_nocase(oper->nick, nick))
				return oper;
		}
	}

	return NULL;
}

/*********************************************************/

/* Add a nick to the database. Returns a pointer to the new Oper
 * structure if the nick was successfully registered, NULL otherwise.
 * Assumes nick does not already exist. */

static Oper *oper_add(CSTR nick, CSTR creator, int accessLevel) {

	Oper *oper;

	TRACE_FCLT(FACILITY_OPER_MAKEOPER);

	oper = mem_calloc(1, sizeof(Oper));
	oper->nick = str_duplicate(nick);

	database_insert_oper(oper);

	str_creator_set(&(oper->creator), creator, NOW);

	oper->lastUpdate = NOW;
	oper->level = accessLevel;

	return oper;
}

/*********************************************************/

static void oper_remove(Oper *oper) {

	User *user;
	unsigned int idx;


	TRACE_FCLT(FACILITY_OPER_DELOPER);

	HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM(onlineuser, idx, user) {

			if (user->oper == oper)
				user->oper = NULL;
		}
	}

	TRACE();
	if (oper->next)
		oper->next->prev = oper->prev;

	if (oper->prev)
		oper->prev->next = oper->next;
	else
		opers[str_char_tolower(*oper->nick)] = oper->next;

	TRACE();

	mem_free(oper->nick);
	str_creator_free(&(oper->creator));

	#ifndef USE_SERVICES
	mem_free(oper->password);
	#endif

	mem_free(oper);
}

/*********************************************************/

#ifdef USE_SERVICES
void oper_remove_nick(CSTR nick) {

	Oper *oper;


	TRACE_FCLT(FACILITY_OPER_REMOVE_NICK);

	if (IS_NOT_NULL(oper = findoper(nick))) {

		switch (oper->level) {

			case ULEVEL_MASTER:
				send_globops(s_OperServ, "\2%s\2 has been expired from the MASTERS list", oper->nick);

				LOG_SNOOP(s_OperServ, "OS X MASTERS [%s]", oper->nick);
				log_services(LOG_SERVICES_OPERSERV, "X MASTERS [%s]", oper->nick);
				break;

			case ULEVEL_CODER:
				send_globops(s_OperServ, "\2%s\2 has been expired from the CODERS list", oper->nick);

				LOG_SNOOP(s_OperServ, "OS X CODERS [%s]", oper->nick);
				log_services(LOG_SERVICES_OPERSERV, "X CODERS [%s]", oper->nick);
				break;

			case ULEVEL_SRA:
				send_globops(s_OperServ, "\2%s\2 has been expired from the SRA list", oper->nick);

				LOG_SNOOP(s_OperServ, "OS X SRA [%s]", oper->nick);
				log_services(LOG_SERVICES_OPERSERV, "X SRA [%s]", oper->nick);
				break;

			case ULEVEL_SA:
				send_globops(s_OperServ, "\2%s\2 has been expired from the SA list", oper->nick);

				LOG_SNOOP(s_OperServ, "OS X SA [%s]", oper->nick);
				log_services(LOG_SERVICES_OPERSERV, "X SA [%s]", oper->nick);
				break;

			case ULEVEL_SOP:
				send_globops(s_OperServ, "\2%s\2 has been expired from the SOP list", oper->nick);

				LOG_SNOOP(s_OperServ, "OS X SOP [%s]", oper->nick);
				log_services(LOG_SERVICES_OPERSERV, "X SOP [%s]", oper->nick);
				break;

			case ULEVEL_HOP:
				send_globops(s_OperServ, "\2%s\2 has been expired from the HOP list", oper->nick);

				LOG_SNOOP(s_OperServ, "OS X HOP [%s]", oper->nick);
				log_services(LOG_SERVICES_OPERSERV, "X HOP [%s]", oper->nick);
				break;
		}

		oper_remove(oper);
	}
}
#endif

/*********************************************************/

int check_oper(User *user, CSTR nick, CSTR password) {

	Oper *oper;

	#ifndef USE_SERVICES
	BOOL match = (str_equals_nocase(user->nick, nick));

	if (IS_NOT_NULL(user->oper)) {

		if (match)
			send_globops(s_Snooper, "\2%s\2 tried to log in (already logged in as \2%s\2)", nick, user->oper->nick);
		else
			send_globops(s_Snooper, "\2%s\2 tried to log in as \2%s\2 (already logged in as \2%s\2)", user->nick, nick, user->oper->nick);

		send_notice_to_user(s_Snooper, user, "You are already logged in as \2%s\2.", user->oper->nick);

		LOG_SNOOP(s_Snooper, "SM *L %s -- by %s [Already logged as %s]", nick, user->nick, user->oper->nick);
		return ULEVEL_USER;
	}
	#endif

	oper = findoper(nick);

	if (IS_NULL(oper)) {

		#ifndef USE_SERVICES
		if (match)
			send_globops(s_Snooper, "\2%s\2 tried to log in (no entry)", nick);
		else
			send_globops(s_Snooper, "\2%s\2 tried to log in as \2%s\2 (no entry)", user->nick, nick);

		send_notice_to_user(s_Snooper, user, "Access denied.");

		LOG_SNOOP(s_Snooper, "SM *L %s -- by %s [No entry]", nick, user->nick);
		#endif

		return ULEVEL_USER;
	}

	if (FlagSet(oper->flags, OPER_FLAG_ENABLED)) {

		if ((oper->level <= ULEVEL_HOP) || user_is_ircop(user)) {

			#ifndef USE_SERVICES
			char accessLevel[64];

			if (str_not_equals(password, oper->password)) {

				if (match)
					send_globops(s_Snooper, "\2%s\2 tried to log in (password mismatch)", nick);
				else
					send_globops(s_Snooper, "\2%s\2 tried to log in as \2%s\2 (password mismatch)", user->nick, nick);

				send_notice_to_user(s_Snooper, user, "Password supplied for \2%s\2 is incorrect.", nick);

				LOG_SNOOP(s_Snooper, "SM *L %s -- by %s [Wrong Pass]", nick, user->nick);
				return ULEVEL_USER;
			}

			switch (oper->level) {

				case ULEVEL_HOP:
					str_copy_checked("You are now logged in as Services HelpOp.", accessLevel, sizeof(accessLevel));
					break;

				case ULEVEL_SOP:
					str_copy_checked("You are now logged in as Services Operator.", accessLevel, sizeof(accessLevel));
					break;

				case ULEVEL_SA:
					str_copy_checked("You are now logged in as Services Admin.", accessLevel, sizeof(accessLevel));
					break;

				case ULEVEL_SRA:
					str_copy_checked("You are now logged in as Services Root.", accessLevel, sizeof(accessLevel));
					break;

				case ULEVEL_CODER:
					str_copy_checked("You are now logged in as Services Coder.", accessLevel, sizeof(accessLevel));
					break;

				case ULEVEL_MASTER:
					str_copy_checked("You are now logged in as Services Master.", accessLevel, sizeof(accessLevel));
					break;

				default:
					LOG_DEBUG_SNOOP("Unknown access return (%d) for user %s", oper->level, user->nick);
					return ULEVEL_USER;
			}

			if (match)
				send_globops(s_Snooper, "\2%s\2 logged in", oper->nick);
			else
				send_globops(s_Snooper, "\2%s\2 logged in as \2%s\2", user->nick, oper->nick);

			send_notice_to_user(s_Snooper, user, accessLevel);

			LOG_SNOOP(s_Snooper, "SM L %s -- by %s (%s@%s) [%s]", oper->nick, user->nick, user->username, user->host, get_access_name(oper->level, FALSE));
			#endif

			if (IS_NULL(user->oper) || (user->oper->level < oper->level))
				user->oper = oper;

			return (user->oper->level);
		}
		#ifndef USE_SERVICES
		else {

			if (match)
				send_globops(s_Snooper, "\2%s\2 tried to log in (no access)", nick);
			else
				send_globops(s_Snooper, "\2%s\2 tried to log in as \2%s\2 (no access)", user->nick, nick);

			send_notice_to_user(s_Snooper, user, "Access denied.");

			LOG_SNOOP(s_Snooper, "SM *L %s -- by %s [No Access]", nick, user->nick);
		}
		#endif
	}
	#ifndef USE_SERVICES
	else {

		if (match)
			send_globops(s_Snooper, "\2%s\2 tried to log in (entry disabled)", nick);
		else
			send_globops(s_Snooper, "\2%s\2 tried to log in as \2%s\2 (entry disabled)", user->nick, nick);

		send_notice_to_user(s_Snooper, user, "Access denied.", nick);

		LOG_SNOOP(s_Snooper, "SM *L %s -- by %s [Entry Disabled]", nick, user->nick);
	}
	#endif

	return ULEVEL_USER;
}

/*********************************************************/

static void send_oper_list(const char *sourceNick, const User *target, int accessLevel, BOOL last) {

	int idx, count = 0;
	BOOL need_header = TRUE;
	Oper *oper;

	for (idx = FIRST_VALID_NICK_CHAR; idx <= LAST_VALID_NICK_CHAR; ++idx) {

		for (oper = opers[idx]; IS_NOT_NULL(oper); oper = oper->next) {

			if (oper->level == accessLevel) {

				if (need_header == TRUE) {

					send_notice_to_user(sourceNick, target, "Current \2%s\2 list:", get_access_name(accessLevel, FALSE));
					need_header = FALSE;
				}

				send_notice_to_user(sourceNick, target, "%d) %s", ++count, oper->nick);
			}
		}
	}

	if (last)
		send_notice_to_user(sourceNick, target, "*** \2End of List\2 ***");
	else if (need_header == FALSE)
		send_notice_to_user(sourceNick, target, s_SPACE);
}

/*********************************************************/

static BOOL send_oper_info(CSTR nick, CSTR sourceNick, const User *target) {

	Oper *oper = findoper(nick);

	if (IS_NOT_NULL(oper)) {

		char timebuf[64];
		struct tm tm;


		send_notice_to_user(sourceNick, target, "Info on \2%s\2:", oper->nick);

		switch (oper->level) {

			case ULEVEL_HOP:
				send_notice_to_user(sourceNick, target, "Access Level: \2HOP\2");
				break;

			case ULEVEL_SOP:
				send_notice_to_user(sourceNick, target, "Access Level: \2SOP\2");
				break;

			case ULEVEL_SA:
				send_notice_to_user(sourceNick, target, "Access Level: \2SA\2");
				break;

			case ULEVEL_SRA:
				send_notice_to_user(sourceNick, target, "Access Level: \2SRA\2");
				break;

			case ULEVEL_CODER:
				send_notice_to_user(sourceNick, target, "Access Level: \2CODER\2");
				break;

			case ULEVEL_MASTER:
				send_notice_to_user(sourceNick, target, "Access Level: \2MASTER\2");
				break;

			case ULEVEL_USER:
				send_notice_to_user(sourceNick, target, "Access Level: \2None\2");

			default:
				send_notice_to_user(sourceNick, target, "Access Level: \2Unknown (%d)\2", oper->level);
		}

		send_notice_to_user(sourceNick, target, "Enabled: %s", FlagSet(oper->flags, OPER_FLAG_ENABLED) ? "Yes" : "No");

		tm = *localtime(&(oper->creator.time));
		strftime(timebuf, sizeof(timebuf), "%d/%m/%Y %H:%M:%S (%Z)", &tm);

		send_notice_to_user(sourceNick, target, "Registered by %s on %s", oper->creator.name, timebuf);

		TRACE_MAIN();
		tm = *localtime(&oper->lastUpdate);
		strftime(timebuf, sizeof(timebuf), "%d/%m/%Y %H:%M:%S (%Z)", &tm);
		send_notice_to_user(sourceNick, target, "Last Update: %s", timebuf);

		send_notice_to_user(sourceNick, target, "*** \2End of Info\2 ***");
		return TRUE;
	}

	return FALSE;
}

static int get_access_level(const char *accessName) {

	if (str_equals_nocase(accessName, "HOP"))
		return ULEVEL_HOP;
	else if (str_equals_nocase(accessName, "SOP"))
		return ULEVEL_SOP;
	else if (str_equals_nocase(accessName, "SA"))
		return ULEVEL_SA;
	else if (str_equals_nocase(accessName, "SRA"))
		return ULEVEL_SRA;
	else if (str_equals_nocase(accessName, "CODER"))
		return ULEVEL_CODER;
	else if (str_equals_nocase(accessName, "MASTER"))
		return ULEVEL_MASTER;
	else
		return ULEVEL_NOACCESS;
}

static char *get_access_name(int accessLevel, BOOL isShort) {

	switch (accessLevel) {

		case ULEVEL_HOP:
			return isShort ? "HOP" : "HelpOp";

		case ULEVEL_SOP:
			return isShort ? "SOP" : "Services Operator";

		case ULEVEL_SA:
			return isShort ? "SA" : "Services Admin";

		case ULEVEL_SRA:
			return isShort ? "SRA" : "Services Root";

		case ULEVEL_CODER:
			return isShort ? "CDR" : "Services Coder";

		case ULEVEL_MASTER:
			return isShort ? "MST" : "Services Master";

		default:
			return isShort ? "USR" : "Normal User";
	}
}

void handle_oper(CSTR source, User *callerUser, ServiceCommandData *data) {

	char	*cmd = strtok(NULL, " ");
	BOOL	access_denied = FALSE;

	TRACE_MAIN_FCLT(FACILITY_OPER_HANDLE_OPER);

	if (IS_NULL(cmd)) {

		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2OPER\2 [ADD|DEL|SET|LIST|INFO] nick [value]");
		send_notice_to_user(data->agent->nick, callerUser, "Type \2/os OHELP OPER\2 for more information.");
	}
	else if (str_equals_nocase(cmd, "LIST")) {

		char *listName = strtok(NULL, " ");
		int accessLevel;

		if (listName) {

			accessLevel = get_access_level(listName);

			if (accessLevel == ULEVEL_NOACCESS) {

				send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2OPER LIST\2 [HOP|SOP|SA|SRA|CODER|MASTER]");
				return;
			}

			send_oper_list(data->agent->nick, callerUser, accessLevel, TRUE);
		}
		else {

			int lists[6] = { ULEVEL_HOP, ULEVEL_SOP, ULEVEL_SA, ULEVEL_SRA, ULEVEL_CODER, ULEVEL_MASTER };
			int idx;

			for (idx = 0; idx < 6; ++idx) {

				accessLevel = lists[idx];
				send_oper_list(data->agent->nick, callerUser, accessLevel, (accessLevel == ULEVEL_MASTER));
			}
		}
	}
	else if (str_equals_nocase(cmd, "INFO")) {

		char *opernick;

		if (IS_NOT_NULL(opernick = strtok(NULL, " "))) {

			if (!send_oper_info(opernick, data->agent->nick, callerUser))
				send_notice_to_user(data->agent->nick, callerUser, "No entry for \2%s\2 found.", opernick);
		}
		else {

			send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2OPER INFO\2 nick");
			send_notice_to_user(data->agent->nick, callerUser, "Type \2/%s OHELP OPER\2 for more information.", data->agent->shortNick);
		}
	}
	else if (IS_NULL(callerUser->oper))
		send_notice_to_user(data->agent->nick, callerUser, "Access denied.");

	else if (str_equals_nocase(cmd, "ADD")) {

		Oper *oper;
		char *opernick, *accessName;

		TRACE_MAIN();
		if (IS_NOT_NULL(opernick = strtok(NULL, " ")) && IS_NOT_NULL(accessName = strtok(NULL, " "))) {

			int accessLevel;

			#ifdef USE_SERVICES
			NickInfo *ni;

			TRACE_MAIN();
			if (IS_NULL(ni = findnick(opernick))) {

				if (data->operMatch)
					LOG_SNOOP(data->agent->nick, "%s +O* %s -- by %s (%s@%s) [Not Registered]", data->agent->shortNick, opernick, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(data->agent->nick, "%s +O* %s -- by %s (%s@%s) through %s [Not Registered]", data->agent->shortNick, opernick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_notice_to_user(data->agent->nick, callerUser, "Nickname \2%s\2 is not registered.", opernick);
				return;
			}

			opernick = ni->nick;
			#endif

			accessLevel = get_access_level(accessName);

			if (accessLevel == ULEVEL_NOACCESS) {

				send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2OPER ADD\2 nick [HOP/SOP/SA/SRA/CODER/MASTER]");
				return;
			}

			#ifdef USE_SERVICES
			if (FlagSet(ni->flags, NI_FORBIDDEN)) {

				send_globops(data->agent->nick, "\2%s\2 tried adding forbidden nick \2%s\2 to the %s list", source, ni->nick, get_access_name(accessLevel, FALSE));
				send_notice_to_user(data->agent->nick, callerUser, "Nickname \2%s\2 is forbidden.", ni->nick);
				return;
			}

			if (FlagSet(ni->flags, NI_FROZEN)) {

				send_globops(data->agent->nick, "\2%s\2 tried adding frozen nick \2%s\2 to the %s list", source, ni->nick, get_access_name(accessLevel, FALSE));
				send_notice_to_user(data->agent->nick, callerUser, "Nickname \2%s\2 is frozen.", ni->nick);
				return;
			}

			if (FlagSet(ni->flags, NI_AUTH)) {

				send_globops(data->agent->nick, "\2%s\2 tried adding unauthorized nick \2%s\2 to the %s list", source, ni->nick, get_access_name(accessLevel, FALSE));
				send_notice_to_user(data->agent->nick, callerUser, "Nickname \2%s\2 has not authorized.", ni->nick);
				return;
			}
			#endif

			switch (accessLevel) {

				case ULEVEL_MASTER:
				case ULEVEL_CODER:
					access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_MASTER);
					break;

				case ULEVEL_SRA:
					access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_CODER);
					break;

				case ULEVEL_SA:
					access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_SRA);
					break;

				case ULEVEL_SOP:
				case ULEVEL_HOP:
					access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_SA);
					break;
			}
			
			if (access_denied) {

				send_notice_to_user(data->agent->nick, callerUser, "Access denied.");
				return;
			}

			if (IS_NOT_NULL(oper = findoper(opernick))) {

				if (oper->level == accessLevel) {

					TRACE_MAIN();
					if (data->operMatch)
						LOG_SNOOP(data->agent->nick, "%s +%s* %s -- by %s (%s@%s) [Already one]", data->agent->shortNick, get_access_name(accessLevel, TRUE), opernick, callerUser->nick, callerUser->username, callerUser->host);
					else
						LOG_SNOOP(data->agent->nick, "%s +%s* %s -- by %s (%s@%s) through %s [Already one]", data->agent->shortNick, get_access_name(accessLevel, TRUE), opernick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

					send_notice_to_user(data->agent->nick, callerUser, "Nickname \2%s\2 is already a %s.", opernick, get_access_name(accessLevel, FALSE));
					return;
				}

				switch (oper->level) {

					case ULEVEL_MASTER:
					case ULEVEL_CODER:
						access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_MASTER);
						break;

					case ULEVEL_SRA:
						access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_CODER);
						break;

					case ULEVEL_SA:
						access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_SRA);
						break;

					case ULEVEL_SOP:
					case ULEVEL_HOP:
						access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_SA);
						break;
				}

				if (access_denied) {

					send_notice_to_user(data->agent->nick, callerUser, "Access denied.");
					return;
				}

				if (data->operMatch) {

					LOG_SNOOP(data->agent->nick, "%s +%s %s -- by %s (%s@%s)", data->agent->shortNick, get_access_name(accessLevel, TRUE), opernick, callerUser->nick, callerUser->username, callerUser->host);
					log_services(data->agent->logID, "+%s %s -- by %s (%s@%s)", get_access_name(accessLevel, TRUE), opernick, callerUser->nick, callerUser->username, callerUser->host);

					send_globops(data->agent->nick, "\2%s\2 %s \2%s\2 to %s", source, (oper->level < accessLevel) ? "raised" : "demoted", opernick, get_access_name(accessLevel, FALSE));
				}
				else {

					LOG_SNOOP(data->agent->nick, "%s +%s %s -- by %s (%s@%s) through %s", data->agent->shortNick, get_access_name(accessLevel, TRUE), opernick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
					log_services(data->agent->logID, "+%s %s -- by %s (%s@%s) through %s", get_access_name(accessLevel, TRUE), opernick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

					send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) %s \2%s\2 to %s", source, data->operName, (oper->level < accessLevel) ? "raised" : "demoted", opernick, get_access_name(accessLevel, FALSE));
				}

				oper->level = accessLevel;
				oper->lastUpdate = NOW;

				str_creator_set(&oper->creator, data->operName, NOW);
				return;
			}

			oper_add(opernick, data->operName, accessLevel);

			if (data->operMatch) {

				LOG_SNOOP(data->agent->nick, "%s +%s %s -- by %s (%s@%s)", data->agent->shortNick, get_access_name(accessLevel, TRUE), opernick, callerUser->nick, callerUser->username, callerUser->host);
				log_services(data->agent->logID, "+%s %s -- by %s (%s@%s)", get_access_name(accessLevel, TRUE), opernick, callerUser->nick, callerUser->username, callerUser->host);

				send_globops(data->agent->nick, "\2%s\2 added \2%s\2 as %s", source, opernick, get_access_name(accessLevel, FALSE));
			}
			else {

				LOG_SNOOP(data->agent->nick, "%s +%s %s -- by %s (%s@%s) through %s", data->agent->shortNick, get_access_name(accessLevel, TRUE), opernick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(data->agent->logID, "+%s %s -- by %s (%s@%s) through %s", get_access_name(accessLevel, TRUE), opernick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) added \2%s\2 as %s", source, data->operName, opernick, get_access_name(accessLevel, FALSE));
			}

			send_notice_to_user(data->agent->nick, callerUser, "\2%s\2 has been successfully added as %s.", opernick, get_access_name(accessLevel, FALSE));
		}
		else
			send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2OPER ADD\2 nick [HOP/SOP/SA/SRA/CODER/MASTER]");
	}
	else if (str_equals_nocase(cmd, "DEL")) {

		char *opernick;
		Oper *oper;


		if (IS_NOT_NULL(opernick = strtok(NULL, " "))) {

			if (IS_NOT_NULL(oper = findoper(opernick))) {

				switch (oper->level) {

					case ULEVEL_MASTER:
					case ULEVEL_CODER:
						access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_MASTER);
						break;

					case ULEVEL_SRA:
						access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_CODER);
						break;

					case ULEVEL_SA:
						access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_SRA);
						break;

					case ULEVEL_SOP:
					case ULEVEL_HOP:
						access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_SA);
						break;
				}

				if (access_denied) {

					send_notice_to_user(data->agent->nick, callerUser, "Access denied.");
					return;
				}

				if (data->operMatch) {

					LOG_SNOOP(data->agent->nick, "%s -%s %s -- by %s (%s@%s)", data->agent->shortNick, get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host);
					log_services(data->agent->logID, "-%s %s -- by %s (%s@%s)", get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host);

					send_globops(data->agent->nick, "\2%s\2 removed \2%s\2 from the %s list", source, oper->nick, get_access_name(oper->level, FALSE));
				}
				else {

					LOG_SNOOP(data->agent->nick, "%s -%s %s -- by %s (%s@%s) through %s", data->agent->shortNick, get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
					log_services(data->agent->logID, "-%s %s -- by %s (%s@%s) through %s", get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

					send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) removed \2%s\2 from the %s list", source, data->operName, oper->nick, get_access_name(oper->level, FALSE));
				}

				send_notice_to_user(data->agent->nick, callerUser, "%s \2%s\2 has been removed.", get_access_name(oper->level, FALSE), oper->nick);
				oper_remove(oper);
			}
			else {

				if (data->operMatch)
					LOG_SNOOP(data->agent->nick, "%s -O* %s -- by %s (%s@%s) [Not Found]", data->agent->shortNick, opernick, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(data->agent->nick, "%s -O* %s -- by %s (%s@%s) through %s [Not Found]", data->agent->shortNick, opernick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_notice_to_user(data->agent->nick, callerUser, "No entry for \2%s\2 found.", opernick);
			}
		}
		else {

			send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2OPER DEL\2 nick");
			send_notice_to_user(data->agent->nick, callerUser, "Type \2/os OHELP OPER\2 for more information.");
		}
	}
	else if (str_equals_nocase(cmd, "SET")) {

		Oper *oper;
		char *opernick, *option, *value;


		if (IS_NOT_NULL(opernick = strtok(NULL, " ")) && IS_NOT_NULL(option = strtok(NULL, " ")) &&
			IS_NOT_NULL(value = strtok(NULL, " "))) {

			if (IS_NOT_NULL(oper = findoper(opernick))) {

				switch (oper->level) {

					case ULEVEL_MASTER:
					case ULEVEL_CODER:
						access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_MASTER);
						break;

					case ULEVEL_SRA:
						access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_CODER);
						break;

					case ULEVEL_SA:
						access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_SRA);
						break;

					case ULEVEL_SOP:
					case ULEVEL_HOP:
						access_denied = !CheckOperAccess(data->userLevel, CMDLEVEL_SA);
						break;
				}

				/* Un oper puo' modificare sé stesso, ma non auto-disabilitarsi. */
				if (access_denied && str_not_equals_nocase(callerUser->oper->nick, opernick)) {

					send_notice_to_user(data->agent->nick, callerUser, "Access denied.");
					return;
				}

				#ifndef USE_SERVICES
				else if (str_equals_nocase(option, "PASS") || str_equals_nocase(option, "PASSWD")
					|| str_equals_nocase(option, "PASSWORD")) {

					size_t len = str_len(value);

					if ((len < 5) || (len > PASSMAX) || string_has_ccodes(value)) {

						if (data->operMatch) {

							LOG_SNOOP(data->agent->nick, "%s %s %s -- by %s (%s@%s) [Invalid Pass]", data->agent->shortNick, get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host);
							log_services(data->agent->logID, "%s %s -- by %s (%s@%s) [Invalid Pass: %s]", get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, value);
						}
						else {

							LOG_SNOOP(data->agent->nick, "%s %s %s -- by %s (%s@%s) through %s [Invalid Pass]", data->agent->shortNick, get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
							log_services(data->agent->logID, "%s %s -- by %s (%s@%s) through %s [Invalid Pass: %s]", get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, value);
						}

						send_notice_to_user(data->agent->nick, callerUser, "Invalid password.");
						return;
					}

					if (IS_NOT_NULL(oper->password)) {

						TRACE_MAIN();
						if (data->operMatch) {

							LOG_SNOOP(data->agent->nick, "%s %s %s -- by %s (%s@%s) [Pass: Changed]", data->agent->shortNick, get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host);
							log_services(data->agent->logID, "%s %s -- by %s (%s@%s) [Pass: %s -> %s]", get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, oper->password, value);
						}
						else {

							LOG_SNOOP(data->agent->nick, "%s %s %s -- by %s (%s@%s) through %s [Pass: Changed]", data->agent->shortNick, get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
							log_services(data->agent->logID, "%s %s -- by %s (%s@%s) through %s [Pass: %s -> %s]", get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, oper->password, value);
						}
					}
					else {

						if (data->operMatch) {

							LOG_SNOOP(data->agent->nick, "%s %s %s -- by %s (%s@%s) [Pass: Set]", data->agent->shortNick, get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host);
							log_services(data->agent->logID, "%s %s -- by %s (%s@%s) [Pass: %s]", get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, value);
						}
						else {

							LOG_SNOOP(data->agent->nick, "%s %s %s -- by %s (%s@%s) through %s [Pass: Set]", data->agent->shortNick, get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
							log_services(data->agent->logID, "%s %s -- by %s (%s@%s) through %s [Pass: %s]", get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, value);
						}
					}

					TRACE_MAIN();
					send_notice_to_user(data->agent->nick, callerUser, "\2PASS\2 field of %s \2%s\2 has been set to \2%s\2.", get_access_name(oper->level, FALSE), oper->nick, value);

					oper->password = str_duplicate(value);
					oper->lastUpdate = NOW;
				}
				#endif

				else if (str_equals_nocase(option, "ENABLED")) {

					int enable;

					if (access_denied) {

						send_notice_to_user(data->agent->nick, callerUser, "Access denied.");
						return;
					}

					TRACE_MAIN();
					if (str_equals_nocase(value, "YES")) {

						#ifndef USE_SERVICES
						if (IS_NULL(oper->password)) {

							if (data->operMatch)
								LOG_SNOOP(data->agent->nick, "%s *%s %s -- by %s (%s@%s) [Not Configured]", data->agent->shortNick, get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host);
							else
								LOG_SNOOP(data->agent->nick, "%s *%s %s -- by %s (%s@%s) through %s [Not Configured]", data->agent->shortNick, get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

							send_notice_to_user(data->agent->nick, callerUser, "This entry is not properly configured and cannot be enabled.");
							return;
						}
						#endif

						enable = TRUE;
					}
					else if (str_equals_nocase(value, "NO"))
						enable = FALSE;

					else {

						send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2OPER SET\2 nick ENABLED [YES|NO]");
						send_notice_to_user(data->agent->nick, callerUser, "Type \2/os OHELP OPER\2 for more information.");
						return;
					}

					if (((enable == TRUE) && FlagSet(oper->flags, OPER_FLAG_ENABLED)) ||
						((enable == FALSE) && FlagUnset(oper->flags, OPER_FLAG_ENABLED))) {

						TRACE_MAIN();
						if (data->operMatch)
							LOG_SNOOP(data->agent->nick, "%s *%s %s -- by %s (%s@%s) [Already %s]", data->agent->shortNick, get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, enable ? "Enabled" : "Disabled");
						else
							LOG_SNOOP(data->agent->nick, "%s *%s %s -- by %s (%s@%s) through %s [Already %s]", data->agent->shortNick, get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, enable ? "Enabled" : "Disabled");

						send_notice_to_user(data->agent->nick, callerUser, "%s entry for \2%s\2 is already \2%s\2.", get_access_name(oper->level, FALSE), oper->nick, enable ? "enabled" : "disabled");
					}
					else {

						TRACE_MAIN();

						if (enable)
							AddFlag(oper->flags, OPER_FLAG_ENABLED);

						else {

							User *user;
							unsigned int idx;

							RemoveFlag(oper->flags, OPER_FLAG_ENABLED);

							HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

								HASH_FOREACH_BRANCH_ITEM(onlineuser, idx, user) {

									if (user->oper == oper)
										user->oper = NULL;
								}
							}
						}

						oper->lastUpdate = NOW;

						if (data->operMatch) {

							LOG_SNOOP(data->agent->nick, "%s %s %s -- by %s (%s@%s) [%s]", data->agent->shortNick, get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, enable ? "Enabled" : "Disabled");
							log_services(data->agent->logID, "%s %s -- by %s (%s@%s) [%s]", get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, enable ? "Enabled" : "Disabled");

							send_globops(data->agent->nick, "\2%s\2 %s %s entry for \2%s\2", source, enable ? "enabled" : "disabled", get_access_name(oper->level, FALSE), oper->nick);
						}
						else {

							LOG_SNOOP(data->agent->nick, "%s %s %s -- by %s (%s@%s) through %s [%s]", data->agent->shortNick, get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, enable ? "Enabled" : "Disabled");
							log_services(data->agent->logID, "%s %s -- by %s (%s@%s) through %s [%s]", get_access_name(oper->level, TRUE), oper->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, enable ? "Enabled" : "Disabled");

							send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) %s %s entry for \2%s\2", source, data->operName, enable ? "enabled" : "disabled", get_access_name(oper->level, FALSE), oper->nick);
						}

						send_notice_to_user(data->agent->nick, callerUser, "%s entry for \2%s\2 has been \2%s\2.", get_access_name(oper->level, TRUE), oper->nick, enable ? "enabled" : "disabled");
					}
				}
				else {

					send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2OPER SET\2 nick [USER|USER2|USER3|HOST|HOST2|HOST3|SERVER|SERVER2|SERVER3|ENABLED] value");
					send_notice_to_user(data->agent->nick, callerUser, "Type \2/os OHELP OPER\2 for more information.");
				}
			}
			else {

				if (data->operMatch)
					LOG_SNOOP(data->agent->nick, "%s *O %s -- by %s (%s@%s) [Not Registered]", data->agent->shortNick, opernick, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(data->agent->nick, "%s *O %s -- by %s (%s@%s) through %s [Not Registered]", data->agent->shortNick, opernick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_notice_to_user(data->agent->nick, callerUser, "No entry for \2%s\2 found.", opernick);
			}
		}
		else {

			send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2OPER SET\2 nick [ENABLED|PASS] value");
			send_notice_to_user(data->agent->nick, callerUser, "Type \2/os OHELP OPER\2 for more information.");
		}
	}
	else {

		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2OPER\2 [ADD|DEL|HOST|INFO|LIST|SET|USER] nick [value]");
		send_notice_to_user(data->agent->nick, callerUser, "Type \2/%s OHELP OPER\2 for more information.", data->agent->shortNick);
	}
}

/*********************************************************/

/* Check to see if the person is our master */
__inline__ BOOL is_services_master(const User *user) {

	return (IS_NOT_NULL(user->oper) && CheckOperAccess(user->oper->level, CMDLEVEL_MASTER));
}

/*********************************************************/

/* Check to see if the person is one of the lovely coders */
__inline__ BOOL is_services_coder(const User *user) {

	return (IS_NOT_NULL(user->oper) && CheckOperAccess(user->oper->level, CMDLEVEL_CODER));
}

/*********************************************************/

/* Does the given nick have Services root privileges? */
__inline__ BOOL is_services_root(const User *user) {

	return (IS_NOT_NULL(user->oper) && CheckOperAccess(user->oper->level, CMDLEVEL_SRA));
}

/*********************************************************/

/* Does the given nick have Services admin privileges? */
__inline__ BOOL is_services_admin(const User *user) {

	return (IS_NOT_NULL(user->oper) && CheckOperAccess(user->oper->level, CMDLEVEL_SA));
}

/*********************************************************/

/* Does the given nick have Services Operator Access privileges? */
__inline__ BOOL is_services_oper(const User *user) {

	return (IS_NOT_NULL(user->oper) && CheckOperAccess(user->oper->level, CMDLEVEL_SOP));
}

/*********************************************************/

/* Does the given nick have Services Help Operator Access privileges? */
__inline__ BOOL is_services_helpop(const User *user) {

	return (IS_NOT_NULL(user->oper) && CheckOperAccess(user->oper->level, CMDLEVEL_HOP));
}

/*********************************************************/

/* Does the given nick have Services Help Operator Access privileges? */
__inline__ BOOL is_services_valid_oper(const User *user) {

	return IS_NOT_NULL(user->oper);
}

/*********************************************************/

/* Return the access level of the given user/nick. */
int get_services_access(const User *user, CSTR nick) {

	Oper *oper;

	if (IS_NULL(user) && (IS_NULL(nick) || IS_EMPTY_STR(nick)))
		return ULEVEL_NOACCESS;

	if (user)
		oper = user->oper;
	else
		oper = findoper(nick);

	if (oper)
		return oper->level;

	return ULEVEL_NOACCESS;
}


/*********************************************************
 * Command handling                                      *
 *********************************************************/

void oper_get_oper_level(const User *callerUser, int *operLevel, char *operName) {

	BOOL isOper = user_is_ircop(callerUser);

	if (IS_NULL(callerUser->oper)) {

		str_copy_checked(callerUser->nick, operName, NICKMAX);

		if (isOper)
			*operLevel = ULEVEL_OPER;

		else if (user_is_services_agent(callerUser))
			*operLevel = ULEVEL_SA;

		else
			*operLevel = ULEVEL_NOACCESS;

		return;
	}

	str_copy_checked(callerUser->oper->nick, operName, NICKSIZE);

	switch (callerUser->oper->level) {
		
		case ULEVEL_MASTER:
		case ULEVEL_CODER:
		case ULEVEL_SRA:
		case ULEVEL_SA:
		case ULEVEL_SOP:
			*operLevel = callerUser->oper->level;
			return;

		case ULEVEL_HOP:
			*operLevel = isOper ? (ULEVEL_HOP | ULEVEL_OPER) : ULEVEL_HOP;
			return;

		default:
			LOG_DEBUG_SNOOP("Unknown level (%d) for Oper %s used by %s", callerUser->oper->level, callerUser->oper->nick, callerUser->nick);
			str_copy_checked(callerUser->nick, operName, NICKSIZE);
			*operLevel = ULEVEL_NOACCESS;
			return;
	}
}

ServiceCommand *oper_get_command_table(char *cmd, ServiceCommand *commands[]) {

	if (cmd && commands) {

		int		idx;

		str_toupper(cmd);
		idx = cmd[0] - 'A';

		if ((idx >= 0) && (idx <= 25)) {

			ServiceCommand	*table;

			table = commands[idx];

			if (table) {

				for (; IS_NOT_NULL(table->command); ++table) {

					if (str_equals(table->command, cmd))
						return table;
				}
			}
		}
	}

	return NULL;
}


void oper_invoke_agent_command(char *cmd, ServiceCommand *commands[], User *callerUser, const Agent *agent) {

	ServiceCommand	*table;

	// NB: cmd e commands sono controllati da oper_get_command_table()
	if (IS_NULL(callerUser) || IS_NULL(agent))
		return;

	table = oper_get_command_table(cmd, commands);

	if (table) {

		char	operName[NICKSIZE], *operNamePtr;
		int		cmdLevel, userLevel, operMatch;

		cmdLevel = table->access_level;

		if (FlagSet(cmdLevel, CMDLEVEL_DISABLED)) {

			send_notice_to_user(agent->nick, callerUser, "This command is currently disabled.");
			LOG_SNOOP(agent->nick, "Disabled command %s invoked by %s", cmd, callerUser->nick);
			return;
		}

		RemoveFlag(cmdLevel, CMDLEVEL_CANT_BE_DISABLED | CMDLEVEL_DISABLED);

		if (cmdLevel != ULEVEL_USER) {

			oper_get_oper_level(callerUser, &userLevel, operName);
			operMatch = str_equals_nocase(callerUser->nick, operName);
			operNamePtr = operName;

		} else {

			userLevel = ULEVEL_USER;
			operMatch = FALSE;
			operNamePtr = NULL;
		}


		if (CheckOperAccess(userLevel, cmdLevel)) {
			// accesso accordato

			ServiceCommandData data;

			data.commandName = table->command;		/* Ensures it's uppercase. */
			data.userLevel = userLevel;
			data.operMatch = operMatch;
			data.operName = operNamePtr;
			data.agent = agent;

			++(table->usage_count);
			table->handler(callerUser->nick, callerUser, &data);
			return;
		
		} else {

			// accesso negato
			if (userLevel != ULEVEL_USER) {

				send_notice_to_user(agent->nick, callerUser, "Access denied.");
				return;
			}
		}
	}

	send_notice_lang_to_user(agent->nick, callerUser, GetCallerLang(), ERROR_UNKNOWN_COMMAND, cmd);
	send_notice_lang_to_user(agent->nick, callerUser, GetCallerLang(), GET_SERVICE_COMMAND_LIST, agent->shortNick);
}


void handle_count(const char *source, User *callerUser, ServiceCommandData *data) {

	int				tableIdx, idx, type, count = 0;
	ServiceCommand	**commands, *table;
	char			buffer[IRCBUFSIZE], reply[IRCBUFSIZE];
	char			*service;
	size_t			len = 0;


	TRACE_MAIN();

	if (IS_NULL(service = strtok(NULL, " "))) {

		service = (char *)data->agent->nick;
		type = data->agent->agentID;
	}
	else if (str_equals_nocase(service, data->agent->nick) || str_equals_nocase(service, data->agent->shortNick))
		type = data->agent->agentID;

	#ifdef USE_STATS
	else if (str_equals_nocase(service, s_SeenServ) || str_equals_nocase(service, s_SS))
		type = AGENTID_SEENSERV;
	#endif

	#ifdef USE_SERVICES
	else if (str_equals_nocase(service, s_ChanServ) || str_equals_nocase(service, s_CS))
		type = AGENTID_CHANSERV;

	else if (str_equals_nocase(service, s_NickServ) || str_equals_nocase(service, s_NS))
		type = AGENTID_NICKSERV;

	else if (str_equals_nocase(service, s_MemoServ) || str_equals_nocase(service, s_MS))
		type = AGENTID_MEMOSERV;

	else if (str_equals_nocase(service, s_RootServ) || str_equals_nocase(service, s_RS))
		type = AGENTID_ROOTSERV;
	#endif

	else {

		send_notice_to_user(data->agent->nick, callerUser, "No such service: %s", service);
		return;
	}

	if (data->operMatch) {

		LOG_SNOOP(data->agent->nick, "%s # %s -- by %s (%s@%s)", data->agent->shortNick, service, callerUser->nick, callerUser->username, callerUser->host);
		log_services(data->agent->logID, "# %s -- by %s (%s@%s)", service, source, callerUser->username, callerUser->host);
	}
	else {

		LOG_SNOOP(data->agent->nick, "%s # %s -- by %s (%s@%s) through %s", data->agent->shortNick, service, callerUser->nick, callerUser->username, callerUser->host, data->operName);
		log_services(data->agent->logID, "# %s -- by %s (%s@%s) through %s", service, source, callerUser->username, callerUser->host, data->operName);
	}

	send_notice_to_user(data->agent->nick, callerUser, "*** %s Commands Usage Count: ***", oper_get_agent_name(type));

	commands = oper_get_agent_command_map(type);

	for (idx = 0; idx < 26; idx++) {

		if (IS_NOT_NULL(table = commands[idx])) {

			for (tableIdx = 0; IS_NOT_NULL(table[tableIdx].command); ++tableIdx) {

				snprintf(buffer, sizeof(buffer), "%s [\2%lu\2]", table[tableIdx].command, table[tableIdx].usage_count);

				if (count > 0) {

					*(reply + len++) = c_COMMA;
					*(reply + len++) = c_SPACE;
				}

				len += str_copy_checked(buffer, (reply + len), (sizeof(reply) - len));

				if (++count == 6) {

					send_notice_to_user(data->agent->nick, callerUser, "%s", reply);
					count = 0;
					len = 0;
				}
			}
		}
	}

	if (len > 0)
		send_notice_to_user(data->agent->nick, callerUser, "%s", reply);

	send_notice_to_user(data->agent->nick, callerUser, "*** End of Count ***");
}



CSTR oper_get_agent_name(agentid_t id) {

	const CSTR	_oper_agent_id_map[] = {

		/* AGENTID_UNKNOWN	*/	NULL,
		#ifdef USE_SERVICES
		/* AGENTID_NICKSERV */	s_NickServ,
		/* AGENTID_CHANSERV */	s_ChanServ,
		/* AGENTID_MEMOSERV */	s_MemoServ,
		/* AGENTID_HELPSERV */	s_HelpServ,
		#else
		/* AGENTID_NICKSERV */	"",
		/* AGENTID_CHANSERV */	"",
		/* AGENTID_MEMOSERV */	"",
		/* AGENTID_HELPSERV */	"",
		#endif

		/* AGENTID_DEBUGSERV */	s_DebugServ,

		#ifdef USE_SERVICES
		/* AGENTID_OPERSERV */	s_OperServ,
		/* AGENTID_ROOTSERV */	s_RootServ,
		#else
		/* AGENTID_OPERSERV */	"",
		/* AGENTID_ROOTSERV */	"",
		#endif

		#ifdef USE_STATS
		/* AGENTID_STATSERV */	s_StatServ,
		/* AGENTID_SEENSERV */	s_SeenServ,
		#else
		/* AGENTID_STATSERV */	"",
		/* AGENTID_SEENSERV */	"",
		#endif

		#ifdef USE_SOCKSMONITOR
		/* AGENTID_CYBCOP */	s_SocksMonitor,
		#else
		/* AGENTID_CYBCOP */	"",
		#endif
		
		#ifdef USE_SERVICES
		/* AGENTID_GNOTICER */	s_GlobalNoticer
		#else
		/* AGENTID_GNOTICER */	""
		#endif
	};
	
	return ((id >= AGENTID_FIRST) && (id <= AGENTID_LAST)) ? _oper_agent_id_map[id] : s_NULL;
}


agentid_t oper_get_agentid(CSTR agentNickname, BOOL performMatch) {

	const CSTR	_oper_agent_id_map[] = {

		/* AGENTID_UNKNOWN	*/	NULL,
		#ifdef USE_SERVICES
		/* AGENTID_NICKSERV */	s_NickServ,
		/* AGENTID_CHANSERV */	s_ChanServ,
		/* AGENTID_MEMOSERV */	s_MemoServ,
		/* AGENTID_HELPSERV */	s_HelpServ,
		#else
		/* AGENTID_NICKSERV */	"",
		/* AGENTID_CHANSERV */	"",
		/* AGENTID_MEMOSERV */	"",
		/* AGENTID_HELPSERV */	"",
		#endif

		/* AGENTID_DEBUGSERV */	s_DebugServ,

		#ifdef USE_SERVICES
		/* AGENTID_OPERSERV */	s_OperServ,
		/* AGENTID_ROOTSERV */	s_RootServ,
		#else
		/* AGENTID_OPERSERV */	"",
		/* AGENTID_ROOTSERV */	"",
		#endif

		#ifdef USE_STATS
		/* AGENTID_STATSERV */	s_StatServ,
		/* AGENTID_SEENSERV */	s_SeenServ,
		#else
		/* AGENTID_STATSERV */	"",
		/* AGENTID_SEENSERV */	"",
		#endif

		#ifdef USE_SOCKSMONITOR
		/* AGENTID_CYBCOP */	s_SocksMonitor,
		#else
		/* AGENTID_CYBCOP */	"",
		#endif
		
		#ifdef USE_SERVICES
		/* AGENTID_GNOTICER */	s_GlobalNoticer
		#else
		/* AGENTID_GNOTICER */	""
		#endif
	};

	agentid_t	agentID;

	if (agentNickname) {

		if (performMatch) {

			char agent_nick[NICKSIZE], match_nick[NICKSIZE];

			str_copy_checked(agentNickname, match_nick, NICKSIZE);
			str_tolower(match_nick);

			for (agentID = AGENTID_FIRST; agentID <= AGENTID_LAST; ++agentID) {

				str_copy_checked(_oper_agent_id_map[agentID], agent_nick, NICKSIZE);
				str_tolower(agent_nick);

				if (str_equals(agent_nick, match_nick))
					return agentID;
			}

		} else {

			for (agentID = AGENTID_FIRST; agentID <= AGENTID_LAST; ++agentID) {

				if (_oper_agent_id_map[agentID] == agentNickname)
					return agentID;
			}
		}
	}

	return AGENTID_UNKNOWN;
}

ServiceCommand **oper_get_agent_command_map(agentid_t agentID) {

	switch (agentID) {

		#ifdef USE_SERVICES
		case AGENTID_NICKSERV: return nickserv_commands;
		case AGENTID_CHANSERV: return chanserv_commands;
		case AGENTID_MEMOSERV: return memoserv_commands;
		case AGENTID_HELPSERV: return NULL /*helpserv_commands*/;
		case AGENTID_OPERSERV: return operserv_commands;
		case AGENTID_ROOTSERV: return rootserv_commands;
		case AGENTID_GNOTICER: return NULL;
		#else
		case AGENTID_NICKSERV: return NULL;
		case AGENTID_CHANSERV: return NULL;
		case AGENTID_MEMOSERV: return NULL;
		case AGENTID_HELPSERV: return NULL;
		case AGENTID_OPERSERV: return NULL;
		case AGENTID_ROOTSERV: return NULL;
		case AGENTID_GNOTICER: return NULL;
		#endif
		
		case AGENTID_DEBUGSERV: return debugserv_commands;

		#ifdef USE_STATS
		case AGENTID_STATSERV: return statserv_commands;
		case AGENTID_SEENSERV: return seenserv_commands;
		#else		
		case AGENTID_STATSERV: return NULL;
		case AGENTID_SEENSERV: return NULL;
		#endif
		
		#ifdef USE_SOCKSMONITOR
		case AGENTID_CYBCOP: return socksmonitor_commands;
		#else
		case AGENTID_CYBCOP: return NULL;
		#endif		
		
		default: return NULL;
	}
}


result_t oper_enable_command(char *cmd, ServiceCommand *commands[], BOOL enable) {

	ServiceCommand	*table;

	table = oper_get_command_table(cmd, commands);
	if (table) {

		if (FlagSet(table->access_level, CMDLEVEL_CANT_BE_DISABLED))
			return RESULT_DENIED;

		if (enable) {
			// abilitare il comando

			if (FlagUnset(table->access_level, CMDLEVEL_DISABLED))
				return RESULT_ALREADY;

			RemoveFlag(table->access_level, CMDLEVEL_DISABLED);

		} else {
			// disabiltare il comando

			if (FlagSet(table->access_level, CMDLEVEL_DISABLED))
				return RESULT_ALREADY;

			AddFlag(table->access_level, CMDLEVEL_DISABLED);
		}

		return RESULT_SUCCESS;
	}

	return RESULT_FAILURE;
}

/*********************************************************/

void oper_send_disabled_command_list(ServiceCommand *commands[], CSTR agentChecked, User *callerUser, CSTR agentNickname) {

	if (commands && agentChecked && callerUser && agentNickname) {

		ServiceCommand	*table;
		int				idx, count = 0;

		send_notice_to_user(agentNickname, callerUser, "\2%s\2 disabled commands:", agentChecked);

		for (idx = 0; idx <= 25; ++idx) {

			if (IS_NOT_NULL(table = commands[idx])) {

				for (; IS_NOT_NULL(table->command); ++table) {

					if (FlagSet(table->access_level, CMDLEVEL_DISABLED))
						send_notice_to_user(agentNickname, callerUser, "%02d) %s", ++count, table->command);
				}
			}
		}

		send_notice_to_user(agentNickname, callerUser, "*** \2End of List\2 ***");
	}
}

/*********************************************************/

void oper_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	STR		cmd = strtok(request, s_SPACE);
	BOOL	needSyntax = FALSE;


	if (IS_NOT_NULL(cmd)) {

		if (str_equals_nocase(cmd, "HELP")) {

			/* HELP ! */
		}
		else if (str_equals_nocase(cmd, "NICK")) {

			char *nick;

			if (IS_NOT_NULL(nick = strtok(NULL, " "))) {

				Oper *oper;


				if (IS_NOT_NULL(oper = findoper(nick))) {

					send_notice_to_user(sourceNick, callerUser, "DUMP: Oper entry for \2%s\2", nick);

					send_notice_to_user(sourceNick, callerUser, "Address 0x%08X, size %d B",						(unsigned long)oper, sizeof(Oper));
					send_notice_to_user(sourceNick, callerUser, "Nick: 0x%08X \2[\2%s\2]\2",						(unsigned long)oper->nick, str_get_valid_display_value(oper->nick));
					send_notice_to_user(sourceNick, callerUser, "Creator: 0x%08X \2[\2%s\2]\2",						(unsigned long)oper->creator.name, str_get_valid_display_value(oper->creator.name));
					send_notice_to_user(sourceNick, callerUser, "Time Added C-time: %ld",							oper->creator.time);
					send_notice_to_user(sourceNick, callerUser, "Last Update C-time: %ld",							oper->lastUpdate);
					send_notice_to_user(sourceNick, callerUser, "Level: %d \2[\2%s\2]\2",							oper->level, get_access_name(oper->level, FALSE));
					send_notice_to_user(sourceNick, callerUser, "Flags: %ld",										oper->flags);
					#ifndef USE_SERVICES
					send_notice_to_user(sourceNick, callerUser, "Pass: %s",											oper->password);
					#endif
					send_notice_to_user(sourceNick, callerUser, "Next/Previous record: 0x%08X / 0x%08X",			(unsigned long)oper->next, (unsigned long)oper->prev);

					LOG_DEBUG_SNOOP("Command: DUMP OPER NICK %s -- by %s (%s@%s)", nick, callerUser->nick, callerUser->username, callerUser->host);
				}
				else
					send_notice_to_user(sourceNick, callerUser, "DUMP: Oper entry for \2%s\2 not found.", nick);
			}
			else
				needSyntax = TRUE;
		}
		else if (str_equals_nocase(cmd, "LIST")) {

			int i, count = 0;
			Oper *oper;

			for (i = FIRST_VALID_NICK_CHAR; i <= LAST_VALID_NICK_CHAR; ++i) {

				for (oper = opers[i]; IS_NOT_NULL(oper); oper = oper->next)
					send_notice_to_user(sourceNick, callerUser, "%d) \2%s\2 [Added by %s]", ++count, oper->nick, oper->creator);
			}
					
			LOG_DEBUG_SNOOP("Command: DUMP OPER LIST -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
		}
		else
			needSyntax = TRUE;
	}
	else
		needSyntax = TRUE;

	if (needSyntax) {

		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 OPER HELP");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 OPER NICK nickname [access]");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 OPER LIST");
	}
}

/*********************************************************/

unsigned long oper_mem_report(CSTR sourceNick, const User *callerUser) {

	Oper *oper;
	unsigned long	mem = 0, total_mem = 0;
	int				i, count = 0;

	send_notice_to_user(sourceNick, callerUser, "\2Opers\2:");

	for (i = FIRST_VALID_NICK_CHAR; i <= LAST_VALID_NICK_CHAR; ++i) {

		for (oper = opers[i]; IS_NOT_NULL(oper); oper = oper->next) {

			TRACE();

			++count;

			mem += sizeof(Oper);

			mem += str_len(oper->nick) + 1;
			mem += str_len(oper->creator.name) + 1;

			#ifndef USE_SERVICES
			mem += str_len(oper->password) + 1;
			#endif
		}
	}

	total_mem += mem;
	send_notice_to_user(sourceNick, callerUser, "Records: \2%lu\2 -> \2%lu\2 KB (\2%lu\2 B)", count, mem / 1024, mem);

	return total_mem;
}
