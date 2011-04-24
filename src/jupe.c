/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* jupe.c - Jupes
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
#include "../inc/jupe.h"


/*********************************************************
 * Local variables                                       *
 *********************************************************/

/* List of Jupes. */
static Jupe *JupeList;


/*********************************************************
 * Public code                                           *
 *********************************************************/

void handle_jupe(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *command;


	TRACE_MAIN_FCLT(FACILITY_JUPE_HANDLE_JUPE);

	if (IS_NULL(command = strtok(NULL, " "))) {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2JUPE\2 [ADD|DEL|INFO|LIST] server [reason]");
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP JUPE\2 for more information");
	}
	else if (str_equals_nocase(command, "LIST")) {

		char	timebuf[64];
		char	*pattern;
		int		jupeIdx = 0, startIdx = 0, endIdx = 30, sentIdx = 0;
		Jupe	*aJupe;


		if (IS_NULL(JupeList)) {

			send_notice_to_user(s_OperServ, callerUser, "The Jupe list is empty.");
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
			send_notice_to_user(s_OperServ, callerUser, "Current \2Jupe\2 List (showing entries %d-%d):", startIdx, endIdx);
		else
			send_notice_to_user(s_OperServ, callerUser, "Current \2Jupe\2 List (showing entries %d-%d matching %s):", startIdx, endIdx, pattern);

		aJupe = JupeList;

		while (IS_NOT_NULL(aJupe)) {

			++jupeIdx;

			if (IS_NOT_NULL(pattern) && !str_match_wild(pattern, aJupe->name)) {

				/* Doesn't match our search criteria, skip it. */
				aJupe = aJupe->next;
				continue;
			}

			++sentIdx;

			if (sentIdx < startIdx) {

				aJupe = aJupe->next;
				continue;
			}

			lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, aJupe->info.creator.time);

			send_notice_to_user(s_OperServ, callerUser, "%d) \2%s\2 [Reason: %s]", jupeIdx, aJupe->name, aJupe->info.reason);
			send_notice_to_user(s_OperServ, callerUser, "Set by \2%s\2 on %s", aJupe->info.creator.name, timebuf);

			if (sentIdx >= endIdx)
				break;

			aJupe = aJupe->next;
		}

		TRACE_MAIN();
		send_notice_to_user(s_OperServ, callerUser, "*** \2End of List\2 ***");
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SA))
		send_notice_lang_to_user(s_OperServ, callerUser, GetCallerLang(), OPER_ERROR_ACCESS_DENIED);

	else if (str_equals_nocase(command, "ADD")) {

		char *name, *reason;
		size_t len;
		Server *server;
		Jupe *aJupe;


		if (IS_NULL(name = strtok(NULL, " ")) || IS_NULL(reason = strtok(NULL, ""))) {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2JUPE ADD\2 servername reason");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP JUPE\2 for more information.");
			return;
		}

		if ((len = str_len(reason)) > SERVER_DESC_MAX) {

			send_notice_to_user(s_OperServ, callerUser, "Maximum length for a jupe reason is %d characters. Yours has: %u", SERVER_DESC_MAX, len);
			return;
		}

		if (!validate_string(reason)) {

			send_notice_to_user(s_OperServ, callerUser, "Invalid reason supplied.");
			return;
		}

		if (!validate_host(name, FALSE, FALSE, FALSE) || (len = str_len(name)) >= HOSTMAX ||
			(len < str_len(CONF_NETWORK_NAME + 3)) || str_equals_nocase(name, CONF_SERVICES_NAME)) {

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 tried juping \2%s\2", source, name);

				LOG_SNOOP(s_OperServ, "OS +J* %s -- by %s (%s@%s) [Lamer]", name, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "+J* %s -- by %s (%s@%s) [Lamer]", name, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried juping \2%s\2", source, data->operName, name);

				LOG_SNOOP(s_OperServ, "OS +J* %s -- by %s (%s@%s) through %s [Lamer]", name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "+J* %s -- by %s (%s@%s) through %s [Lamer]", name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}

			send_notice_to_user(s_OperServ, callerUser, "Bogus JUPE server. Smarten up!");
			return;
		}

		if (IS_NOT_NULL(server = findserver(name)) && FlagSet(server->flags, SERVER_FLAG_LINKED)) {

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 tried juping existent server \2%s\2", source, name);

				LOG_SNOOP(s_OperServ, "OS +J* %s -- by %s (%s@%s) [Server Exists]", name, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "+J* %s -- by %s (%s@%s) [Server Exists]", name, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) tried juping existent server \2%s\2", source, data->operName, name);

				LOG_SNOOP(s_OperServ, "OS +J* %s -- by %s (%s@%s) through %s [Server Exists]", name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "+J* %s -- by %s (%s@%s) through %s [Server Exists]", name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}

			send_notice_to_user(s_OperServ, callerUser, "Server \2%s\2 is currently connected to the network.", name);
			return;
		}

		aJupe = JupeList;

		while (IS_NOT_NULL(aJupe)) {

			if (str_equals_nocase(name, aJupe->name)) {

				TRACE_MAIN();
				send_notice_to_user(s_OperServ, callerUser, "%s is already present on the JUPE list.", name);

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "OS +J* %s -- by %s (%s@%s) [Already Juped]", name, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(s_OperServ, "OS +J* %s -- by %s (%s@%s) through %s [Already Juped]", name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				return;
			}

			aJupe = aJupe->next;
		}

		TRACE_MAIN();

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 juped \2%s\2 because: %s", source, name, reason);

			LOG_SNOOP(s_OperServ, "OS +J %s -- by %s (%s@%s) [%s]", name, callerUser->nick, callerUser->username, callerUser->host, reason);
			log_services(LOG_SERVICES_OPERSERV, "+J %s -- by %s (%s@%s) [%s]", name, callerUser->nick, callerUser->username, callerUser->host, reason);
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) juped \2%s\2 because: %s", source, data->operName, name, reason);

			LOG_SNOOP(s_OperServ, "OS +J %s -- by %s (%s@%s) through %s [%s]", name, callerUser->nick, callerUser->username, callerUser->host, data->operName, reason);
			log_services(LOG_SERVICES_OPERSERV, "+J %s -- by %s (%s@%s) through %s [%s]", name, callerUser->nick, callerUser->username, callerUser->host, data->operName, reason);
		}

		send_notice_to_user(s_OperServ, callerUser, "Juping \2%s\2 because: %s", name, reason);

		if (CONF_SET_READONLY)
			send_notice_to_user(s_OperServ, callerUser, "\2Notice:\2 Services is in read-only mode. Changes will not be saved!");

		terminate_string_ccodes(reason);

		/* Allocate the new entry. */
		aJupe = mem_malloc(sizeof(Jupe));

		/* Fill it. */
		aJupe->name = str_duplicate(name);

		str_creationinfo_init(&(aJupe->info));
		str_creationinfo_set(&(aJupe->info), data->operName, reason, NOW);

		/* Link it. */
		aJupe->next = JupeList;
		aJupe->prev = NULL;

		if (IS_NOT_NULL(JupeList))
			JupeList->prev = aJupe;

		JupeList = aJupe;

		/* Send it off. */
		send_cmd("SERVER %s 2 :Jupitered (%s)", name, reason);
	}
	else if (str_equals_nocase(command, "DEL")) {

		char *name, *err;
		Jupe *aJupe;
		long int jupeIdx;


		if (IS_NULL(name = strtok(NULL, " "))) {

			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2JUPE DEL\2 server");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP JUPE\2 for more information.");
			return;
		}

		aJupe = JupeList;

		jupeIdx = strtol(name, &err, 10);

		if ((jupeIdx > 0) && (*err == '\0')) {

			while (--jupeIdx > 0) {

				aJupe = aJupe->next;

				if (IS_NULL(aJupe)) {

					send_notice_to_user(s_OperServ, callerUser, "JUPE entry \2%s\2 not found.", name);
					return;
				}
			}
		}
		else {

			while (IS_NOT_NULL(aJupe)) {

				if (str_equals_nocase(name, aJupe->name))
					break;

				aJupe = aJupe->next;
			}

			if (IS_NULL(aJupe)) {

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "OS -J* %s -- by %s (%s@%s) [Not Juped]", name, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(s_OperServ, "OS -J* %s -- by %s (%s@%s) through %s [Not Juped]", name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_notice_to_user(s_OperServ, callerUser, "JUPE for \2%s\2 not found.", name);
				return;
			}
		}

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 removed \2%s\2 from the JUPE list", source, aJupe->name);

			LOG_SNOOP(s_OperServ, "OS -J %s -- by %s (%s@%s)", aJupe->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_OPERSERV, "-J %s -- by %s (%s@%s)", aJupe->name, callerUser->nick, callerUser->username, callerUser->host);
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) removed \2%s\2 from the JUPE list", source, data->operName, aJupe->name);

			LOG_SNOOP(s_OperServ, "OS -J %s -- by %s (%s@%s) through %s", aJupe->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_OPERSERV, "-J %s -- by %s (%s@%s) through %s", aJupe->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
		}

		send_notice_to_user(s_OperServ, callerUser, "\2%s\2 removed from JUPE list.", aJupe->name);

		if (CONF_SET_READONLY)
			send_notice_to_user(s_OperServ, callerUser, "\2Notice:\2 Services is in readonly mode. Changes will not be saved!.");

		send_cmd("SQUIT %s :Deleting JUPE", aJupe->name);

		/* Link around it. */
		if (IS_NOT_NULL(aJupe->next))
			aJupe->next->prev = aJupe->prev;

		if (IS_NOT_NULL(aJupe->prev))
			aJupe->prev->next = aJupe->next;
		else
			JupeList = aJupe->next;

		/* Free it. */
		TRACE();
		mem_free(aJupe->name);
		str_creationinfo_free(&(aJupe->info));
		mem_free(aJupe);
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SRA))
		send_notice_lang_to_user(s_OperServ, callerUser, GetCallerLang(), OPER_ERROR_ACCESS_DENIED);

	else if (str_equals_nocase(command, "INFO")) {

		char		*name, *reason, *err;
		long int	jupeIdx;
		Jupe		*aJupe;
		size_t		len;


		if (IS_NULL(name = strtok(NULL, " ")) || IS_NULL(reason = strtok(NULL, ""))) {

			TRACE_MAIN();
			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2JUPE INFO\2 server reason");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP JUPE\2 for more information.");
			return;
		}

		if ((len = str_len(reason)) > SERVER_DESC_MAX) {

			send_notice_to_user(s_OperServ, callerUser, "Maximum length for a jupe reason is %d characters. Yours has: %u", SERVER_DESC_MAX, len);
			return;
		}

		if (!validate_string(reason)) {

			send_notice_to_user(s_OperServ, callerUser, "Invalid reason supplied.");
			return;
		}

		aJupe = JupeList;

		jupeIdx = strtol(name, &err, 10);

		if ((jupeIdx > 0) && (*err == '\0')) {

			while (--jupeIdx > 0) {

				aJupe = aJupe->next;

				if (IS_NULL(aJupe)) {

					send_notice_to_user(s_OperServ, callerUser, "JUPE entry \2%s\2 not found.", name);
					return;
				}
			}
		}
		else {

			while (IS_NOT_NULL(aJupe)) {

				if (str_equals_nocase(name, aJupe->name))
					break;

				aJupe = aJupe->next;
			}

			if (IS_NULL(aJupe)) {

				send_notice_to_user(s_OperServ, callerUser, "JUPE for \2%s\2 not found.", name);
				return;
			}
		}

		terminate_string_ccodes(reason);

		if (data->operMatch) {

			send_globops(s_OperServ, "\2%s\2 changed JUPE reason for \2%s\2 to: %s [Was: %s]", source, aJupe->name, reason, aJupe->info.reason);

			LOG_SNOOP(s_OperServ, "OS Jr %s -- by %s (%s@%s) [%s -> %s]", aJupe->name, callerUser->nick, callerUser->username, callerUser->host, aJupe->info.reason, reason);
			log_services(LOG_SERVICES_OPERSERV, "Jr %s -- by %s (%s@%s) [%s -> %s]", aJupe->name, callerUser->nick, callerUser->username, callerUser->host, aJupe->info.reason, reason);
		}
		else {

			send_globops(s_OperServ, "\2%s\2 (through \2%s\2) changed JUPE reason for \2%s\2 to: %s [Was: %s]", source, data->operName, aJupe->name, reason, aJupe->info.reason);

			LOG_SNOOP(s_OperServ, "OS Jr %s -- by %s (%s@%s) through %s [%s -> %s]", aJupe->name, callerUser->nick, callerUser->username, callerUser->host, data->operName, aJupe->info.reason, reason);
			log_services(LOG_SERVICES_OPERSERV, "Jr %s -- by %s (%s@%s) through %s [%s -> %s]", aJupe->name, callerUser->nick, callerUser->username, callerUser->host, data->operName, aJupe->info.reason, reason);
		}

		send_notice_to_user(s_OperServ, callerUser, "Jupe reason for \2%s\2 changed to: %s", aJupe->name, reason);

		str_creationinfo_free(&(aJupe->info));
		str_creationinfo_init(&(aJupe->info));
		str_creationinfo_set(&(aJupe->info), data->operName, reason, NOW);

		send_cmd("SQUIT %s :Changing Jupe Reason", aJupe->name);
		send_cmd("SERVER %s 2 :Jupitered (%s)", aJupe->name, aJupe->info.reason);
	}
	else {

		send_notice_to_user(s_OperServ, callerUser, "Syntax: \2JUPE\2 [ADD|DEL|INFO|LIST] server [reason]");
		send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP JUPE\2 for more information");
	}
}


BOOL jupe_match(CSTR server, const User *callerUser, const BOOL sendSquit) {

	Jupe	*aJupe;


	TRACE_FCLT(FACILITY_JUPE_MATCH);

	if (IS_NULL(server) || IS_EMPTY_STR(server)) {

		log_error(FACILITY_JUPE_MATCH, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "jupe_match()", s_LOG_NULL, "server");

		return FALSE;
	}

	aJupe = JupeList;

	while (IS_NOT_NULL(aJupe)) {

		if (str_equals_nocase(server, aJupe->name)) {

			if (IS_NOT_NULL(callerUser))
				send_notice_to_user(s_OperServ, callerUser, "Do not squit Jupitered Servers, use \2/os JUPE DEL %s\2 to delete it.", aJupe->name);

			if (sendSquit)
				send_cmd("SQUIT %s :Jupitered Server [%s]", aJupe->name, aJupe->info.reason);

			send_cmd("SERVER %s 2 :Jupitered [%s]", aJupe->name, aJupe->info.reason);
			return TRUE;
		}

		aJupe = aJupe->next;
	}

	return FALSE;
}


void jupe_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	Jupe	*aJupe;
	int		startIdx = 0, endIdx = 5, jupeIdx = 0, sentIdx = 0;


	TRACE_FCLT(FACILITY_JUPE_DS_DUMP);

	if (IS_NULL(JupeList)) {

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2Jupe\2 List is empty.");
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

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2Jupe\2 List (showing entries %d-%d):", startIdx, endIdx);
		LOG_DEBUG_SNOOP("Command: DUMP JUPES %d-%d -- by %s (%s@%s)", startIdx, endIdx, callerUser->nick, callerUser->username, callerUser->host);
	}
	else {

		send_notice_to_user(sourceNick, callerUser, "DUMP: \2Jupe\2 List (showing entries %d-%d matching %s):", startIdx, endIdx, request);
		LOG_DEBUG_SNOOP("Command: DUMP JUPES %d-%d -- by %s (%s@%s) [Pattern: %s]", startIdx, endIdx, callerUser->nick, callerUser->username, callerUser->host, request);
	}

	aJupe = JupeList;

	while (IS_NOT_NULL(aJupe)) {

		++jupeIdx;

		if (IS_NOT_NULL(request) && !str_match_wild_nocase(request, aJupe->name)) {

			/* Doesn't match our search criteria, skip it. */
			aJupe = aJupe->next;
			continue;
		}

		++sentIdx;

		if (sentIdx < startIdx) {

			aJupe = aJupe->next;
			continue;
		}

		send_notice_to_user(sourceNick, callerUser, "%d) Address 0x%08X, size %d B",		jupeIdx, (unsigned long)aJupe, sizeof(Jupe));
		send_notice_to_user(sourceNick, callerUser, "Server: 0x%08X \2[\2%s\2]\2",			(unsigned long)aJupe->name, str_get_valid_display_value(aJupe->name));
		send_notice_to_user(sourceNick, callerUser, "Creator: 0x%08X \2[\2%s\2]\2",			(unsigned long)aJupe->info.creator.name, str_get_valid_display_value(aJupe->info.creator.name));
		send_notice_to_user(sourceNick, callerUser, "Reason: 0x%08X \2[\2%s\2]\2",			(unsigned long)aJupe->info.reason, str_get_valid_display_value(aJupe->info.reason));
		send_notice_to_user(sourceNick, callerUser, "Time Set C-time: %d",					aJupe->info.creator.time);
		send_notice_to_user(sourceNick, callerUser, "Next/Prev records: 0x%08X / 0x%08X",	(unsigned long)aJupe->next, (unsigned long)aJupe->prev);

		if (sentIdx >= endIdx)
			break;

		aJupe = aJupe->next;
	}
}


unsigned long int jupe_mem_report(CSTR sourceNick, const User *callerUser) {

	unsigned long int count = 0, mem = 0;
	Jupe *aJupe;


	TRACE_FCLT(FACILITY_JUPE_MEM_REPORT);

	send_notice_to_user(sourceNick, callerUser, "\2JUPES\2:");

	aJupe = JupeList;

	while (IS_NOT_NULL(aJupe)) {

		++count;

		mem += sizeof(Jupe);

		mem += str_len(aJupe->name) + 1;
		mem += str_len(aJupe->info.creator.name) + 1;
		mem += str_len(aJupe->info.reason) + 1;

		aJupe = aJupe->next;
	}

	send_notice_to_user(sourceNick, callerUser, "Jupe List: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", count, mem / 1024, mem);
	return mem;
}
