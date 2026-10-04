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

#include <services/common.h>
#include <services/strings.h>
#include <services/messages.h>
#include <services/logging.h>
#include <services/memory.h>
#include <services/main.h>
#include <services/send.h>
#include <services/storage.h>
#include <services/conf.h>
#include <services/misc.h>
#include <services/tagline.h>
#include <services/database.h>
#include <services/hook.h>
#include <services/hooktypes.h>

/*********************************************************
 * Forward decls                                         *
 *********************************************************/
static void tg_db_write(struct database_handle *db);
static void tg_db_h_tl(struct database_handle *db, const char *type);

/*********************************************************
 * Global variables                                      *
 *********************************************************/

/* Number of Tag lines in the database. */
int TaglineCount;


/*********************************************************
 * Local variables                                       *
 *********************************************************/

/* List of Tag lines. */
static mowgli_list_t TaglineList = { NULL, NULL, 0 };

/*********************************************************
 * Public code                                           *
 *********************************************************/

void tagline_init(void) {
	hook_add_db_write(&tg_db_write, DB_HOOK_PRIO_OTHER);
	db_register_type_handler("TL", &tg_db_h_tl);
}

void tagline_terminate(void) {
	hook_del_db_write(&tg_db_write);
	db_unregister_type_handler("TL");
}

/* Load handler for TL record type */
static void tg_db_h_tl(struct database_handle *db, const char *type) {
	/* TL creator timestamp tagline */
	const char *creator = db_sread_word(db);
	time_t created_at = db_sread_time(db);
	const char *text = db_sread_str(db);

	Tagline *aTagline = smalloc(sizeof(Tagline));
	aTagline->text = sstrdup(text);
	str_creator_set(&(aTagline->creator), creator, created_at);

	mowgli_node_add(aTagline, &(aTagline->node), &TaglineList);

	/* Increase tagline counter. */
	++TaglineCount;
}

/* Write event handler for taglines */
static void tg_db_write(struct database_handle *db) {
	Tagline *aTagline;
	mowgli_node_t *n;

	MOWGLI_LIST_FOREACH(n, TaglineList.head) {
		aTagline = n->data;

		db_start_row(db, "TL");
		db_write_word(db, aTagline->creator.name);
		db_write_time(db, aTagline->creator.time);
		db_write_str(db, aTagline->text);
		db_commit_row(db);
	}
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
		mowgli_node_t *n;


		if (TaglineList.count == 0) {
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

		MOWGLI_LIST_FOREACH(n, TaglineList.head) {
			aTagline = n->data;
			++taglineIdx;

			if (IS_NOT_NULL(pattern) && !str_match_wild_nocase(pattern, aTagline->text)) {
				/* Doesn't match our search criteria, skip it. */
				continue;
			}

			++sentIdx;

			if (sentIdx < startIdx) {
				continue;
			}

			lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, aTagline->creator.time);

			send_notice_to_user(s_OperServ, callerUser, "%d) %s", taglineIdx, aTagline->text);
			send_notice_to_user(s_OperServ, callerUser, "Set by \2%s\2 on %s", aTagline->creator.name, timebuf);

			if (sentIdx >= endIdx)
				break;
		}

		send_notice_to_user(s_OperServ, callerUser, "*** \2End of List\2 ***");
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SOP))
		send_notice_lang_to_user(s_OperServ, callerUser, GetCallerLang(), OPER_ERROR_ACCESS_DENIED);

	else if (str_equals_nocase(command, "ADD")) {
		char		*text;
		size_t		len;
		Tagline		*aTagline;
		mowgli_node_t *n;

		if (IS_NULL(text = strtok(NULL, ""))) {
			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2TAGLINE ADD\2 text");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP SGLINE\2 for more information.");
			return;
		}

		if ((len = str_len(text)) > 260) {
			send_notice_to_user(s_OperServ, callerUser, "The maximum length for a tagline is 260 characters. Your tagline has %zu.", len);
			return;
		}

		if (!validate_string(text)) {
			send_notice_to_user(s_OperServ, callerUser, "Invalid text supplied.");
			return;
		}

		terminate_string_ccodes(text);

		MOWGLI_LIST_FOREACH(n, TaglineList.head) {
			aTagline = n->data;
			if (str_equals_nocase(text, aTagline->text)) {
				send_notice_to_user(s_OperServ, callerUser, "This text is already taglined!");

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "OS +TG* -- by %s (%s@%s) [Already Taglined]", callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(s_OperServ, "OS +TG* -- by %s (%s@%s) through %s [Already Taglined]", callerUser->nick, callerUser->username, callerUser->host, data->operName);

				return;
			}
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
		aTagline = smalloc(sizeof(Tagline));

		/* Fill it. */
		aTagline->text = str_duplicate(text);

		str_creator_init(&(aTagline->creator));
		str_creator_set(&(aTagline->creator), data->operName, NOW);

		/* Link it. */
		mowgli_node_add(aTagline, &(aTagline->node), &TaglineList);

		/* Increase tagline counter. */
		++TaglineCount;
	}
	else if (str_equals_nocase(command, "DEL")) {

		char			*text, *err;
		long int		taglineIdx;
		Tagline			*aTagline;
		mowgli_node_t	*n;

		if (IS_NULL(text = strtok(NULL, ""))) {
			send_notice_to_user(s_OperServ, callerUser, "Syntax: \2TAGLINE DEL\2 [text|number]");
			send_notice_to_user(s_OperServ, callerUser, "Type \2/os OHELP SGLINE\2 for more information.");
			return;
		}

		if (str_len(text) > 260) {
			send_notice_to_user(s_OperServ, callerUser, "Tagline not found.");
			return;
		}

		taglineIdx = strtol(text, &err, 10);

		if ((taglineIdx > 0) && (*err == '\0')) {
			aTagline = mowgli_node_nth_data(&TaglineList, taglineIdx - 1);

			if (IS_NULL(aTagline)) {
				send_notice_to_user(s_OperServ, callerUser, "Tagline entry %s not found.", text);
				return;
			}
		}
		else {
			MOWGLI_LIST_FOREACH(n, TaglineList.head) {
				aTagline = n->data;

				if (str_equals_nocase(text, aTagline->text))
					break;
			}

			if (IS_NULL(n)) {
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
		mowgli_node_delete(&(aTagline->node), &TaglineList);

		/* Decrease the tagline counter. */
		--TaglineCount;

		/* Free data. */
		sfree(aTagline->text);
		str_creator_free(&(aTagline->creator));
		sfree(aTagline);
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

	if (!CONF_SHOW_TAGLINES || TaglineList.count == 0) {
		send_globops(NULL, "Completed database write (%ld secs)", time(NULL) - now);
		return;
	}

	srand(randomseed());
	tagIdx = getrandom(0, TaglineCount - 1);

	aTagline = mowgli_node_nth_data(&TaglineList, tagIdx);

	if (IS_NULL(aTagline)) {
		log_error(FACILITY_TAGLINE_SHOW, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"tagline_show() returned NULL value (tagIdx: %d)", tagIdx);

		send_globops(NULL, "Completed database write (%ld secs)", time(NULL) - now);
		return;
	}

	send_globops(NULL, "Completed database write (%ld secs) -> %s", (time(NULL) - now), aTagline->text);
}


void tagline_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {
	Tagline			*aTagline;
	int				startIdx = 0, endIdx = 5, taglineIdx = 0, sentIdx = 0;
	mowgli_node_t	*n;


	TRACE_FCLT(FACILITY_TAGLINE_DS_DUMP);

	if (TaglineList.count == 0) {
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


	MOWGLI_LIST_FOREACH(n, TaglineList.head) {
		aTagline = n->data;

		++taglineIdx;

		if (IS_NOT_NULL(request) && !str_match_wild_nocase(request, aTagline->text)) {
			/* Doesn't match our search criteria, skip it. */
			continue;
		}

		++sentIdx;

		if (sentIdx < startIdx) {
			continue;
		}

		send_notice_to_user(sourceNick, callerUser, "%d) Address %p, size %zu B",	taglineIdx, (void *)aTagline, sizeof(Tagline));
		send_notice_to_user(sourceNick, callerUser, "Text: %p \2[\2%s\2]\2",		(void *)aTagline->text, str_get_valid_display_value(aTagline->text));
		send_notice_to_user(sourceNick, callerUser, "Creator: %p \2[\2%s\2]\2",		(void *)aTagline->creator.name, str_get_valid_display_value(aTagline->creator.name));
		send_notice_to_user(sourceNick, callerUser, "Time Set C-time: %ld",			aTagline->creator.time);
		send_notice_to_user(sourceNick, callerUser, "Next/Prev records: %p / %p",	(void *)aTagline->node.next, (void *)aTagline->node.prev);
		send_notice_to_user(sourceNick, callerUser, "Mowgli node data pointr: %p",	(void *)aTagline->node.data);

		if (sentIdx >= endIdx)
			break;
	}
}


unsigned long int tagline_mem_report(CSTR sourceNick, const User *callerUser) {
	unsigned long int count = 0, mem = 0;
	Tagline *aTagline;
	mowgli_node_t *n;

	TRACE_FCLT(FACILITY_TAGLINE_MEM_REPORT);

	send_notice_to_user(sourceNick, callerUser, "\2TAGLINES\2:");

	MOWGLI_LIST_FOREACH(n, TaglineList.head) {
		++count;

		mem += sizeof(Tagline);

		mem += str_len(aTagline->text) + 1;
		mem += str_len(aTagline->creator.name) + 1;
	}

	send_notice_to_user(sourceNick, callerUser, "Tagline List: \2%lu\2 -> \2%lu\2 KB (\2%lu\2 B)", count, mem / 1024, mem);
	return mem;
}
