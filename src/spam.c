/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* spam.c - Gestione SPAM Lines
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/memory.h"
#include "../inc/main.h"
#include "../inc/logging.h"
#include "../inc/storage.h"
#include "../inc/conf.h"
#include "../inc/send.h"
#include "../inc/spam.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/


typedef	struct _SpamItem	SpamItem;

struct _SpamItem {

	SpamItem		*next;

	char			*text;
	flags_t			flags;	// SPF_*
	unsigned char	type;

	Creator			creator;
	char			*reason;

	unsigned char	pad;
};


/*********************************************************
 * Constants                                             *
 *********************************************************/

// SpamItem.flags;
#define SPF_ENABLED			0x00000001


#define	SPAM_REASON_MAXLEN	200

#define	SPAM_DB				"spam.db"


/*********************************************************
 * Local data                                            *
 *********************************************************/

static SpamItem				*spam_list;
static unsigned short int	spam_count;
static BOOL					spam_modified;


/*********************************************************
 * Private code                                          *
 *********************************************************/

#define send_SPAM(spamtext, type, reason)	send_cmd("SPAM %s %d :%s", (spamtext), (type), (reason))
#define send_UNSPAM(spamtext)				send_cmd("UNSPAM %s", (spamtext))


SpamItem *spam_create(CSTR text, int type, CSTR reason, CSTR creator_name) {

	if (IS_NOT_NULL(text) && IS_NOT_NULL(creator_name) && IS_NOT_NULL(reason)) {

		SpamItem *spam;

		spam = mem_malloc(sizeof(SpamItem));

		spam->next = NULL;

		spam->flags = SPF_ENABLED;

		spam->text = str_duplicate(text);
		spam->type = type;
		spam->reason = str_duplicate(reason);

		str_creator_init(&(spam->creator));
		str_creator_set(&(spam->creator), creator_name, 0);

		return spam;
	}
	else
		return NULL;
}


void spam_delete(SpamItem *spam) {

	if (IS_NOT_NULL(spam)) {

		mem_free(spam->text);
		mem_free(spam->reason);
		str_creator_free(&(spam->creator));
		mem_free(spam);
	}
}


BOOL spam_list_add(SpamItem *spam) {

	if (IS_NOT_NULL(spam)) {

		spam->next = spam_list;
		spam_list = spam;

		++spam_count;
		spam_modified = TRUE;

		return TRUE;
	}
	else
		return FALSE;
}


void spam_list_remove(SpamItem *spam) {

	if (IS_NOT_NULL(spam_list) && IS_NOT_NULL(spam)) {

		SpamItem *ptr = spam_list;

		do {

			if (ptr == spam) { // fist item

				spam_list = ptr->next;

				--spam_count;
				spam_modified = TRUE;
				break;
			}
			else if (ptr->next == spam) { // the next item is the one being deleted

				ptr->next = spam->next;

				--spam_count;
				spam_modified = TRUE;
				break;
			}

			ptr = ptr->next;

		} while (IS_NOT_NULL(ptr));
	}
}


SpamItem *spam_list_find(CSTR text) {

	if (IS_NOT_NULL(spam_list) && IS_NOT_NULL(text)) {

		SpamItem *ptr = spam_list;

		do {

			if (str_equals_nocase(text, ptr->text))
				return ptr;

			ptr = ptr->next;

		} while (IS_NOT_NULL(ptr));
	}

	return NULL;
}


/*********************************************************
 * Public code                                           *
 *********************************************************/

void spam_init(void) {

	spam_list = NULL;
	spam_count = 0;
	spam_modified = FALSE;
}


void spam_terminate(void) {
	SpamItem *spam;

	while (IS_NOT_NULL(spam_list)) {
		spam = spam_list;
		spam_list_remove(spam_list);
		spam_delete(spam);
	}
}


BOOL spam_db_load(void) {

	STGHANDLE	stg = STG_INVALID_HANDLE;
	STG_RESULT	result;
	SpamItem	*spam;


	TRACE_FCLT(FACILITY_SPAM_DB_LOAD);

	spam_count = 0;
	spam_modified = FALSE;

	result = stg_open(SPAM_DB, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version;


			version = stg_data_version(stg);

			switch (version) {

				case SPAM_DB_CURRENT_VERSION: {

					BOOL	read_done, data_available = TRUE;

					do {

						spam = mem_malloc(sizeof(SpamItem));
						result = stg_read_record(stg, (PBYTE)spam, sizeof(SpamItem));

						switch (result) {

							case stgSuccess: // a valid item

								read_done = TRUE;
								if (spam->text)
									read_done &= (result = stg_read_string(stg, &(spam->text), NULL)) == stgSuccess;

								if (read_done && IS_NOT_NULL(spam->creator.name))
									read_done &= (result = stg_read_string(stg, &(spam->creator.name), NULL)) == stgSuccess;

								if (read_done && IS_NOT_NULL(spam->reason))
									read_done &= (result = stg_read_string(stg, &(spam->reason), NULL)) == stgSuccess;

								if (!read_done)
									fatal_error(FACILITY_SPAM_DB_LOAD, __LINE__, "Read error on %s (2) - %s", SPAM_DB, stg_result_to_string(result));

								spam->next = NULL;
								spam_list_add(spam);
								break;

							case stgEndOfData:
								data_available = FALSE;
								mem_free(spam);
								break;

							default: // some error
								fatal_error(FACILITY_SPAM_DB_LOAD, __LINE__, "Read error on %s - %s", SPAM_DB, stg_result_to_string(result));
								return FALSE;
						}
					} while (data_available);

					stg_close(stg, SPAM_DB);
					return TRUE;
				}

				default:
					fatal_error(FACILITY_SPAM_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, SPAM_DB);
					return FALSE;
			}
		}

		case stgNotFound: // no data to load
			return TRUE;

		default: // error!
			stg_close(stg, SPAM_DB);

			fatal_error(FACILITY_SPAM_DB_LOAD, __LINE__, "Error opening %s - %s", SPAM_DB, stg_result_to_string(result));
			return FALSE;
	}
}


BOOL spam_db_save(void) {

	STGHANDLE	stg;
	STG_RESULT	result;
	SpamItem	*spam;
	BOOL		write_done;


	TRACE_FCLT(FACILITY_SPAM_DB_SAVE);

	if (!spam_modified)
		return TRUE;

	result = stg_create(SPAM_DB, SF_NOFLAGS, SPAM_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_SPAM_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"spam_db_save(): Could not create database file %s: %s [Error %d: %s]", SPAM_DB, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	spam = spam_list;

	while (IS_NOT_NULL(spam)) {

		result = stg_write_record(stg, (PBYTE)spam, sizeof(SpamItem));

		if (result != stgSuccess)
			fatal_error(FACILITY_SPAM_DB_SAVE, __LINE__, "Write error on %s - %s", SPAM_DB, stg_result_to_string(result));

		write_done = TRUE;

		if (spam->text)
			write_done &= (result = stg_write_string(stg, spam->text)) == stgSuccess;

		if (write_done && IS_NOT_NULL(spam->creator.name))
			write_done &= (result = stg_write_string(stg, spam->creator.name)) == stgSuccess;

		if (write_done && IS_NOT_NULL(spam->reason))
			write_done &= (result = stg_write_string(stg, spam->reason)) == stgSuccess;

		if (!write_done)
			fatal_error(FACILITY_SPAM_DB_SAVE, __LINE__, "Write error on %s - %s", SPAM_DB, stg_result_to_string(result));

		spam = spam->next;
	}

	stg_close(stg, SPAM_DB);

	return TRUE;
}


void spam_burst_send(void) {

	SpamItem *spam = spam_list;

	while (spam) {

		if (FlagSet(spam->flags, SPF_ENABLED))
			send_SPAM(spam->text, spam->type, spam->reason);

		spam = spam->next;
	}
}




void handle_spam(CSTR source, User *callerUser, ServiceCommandData *data) {
	/*
	SPAM ADD spamtext reason
	SPAM DEL spamtext
	SPAM SET spamtext ENABLED|DISABLED
	SPAM LIST
	*/

	SpamItem		*spam;
	char			*action = strtok(NULL, s_SPACE);
	BOOL 			needSyntax = FALSE;


	if (IS_NULL(action))
		needSyntax = TRUE;

	else if (str_equals_nocase(action, "ADD") || str_equals_nocase(action, "OVERRIDE")) {

		char *spamtext = strtok(NULL, s_SPACE);
		char *spamtype = strtok(NULL, s_SPACE);
		char *reason = strtok(NULL, s_NULL);

		if (IS_NOT_NULL(spamtext) && IS_NOT_NULL(spamtype) && IS_NOT_NULL(reason)) {

			spam = spam_list_find(spamtext);

			if (IS_NULL(spam)) {

				long int	type;
				char		*err;

				if (str_char_toupper(action[0]) == 'A') {

					char	*ptr;
					int		valid = 0;

					ptr = spamtext;

					while (*ptr) {

						switch (*ptr++) {

							case '*':
							case '?':
								break;

							default:
								++valid;
						}
					}

					if (valid < 5) {

						if (data->operMatch) {
							LOG_SNOOP(data->agent->nick, "%s +SP* %s -- by %s (%s@%s) [Lamer]", data->agent->shortNick, spamtext, callerUser->nick, callerUser->username, callerUser->host);
							send_SPAMOPS(data->agent->nick, "\2%s\2 tried to add \2%s\2 to the SPAM list!", source, spamtext);
						} else {
							LOG_SNOOP(data->agent->nick, "%s +SP* %s -- by %s (%s@%s) through %s [Lamer]", data->agent->shortNick, spamtext, callerUser->nick, callerUser->username, callerUser->host, data->operName);
							send_SPAMOPS(data->agent->nick, "\2%s\2 (through \2%s\2) tried to add \2%s\2 to the SPAM list!", source, data->operName, spamtext);
						}

						send_notice_to_user(data->agent->nick, callerUser, "\2ERROR:\2 SPAM text is too short.");
						return;
					}
				}

				if (str_len(reason) > SPAM_REASON_MAXLEN) {

					send_notice_to_user(data->agent->nick, callerUser, "\2ERROR:\2 SPAM reasons may not exceed \2%d\2 characters in length.", SPAM_REASON_MAXLEN);
					return;
				}

				type = strtol(spamtype, &err, 10);

				if ((*err == '\0') && (type >= 0) && (type <= 5)) {

					spam = spam_create(spamtext, type, reason, data->operName);

					spam_list_add(spam);

					send_SPAM(spamtext, type, reason);

					if (data->operMatch) {
						LOG_SNOOP(data->agent->nick, "%s +SP %s -- by %s (%s@%s) [Type: %d - Reason: %s]", data->agent->shortNick, spamtext, callerUser->nick, callerUser->username, callerUser->host, type, reason);
						log_services(data->agent->logID, "+SP %s -- by %s (%s@%s) [Type: %d - Reason: %s]", spamtext, callerUser->nick, callerUser->username, callerUser->host, type, reason);
						send_SPAMOPS(data->agent->nick, "\2%s\2 added a new SPAM [Text: \2%s\2] [Type: %d] [Reason: %s]", source, spamtext, type, reason);
					} else {
						LOG_SNOOP(data->agent->nick, "%s +SP %s -- by %s (%s@%s) through %s [Type: %d - Reason: %s]", data->agent->shortNick, spamtext, callerUser->nick, callerUser->username, callerUser->host, data->operName, type, reason);
						log_services(data->agent->logID, "+SP %s -- by %s (%s@%s) through %s [Type: %d - Reason: %s]", spamtext, callerUser->nick, callerUser->username, callerUser->host, data->operName, type, reason);
						send_SPAMOPS(data->agent->nick, "\2%s\2 (through \2%s\2) added a new SPAM [Text: \2%s\2] [Type: %d] [Reason: %s]", source, data->operName, spamtext, type, reason);
					}

					send_notice_to_user(data->agent->nick, callerUser, "\2%s\2 added to SPAM list.", spamtext);

				}
				else
					send_notice_to_user(data->agent->nick, callerUser, "\2ERROR:\2 Invalid type supplied.");
			}
			else {
				if (data->operMatch)
					LOG_SNOOP(data->agent->nick, "%s +SP* %s -- by %s (%s@%s) [Already on list]", data->agent->shortNick, spamtext, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(data->agent->nick, "%s +SP* %s -- by %s (%s@%s) through %s [Already on list]", data->agent->shortNick, spamtext, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				send_notice_to_user(data->agent->nick, callerUser, "String \2%s\2 is already on SPAM list.", spamtext);
			}
		}
		else
			send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2SPAM ADD\2 *text* type reason");

		return;
	}
	else if (str_equals_nocase(action, "DEL")) {

		char *spamtext = strtok(NULL, s_SPACE);

		if (IS_NOT_NULL(spamtext)) {

			send_UNSPAM(spamtext);

			spam = spam_list_find(spamtext);

			if (IS_NOT_NULL(spam)) {

				if (data->operMatch) {
					LOG_SNOOP(data->agent->nick, "%s -SP %s -- by %s (%s@%s)", data->agent->shortNick, spamtext, callerUser->nick, callerUser->username, callerUser->host);
					log_services(data->agent->logID, "-SP %s -- by %s (%s@%s)", spamtext, callerUser->nick, callerUser->username, callerUser->host);
					send_SPAMOPS(data->agent->nick, "\2%s\2 removed SPAM on string \2%s\2", source, spam->text);
				} else {
					LOG_SNOOP(data->agent->nick, "%s -SP %s -- by %s (%s@%s) through %s", data->agent->shortNick, spamtext, callerUser->nick, callerUser->username, callerUser->host, data->operName);
					log_services(data->agent->logID, "-SP %s -- by %s (%s@%s) through %s", spamtext, callerUser->nick, callerUser->username, callerUser->host, data->operName);
					send_SPAMOPS(data->agent->nick, "\2%s\2 (through \2%s\2) removed SPAM on string \2%s\2", source, data->operName, spam->text);
				}

				send_notice_to_user(data->agent->nick, callerUser, "SPAM on string \2%s\2 removed.", spam->text);

				spam_list_remove(spam);
				spam_delete(spam);
			}
			else {
				if (data->operMatch)
					LOG_SNOOP(data->agent->nick, "%s -SP* %s -- by %s (%s@%s) [Not Found]", data->agent->shortNick, spamtext, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(data->agent->nick, "%s -SP* %s -- by %s (%s@%s) through %s [Not Found]", data->agent->shortNick, spamtext, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				send_notice_to_user(data->agent->nick, callerUser, "String \2%s\2 not found on SPAM list.", spamtext);
			}
		}
		else
			needSyntax = TRUE;

		if (needSyntax)
			send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2SPAM DEL\2 text");

		return;
	}
	else if (str_equals_nocase(action, "SET")) {

		char *spamtext = strtok(NULL, s_SPACE);
		char *option = strtok(NULL, s_SPACE);

		if (IS_NOT_NULL(option)) {

			spam = spam_list_find(spamtext);

			if (IS_NOT_NULL(spam)) {

				if (str_equals_nocase(option, "TYPE")) {

					char *spamtype = strtok(NULL, s_SPACE);

					if (IS_NOT_NULL(spamtype)) {

						long int type;
						char *err;


						type = strtol(spamtype, &err, 10);

						if ((*err == '\0') && (type >= 0) && (type <= 5)) {

							if (spam->type == type) {
								if (data->operMatch)
									LOG_SNOOP(data->agent->nick, "%s *SPT %s -- by %s (%s@%s) [Already %d]", data->agent->shortNick, spam->text, callerUser->nick, callerUser->username, callerUser->host, spam->type);
								else
									LOG_SNOOP(data->agent->nick, "%s *SPT %s -- by %s (%s@%s) through %s [Already %d]", data->agent->shortNick, spam->text, callerUser->nick, callerUser->username, callerUser->host, data->operName, spam->type);
								send_notice_to_user(data->agent->nick, callerUser, "Type for SPAM string \2%s\2 is already set to \2%d\2.", spam->text, type);
							} else {
								if (data->operMatch) {
									LOG_SNOOP(data->agent->nick, "%s SPT %s -- by %s (%s@%s) [%d -> %d]", data->agent->shortNick, spam->text, callerUser->nick, callerUser->username, callerUser->host, spam->type, type);
									log_services(data->agent->logID, "SPT %s -- by %s (%s@%s) [%d -> %d]", spam->text, callerUser->nick, callerUser->username, callerUser->host, spam->type, type);
									send_SPAMOPS(data->agent->nick, "\2%s\2 changed type for SPAM string \2%s\2 from \2%d\2 to \2%d\2", source, spam->text, spam->type, type);
								} else {
									LOG_SNOOP(data->agent->nick, "%s SPT %s -- by %s (%s@%s) through %s [%d -> %d]", data->agent->shortNick, spam->text, callerUser->nick, callerUser->username, callerUser->host, data->operName, spam->type, type);
									log_services(data->agent->logID, "SPT %s -- by %s (%s@%s) through [%d -> %d]", spam->text, callerUser->nick, callerUser->username, callerUser->host, data->operName, spam->type, type);
									send_SPAMOPS(data->agent->nick, "\2%s\2 (through \2%s\2) changed type for SPAM string \2%s\2 from \2%d\2 to \2%d\2", source, data->operName, spam->text, spam->type, type);
								}

								send_notice_to_user(data->agent->nick, callerUser, "Type for SPAM string \2%s\2 is now set to \2%d\2.", spam->text, type);

								spam->type = type;

								send_UNSPAM(spam->text);
								send_SPAM(spam->text, spam->type, spam->reason);
							}
						}
						else
							needSyntax = TRUE;
					}
					else
						needSyntax = TRUE;
				}
				else {

					switch (str_parse_standard_value(option)) {

						case STDVAL_ENABLED:

							if (FlagSet(spam->flags, SPF_ENABLED)) {
								if (data->operMatch)
									LOG_SNOOP(data->agent->nick, "%s *SP! %s -- by %s (%s@%s) [Already enabled]", data->agent->shortNick, spam->text, callerUser->nick, callerUser->username, callerUser->host);
								else
									LOG_SNOOP(data->agent->nick, "%s *SP! %s -- by %s (%s@%s) through %s [Already enabled]", data->agent->shortNick, spam->text, callerUser->nick, callerUser->username, callerUser->host, data->operName);
								send_notice_to_user(data->agent->nick, callerUser, "SPAM entry for string \2%s\2 is already enabled.", spam->text);
							} else {

								AddFlag(spam->flags, SPF_ENABLED);
								send_SPAM(spam->text, spam->type, spam->reason);

								if (data->operMatch) {
									LOG_SNOOP(data->agent->nick, "%s SP! %s -- by %s (%s@%s) [Enabled]", data->agent->shortNick, spam->text, callerUser->nick, callerUser->username, callerUser->host);
									log_services(data->agent->logID, "SP! %s -- by %s (%s@%s) [Enabled]", spam->text, callerUser->nick, callerUser->username, callerUser->host);
									send_SPAMOPS(data->agent->nick, "\2%s\2 enabled SPAM entry for string \2%s\2", source, spam->text);
								} else {
									LOG_SNOOP(data->agent->nick, "%s SP! %s -- by %s (%s@%s) through %s [Enabled]", data->agent->shortNick, spam->text, callerUser->nick, callerUser->username, callerUser->host, data->operName);
									log_services(data->agent->logID, "SP! %s -- by %s (%s@%s) through %s [Enabled]", spam->text, callerUser->nick, callerUser->username, callerUser->host, data->operName);
									send_SPAMOPS(data->agent->nick, "\2%s\2 (through \2%s\2) enabled SPAM entry for string \2%s\2", source, data->operName, spam->text);
								}

								send_notice_to_user(data->agent->nick, callerUser, "SPAM entry for string \2%s\2 has been enabled.", spam->text);
							}
							break;


						case STDVAL_DISABLED:

							if (FlagUnset(spam->flags, SPF_ENABLED)) {
								if (data->operMatch)
									LOG_SNOOP(data->agent->nick, "%s *SP! %s -- by %s (%s@%s) [Already disabled]", data->agent->shortNick, spam->text, callerUser->nick, callerUser->username, callerUser->host);
								else
									LOG_SNOOP(data->agent->nick, "%s *SP! %s -- by %s (%s@%s) through %s [Already disabled]", data->agent->shortNick, spam->text, callerUser->nick, callerUser->username, callerUser->host, data->operName);
								send_notice_to_user(data->agent->nick, callerUser, "SPAM entry for string \2%s\2 is already disabled.", spam->text);
							} else {

								RemoveFlag(spam->flags, SPF_ENABLED);
								send_UNSPAM(spam->text);

								if (data->operMatch) {
									LOG_SNOOP(data->agent->nick, "%s SP! %s -- by %s (%s@%s) [Disabled]", data->agent->shortNick, spam->text, callerUser->nick, callerUser->username, callerUser->host);
									log_services(data->agent->logID, "SP! %s -- by %s (%s@%s) [Disabled]", spam->text, callerUser->nick, callerUser->username, callerUser->host);
									send_SPAMOPS(data->agent->nick, "\2%s\2 disabled SPAM entry for string \2%s\2", source, spam->text);
								} else {
									LOG_SNOOP(data->agent->nick, "%s SP! %s -- by %s (%s@%s) through %s [Disabled]", data->agent->shortNick, spam->text, callerUser->nick, callerUser->username, callerUser->host, data->operName);
									log_services(data->agent->logID, "SP! %s -- by %s (%s@%s) through %s [Disabled]", spam->text, callerUser->nick, callerUser->username, callerUser->host, data->operName);
									send_SPAMOPS(data->agent->nick, "\2%s\2 (through \2%s\2) disabled SPAM entry for string \2%s\2", source, data->operName, spam->text);
								}

								send_notice_to_user(data->agent->nick, callerUser, "SPAM entry for string \2%s\2 has been disabled.", spam->text);
							}
							break;


						default:
							needSyntax = TRUE;
					}
				}
			}
			else
				send_notice_to_user(data->agent->nick, callerUser, "String \2%s\2 not found on SPAM list.", spamtext);
		}
		else
			needSyntax = TRUE;

		if (needSyntax)
			send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2SPAM SET\2 option value");

		return;
	}
	else if (str_equals_nocase(action, "LIST")) {

		char	*pattern, timebuf[64];
		int		startIdx = 0, endIdx = 30, sentIdx = 0, spamIdx = 0;


		if (IS_NULL(spam_list)) {

			send_notice_to_user(data->agent->nick, callerUser, "SPAM list is empty.");
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
			send_notice_to_user(data->agent->nick, callerUser, "Current SPAM list (showing entries %d-%d):", startIdx, endIdx);
		else
			send_notice_to_user(data->agent->nick, callerUser, "Current SPAM list (showing entries %d-%d matching %s):", startIdx, endIdx, pattern);

		spam = spam_list;

		while (IS_NOT_NULL(spam)) {

			++spamIdx;

			if (IS_NOT_NULL(pattern) && !str_match_wild_nocase(pattern, spam->text)) {

				spam = spam->next;
				continue;
			}

			++sentIdx;

			if (sentIdx < startIdx) {

				spam = spam->next;
				continue;
			}

			lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, spam->creator.time);

			send_notice_to_user(data->agent->nick, callerUser, "%d) \2%s\2 [Type: %d] [Reason: %s]",
				spamIdx, spam->text, spam->type, spam->reason);

			send_notice_to_user(data->agent->nick, callerUser, "Set by \2%s\2 on %s.%s",
				spam->creator.name, timebuf, FlagUnset(spam->flags, SPF_ENABLED) ? " Currently disabled." : "");

			if (sentIdx >= endIdx)
				break;

			spam = spam->next;
		}

		send_notice_to_user(data->agent->nick, callerUser, "*** \2End of List\2 ***");
	}
	else
		needSyntax = TRUE;

	if (needSyntax)
		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2SPAM\2 ADD|DEL|LIST|SET [text] [type] [reason]");
}
