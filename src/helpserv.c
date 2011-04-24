/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* helpserv.c - HelpServ
*
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/logging.h"
#include "../inc/send.h"
#include "../inc/conf.h"
#include "../inc/helpserv.h"
#include "../inc/macros.h"
#include "../inc/main.h"


/* Stuff to pass to the command handler. */
static Agent a_HelpServ;

/*********************************************************/

void handle_help(CSTR source, User *callerUser, ServiceCommandData *data) {

	FILE		*f;
	struct stat	st;
	char		path[MAX_PATH];
	char		*topic, *ptr = path;

	if (data->commandName[0] == 'O') {

		/* OHELP */
		ptr += str_copy_checked(HELPSERV_OPER_DIR, path, sizeof(path));
		topic = strtok(NULL, s_NULL);
	}
	else if (data->commandName[1] == 'H') {

		/* HHELP */
		ptr += str_copy_checked(HELPSERV_OPER_DIR, path, sizeof(path));
		topic = data->commandName;
	}
	else if (data->commandName[0] == 'H') {

		/* HELP */
		ptr += str_copy_checked(HELPSERV_DIR, path, sizeof(path));
		topic = strtok(NULL, s_NULL);
	}
	else {

		/* HelpServ commands. */
		ptr += str_copy_checked(HELPSERV_DIR, path, sizeof(path));
		topic = data->commandName;
	}

	*ptr++ = c_SPACE;							/* Verra' poi sostituito da un '/' */

	/* Cartella della lingua. */
	ptr += str_append_checked(lang_get_shortname(GetCallerLang()), path, sizeof(path) - (ptr - path));

	*ptr++ = c_SPACE;							/* Verra' poi sostituito da un '/' */

	/* Cartella dell'Agent. */
	ptr += str_append_checked(data->agent->nick, path, sizeof(path) - (ptr - path));

	/* Argomento specifico richiesto. */
	if (IS_NOT_NULL(topic)) {

		*ptr++ = c_SPACE;						/* Verra' poi sostituito da un '/' */

		ptr += str_append_checked(topic, path, sizeof(path) - (ptr - path));

		/* Get rid of the extra spaces at the end, if any. */
		while (*(ptr - 1) == c_SPACE)
			--ptr;
	}

	*ptr = '\0';

	str_tolower(path); 

	/* Eliminazione caratteri non validi. */
	ptr = path;

	while (*ptr) {

		switch (*ptr) {
		
			case '.':
			case '/':
				*ptr = '_';
				break;

			case ' ':
				*ptr = c_SLASH;
				break;
		}

		++ptr;
	}

	/* If we end up at a directory, go for an "index" file/dir if possible.	*/
	while (((ptr - path) < (int)sizeof(path) - 1) && (stat(path, &st) == 0) && S_ISDIR(st.st_mode)) {

		*ptr++ = c_SLASH;
		str_copy_checked("index", ptr, sizeof(path) - (ptr - path));
		ptr += str_len(ptr);
	}

	/* Send the file, if it exists. */
	if (!(f = fopen(path, "r"))) {
		
		LOG_DEBUG("debug: Cannot open help file %s", path);

		send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), ERROR_UNKNOWN_COMMAND, topic);
		send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), GET_SERVICE_COMMAND_LIST_MSG, data->agent->nick);
		return;
	}

	while (fgets(path, sizeof(path), f)) {

		ptr = strtok(path, "\r\n");

        /* Use this odd construction to prevent any %'s in the text from
		   doing weird stuff to the output. Also replace blank lines by
		   spaces or the ircd will block it. */

		send_notice_to_user(data->agent->nick, callerUser, "%s", IS_NOT_NULL(ptr) ? ptr : s_SPACE);
	}

	fclose(f);

	if (data->agent->agentID == AGENTID_CHANSERV) {

		if (IS_NULL(topic) || str_equals_nocase(topic, "REGISTER"))
			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_CHAN_EXPIRE, CONF_CHANNEL_EXPIRE);
	}
	else if (data->agent->agentID == AGENTID_NICKSERV) {

		if (IS_NULL(topic) || str_equals_nocase(topic, "REGISTER"))
			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), NS_NICK_EXPIRE, CONF_NICK_EXPIRE);
	}
}

/*********************************************************/

void helpserv_init(void) {

	/* Initialize this struct. */
	a_HelpServ.nick = s_HelpServ;
	a_HelpServ.shortNick = s_HS;
	a_HelpServ.agentID = AGENTID_HELPSERV;
	a_HelpServ.logID = logid_from_agentid(AGENTID_HELPSERV);
}

/*********************************************************/

/* Main HelpServ routine. */
void helpserv(const char *source, User *callerUser, char *buf) {

	TRACE_MAIN_FCLT(FACILITY_HELPSERV);

	if (IS_NULL(buf) || IS_EMPTY_STR(buf))
		send_notice_lang_to_user(s_HelpServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

	else if (buf[0] == '\001') {

		if (IS_EMPTY_STR(buf + 1))
			LOG_SNOOP(s_HelpServ, "Invalid CTCP from \2%s\2", source);

		else if (str_equals_nocase(buf + 1, "PING")) {

			send_notice_to_user(s_HelpServ, callerUser, "\1%s", buf + 1);
			LOG_SNOOP(s_HelpServ, "CTCP: PING from \2%s\2", source);
		}
		else {

			if (buf[str_len(buf) - 1] == '\001')
				buf[str_len(buf) - 1] = '\0';

			LOG_SNOOP(s_HelpServ, "CTCP: %s from \2%s\2", buf + 1, source);
		}
	}
	else {

		ServiceCommandData data;

		data.commandName = buf;
		data.userLevel = ULEVEL_NOACCESS;
		data.operMatch = TRUE;
		data.operName = NULL;
		data.agent = &a_HelpServ;

		handle_help(source, callerUser, &data);
	}
}
