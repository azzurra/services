/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* send.c - Routines for sending stuff to the network
*
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
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
#include "../inc/main.h"
#include "../inc/sockutil.h"	/* For socket_write */
#include "../inc/servers.h"		/* For CAPAB_NICKIP */


/*********************************************************
 * Global variables                                      *
 *********************************************************/

unsigned long int total_sendM = 0;


/*********************************************************
 * Local variables                                       *
 *********************************************************/

static char send_local_buffer[IRCBUFSIZE + 4];


/*********************************************************
 * Public code                                           *
 *********************************************************/

void send_cmd(CSTR fmt, ...) {

	char cmd_buffer[BUFSIZE];
	size_t len;
	va_list args;

	++total_sendM;

	va_start(args, fmt);

	len = vsnprintf(cmd_buffer, IRCBUFSIZE, fmt, args);

	if (len < 0)
		len = IRCBUFSIZE;

	LOG_DEBUG("Sent: %s", cmd_buffer);

	cmd_buffer[len++] = '\r';
	cmd_buffer[len++] = '\n';
	cmd_buffer[len] = '\0';

	socket_write(cmd_buffer, len);

	va_end(args);
}

/* Globals */
void send_globops(CSTR source, CSTR fmt, ...) {

	va_list args;

	va_start(args, fmt);
	vsnprintf(send_local_buffer, IRCBUFSIZE, fmt, args);
	send_cmd(":%s GLOBOPS :%s", source ? source : CONF_SERVICES_NAME, send_local_buffer);
	va_end(args);
}

void send_chatops(CSTR source, CSTR fmt, ...) {

	va_list args;

	va_start(args, fmt);
	vsnprintf(send_local_buffer, IRCBUFSIZE, fmt, args);
	send_cmd(":%s CHATOPS :%s", source ? source : CONF_SERVICES_NAME, send_local_buffer);
	va_end(args);
}

void send_SPAMOPS(CSTR source, CSTR fmt, ...) {

	va_list args;

	va_start(args, fmt);
	vsnprintf(send_local_buffer, IRCBUFSIZE, fmt, args);
	send_cmd(":%s SNOTICE :%s", source ? source : CONF_SERVICES_NAME, send_local_buffer);
	va_end(args);
}


/* Send a NOTICE from the given source to the given nick. */
void send_notice_to_nick(CSTR source, CSTR dest, CSTR fmt, ...) {
	
	va_list args;

	if (nick_is_service(dest)) // non mandiamoci messaggi da soli che non e' il caso ...
		return;

	va_start(args, fmt);
	vsnprintf(send_local_buffer, IRCBUFSIZE, fmt, args);
	send_cmd(":%s NOTICE %s :%s", source, dest, send_local_buffer);
	va_end(args);
}


/* Send a NOTICE from the given source to the given nick. Faster if we have the User. */
void send_notice_to_user(CSTR source, const User *dest, CSTR fmt, ...) {
	
	va_list args;

	if (user_is_services_client(dest))	// non mandiamoci messaggi da soli che non e' il caso ...
		return;

	va_start(args, fmt);
	vsnprintf(send_local_buffer, IRCBUFSIZE, fmt, args);
	send_cmd(":%s NOTICE %s :%s", source, dest->nick, send_local_buffer);
	va_end(args);
}

void send_notice_lang_to_nick(CSTR source, CSTR dest, const LANG_ID lang_id, const LANG_MSG_ID msg_id, ...) {

	va_list args;
	static char	buffer[4096];
	const LANG_MSG	fmt = lang_msg(lang_id, msg_id);
	STR row, row_end;


	if (nick_is_service(dest)) // non mandiamoci messaggi da soli che non e' il caso ...
		return;
	
	va_start(args, msg_id);

	memset(buffer, 0, sizeof(buffer));
	vsnprintf(buffer, sizeof(buffer), fmt, args);

	row_end = buffer;

	while (*row_end) {

		row = row_end;
		row_end += strcspn(row_end, s_LF);

		if (*row_end)
			*row_end++ = 0;

		send_cmd(":%s NOTICE %s :%s", source, dest, *row ? row : s_SPACE);
	}

	va_end(args);
}

void send_notice_lang_to_user(CSTR source, const User *dest, const LANG_ID lang_id, const LANG_MSG_ID msg_id, ...) {

	va_list		args;
	static char	buffer[4096];
	const LANG_MSG	fmt = lang_msg(lang_id, msg_id);
	STR		row, row_end;

	if (user_is_services_client(dest)) // non mandiamoci messaggi da soli che non e' il caso ...
		return;
	
	va_start(args, msg_id);

	memset(buffer, 0, sizeof(buffer));
	vsnprintf(buffer, sizeof(buffer), fmt, args);

	row_end = buffer;

	while (*row_end) {

		row = row_end;
		row_end += strcspn(row_end, s_LF);

		if (*row_end)
			*row_end++ = 0;

		send_cmd(":%s NOTICE %s :%s", source, dest->nick, *row ? row : s_SPACE);
	}

	va_end(args);
}

/* Remove a user from the IRC network. 'source' is the nick which should generate the kill. */
void send_KILL(const char *source, const char *who, const char *reason, BOOL killUser) {

    if (IS_NULL(who) || IS_NULL(reason)) {

		log_error(FACILITY_SEND, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"send_KILL() called with NULL parameter(s) (%s, %s, %s)", source, who, reason);

		return;
	}

    if (IS_NULL(source))
		source = CONF_SERVICES_NAME;

    send_cmd(":%s KILL %s :%s (%s)", source, who, source, reason);

	if (killUser == TRUE) {

	    char *av[1];

		/* We don't care for the reason when processing a KILL internally. */

		av[0] = (char *)who;
		user_handle_KILL(source, 1, av);
	}
}


/* Send a PRIVMSG from the given source to the given nick. */
void send_PRIVMSG(CSTR source, CSTR dest, CSTR fmt, ...) {

	va_list args;

	va_start(args, fmt);
	vsnprintf(send_local_buffer, IRCBUFSIZE, fmt, args);
	send_cmd(":%s PRIVMSG %s :%s", source, dest, send_local_buffer);
	va_end(args);
}

/* Send a NICK from services, and fake the client loading. */
void send_NICK(CSTR nickname, CSTR umode, CSTR username, CSTR hostname, CSTR realname) {

	if (IS_NULL(nickname) || IS_NULL(umode) || IS_NULL(username) || IS_NULL(hostname) || IS_NULL(realname)) {

		LOG_DEBUG_SNOOP("send_nick() called with NULL parameter(s)");
		return;
	}

	#ifndef ENABLE_CAPAB_NICKIP
	send_cmd("NICK %s 1 %ld %s %s %s %s 0 :%s", nickname, time(NULL), umode, username, hostname, CONF_SERVICES_NAME, realname);
	#else
	if (FlagSet(uplink_capab, CAPAB_NICKIP))
		send_cmd("NICK %s 1 %ld %s %s %s %s 0 %lu :%s", nickname, time(NULL), umode, username, hostname, CONF_SERVICES_NAME, SERVICES_IP_HOST_ORDER, realname);
	else
		send_cmd("NICK %s 1 %ld %s %s %s %s 0 :%s", nickname, time(NULL), umode, username, hostname, CONF_SERVICES_NAME, realname);
	#endif
}

/* Send an 'user SVSMODE' */
void send_user_SVSMODE(CSTR source, CSTR target, CSTR modes, time_t ts) {

	// Note: source may be NULL
	if (IS_NULL(target) || IS_NULL(modes))
		log_error(FACILITY_SEND, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, s_LOG_ERR_PARAMETER, "send_user_SVSMODE()", s_LOG_NULL, IS_NULL(target) ? "target" : "modes");
	else
		send_cmd(":%s SVSMODE %s %ld %s 0", source, target, ts, modes);
}

void send_chan_MODE(CSTR agentNick, CSTR channel, CSTR modes, const unsigned long int limit, CSTR key) {

	if (IS_NULL(agentNick) || IS_NULL(channel) || IS_NULL(modes) || limit < 0) {

		log_error(FACILITY_SEND, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"send_chan_MODE() called with invalid parameter(s) (%s, %s, %s, %lu, %s)", agentNick, channel, modes, limit, key);
		return;
	}

	if (limit && key) {

		char *pk = strrchr(modes, 'k');
		char *pl = strrchr(modes, 'l');

		if (pk > pl)
			send_cmd(":%s MODE %s %s %lu %s", agentNick, channel, modes, limit, key);
		else
			send_cmd(":%s MODE %s %s %s %lu", agentNick, channel, modes, key, limit);
	}
	else if (limit)
		send_cmd(":%s MODE %s %s %lu", agentNick, channel, modes, limit);

	else if (key)
		send_cmd(":%s MODE %s %s %s", agentNick, channel, modes, key);

	else
		send_cmd(":%s MODE %s %s", agentNick, channel, modes);
}

/* Remove a user from the IRC network. */
void send_SVSKILL(const char *who, const char *reason) {

	if (IS_NULL(who) || IS_NULL(reason)) {

		log_error(FACILITY_SEND, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"send_SVSKILL() called with NULL parameter(s) (%s, %s)", who, reason);
		return;
	}

	send_cmd("SVSKILL %s :%s", who, reason);
}

/* Add an AutoKill. */
void send_AKILL(CSTR username, CSTR host, CSTR who, CSTR reason, const unsigned long id, CSTR type) {

	char buffer[IRCBUFSIZE];

	if (IS_NULL(username) || IS_NULL(host) || IS_NULL(who)|| IS_NULL(reason) || (id == 0) || IS_NULL(type)) {

		log_error(FACILITY_SEND, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"send_AKILL() called with NULL parameter(s) (%s, %s, %s, %s, %lu, %s)", username, host, who, reason, id, type);

		return;
	}

	snprintf(buffer, sizeof(buffer), "%s [AKill ID: %lu-%s]", reason, id, type);

	send_cmd("AKILL %s %s 0 %s %lu :%s", host, username, who, time(NULL), buffer);
}

/* Remove an AutoKill. */
void send_RAKILL(const char *username, const char *host) {

	if (IS_NULL(username) || IS_NULL(host)) {

		log_error(FACILITY_SEND, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"send_RAKILL() called with NULL parameter(s) (%s, %s)", username, host);

		return;
	}

	send_cmd("RAKILL %s %s", host, username);
}

/* Send a SJOIN for a services client. */
void send_SJOIN(CSTR nickname, CSTR channel) {

#if !defined(USE_SERVICES) && !defined(USE_STATS)
	time_t now = time(NULL);
#endif

	if (IS_NULL(nickname) || IS_NULL(channel)) {

		LOG_DEBUG_SNOOP("send_sjoin() called with NULL parameter(s)");
		return;
	}

#if defined(USE_SERVICES) || defined(USE_STATS)
	chan_handle_internal_SJOIN(nickname, channel);
#else

#ifdef ENABLE_CAPAB_SSJOIN
	if (FlagSet(uplink_capab, CAPAB_SSJOIN))
		send_cmd(":%s SJOIN %ld %s", nickname, now, channel);

	else
#endif
		send_cmd("SJOIN %ld %ld %s 0 :%s", now, now, channel, nickname);

#endif
}

/* Send a PART from a services client, and fake the client part. */
void send_PART(CSTR nickname, CSTR channel) {

#if defined(USE_SERVICES) || defined(USE_STATS)
	char *av[1];
#endif

	if (IS_NULL(nickname) || IS_NULL(channel)) {

		LOG_DEBUG_SNOOP("send_part() called with NULL parameter(s)");
		return;
	}
	send_cmd(":%s PART %s", nickname, channel);

#if defined(USE_SERVICES) || defined(USE_STATS)
	/* We don't care for the reason when processing a PART internally. */

	av[0] = (char *)channel;
	user_handle_PART(nickname, 1, av);
#endif
}

/* Send a QUIT from a services client, and fake the client quit. */
void send_QUIT(CSTR nickname, CSTR reason) {

	if (IS_NULL(nickname)) {

		LOG_DEBUG_SNOOP("send_quit() called with NULL nickname");
		return;
	}

	send_cmd(":%s QUIT :Quit: %s", nickname, reason);
	user_delete_services_client(nickname);
}

void send_SVSNOOP(CSTR server, char action) {

	if (IS_NULL(server) || ((action != '+') && (action != '-'))) {

		log_error(FACILITY_SEND, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"send_SVSNOOP() called with NULL or invalid parameter(s) (%s, %c)", server, action);

		return;
	}

	send_cmd("SVSNOOP %s %c", server, action);
}

void send_SVSNICK(CSTR nick, CSTR newnick) {

	if (IS_NULL(nick) || IS_NULL(newnick)) {

		log_error(FACILITY_SEND, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"send_SVSNICK() called with NULL parameter(s) (%s, %s)", nick, newnick);

		return;
	}

	send_cmd("SVSNICK %s %s %ld", nick, newnick, time(NULL));
}

/* Shun a client. */
void send_SHUN(CSTR source, CSTR target, CSTR reason) {

	if (IS_NULL(source) || IS_NULL(target) || IS_NULL(reason)) {

		log_error(FACILITY_SEND, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"send_SHUN() called with NULL parameter(s): %s %s %s", source, target, reason);

		return;
	}

	send_cmd(":%s SHUN %s :%s", source, target, reason);
}

#ifdef USE_SOCKSMONITOR
/* Send a CTCP to a client. */
void send_CTCP(CSTR target, CSTR type) {

	if (IS_NULL(target) || IS_NULL(type)) {

		log_error(FACILITY_SEND, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"send_CTCP() called with NULL parameter(s): %s %s", target, type);
		return;
	}

	send_cmd(":%s PRIVMSG %s :%c%s%c", s_SocksMonitor, target, 1, type, 1);
}
#endif
