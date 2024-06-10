/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* messages.c - Gestione messaggi
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
#include "../inc/memory.h"
#include "../inc/send.h"
#include "../inc/lang.h"
#include "../inc/version.h"
#include "../inc/servers.h"
#include "../inc/main.h"
#include "../inc/conf.h"
#include "../inc/misc.h"
#include "../inc/sockutil.h"
#include "../inc/process.h"
#include "../inc/users.h"
#include "../inc/channels.h"
#include "../inc/debugserv.h"
#include "../inc/nickserv.h"
#include "../inc/chanserv.h"
#include "../inc/memoserv.h"
#include "../inc/operserv.h"
#include "../inc/rootserv.h"
#include "../inc/seenserv.h"
#include "../inc/statserv.h"
#include "../inc/helpserv.h"
#include "../inc/ignore.h"


/*********************************************************
 * Variabili globali                                     *
 *********************************************************/

unsigned int	uplink_capab = CAPAB_UNKNOWN;


/*********************************************************
 * Variabili locali                                      *
 *********************************************************/

unsigned long int npings = 0;

int nservers = 0;

/*********************************************************
 * msg_update_flood_levels()                             *
 *                                                       *
 * Updates flood levels of a user.                       *
 * If exceeds max, warn, if continues, kill user.        *
 *********************************************************/

static BOOL msg_update_flood_levels(User *user, CSTR command, CSTR target, CSTR text) {

	if (IS_NULL(user))
		return FALSE;

	if (NOW >= user->flood_reset_time) {

		// e' trascorso il tempo necessario all'azzeramento del conteggio di messaggi inviati
		user->flood_msg_count = 0;

		// e' trascorso il tempo necessario ad abbassare il livello?
		if ((user->flood_current_level != FLOOD_LEVEL_0) && (NOW - user->flood_reset_time >= CONF_FLOOD_LEVEL_RESET))
			--(user->flood_current_level);
	}

	// aggiungere un nuovo messaggio al conteggio attuale
	++(user->flood_msg_count);

	// nuovo azzeramento previsto
	user->flood_reset_time = NOW + CONF_FLOOD_MESSAGE_RESET;

	// avanzarlo di livello ?
	if (user->flood_msg_count >= CONF_FLOOD_MAX_MESSAGES) {

		++(user->flood_current_level);

		switch (user->flood_current_level) {

			default: // paranoia ...
			case FLOOD_LEVEL_4: // - User is killed

				if (user_is_ircop(user)) {

					send_globops(NULL, "Oper \2%s\2 has been SEVERELY flooding services", user->nick);
					user->flood_msg_count = 0;
				}
				else {

					send_globops(NULL, "User \2%s\2 (%s@%s) has been killed for flooding.", user->nick, user->username, user->host);

					AddFlag(user->flags, USER_FLAG_FLOODER);
					send_SVSKILL(user->nick, lang_msg(GetCallerLang(), SERVICES_FLOOD_KILL_MESSAGE));
					return TRUE;
				}

				break;


			case FLOOD_LEVEL_3: // - Warns user, globops network again with "SEVERELY" message

				user->flood_msg_count = 0;

				send_notice_lang_to_user(s_Snooper, user, GetCallerLang(), SERVICES_FLOOD_SECOND_WARNING);

				if (!user_is_ircop(user)) {

					send_globops(NULL, "Services are being \2SEVERELY\2 flooded by \2%s\2 (%s@%s)", user->nick, user->username, user->host);

					LOG_SNOOP(s_OperServ, "%s (%s@%s) is SEVERELY flooding services. Last command sent: %s %s %s", user->nick, user->username, user->host, command, IS_NOT_NULL(target) ? target : s_NULL, IS_NOT_NULL(text) ? text : s_NULL);
				}

				break;


			case FLOOD_LEVEL_2: // - Warns user, globops network

				user->flood_msg_count = 0;

				send_notice_lang_to_user(s_Snooper, user, GetCallerLang(), SERVICES_FLOOD_FIRST_WARNING);

				if (!user_is_ircop(user)) {

					send_globops(NULL, "Services are being flooded by \2%s\2 (%s@%s)", user->nick, user->username, user->host);

					LOG_SNOOP(s_OperServ, "%s (%s@%s) is flooding services. Last command sent: %s %s %s", user->nick, user->username, user->host, command, IS_NOT_NULL(target) ? target : s_NULL, IS_NOT_NULL(text) ? text : s_NULL);
				}

				break;


			case FLOOD_LEVEL_1: // - Grace Level

				user->flood_msg_count = 0;
				break;


			case FLOOD_LEVEL_0: // - Start here
				// nulla da fare a questo livello
				break;
		}
	}

	return FALSE;
}

/*********************************************************/
/*
static void m_nickcoll(CSTR source, const int ac, char **av) {

	char * const uv[1] = { av[2] };

	user_handle_QUIT(av[0], 1, uv);
}
*/

/*********************************************************/

static void m_mode(CSTR source, const int ac, char **av) {

	if (av[0][0] != '#')
		user_handle_userMODE(source, ac, av);
	else
		chan_handle_chanMODE(source, ac, av);
}

/*********************************************************/

static void m_sjoin(CSTR source, const int ac, char **av) {
	chan_handle_SJOIN(source, ac, av);		/* Normal SJOIN. */
}

/*********************************************************/

static void m_svsmode(CSTR source, const int ac, char **av) {

	if ((ac < 3) || (av[0][0] == '#'))
		return;

	else {

		char *ov[2];

		ov[0] = av[0];
		ov[1] = av[2];

		user_handle_userMODE(av[0], 2, ov);
	}
}


/*********************************************************
 * m_version()				                             *
 *                                                       *
 * Response to the VERSION message                       *
 *********************************************************/

static void m_version(CSTR source, const int ac, char **av) {

	User *user;

	if (IS_NULL(user = hash_onlineuser_find(source))) {

		log_error(FACILITY_MESSAGES, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"m_version: Version from nonexistent user %s", source);

		return;
	}

	SetCallerLang(user->current_lang);

	/* Check if we have a flooder. Operators are ignored. */
	if ((CONF_SET_FLOOD == TRUE) && (msg_update_flood_levels(user, "VERSION", NULL, NULL) == TRUE))
		return;

	/* Check if we should ignore. Operators always get through. */
	if (!user_is_ircop(user) && ignore_match(user))
		return;

	servers_increase_messages(user);

	LOG_SNOOP(s_Snooper, "VERSION requested by \2%s\2", source);

	if (IS_NOT_NULL(source))
		send_cmd("351 %s %s (%s) :%s", source, s_vers_name, s_vers_build_name, s_vers_version);
}

/*********************************************************/

static void m_ping(CSTR source, const int ac, char **av) {

	if (ac < 1)
		return;

	if (FlagUnset(uplink_capab, CAPAB_BURST) && (++npings == 2)) {

		synch_topics();

		synch_servers();

		synched = TRUE;
		LOG_SNOOP(s_Snooper, "Synched to network data.");
		send_SJOIN(s_DebugServ, CONF_DEBUG_CHAN);
		send_SJOIN(s_GlobalNoticer, CONF_SNOOP_CHAN);
		send_SJOIN(s_NickServ, CONF_SNOOP_CHAN);
		send_SJOIN(s_ChanServ, CONF_SNOOP_CHAN);
		send_SJOIN(s_HelpServ, CONF_SNOOP_CHAN);
		send_SJOIN(s_MemoServ, CONF_SNOOP_CHAN);
		send_SJOIN(s_OperServ, CONF_SNOOP_CHAN);
		send_SJOIN(s_RootServ, CONF_SNOOP_CHAN);
		send_SJOIN(s_StatServ, CONF_SNOOP_CHAN);
		send_SJOIN(s_SeenServ, CONF_SNOOP_CHAN);
	}

	send_cmd("PONG %s %s", ac > 1 ? av[1] : CONF_SERVICES_NAME, av[0]);
}

/*********************************************************/

static void m_burst(CSTR source, const int ac, char **av) {

#ifdef ENABLE_CAPAB_BURST
	if (ac > 0) {

		/* Let our uplink know we're synched. */
		send_cmd("BURST 0");

		synch_topics();

		synch_servers();

		synched = TRUE;
		LOG_SNOOP(s_Snooper, "Synched to network data.");
		send_SJOIN(s_DebugServ, CONF_DEBUG_CHAN);
		send_SJOIN(s_GlobalNoticer, CONF_SNOOP_CHAN);
		send_SJOIN(s_NickServ, CONF_SNOOP_CHAN);
		send_SJOIN(s_ChanServ, CONF_SNOOP_CHAN);
		send_SJOIN(s_HelpServ, CONF_SNOOP_CHAN);
		send_SJOIN(s_MemoServ, CONF_SNOOP_CHAN);
		send_SJOIN(s_OperServ, CONF_SNOOP_CHAN);
		send_SJOIN(s_RootServ, CONF_SNOOP_CHAN);
		send_SJOIN(s_StatServ, CONF_SNOOP_CHAN);
		send_SJOIN(s_SeenServ, CONF_SNOOP_CHAN);

	}
#endif
}

/*********************************************************/

static void m_motd(CSTR source, const int ac, char **av) {

	FILE *f;
	char buf[BUFSIZE];
	User *user;

	if (IS_NULL(user = hash_onlineuser_find(source))) {

		log_error(FACILITY_MESSAGES, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"m_motd: MOTD from nonexistent user %s", source);

		return;
	}

	SetCallerLang(user->current_lang);

	/* Check if we have a flooder. Operators are ignored. */
	if ((CONF_SET_FLOOD == TRUE) && (msg_update_flood_levels(user, "MOTD", NULL, NULL) == TRUE))
		return;

	/* Check if we should ignore. Operators always get through. */
	if (!user_is_ircop(user) && ignore_match(user))
		return;

	servers_increase_messages(user);

	LOG_SNOOP(s_Snooper, "MOTD requested by \2%s\2", source);

	send_cmd("375 %s :- %s Message of the Day", source, CONF_SERVICES_NAME);

	if (IS_NOT_NULL(f = fopen(MOTD_FILENAME, "r"))) {

		while (fgets(buf, sizeof(buf), f)) {

			buf[str_len(buf)-1] = 0;
			send_cmd("372 %s :- %s", source, buf);
		}

		fclose(f);
	}

	send_cmd("376 %s :End of /MOTD command.", source);
}

/*********************************************************/

static void m_privmsg(CSTR source, const int ac, char **av) {

	char		buffer[NICKSIZE];
	const char	*nick;
	User		*currentUser;
	BOOL		isOper;

	if (ac < 2 || strchr(source, '.'))
		return;

	if (av[0][0] == '#') {
		return;
	}

	if (IS_NULL(currentUser = hash_onlineuser_find(source))) {

		if (str_not_equals_partial(av[1], "SIDENTIFY", 9))
			log_error(FACILITY_MESSAGES, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
				"m_privmsg: Privmsg from nonexistent user %s: %s", source, av[1]);

		return;
	}

	/* Ignore this message if the user is going to be killed for flooding. */
	if (FlagSet(currentUser->flags, USER_FLAG_FLOODER))
		return;

	isOper = user_is_ircop(currentUser);

	SetCallerLang(currentUser->current_lang);

	/* Check if we have a flooder. Operators are ignored. */
	if ((CONF_SET_FLOOD == TRUE) && (msg_update_flood_levels(currentUser, "PRIVMSG", av[0], av[1]) == TRUE))
		return;

	/* Check if we should ignore. Operators always get through. */
	if (!isOper && ignore_match(currentUser))
		return;

	servers_increase_messages(currentUser);

	if (strchr(av[0], '@')) {

		str_tokenize(av[0], buffer, sizeof(buffer), c_AT);
		nick = buffer;
	}
	else
		nick = av[0];

	if (IS_NULL(av[1]))
		return;

	else if (str_equals_nocase(nick, s_ChanServ))
		chanserv(source, currentUser, av[1]);

	else if (str_equals_nocase(nick, s_NickServ))
		nickserv(source, currentUser, av[1]);

	else if (str_equals_nocase(nick, s_MemoServ))
		memoserv(source, currentUser, av[1]);

	else if (isOper && str_equals_nocase(nick, s_OperServ))
		operserv(source, currentUser, av[1]);

	else if (isOper && str_equals_nocase(nick, s_RootServ))
		rootserv(source, currentUser, av[1]);

	else if (str_equals_nocase(nick, s_HelpServ))
		helpserv(source, currentUser, av[1]);

	else if (str_equals_nocase(nick, s_StatServ))
		statserv(source, currentUser, av[1]);

	else if (str_equals_nocase(nick, s_SeenServ))
		seenserv(source, currentUser, av[1]);

	else if (is_services_coder(currentUser) && str_equals_nocase(nick, s_DebugServ))
		debugserv(source, currentUser, av[1]);
}

/*********************************************************/

static void m_stats(CSTR source, const int ac, char **av) {

	User *user;

	if (ac != 2)
		return;

	if (IS_NULL(user = hash_onlineuser_find(source))) {

		log_error(FACILITY_MESSAGES, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"m_stats: Stats from nonexistent user %s", source);

		return;
	}

	SetCallerLang(user->current_lang);

	/* Check if we have a flooder. Operators are ignored. */
	if ((CONF_SET_FLOOD == TRUE) && (msg_update_flood_levels(user, "STATS", av[0], NULL) == TRUE))
		return;

	/* Check if we should ignore. Operators always get through. */
	if (!user_is_ircop(user) && ignore_match(user))
		return;

	servers_increase_messages(user);

	switch (*av[0]) {

	case 'u':
		send_cmd("242 %s :Services up %s", source, convert_time(misc_buffer, MISC_BUFFER_SIZE, (NOW - start_time), LANG_DEFAULT));
		send_cmd("219 %s u :End of /STATS report.", source);
		return;

	case 'm':
		if (user_is_ircop(user)) {

			int			count = 0;
			Message		*msg;
			char		buffer[IRCBUFSIZE], reply[IRCBUFSIZE];
			size_t		len = 0;


			send_notice_to_user(s_Snooper, user, "*** Commands Usage Count: ***");

			for (msg = messages; msg->name; ++msg) {

				snprintf(buffer, sizeof(buffer), "%s [\2%lu\2]", msg->name, msg->usage_count);

				if (count > 0) {

					*(reply + len++) = c_COMMA;
					*(reply + len++) = c_SPACE;
				}

				len += str_copy_checked(buffer, (reply + len), (sizeof(reply) - len));

				if (++count == 6) {

					send_notice_to_user(s_Snooper, user, "%s", reply);
					count = 0;
					len = 0;
				}
			}

			if (len > 0)
				send_notice_to_user(s_Snooper, user, "%s", reply);
		}
		break;

	case 't':
		if (user_is_ircop(user)) {

			#define	_1K	(1024.0)
			#define	_1M	(1024.0*1024.0)
			#define	_1G	(1024.0*1024.0*1024.0)
			#define	_1T	(1024.0*1024.0*1024.0*1024.0)

			#define	GETf(x) ((x > _1T) ? (float)(x/_1T) : ((x > _1G) ? (float)(x/_1G) : ((x > _1M) ? (float)(x/_1M) : ((x > _1K) ? (float)(x/_1K) : (float)x))))
			#define	GETs(x) ((x > _1T) ? "Terabytes" : ((x > _1G) ? "Gigabytes" : ((x > _1M) ? "Megabytes" : ((x > _1K) ? "Kilobytes" : "Bytes"))))
			#define GETb(x) (float) ((float)(x / 1024) / (float) (NOW - start_time))

			send_notice_to_user(s_Snooper, user, "Bandwidth usage statistics:");

			send_notice_to_user(s_Snooper, user, "Bytes sent: %7.2f %s (%4.1f K/s)",
				GETf(total_written), GETs(total_written), GETb(total_written));
			send_notice_to_user(s_Snooper, user, "Bytes recv: %7.2f %s (%4.1f K/s)",
				GETf(total_read), GETs(total_read), GETb(total_read));

			send_notice_to_user(s_Snooper, user, "Messages sent: %lu (%4.1f wpl)",
				total_sendM, (float) ((float) total_written / (float) total_sendM));
			send_notice_to_user(s_Snooper, user, "Messages recv: %lu (%4.1f wpl)",
				total_recvM, (float) ((float) total_read / (float) total_recvM));

			#undef _1K
			#undef _1M
			#undef _1G
			#undef _1T

			#undef GETf
			#undef GETs
			#undef GETb
		}
		break;
	}
}

/*********************************************************/

static void m_whois(CSTR source, const int ac, char **av) {

	User *user, *localUser;

	if (ac < 2)
		return;

	if (IS_NULL(user = hash_onlineuser_find(source))) {

		log_error(FACILITY_MESSAGES, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"m_whois: Whois from nonexistent user %s", source);

		return;
	}

	SetCallerLang(user->current_lang);

	/* Check if we have a flooder. Operators are ignored. */
	if ((CONF_SET_FLOOD == TRUE) && (msg_update_flood_levels(user, "WHOIS", av[0], av[1]) == TRUE))
		return;

	/* Check if we should ignore. Operators always get through. */
	if (!user_is_ircop(user) && ignore_match(user))
		return;

	servers_increase_messages(user);

	if (IS_NULL(localUser = hash_onlineuser_find(av[1])))
		send_cmd("401 %s %s :No such service.", source, av[1]);

	else {

		send_cmd("311 %s %s %s %s * :%s", source, localUser->nick, localUser->username, localUser->maskedHost, localUser->realname);
		send_cmd("312 %s %s %s :%s", source, localUser->nick, CONF_SERVICES_NAME, CONF_SERVICES_DESC);
		send_cmd("317 %s %s %lu %lu :seconds idle, signon time", source, localUser->nick, (NOW - localUser->signon), localUser->signon);
	}

	send_cmd("318 %s %s :End of /WHOIS list.", source, av[1]);
}

/*********************************************************/

static void m_admin(CSTR source, const int ac, char **av) {

	User *user;

	if (IS_NULL(user = hash_onlineuser_find(source))) {

		log_error(FACILITY_MESSAGES, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"m_whois: Whois from nonexistent user %s", source);

		return;
	}

	SetCallerLang(user->current_lang);

	/* Check if we have a flooder. Operators are ignored. */
	if ((CONF_SET_FLOOD == TRUE) && (msg_update_flood_levels(user, "ADMIN", NULL, NULL) == TRUE))
		return;

	/* Check if we should ignore. Operators always get through. */
	if (!user_is_ircop(user) && ignore_match(user))
		return;

	servers_increase_messages(user);

	send_cmd("256 %s :Administrative info about %s", source, CONF_SERVICES_NAME);
	send_cmd("257 %s :Azzurra IRC Network IRC Services", source);
	send_cmd("258 %s :Admin: Azzurra Network Roots", source);
	send_cmd("259 %s :E-Mail Address: irc@azzurra.chat", source);
}

/*********************************************************/

static void m_time(CSTR source, const int ac, char **av) {

	User *user;
	char timebuf[64];

	if (IS_NULL(user = hash_onlineuser_find(source))) {

		log_error(FACILITY_MESSAGES, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"m_whois: Whois from nonexistent user %s", source);

		return;
	}

	SetCallerLang(user->current_lang);

	/* Check if we have a flooder. Operators are ignored. */
	if ((CONF_SET_FLOOD == TRUE) && (msg_update_flood_levels(user, "TIME", NULL, NULL) == TRUE))
		return;

	/* Check if we should ignore. Operators always get through. */
	if (!user_is_ircop(user) && ignore_match(user))
		return;

	servers_increase_messages(user);

	lang_format_localtime(timebuf, sizeof(timebuf), LANG_US, TIME_FORMAT_FULLDATE, NOW);

	send_cmd("391 %s %s :%s", source, CONF_SERVICES_NAME, timebuf);
}

/*********************************************************/

static void m_info(CSTR source, const int ac, char **av) {

	FILE *f;
	char buf[BUFSIZE];
	User *user;

	if (IS_NULL(user = hash_onlineuser_find(source))) {

		log_error(FACILITY_MESSAGES, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"m_info: INFO from nonexistent user %s", source);

		return;
	}

	SetCallerLang(user->current_lang);

	/* Check if we have a flooder. Operators are ignored. */
	if ((CONF_SET_FLOOD == TRUE) && (msg_update_flood_levels(user, "INFO", NULL, NULL) == TRUE))
		return;

	/* Check if we should ignore. Operators always get through. */
	if (!user_is_ircop(user) && ignore_match(user))
		return;

	servers_increase_messages(user);

	if (IS_NOT_NULL(f = fopen(MOTD_FILENAME, "r"))) {

		while (fgets(buf, sizeof(buf), f)) {

			buf[str_len(buf)-1] = 0;
			send_cmd("371 %s :%s", source, buf);
		}

		fclose(f);
	}

	send_cmd("374 %s :End of /INFO list.", source);
}


/*********************************************************
 * Handle routing notices, used to know when a certain   *
 * server has synched to network data so we can start    *
 * scanning it for proxies again.                        *
 *********************************************************/

static void m_gnotice(CSTR source, const int ac, char **av) {

	if (str_match_wild("* has synched to network data.", av[0])) {

		char servername[HOSTMAX];
		Server *server;

		memset(servername, 0, sizeof(servername));

		str_tokenize(av[0], servername, sizeof(servername), c_SPACE);

		if (IS_NULL(server = findserver(servername))) {

			LOG_DEBUG_SNOOP("Could not find server %s supplied by GNOTICE %s", servername, av[0]);
			return;
		}

		if (FlagSet(server->flags, SERVER_FLAG_LINKED) &&
			FlagSet(server->flags, SERVER_FLAG_BURSTING)) {

			RemoveFlag(server->flags, SERVER_FLAG_BURSTING);
			LOG_SNOOP(s_Snooper, "Synched with \2%s\2%s [Users: %u]", server->name, FlagSet(server->flags, SERVER_FLAG_UPLINK) ? " [Uplink]" : s_NULL, server->userCount);
		}

		burst_servers(server);
	}
}

/*********************************************************/

struct	_capab {
	
	char			*name;
	unsigned int	flag;
};
typedef struct _capab	Capab;

static void m_capab(CSTR source, const int ac, char **av) {

	static Capab	known_capabs[] = {

		{ "TS3",		CAPAB_TS3 },
		{ "NOQUIT",		CAPAB_NOQUIT },
		{ "SSJOIN",		CAPAB_SSJOIN },
		{ "BURST",		CAPAB_BURST },
		{ "UNCONNECT",		CAPAB_UNCONNECT },
		{ "ZIP",		CAPAB_ZIP },
		{ "NICKIP",		CAPAB_NICKIP },
		{ "TSMODE",		CAPAB_TSMODE },
		{ "DKEY",		CAPAB_DKEY },

		{ NULL,			CAPAB_UNKNOWN }
	};

	int		idx, capab_idx;

	if (uplink_capab != CAPAB_UNKNOWN)
		return;

	for (idx = 0; idx < ac; ++idx) {
		
		const char *capab = av[idx];

		for (capab_idx = 0; ; ++capab_idx) {
			
			if (IS_NULL(known_capabs[capab_idx].name))
				break;

			if (str_equals(capab, known_capabs[capab_idx].name))
				AddFlag(uplink_capab, known_capabs[capab_idx].flag);
		}
	}

	introduce_services_agent(NULL);
}

/*********************************************************/

Message messages[] = {
	{ "SJOIN",		0,	m_sjoin },
	{ "NICK",		0,	user_handle_NICK },
	{ "PRIVMSG",		0,	m_privmsg },
	{ "QUIT",		0,	user_handle_QUIT },
	{ "MODE",		0,	m_mode },
	{ "PART",		0,	user_handle_PART },
	{ "KICK",		0,	user_handle_KICK },
	{ "TOPIC",		0,	chan_handle_TOPIC },
	{ "JOIN",		0,	user_handle_JOIN },
	{ "WHOIS",		0,	m_whois },
	{ "KILL",		0,	user_handle_KILL },
	{ "PING",		0,	m_ping },
	{ "STATS",		0,	m_stats },
	{ "SQUIT",		0,	server_handle_SQUIT },
	{ "SERVER",		0,	server_handle_SERVER },
	{ "AWAY",		0,	NULL },
	{ "NOTICE",		0,	NULL },
	{ "401",		0,	NULL },		/* 401 NickServ nick :No such nick/channel */
	{ "402",		0,	NULL },		/* 402 services.azzurra.chat nick :No such server */
	{ "403",		0,	NULL },		/* 403 ChanServ #channel :No such channel */
	{ "441",		0,	NULL },		/* 441 services.azzurra.chat nick #channel :They aren't on that channel */
	{ "443",		0,	NULL },		/* 443 ChanServ nick #channel :is already on channel */
	{ "503",		0,	NULL },		/* 503 Message could not be delivered to nick */
	{ "SVSMODE",		0,	m_svsmode },
	{ "VERSION",		0,	m_version },
	{ "SHUN",		0,	NULL },
	{ "UNSHUN",		0,	NULL },
	{ "WALLOPS",		0,	NULL },
	{ "RAKILL",		0,	NULL },
	{ "CHATOPS",		0,	NULL },
	{ "GLOBOPS",		0,	NULL },
	{ "GNOTICE",		0,	m_gnotice },
	{ "AKILL",		0,	NULL },
	{ "SGLINE",		0,	NULL },
	{ "SILENCE",		0,	NULL },
	{ "SNOTICE",		0,	NULL },
	{ "SQLINE",		0,	NULL },
	{ "UNSGLINE",		0,	NULL },
	{ "UNSQLINE",		0,	NULL },
	{ "301",		0,	NULL },		/* 301 CybCop NICK :Away message */
	{ "436",		0,	NULL },		/* 436 NICK NICK :Nickname collision KILL */
	{ "ADMIN",		0,	m_admin },
	{ "INFO",		0,	m_info },
	{ "MOTD",		0,	m_motd },
	{ "TIME",		0,	m_time },
	{ "CAPAB",		0,	m_capab },
	{ "BURST",		0,	m_burst },
	{ "HELP",		0,	NULL },
	{ "LUSERS",		0,	NULL },
	{ "PASS",		0,	NULL },
	{ "SVINFO",		0,	NULL },
	{ "TRACE",		0,	NULL },
	{ "USERS",		0,	NULL },
	{ "GOPER",		0,	NULL },
	{ "INVITE",		0,	NULL },
	{ "SPAM",		0,	NULL },
	{ "UNSPAM",		0,	NULL },
	{ NULL }
};

/*********************************************************/

static __inline__ int message_str_compare(CSTR string1, CSTR string2) {

	register const unsigned char	*str1 = (const unsigned char *) string1;
	register const unsigned char	*str2 = (const unsigned char *) string2;
	register unsigned char			ch1, ch2;


	if (IS_NULL(str1) || IS_NULL(str2))
		return (int)(str1 - str2);

	do {
		ch1 = (unsigned char) *str1++;
		ch2 = (unsigned char) *str2++;
	} while ((ch1 != c_NULL) && (ch1 == ch2));
	return ch1 - ch2;
}

/*********************************************************/

Message *find_message(const char *name) {

	Message *m;

	for (m = messages; m->name; ++m) {

		if (message_str_compare(name, m->name) == 0)
			return m;
	}

	return NULL;
}
