/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* servers.c - Gestione servers
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/logging.h"
#include "../inc/servers.h"
#include "../inc/memory.h"
#include "../inc/send.h"
#include "../inc/conf.h"
#include "../inc/main.h"
#include "../inc/list.h"
#include "../inc/cidr.h"
#include "../inc/jupe.h"
#include "../inc/statserv.h"


/*********************************************************
 * Global variables                                      *
 *********************************************************/

Server	*server_myself = NULL;


/*********************************************************
 * Local variables                                       *
 *********************************************************/

static Server *server_list[256]; /* One for each initial character */


/*********************************************************
 * Private code                                          *
 *********************************************************/

static Server *server_create_record(CSTR hub, CSTR name, CSTR hops, CSTR desc) {

	Server *server, *branch_head;
	int branch_name;

	/* Allocate it. */
	server = mem_calloc(1, sizeof(Server));

	/* Fill it. */
	server->name = str_duplicate(name);
	server->hops = atoi(hops);
	server->desc = str_duplicate(desc);
	server->uplink = findserver(hub);		/* If hub is NULL, this will be NULL. */

	/* Link it. */
	branch_name = str_char_tolower(name[0]);
	branch_head = server_list[branch_name];

	server_list[branch_name] = server;

	server->next = branch_head;
	server->prev = NULL;

	if (IS_NOT_NULL(branch_head))
		branch_head->prev = server;

	return server;
}

/*********************************************************/

Server *findserver(CSTR name) {

	Server *server;

	/* This is likely to be called with a NULL parameter. */
	if (IS_NOT_NULL(name) && IS_NOT_EMPTY_STR(name)) {

		for (server = server_list[str_char_tolower(*name)]; server; server = server->next) {

			if (str_equals_nocase(server->name, name))
				return server;
		}
	}

	return NULL;
}

/*********************************************************/

void servers_init() {

	server_create_entry(CONF_SERVICES_NAME, CONF_SERVICES_DESC, (SERVER_FLAG_MYSELF | SERVER_FLAG_LINKED));
	server_myself = findserver(CONF_SERVICES_NAME);
}

/*********************************************************/

void server_create_entry(CSTR servername, CSTR desc, int flags) {

	Server *server;

	server = server_create_record(NULL, servername, "0", desc);

	AddFlag(server->flags, flags);
}

/*********************************************************/

static void unlink_server(Server *removed) {

	Server *server;
	int serverIdx, userCount;


	TRACE_FCLT(FACILITY_SERVERS_UNLINK_SERVER);

	for (serverIdx = FIRST_VALID_HOST_CHAR; serverIdx <= LAST_VALID_HOST_CHAR; ++serverIdx) {

		for (server = server_list[serverIdx]; server; server = server->next) {

			if (server->uplink == removed) {

				RemoveFlag(server->flags, SERVER_FLAG_LINKED);

				#ifdef ENABLE_CAPAB_NOQUIT
				if (FlagSet(uplink_capab, CAPAB_NOQUIT)) {

					userCount = user_handle_server_SQUIT(server);

					LOG_SNOOP(s_Snooper, "Lost server: \2%s\2 [Reason: Hub went down] [Users: %d]", server->name, userCount);
				}
				#else
				LOG_SNOOP(s_Snooper, "Lost server: \2%s\2 [Reason: Hub went down]", server->name);
				#endif

				if (IS_NOT_NULL(server->stats)) {

					RemoveFlag(server->stats->flags, STATS_SERVER_ONLINE);

					server->stats->squit = NOW;
					--nservers;
				}

				server->uplink = NULL;
				unlink_server(server);
			}
		}
	}
}

/*********************************************************/

void server_handle_SERVER(CSTR source, const int ac, char **av) {

	Server *server;

	ServerStats *ss;

	TRACE_FCLT(FACILITY_SERVERS_HANDLE_SERVER);

	if (ac < 3)
		return;

	/* If it's juped, squit it and reconnect ours. */
	if (jupe_match(av[0], NULL, TRUE))
		return;

	if (IS_NOT_NULL(server = findserver(av[0]))) {

		server->uplink = findserver(source);
		server->hops = atoi(av[1]);

		mem_free(server->desc);
		server->desc = str_duplicate(av[2]);
	}
	else
		server = server_create_record(source, av[0], av[1], av[2]);

	AddFlag(server->flags, SERVER_FLAG_LINKED);
	server->connected = NOW;

	if (server->hops == 1)
		AddFlag(server->flags, SERVER_FLAG_UPLINK);

	if (synched == TRUE)
		LOG_SNOOP(s_Snooper, "New server: \2%s\2 [Hub: %s]", server->name, server->uplink ? server->uplink->name : "None");

	if (IS_NOT_NULL(ss = findserverstats(av[0]))) {

		/* Don't update connect if it's us who split */
		if (synched == TRUE)
			ss->connect = NOW;
	}
	else
		ss = make_server_stats(av[0]);

	server->stats = ss;

	AddFlag(ss->flags, STATS_SERVER_ONLINE);

	++nservers;

	if (nservers > records.maxservers) {

		records.maxservers = nservers;
		records.maxservers_time = NOW;
	}

	/* To prevent clients' scan */
	AddFlag(server->flags, SERVER_FLAG_BURSTING);
}

/*********************************************************/

void server_handle_SQUIT(CSTR source, const int ac, char **av) {

	Server *server;


	TRACE_FCLT(FACILITY_SERVERS_HANDLE_SQUIT);

	if (IS_NOT_NULL(source) && IS_NOT_EMPTY_STR(source)) {

		User *user;

		if (IS_NULL(user = hash_onlineuser_find(source))) {

			log_error(FACILITY_SERVERS_HANDLE_SQUIT, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_PROPAGATED, 
				"server_handle_SQUIT() called by nonexistent user %s", source);
		}
		else {

			if (jupe_match(av[0], user, FALSE))
				return;
		}
	}

	if (IS_NULL(server = findserver(av[0]))) {

		log_error(FACILITY_SERVERS_HANDLE_SQUIT, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"servers_handle_SQUIT(): Couldn't find server %s (source: %s)", av[0], source);

		return;
	}
	else {

		RemoveFlag(server->flags, SERVER_FLAG_LINKED);
		RemoveFlag(server->flags, SERVER_FLAG_UPLINK);
	}

	if (IS_NOT_NULL(server->stats)) {

		RemoveFlag(server->stats->flags, STATS_SERVER_ONLINE);

		server->stats->squit = NOW;
		--nservers;

		++(server->stats->dailysplits);
		++(server->stats->weeklysplits);
		++(server->stats->monthlysplits);
		++(server->stats->totalsplits);
	}
	else
		log_error(FACILITY_SERVERS_HANDLE_SQUIT, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"servers_handle_SQUIT(): Couldn't find stats for server %s", av[0]);

	#ifdef ENABLE_CAPAB_NOQUIT
	/* Remove users from this server. */
	if (FlagSet(uplink_capab, CAPAB_NOQUIT)) {

		int users;

		users = user_handle_server_SQUIT(server);

		LOG_SNOOP(s_Snooper, "Lost server: \2%s\2 [Reason: %s] [Users: %d]", av[0], av[1], users);
	}
	#else
	LOG_SNOOP(s_Snooper, "Lost server: \2%s\2 [Reason: %s]", av[0], av[1]);
	#endif

	unlink_server(server);
}

/*********************************************************/

void synch_servers(void) {

	Server *server;
	int serverIdx;


	TRACE_FCLT(FACILITY_SERVERS_SYNCH_SERVERS);

	for (serverIdx = FIRST_VALID_HOST_CHAR; serverIdx <= LAST_VALID_HOST_CHAR; ++serverIdx) {

		for (server = server_list[serverIdx]; server; server = server->next) {

			if (FlagSet(server->flags, SERVER_FLAG_LINKED) && FlagSet(server->flags, SERVER_FLAG_BURSTING))
				RemoveFlag(server->flags, SERVER_FLAG_BURSTING);
		}
	}
}

/*********************************************************/

void burst_servers(Server *hub) {

	Server *server;
	int serverIdx;


	TRACE_FCLT(FACILITY_SERVERS_BURST_SERVERS);

	for (serverIdx = FIRST_VALID_HOST_CHAR; serverIdx <= LAST_VALID_HOST_CHAR; ++serverIdx) {

		for (server = server_list[serverIdx]; server; server = server->next) {

			if (server->uplink == hub) {

				RemoveFlag(server->flags, SERVER_FLAG_BURSTING);

				LOG_SNOOP(s_Snooper, "Synched with \2%s\2 [Via Hub: %s] [Users: %u]", server->name, server->uplink->name, server->userCount);

				burst_servers(server);
			}
		}
	}
}

/*********************************************************/

void servers_user_add(User *user) {

	Server *server;

	ServerStats *stats;

	TRACE_FCLT(FACILITY_SERVERS_USER_ADD);

	if (IS_NULL(user)) {

		log_error(FACILITY_SERVERS_USER_ADD, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "servers_user_add()", s_LOG_NULL, "user");

		return;
	}

	if (IS_NULL(user->server)) {

		log_error(FACILITY_SERVERS_USER_ADD, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"servers_user_add(): User %s has an empty server record", user->nick);

		return;
	}

	server = user->server;

	++(server->userCount);

	/*
	if (NOW >= server->floodResetTime) {
		server->floodHits = 0;
		server->lastFloodHits = 0;
		server->floodTime = 0;
	}
	// Increase number of connections received.
	++(server->floodHits);
	// Update the reset time.
	server->floodResetTime = (NOW + CONF_SERVER_FLOOD_RESET);
	if (server->floodHits >= CONF_SERVER_FLOOD_COUNT) {
		time_t floodDuration;
		if (server->floodTime == 0)
			server->floodTime = NOW;
		floodDuration = (NOW - server->floodTime);
		switch (floodDuration) {
			case 0:
				send_globops(s_StatServ, "Possible connect flood on server \2%s\2 [\2%d\2 new clients in \2less than %d\2 second]",
					server->name, (server->floodConnects + server->lastFloodHits), 1);
				break;
			case 1:
				send_globops(s_StatServ, "Possible connect flood on server \2%s\2 [\2%d\2 new clients in \2%d\2 second]",
					server->name, (server->floodConnects + server->lastFloodHits), 1);
				break;
			default:
				send_globops(s_StatServ, "Possible connect flood on server \2%s\2 [\2%d\2 new clients in \2%d\2 seconds]",
					server->name, (server->floodConnects + server->lastFloodHits), floodDuration);
				break;
		}
		// Keep track of all connections until the timer resets.
		server->lastFloodHits += server->floodHits;
		server->floodHits = 0;
	}
*/

	if (IS_NULL(stats = server->stats)) {

		log_error(FACILITY_SERVERS_USER_ADD, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"servers_user_add(): Server %s has an empty stats record", server->name);

		return;
	}

	++(stats->clients);
	++(stats->hits);
	++(stats->msgs);		/* NICK line */

	if (stats->clients > stats->maxclients) {

		stats->maxclients = stats->clients;
		stats->maxclients_time = NOW;
	}
}

/*********************************************************/

void servers_user_remove(User *user) {

	Server *server;

	ServerStats *stats;

	TRACE_FCLT(FACILITY_SERVERS_USER_REMOVE);

	if (IS_NULL(user)) {

		log_error(FACILITY_SERVERS_USER_REMOVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "servers_user_remove()", s_LOG_NULL, "user");

		return;
	}

	if (IS_NULL(server = user->server)) {

		log_error(FACILITY_SERVERS_USER_REMOVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"servers_user_remove(): User %s has an empty server record", user->nick);

		return;
	}

	/* Decrease this server's user count. */
	--(server->userCount);

	if (IS_NULL(stats = server->stats)) {

		log_error(FACILITY_SERVERS_USER_REMOVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"servers_user_remove(): Server %s has an empty stats record", server->name);

		return;
	}

	--(stats->clients);

	if (user_is_ircop(user))
		--(stats->opers);
}

/*********************************************************/

void servers_oper_add(User *user) {

	ServerStats *stats;


	TRACE_FCLT(FACILITY_SERVERS_OPER_ADD);

	if (IS_NULL(user)) {

		log_error(FACILITY_SERVERS_OPER_ADD, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "servers_oper_add()", s_LOG_NULL, "user");

		return;
	}

	if (IS_NULL(user->server)) {

		log_error(FACILITY_SERVERS_OPER_ADD, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"servers_oper_add(): User %s has an empty server record", user->nick);

		return;
	}

	if (IS_NULL(stats = user->server->stats)) {

		log_error(FACILITY_SERVERS_OPER_ADD, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"servers_oper_add(): Server %s has an empty stats record", user->server->name);

		return;
	}

	++(stats->opers);

	if (stats->opers > stats->maxopers) {

		stats->maxopers = stats->opers;
		stats->maxopers_time = NOW;
	}
}

/*********************************************************/

void servers_oper_remove(User *user) {

	TRACE_FCLT(FACILITY_SERVERS_OPER_REMOVE);

	if (IS_NULL(user)) {

		log_error(FACILITY_SERVERS_OPER_REMOVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "servers_oper_remove()", s_LOG_NULL, "user");

		return;
	}

	if (IS_NULL(user->server)) {

		log_error(FACILITY_SERVERS_OPER_REMOVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"servers_oper_remove(): User %s has an empty server record", user->nick);

		return;
	}

	if (IS_NULL(user->server->stats)) {

		log_error(FACILITY_SERVERS_OPER_REMOVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"servers_oper_remove(): Server %s has an empty stats record", user->server->name);

		return;
	}

	--(user->server->stats->opers);
}

/*********************************************************/

void servers_update_killcount(User *user, User *killer) {

	TRACE_FCLT(FACILITY_SERVERS_UPDATE_KILLCOUNT);

	if (IS_NULL(user)) {

		log_error(FACILITY_SERVERS_UPDATE_KILLCOUNT, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "servers_update_killcount()", s_LOG_NULL, "user");

		return;
	}

	if (IS_NULL(user->server)) {

		log_error(FACILITY_SERVERS_UPDATE_KILLCOUNT, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"servers_update_killcount(): Killed user %s has an empty server record", user->nick);

		return;
	}

	if (IS_NULL(user->server->stats)) {

		log_error(FACILITY_SERVERS_UPDATE_KILLCOUNT, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"servers_update_killcount(): Server %s has an empty stats record", user->server->name);

		return;
	}

	++(user->server->stats->servkills);

	if (IS_NOT_NULL(killer)) {

		if (IS_NULL(killer->server)) {

			log_error(FACILITY_SERVERS_UPDATE_KILLCOUNT, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
				"servers_update_killcount(): Killer user %s has an empty server record", killer->nick);

			return;
		}

		if (IS_NULL(killer->server->stats)) {

			log_error(FACILITY_SERVERS_UPDATE_KILLCOUNT, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
				"servers_update_killcount(): Server %s has an empty stats record", killer->server->name);

			return;
		}

		++(killer->server->stats->operkills);
	}
}

/*********************************************************/

void servers_increase_messages(User *user) {

	TRACE_FCLT(FACILITY_SERVERS_INCREASE_MESSAGES);

	if (IS_NULL(user)) {

		log_error(FACILITY_SERVERS_INCREASE_MESSAGES, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "servers_increase_messages()", s_LOG_NULL, "user");

		return;
	}

	if (IS_NULL(user->server)) {

		log_error(FACILITY_SERVERS_INCREASE_MESSAGES, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"servers_increase_messages(): User %s has an empty server record", user->nick);

		return;
	}

	if (user_is_services_client(user))
		return;

	if (IS_NULL(user->server->stats)) {

		log_error(FACILITY_SERVERS_INCREASE_MESSAGES, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"servers_increase_messages(): Server %s has an empty stats record", user->server->name);

		return;
	}

	++(user->server->stats->msgs);
}

/*********************************************************/

void send_servers_list(CSTR sourceNick, const User *callerUser) {

	int		serverIdx, count = 0;
	Server	*server;
	char	buffer[IRCBUFSIZE];
	size_t	len;


	TRACE_FCLT(FACILITY_SERVERS_SEND_LIST);

	send_notice_to_user(sourceNick, callerUser, "Current servers list:");
	send_notice_to_user(sourceNick, callerUser, s_SPACE);

	for (serverIdx = FIRST_VALID_HOST_CHAR; serverIdx <= LAST_VALID_HOST_CHAR; ++serverIdx) {

		for (len = 0, server = server_list[serverIdx]; server; server = server->next) {

			if (FlagUnset(server->flags, SERVER_FLAG_LINKED))
				len += str_copy_checked("Not Linked", buffer, sizeof(buffer));

			APPEND_FLAG(server->flags, SERVER_FLAG_UPLINK, "Uplink")
			APPEND_FLAG(server->flags, SERVER_FLAG_BURSTING, "Bursting")
			APPEND_FLAG(server->flags, SERVER_FLAG_SCANEXEMPT, "Scan Exempt")
			APPEND_FLAG(server->flags, SERVER_FLAG_HAVEAPM, "Has APM")

			send_notice_to_user(sourceNick, callerUser, "%d) \2%s\2 [Uplink: %s] [Status: %s]", ++count, server->name, server->uplink ? server->uplink->name : "None", (len > 0) ? buffer : "None");
		}
	}

	send_notice_to_user(sourceNick, callerUser, s_SPACE);
	send_notice_to_user(sourceNick, callerUser, "\2*** End of Servers ***\2");
}

/*********************************************************/

void handle_noop(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *servername, *param;
	Server *server;


	TRACE_FCLT(FACILITY_SERVERS_HANDLE_NOOP);

	if (IS_NULL(servername = strtok(NULL, " ")) || IS_NULL(param = strtok(NULL, " "))) {

		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2NOOP\2 servername <ON|OFF> reason");
		send_notice_to_user(data->agent->nick, callerUser, "Type \2/%s OHELP NOOP\2 for more information.", data->agent->shortNick);
	}
	else if (IS_NULL(server = findserver(servername))) {

		if (data->operMatch)
			LOG_SNOOP(data->agent->nick, "%s *N %s -- by %s (%s@%s) [Unknown Server]", data->agent->shortNick, servername, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(data->agent->nick, "%s *N %s -- by %s (%s@%s) through %s [Unknown Server]", data->agent->shortNick, servername, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_to_user(data->agent->nick, callerUser, "Server \2%s\2 does not exist.", servername);
	}
	else if (str_equals_nocase(param, "ON")) {

		User *user, *next;
		unsigned int idx;
		char *reason;

		if (callerUser->server == server) {

			send_notice_to_user(data->agent->nick, callerUser, "You cannot freeze your own O:Lines.");
			return;
		}

		send_SVSNOOP(server->name, '+');

		if (IS_NULL(reason = strtok(NULL, "")))
			reason = "Desynch";

		HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

			HASH_FOREACH_BRANCH_ITEM_SAFE(onlineuser, idx, user, next) {

				if (user_is_ircop(user) && (user->server == server))
					send_KILL(NULL, user->nick, reason, TRUE);
			}
		}

		if (data->operMatch) {

			LOG_SNOOP(data->agent->nick, "%s +N %s -- by %s (%s@%s)", data->agent->shortNick, server->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(data->agent->logID, "+N %s -- by %s (%s@%s)", server->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(data->agent->nick, "\2%s\2 froze O:Lines on server \2%s\2", source, server->name);
		}
		else {

			LOG_SNOOP(data->agent->nick, "%s +N %s -- by %s (%s@%s) through %s", data->agent->shortNick, server->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(data->agent->logID, "+N %s -- by %s (%s@%s) through %s", server->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) froze O:Lines on server \2%s\2", source, data->operName, server->name);
		}

		send_notice_to_user(data->agent->nick, callerUser, "O:Lines on \2%s\2 have been frozen.", server->name);
	}
	else if (str_equals_nocase(param, "OFF")) {

		send_SVSNOOP(server->name, '-');

		if (data->operMatch) {

			LOG_SNOOP(data->agent->nick, "%s -N %s -- by %s (%s@%s)", data->agent->shortNick, server->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(data->agent->logID, "-N %s -- by %s (%s@%s)", server->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(data->agent->nick, "\2%s\2 unfroze O:Lines on server \2%s\2", source, server->name);
		}
		else {

			LOG_SNOOP(data->agent->nick, "%s -N %s -- by %s (%s@%s) through %s", data->agent->shortNick, server->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(data->agent->logID, "-N %s -- by %s (%s@%s) through %s", server->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) unfroze O:lines on server \2%s\2", source, data->operName, server->name);
		}

		send_notice_to_user(data->agent->nick, callerUser, "O:Lines on \2%s\2 have been unfrozen.", server->name);
	}
	else {

		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2NOOP\2 servername <ON|OFF> reason");
		send_notice_to_user(data->agent->nick, callerUser, "Type \2/%s OHELP NOOP\2 for more information.", data->agent->shortNick);
	}
}

/*********************************************************/

void server_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	STR		value = strtok(request, s_SPACE);
	STR		what = strtok(NULL, s_SPACE);
	BOOL	needSyntax = FALSE;
	Server	*server;


	TRACE_FCLT(FACILITY_SERVERS_DUMP);

	if (IS_NOT_NULL(value)) {

		if (IS_NULL(what)) {

			server = findserver(value);

			if (IS_NULL(server))
				send_notice_to_user(sourceNick, callerUser, "DUMP: Server \2%s\2 not found.", value);

			else {

				send_notice_to_user(sourceNick, callerUser, "DUMP: Server \2%s\2", value);

				send_notice_to_user(sourceNick, callerUser, "Address 0x%08X, size %d B",						(unsigned long)server, sizeof(Server) + str_len(server->name) + str_len(server->desc) + 2);
				send_notice_to_user(sourceNick, callerUser, "Name: 0x%08X \2[\2%s\2]\2",						(unsigned long)server->name, str_get_valid_display_value(server->name));
				send_notice_to_user(sourceNick, callerUser, "Desc: 0x%08X \2[\2%s\2]\2",						(unsigned long)server->desc, str_get_valid_display_value(server->desc));
				send_notice_to_user(sourceNick, callerUser, "Uplink: 0x%08X \2[\2%s\2]\2",						(unsigned long)server->uplink, str_get_valid_display_value(server->uplink->name));
				send_notice_to_user(sourceNick, callerUser, "Hops: %u",											server->hops);
				send_notice_to_user(sourceNick, callerUser, "Users: %u",										server->userCount);
				send_notice_to_user(sourceNick, callerUser, "Connected C-time: %ld",							server->connected);
				send_notice_to_user(sourceNick, callerUser, "Flags: %ld",										server->flags);
				send_notice_to_user(sourceNick, callerUser, "Stats: 0x%08X",									(unsigned long)server->stats);
				send_notice_to_user(sourceNick, callerUser, "Next / previous record: 0x%08X / 0x%08X",			(unsigned long)server->next, (unsigned long)server->prev);

				LOG_DEBUG_SNOOP("Command: DUMP SERVER %s -- by %s (%s@%s)", value, callerUser->nick, callerUser->username, callerUser->host);
			}
		}
		else if (str_equals_nocase(what, "USERS")) {

			server = findserver(value);

			if (IS_NULL(server))
				send_notice_to_user(sourceNick, callerUser, "DUMP: Server \2%s\2 not found.", value);

			else {

				int idx, count = 0;
				User *user;

				HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {
					HASH_FOREACH_BRANCH_ITEM(onlineuser, idx, user) {

						if (user->server == server)
							send_notice_to_user(sourceNick, callerUser, "%d) %s [idx: %d]", ++count, user->nick, idx);
					}
				}

				send_notice_to_user(sourceNick, callerUser, "End of search. Users found: %d", count);

				LOG_DEBUG_SNOOP("Command: DUMP SERVER %s -- by %s (%s@%s) [USERS]", value, callerUser->nick, callerUser->username, callerUser->host);
			}
		}
		else
			needSyntax = TRUE;
	}
	else
		needSyntax = TRUE;

	if (needSyntax)
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 SERVER servername [users]");
}

/*********************************************************/

unsigned long server_mem_report(CSTR sourceNick, const User *callerUser) {

	unsigned long count = 0, mem = 0;
	int idx;
	Server *server;


	TRACE_FCLT(FACILITY_SERVERS_MEM_REPORT);

	for (idx = FIRST_VALID_HOST_CHAR; idx <= LAST_VALID_HOST_CHAR; ++idx) {

		for (server = server_list[idx]; server; server = server->next) {

			++count;
			mem += sizeof(Server);

			TRACE();

			if (IS_NOT_NULL(server->name))
				mem += str_len(server->name) + 1;

			if (IS_NOT_NULL(server->desc))
				mem += str_len(server->desc) + 1;
		}
	}

	send_notice_to_user(sourceNick, callerUser, "Server list: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", count, mem / 1024, mem);
	return mem;
}
