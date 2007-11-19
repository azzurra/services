/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* rootserv.c - Service Roots services
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
#include "../inc/regions.h"
#include "../inc/logging.h"
#include "../inc/memory.h"
#include "../inc/send.h"
#include "../inc/conf.h"
#include "../inc/memoserv.h"
#include "../inc/helpserv.h"
#include "../inc/rootserv.h"
#include "../inc/misc.h"
#include "../inc/main.h"
#include "../inc/spam.h"
#include "../inc/crypt_userhost.h"
#include "../inc/storage.h"


#ifdef USE_SERVICES

/*********************************************************
 * Local and global variables                            *
 *********************************************************/

/* List of server bots. */
Access *serverBotList;
int serverBotListLoadComplete;

/* Struct holding dynamic configuration variables. */
dynConfig dynConf;

/* Stuff to pass to the command handler. */
static Agent a_RootServ;


/*********************************************************
 * Prototypes                                            *
 *********************************************************/

static BOOL dynconf_db_load(void);
static BOOL dynconf_db_save(void);
static void dynconf_mem_free(void);

static void do_bot(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_dynconf(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_floodreset(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_inject(CSTR source, User *callerUser, ServiceCommandData *data);


/*********************************************************
 * Initialization/termination routines                   *
 *********************************************************/

void rootserv_init(void) {

	/* Initialize this struct. */
	a_RootServ.nick = s_RootServ;
	a_RootServ.shortNick = s_RS;
	a_RootServ.agentID = AGENTID_ROOTSERV;
	a_RootServ.logID = logid_from_agentid(AGENTID_ROOTSERV);
}

void rootserv_terminate(void) {

	free_access_list(serverBotList, &serverBotListLoadComplete);
	dynconf_mem_free();
}

static void dynconf_mem_free(void) {

	TRACE_FCLT(FACILITY_ROOTSERV_DYNCONF_MEM_FREE);

	if (dynConf.welcomeNotice)
		mem_free(dynConf.welcomeNotice);
}


/*********************************************************
 * Command handler                                       *
 *********************************************************/

// 'A' (65 / 0)
// 'B' (66 / 1)
static ServiceCommand	rootserv_commands_B[] = {
	{ "BOT",		ULEVEL_SRA,		0, do_bot },
	{ NULL,			0,				0, NULL }
};
// 'C' (67 / 2)
static ServiceCommand	rootserv_commands_C[] = {
	{ "CONF",		ULEVEL_SRA,		0, do_dynconf },
	{ "CRYPTKEY",	ULEVEL_SRA,		0, handle_cryptkey },
	{ NULL,			0,				0, NULL }
};
// 'D' (68 / 3)
// 'E' (69 / 4)
// 'F' (70 / 5)
static ServiceCommand	rootserv_commands_F[] = {
	{ "FLOODRESET",	ULEVEL_SRA,		0, do_floodreset },
	{ NULL,			0,				0, NULL }
};
// 'G' (71 / 6)
// 'H' (72 / 7)
// 'I' (73 / 8)
static ServiceCommand	rootserv_commands_I[] = {
	{ "INJECT",		ULEVEL_SRA,		0, do_inject },
	{ NULL,			0,				0, NULL }
};
// 'J' (74 / 9)
// 'K' (75 / 10)
// 'L' (76 / 11)
static ServiceCommand	rootserv_commands_L[] = {
	{ "LANG",		ULEVEL_SRA,		0, handle_lang },
	{ NULL,			0,				0, NULL }
};
// 'M' (77 / 12)
static ServiceCommand	rootserv_commands_M[] = {
	{ "MODE",		ULEVEL_SRA,		0, handle_mode },
	{ NULL,			0,				0, NULL }
};
// 'N' (78 / 13)
static ServiceCommand	rootserv_commands_N[] = {
	{ "NOOP",		ULEVEL_SRA,		0, handle_noop },
	{ NULL,			0,				0, NULL }
};
// 'O' (79 / 14)
static ServiceCommand	rootserv_commands_O[] = {
	{ "OHELP",		ULEVEL_SRA,		0, handle_help },
	{ NULL,			0,				0, NULL }
};
// 'P' (80 / 15)
// 'Q' (81 / 16)
static ServiceCommand	rootserv_commands_Q[] = {
	{ "QUIT",		ULEVEL_SRA,		0, handle_quit },
	{ NULL,			0,				0, NULL }
};
// 'R' (82 / 17)
static ServiceCommand	rootserv_commands_R[] = {
	{ "REHASH",		ULEVEL_SRA,		0, handle_rehash },
	{ "RESTART",	ULEVEL_SRA,		0, handle_restart },
	{ "REGIONS",	ULEVEL_SRA,		0, handle_regions },
	{ NULL,			0,				0, NULL }
};
// 'S' (83 / 18)
static ServiceCommand	rootserv_commands_S[] = {
	{ "SEARCH",		ULEVEL_SRA,		0, handle_search },
	{ "SET",		ULEVEL_SRA,		0, handle_set },
	{ "SHUTDOWN",	ULEVEL_SRA,		0, handle_shutdown },
	{ "SPAM",		ULEVEL_SRA,		0, handle_spam },
	{ NULL,			0,				0, NULL }
};
// 'T' (84 / 19)
// 'U' (85 / 20)
// 'V' (86 / 21)
// 'W' (87 / 22)
// 'X' (88 / 23)
// 'Y' (89 / 24)
// 'Z' (90 / 25)

ServiceCommand	*rootserv_commands[26] = {
	NULL,					rootserv_commands_B,
	rootserv_commands_C,	NULL,
	NULL,					rootserv_commands_F,
	NULL,					NULL,
	rootserv_commands_I,	NULL,
	NULL,					rootserv_commands_L,
	rootserv_commands_M,	rootserv_commands_N,
	rootserv_commands_O,	NULL,
	rootserv_commands_Q,	rootserv_commands_R,
	rootserv_commands_S,	NULL,
	NULL,					NULL,
	NULL,					NULL,
	NULL,					NULL
};


/*********************************************************
 * Main routine                                          *
 *********************************************************/

void rootserv(CSTR source, User *callerUser, char *buf) {

	char *command;


	TRACE_MAIN_FCLT(FACILITY_ROOTSERV);

	if (IS_NULL(callerUser->oper) || (callerUser->oper->level < ULEVEL_SRA)) {

		LOG_SNOOP(s_RootServ, "\2%s\2 tried sending the following command: %s", source, buf);
		return;
	}

	command = strtok(buf, " ");

	if (IS_NULL(command))
		send_notice_to_user(s_RootServ, callerUser, "Type \2/rs OHELP\2 for a listing of RootServ commands.");

	else if (command[0] == '\001') {

		++command;

		if (IS_EMPTY_STR(command))
			LOG_SNOOP(s_RootServ, "Invalid CTCP from \2%s\2", source);

		else {

			char *action;


			if (IS_NOT_NULL(action = strtok(NULL, ""))) {

				action[str_len(action) - 1] = '\0';
				LOG_SNOOP(s_RootServ, "CTCP: %s %s from \2%s\2", command, action, source);
			}
			else {

				command[str_len(command) - 1] = '\0';
				LOG_SNOOP(s_RootServ, "CTCP: %s from \2%s\2", command, source);
			}
		}
	}
	else
		oper_invoke_agent_command(command, rootserv_commands, callerUser, &a_RootServ);
}


/*********************************************************
 * Database load/save routines                           *
 *********************************************************/

void rootserv_db_load(void) {

	access_db_load(&serverBotList, SERVERBOT_DB, &serverBotListLoadComplete);
	dynconf_db_load();
}

void rootserv_db_save(void) {

	access_db_save(serverBotList, SERVERBOT_DB, serverBotListLoadComplete);
	dynconf_db_save();
}

static BOOL dynconf_db_load(void) {

	STGHANDLE	stg = 0;
	STG_RESULT	result;


	TRACE_MAIN_FCLT(FACILITY_ROOTSERV_DYNCONF_DB_LOAD);

	result = stg_open(DYNCONF_DB, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version;


			version = stg_data_version(stg);

			switch (version) {

				case DYNCONF_DB_CURRENT_VERSION: {

					// start-of-section marker
					result = stg_read_record(stg, NULL, 0);

					if (result == stgBeginOfSection) {

						result = stg_read_record(stg, (PBYTE)&dynConf, sizeof(dynConfig));

						if (result != stgSuccess)
							fatal_error(FACILITY_ROOTSERV_DYNCONF_DB_LOAD, __LINE__, "Read error on %s - %s", DYNCONF_DB, stg_result_to_string(result));

						if (IS_NOT_NULL(dynConf.welcomeNotice)) {

							result = stg_read_string(stg, &(dynConf.welcomeNotice), NULL);

							if (result != stgSuccess)
								fatal_error(FACILITY_ROOTSERV_DYNCONF_DB_LOAD, __LINE__, "Read error (2) on %s - %s", DYNCONF_DB, stg_result_to_string(result));
						}

						result = stg_read_record(stg, NULL, 0);

						if (result != stgEndOfSection)
							fatal_error(FACILITY_ROOTSERV_DYNCONF_DB_LOAD, __LINE__, "Read error (3) on %s - %s", DYNCONF_DB, stg_result_to_string(result));
					}
					else
						fatal_error(FACILITY_ROOTSERV_DYNCONF_DB_LOAD, __LINE__, "Read error on %s : invalid format", DYNCONF_DB);

					stg_close(stg, DYNCONF_DB);
					return TRUE;
				}

				default:
					fatal_error(FACILITY_ROOTSERV_DYNCONF_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, DYNCONF_DB);
			}
		}

		case stgNotFound: // no data to load
			return TRUE;

		default: // error!
			stg_close(stg, DYNCONF_DB);

			fatal_error(FACILITY_ROOTSERV_DYNCONF_DB_LOAD, __LINE__, "Error opening %s - %s", DYNCONF_DB, stg_result_to_string(result));
			return FALSE;
	}
}

static BOOL dynconf_db_save(void) {

	STGHANDLE	stg;
	STG_RESULT	result;


	TRACE_FCLT(FACILITY_ROOTSERV_DYNCONF_DB_SAVE);

	result = stg_create(DYNCONF_DB, SF_NOFLAGS, ACCESS_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_ROOTSERV_DYNCONF_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"rootserv_dynconf_db_save(): Could not create database file %s: %s [Error %d: %s]", DYNCONF_DB, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	result = stg_start_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_ROOTSERV_DYNCONF_DB_SAVE, __LINE__, "Write error on %s - %s", DYNCONF_DB, stg_result_to_string(result));

	result = stg_write_record(stg, (PBYTE)&dynConf, sizeof(dynConfig));

	if (result != stgSuccess)
		fatal_error(FACILITY_ROOTSERV_DYNCONF_DB_SAVE, __LINE__, "Write error on %s - %s", DYNCONF_DB, stg_result_to_string(result));

	if (IS_NOT_NULL(dynConf.welcomeNotice))
		result = stg_write_string(stg, dynConf.welcomeNotice);

	result = stg_end_section(stg);

	if (result != stgSuccess)
		fatal_error(FACILITY_ROOTSERV_DYNCONF_DB_SAVE, __LINE__, "Write error on %s - %s", DYNCONF_DB, stg_result_to_string(result));

	stg_close(stg, DYNCONF_DB);
	return TRUE;
}


/*********************************************************
 * Command routines                                      *
 *********************************************************/

static void do_floodreset(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *nick;
	User *user;


	TRACE_MAIN_FCLT(FACILITY_ROOTSERV_HANDLE_FLOODRESET);

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_to_user(s_RootServ, callerUser, "Syntax: \2FLOODRESET\2 nick");
		send_notice_to_user(s_RootServ, callerUser, "Type \2/rs OHELP FLOODRESET\2 for more information.");
	}
	else if (IS_NULL(user = hash_onlineuser_find(nick))) {

		TRACE_MAIN();
		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "RS *F %s -- by %s (%s@%s) [Not Online]", nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "RS *F %s -- by %s (%s@%s) through %s [Not Online]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_to_user(s_RootServ, callerUser, "User \2%s\2 is not online.", nick);
	}
	else {

		user->flood_msg_count = 0;
		user->flood_current_level = FLOOD_LEVEL_0;

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "RS F %s -- by %s (%s@%s)", user->nick, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_ROOTSERV, "F %s -- by %s (%s@%s)", user->nick, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_RootServ, "\2%s\2 reset flood levels for nickname \2%s\2", source, user->nick);
		}
		else {

			LOG_SNOOP(s_OperServ, "RS F %s -- by %s (%s@%s) through %s", user->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_ROOTSERV, "F %s -- by %s (%s@%s) through %s", user->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_RootServ, "\2%s\2 (through \2%s\2) reset flood levels for nickname \2%s\2", source, data->operName, user->nick);
		}

		send_notice_to_user(s_RootServ, callerUser, "Flood levels for \2%s\2 have been reset.", user->nick);
	}
}

/*********************************************************/

static void do_inject(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *nick, *service, *command;
	User *target;


	TRACE_MAIN_FCLT(FACILITY_ROOTSERV_HANDLE_INJECT);

	if (IS_NULL(nick = strtok(NULL, " ")) || IS_NULL(service = strtok(NULL, " ")) || IS_NULL(command = strtok(NULL, ""))) {

		send_notice_to_user(s_RootServ, callerUser, "Syntax: \2INJECT\2 nick service command");
		send_notice_to_user(s_RootServ, callerUser, "Type \2/%s OHELP INJECT\2 for more information.", data->agent->shortNick);
	}
	else if (IS_NULL(target = hash_onlineuser_find(nick))) {

		TRACE_MAIN();
		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "RS *I %s -- by %s (%s@%s) [Not Online]", nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "RS *I %s -- by %s (%s@%s) through %s [Not Online]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_to_user(s_RootServ, callerUser, "User \2%s\2 is not online.", nick);
	}
	else if (is_services_valid_oper(target)) {

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "RS *I %s -- by %s (%s@%s) [Valid Oper]", nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "RS *I %s -- by %s (%s@%s) through %s [Valid Oper]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		send_notice_to_user(s_RootServ, callerUser, "Permission denied.");
	}
	else if (str_equals_nocase(service, s_NickServ)) {

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "RS I %s -- by %s (%s@%s) [NS: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, command);
			log_services(LOG_SERVICES_ROOTSERV, "I %s -- by %s (%s@%s) [NS: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, command);

			send_globops(s_RootServ, "\2%s\2 forced \2%s\2 to perform the following command to \2%s\2: %s", source, nick, s_NickServ, command);
		}
		else {

			LOG_SNOOP(s_OperServ, "RS I %s -- by %s (%s@%s) through %s [NS: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, command);
			log_services(LOG_SERVICES_ROOTSERV, "I %s -- by %s (%s@%s) through %s [NS: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, command);

			send_globops(s_RootServ, "\2%s\2 (through \2%s\2) forced \2%s\2 to perform the following command to \2%s\2: %s", source, data->operName, nick, s_NickServ, command);
		}

		send_notice_to_user(s_RootServ, callerUser, "Successfully forced user \2%s\2.", nick);

		TRACE_MAIN();
		nickserv(nick, target, command);
		TRACE_MAIN();
	}
	else if (str_equals_nocase(service, s_ChanServ)) {

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "RS I %s -- by %s (%s@%s) [CS: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, command);
			log_services(LOG_SERVICES_ROOTSERV, "I %s -- by %s (%s@%s) [CS: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, command);

			send_globops(s_RootServ, "\2%s\2 forced \2%s\2 to perform the following command to \2%s\2: %s", source, nick, s_ChanServ, command);
		}
		else {

			LOG_SNOOP(s_OperServ, "RS I %s -- by %s (%s@%s) through %s [CS: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, command);
			log_services(LOG_SERVICES_ROOTSERV, "I %s -- by %s (%s@%s) through %s [CS: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, command);

			send_globops(s_RootServ, "\2%s\2 (through \2%s\2) forced \2%s\2 to perform the following command to \2%s\2: %s", source, data->operName, nick, s_ChanServ, command);
		}

		send_notice_to_user(s_RootServ, callerUser, "Successfully forced user \2%s\2.", nick);

		TRACE_MAIN();
		chanserv(nick, target, command);
		TRACE_MAIN();
	}
	else if (str_equals_nocase(service, s_MemoServ)) {

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "RS I %s -- by %s (%s@%s) [MS: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, command);
			log_services(LOG_SERVICES_ROOTSERV, "I %s -- by %s (%s@%s) [MS: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, command);

			send_globops(s_RootServ, "\2%s\2 forced \2%s\2 to perform the following command to \2%s\2: %s", source, nick, s_MemoServ, command);
		}
		else {

			LOG_SNOOP(s_OperServ, "RS I %s -- by %s (%s@%s) through %s [MS: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, command);
			log_services(LOG_SERVICES_ROOTSERV, "I %s -- by %s (%s@%s) through %s [MS: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, command);

			send_globops(s_RootServ, "\2%s\2 (through \2%s\2) forced \2%s\2 to perform the following command to \2%s\2: %s", source, data->operName, nick, s_MemoServ, command);
		}

		send_notice_to_user(s_RootServ, callerUser, "Successfully forced user \2%s\2.", nick);

		TRACE_MAIN();
		memoserv(nick, target, command);
		TRACE_MAIN();
	}
	else if (str_equals_nocase(service, s_RootServ) || str_equals_nocase(service, s_OperServ)) {

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "RS *I %s -- by %s (%s@%s) [%s: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, service, command);
			log_services(LOG_SERVICES_ROOTSERV, "*I %s -- by %s (%s@%s) [%s: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, service, command);
		}
		else {

			LOG_SNOOP(s_OperServ, "RS *I %s -- by %s (%s@%s) through %s [RS: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, command);
			log_services(LOG_SERVICES_ROOTSERV, "*I %s -- by %s (%s@%s) through %s [RS: %s]", nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, command);
		}

		send_notice_to_user(s_RootServ, callerUser, "You cannot force \2%s\2 commands.", s_RootServ);
	}
	else {

		send_notice_to_user(s_RootServ, callerUser, "Syntax: \2INJECT\2 nick service command");
		send_notice_to_user(s_RootServ, callerUser, "Type \2/%s OHELP INJECT\2 for more information.", data->agent->shortNick);
	}
}

/*********************************************************/

static void do_bot(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *command;
	Access *bot;


	TRACE_MAIN_FCLT(FACILITY_ROOTSERV_HANDLE_BOT);

	if (IS_NULL(command = strtok(NULL, " "))) {

		send_notice_to_user(s_RootServ, callerUser, "Syntax: \2BOT\2 [ADD|DEL|SET|LIST|INFO] nick [value]");
		send_notice_to_user(s_RootServ, callerUser, "Type \2/rs OHELP BOT\2 for more information.");
	}
	else if (str_equals_nocase(command, "ADD")) {

		char *botnick;


		if (IS_NOT_NULL(botnick = strtok(NULL, " "))) {

			NickInfo *ni;


			if (IS_NULL(ni = findnick(botnick))) {

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "RS +B* %s -- by %s (%s@%s) [Not Registered]", botnick, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(s_OperServ, "RS +B* %s -- by %s (%s@%s) through %s [Not Registered]", botnick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_notice_to_user(s_RootServ, callerUser, "Nickname \2%s\2 is not registered.", botnick);
				return;
			}

			bot = find_access(serverBotList, botnick);

			if (IS_NOT_NULL(bot)) {

				TRACE_MAIN();
				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "RS +B* %s -- by %s (%s@%s) [Already a Bot]", botnick, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(s_OperServ, "RS +B* %s -- by %s (%s@%s) through %s [Already a Bot]", botnick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_notice_to_user(s_RootServ, callerUser, "Nickname \2%s\2 is already on the Bot list.", botnick);
				return;
			}

			access_add(&serverBotList, ni->nick, data->operName);

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "RS +B %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_ROOTSERV, "+B %s -- by %s (%s@%s)", ni->nick, callerUser->nick, callerUser->username, callerUser->host);

				send_globops(s_RootServ, "\2%s\2 added \2%s\2 to the Services Bot list", source, ni->nick);
			}
			else {

				LOG_SNOOP(s_OperServ, "RS +B %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_ROOTSERV, "+B %s -- by %s (%s@%s) through %s", ni->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_globops(s_RootServ, "\2%s\2 (through \2%s\2) added \2%s\2 to the Services Bot list", source, data->operName, ni->nick);
			}

			send_notice_to_user(s_RootServ, callerUser, "Bot \2%s\2 has been successfully added to the Bot list.", ni->nick);

			TRACE_MAIN();
			if (serverBotListLoadComplete != 1)
				send_notice_to_user(s_RootServ, callerUser, "\2Warning:\2 Not all bots on the list have been loaded at startup. Changes will \2NOT\2 be saved.");
		}
		else
			send_notice_to_user(s_RootServ, callerUser, "Syntax: \2BOT ADD\2 nick");
	}
	else if (str_equals_nocase(command, "DEL")) {

		char *botnick;


		if (IS_NOT_NULL(botnick = strtok(NULL, " "))) {

			char removed[NICKSIZE];


			memset(removed, 0, NICKSIZE);

			access_remove(&serverBotList, botnick, removed);

			if (*removed) {

				if (data->operMatch) {

					LOG_SNOOP(s_OperServ, "RS -B %s -- by %s (%s@%s)", removed, callerUser->nick, callerUser->username, callerUser->host);
					log_services(LOG_SERVICES_ROOTSERV, "-B %s -- by %s (%s@%s)", removed, callerUser->nick, callerUser->username, callerUser->host);

					send_globops(s_RootServ, "\2%s\2 removed \2%s\2 from the Services Bot list", source, removed);
				}
				else {

					LOG_SNOOP(s_OperServ, "RS -B %s -- by %s (%s@%s) through %s", removed, callerUser->nick, callerUser->username, callerUser->host, data->operName);
					log_services(LOG_SERVICES_ROOTSERV, "-B %s -- by %s (%s@%s) through %s", removed, callerUser->nick, callerUser->username, callerUser->host, data->operName);

					send_globops(s_RootServ, "\2%s\2 (through \2%s\2) removed \2%s\2 from the Services Bot list", source, data->operName, removed);
				}

				send_notice_to_user(s_RootServ, callerUser, "Bot \2%s\2 has been removed.", removed);

				if (serverBotListLoadComplete != 1)
					send_notice_to_user(s_RootServ, callerUser, "\2Warning:\2 Not all bots on the list have been loaded at startup. Changes will \2NOT\2 be saved.");
			}
			else {

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "RS -B* %s -- by %s (%s@%s) [Not Found]", botnick, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(s_OperServ, "RS -B* %s -- by %s (%s@%s) through %s [Not Found]", botnick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_notice_to_user(s_RootServ, callerUser, "Bot \2%s\2 was not found on the list.", botnick);
			}
		}
		else {

			send_notice_to_user(s_RootServ, callerUser, "Syntax: \2BOT DEL\2 nick");
			send_notice_to_user(s_RootServ, callerUser, "Type \2/rs OHELP BOT\2 for more information.");
		}
	}
	else if (str_equals_nocase(command, "SET")) {

		char *botnick, *opt, *val;


		if (IS_NOT_NULL(botnick = strtok(NULL, " ")) && IS_NOT_NULL(opt = strtok(NULL, " ")) &&
			IS_NOT_NULL(val = strtok(NULL, " "))) {

			if (IS_NOT_NULL(bot = find_access(serverBotList, botnick))) {

				if (str_equals_nocase(opt, "USER")) {

					if (!validate_username(val, TRUE)) {

						send_notice_to_user(s_RootServ, callerUser, "Invalid username.");
						return;
					}

					if (bot->user) {

						TRACE_MAIN();
						if (data->operMatch) {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) [User: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, bot->user, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) [User: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, bot->user, val);
						}
						else {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) through %s [User: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, bot->user, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) through %s [User: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, bot->user, val);
						}

						send_notice_to_user(s_RootServ, callerUser, "\2USER\2 field of Bot \2%s\2 has been changed from \2%s\2 to \2%s\2.", bot->nick, bot->user, val);
						mem_free(bot->user);
					}
					else {

						if (data->operMatch) {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) [User: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) [User: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, val);
						}
						else {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) through %s [User: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) through %s [User: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, val);
						}

						send_notice_to_user(s_RootServ, callerUser, "\2USER\2 field of Bot \2%s\2 has been set to \2%s\2.",	bot->nick, val);
					}

					TRACE_MAIN();
					bot->user = str_duplicate(val);
					bot->lastUpdate = NOW;
				}
				else if (str_equals_nocase(opt, "HOST")) {

					if (!validate_host(val, TRUE, FALSE, FALSE)) {

						send_notice_to_user(s_RootServ, callerUser, "Invalid host.");
						return;
					}

					if (IS_NOT_NULL(bot->host)) {

						TRACE_MAIN();
						if (data->operMatch) {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) [Host: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, bot->host, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) [Host: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, bot->host, val);
						}
						else {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) through %s [Host: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, bot->host, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) through %s [Host: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, bot->host, val);
						}

						send_notice_to_user(s_RootServ, callerUser, "\2HOST\2 field of Bot \2%s\2 has been changed from \2%s\2 to \2%s\2.", bot->nick, bot->host, val);
						mem_free(bot->host);
					}
					else {

						if (data->operMatch) {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) [Host: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) [User: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, val);
						}
						else {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) through %s [Host: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) through %s [User: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, val);
						}

						send_notice_to_user(s_RootServ, callerUser, "\2HOST\2 field of Bot \2%s\2 has been set to \2%s\2.", bot->nick, val);
					}

					TRACE_MAIN();
					bot->host = str_duplicate(val);
					bot->lastUpdate = NOW;
				}
				else if (str_equals_nocase(opt, "HOST2")) {

					if (!validate_host(val, TRUE, FALSE, FALSE)) {

						send_notice_to_user(s_RootServ, callerUser, "Invalid host.");
						return;
					}

					if (IS_NOT_NULL(bot->host2)) {

						TRACE_MAIN();
						if (data->operMatch) {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) [Host2: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, bot->host2, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) [Host2: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, bot->host2, val);
						}
						else {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) through %s [Host2: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, bot->host2, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) through %s [Host2: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, bot->host2, val);
						}

						send_notice_to_user(s_RootServ, callerUser, "\2HOST2\2 field of Bot \2%s\2 has been changed from \2%s\2 to \2%s\2.", bot->nick, bot->host2, val);
						mem_free(bot->host2);
					}
					else {

						if (data->operMatch) {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) [User: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) [User: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, val);
						}
						else {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) through %s [User: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) through %s [User: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, val);
						}

						send_notice_to_user(s_RootServ, callerUser, "\2HOST2\2 field of Bot \2%s\2 has been set to \2%s\2.", bot->nick, val);
					}

					TRACE_MAIN();
					bot->host2 = str_duplicate(val);
					bot->lastUpdate = NOW;
				}
				else if (str_equals_nocase(opt, "SERVER")) {

					if (!validate_host(val, TRUE, FALSE, FALSE)) {

						send_notice_to_user(s_RootServ, callerUser, "Invalid server.");
						return;
					}

					if (IS_NOT_NULL(bot->server)) {

						TRACE_MAIN();
						if (data->operMatch) {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) [Server: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, bot->server, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) [User: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, bot->server, val);
						}
						else {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) through %s [Server: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, bot->server, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) through %s [User: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, bot->server, val);

						}

						send_notice_to_user(s_RootServ, callerUser, "\2SERVER\2 field of Bot \2%s\2 has been changed from \2%s\2 to \2%s\2.", bot->nick, bot->server, val);
						mem_free(bot->server);
					}
					else {

						if (data->operMatch) {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) [Server: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) [User: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, val);
						}
						else {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) through %s [Server: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) through %s [User: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, val);
						}

						send_notice_to_user(s_RootServ, callerUser, "\2SERVER\2 field of Bot \2%s\2 has been set to \2%s\2.", bot->nick, val);
					}

					TRACE_MAIN();
					bot->server = str_duplicate(val);
					bot->lastUpdate = NOW;
				}
				else if (str_equals_nocase(opt, "SERVER2")) {

					if (!validate_host(val, TRUE, FALSE, FALSE)) {

						send_notice_to_user(s_RootServ, callerUser, "Invalid server.");
						return;
					}

					if (IS_NOT_NULL(bot->server2)) {

						TRACE_MAIN();
						if (data->operMatch) {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) [Server2: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, bot->server2, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) [User: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, bot->server2, val);
						}
						else {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) through %s [Server2: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, bot->server2, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) through %s [User: %s -> %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, bot->server2, val);
						}

						send_notice_to_user(s_RootServ, callerUser, "\2SERVER2\2 field of Bot \2%s\2 has been changed from \2%s\2 to \2%s\2.", bot->nick, bot->server2, val);
						mem_free(bot->server2);
					}
					else {

						if (data->operMatch) {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) [Server2: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) [Server2: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, val);
						}
						else {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) through %s [Server2: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, val);
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) through %s [Server2: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, val);
						}

						send_notice_to_user(s_RootServ, callerUser, "\2SERVER2\2 field of Bot \2%s\2 has been set to \2%s\2.", bot->nick, val);
					}
					
					TRACE_MAIN();
					bot->server2 = str_duplicate(val);
					bot->lastUpdate = NOW;
				}
				else if (str_equals_nocase(opt, "ENABLED")) {

					int enable;

					TRACE_MAIN();
					if (str_equals_nocase(val, "YES")) {

						if (IS_NULL(bot->user) || IS_NULL(bot->host) || IS_NULL(bot->server)) {

							if (data->operMatch)
								LOG_SNOOP(s_OperServ, "RS *B %s -- by %s (%s@%s) [Not Configured]", bot->nick, callerUser->nick, callerUser->username, callerUser->host);
							else

								LOG_SNOOP(s_OperServ, "RS *B %s -- by %s (%s@%s) through %s [Not Configured]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

							send_notice_to_user(s_RootServ, callerUser, "The bot is not properly configured and cannot be enabled.");
							return;
						}
						enable = 1;
					}
					else if (str_equals_nocase(val, "NO"))
						enable = 0;

					else {

						send_notice_to_user(s_RootServ, callerUser, "Syntax: \2BOT SET\2 ENABLED [YES|NO]");
						send_notice_to_user(s_RootServ, callerUser, "Type \2/rs OHELP BOT\2 for more information.");
						return;
					}

					if ((enable == 1 && FlagSet(bot->flags, AC_FLAG_ENABLED)) ||
						(enable == 0 && FlagUnset(bot->flags, AC_FLAG_ENABLED))) {

						TRACE_MAIN();
						if (data->operMatch)
							LOG_SNOOP(s_OperServ, "RS *B %s -- by %s (%s@%s) [Already %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, enable ? "Enabled" : "Disabled");
						else
							LOG_SNOOP(s_OperServ, "RS *B %s -- by %s (%s@%s) through %s [Already %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, enable ? "Enabled" : "Disabled");

						send_notice_to_user(s_RootServ, callerUser, "Bot \2%s\2 is already \2%s\2.", bot->nick, enable ? "enabled" : "disabled");
					}
					else {

						TRACE_MAIN();

						if (enable)
							AddFlag(bot->flags, AC_FLAG_ENABLED);
						else
							RemoveFlag(bot->flags, AC_FLAG_ENABLED);

						bot->lastUpdate = NOW;

						if (data->operMatch) {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) [%s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, enable ? "Enabled" : "Disabled");
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) [%s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, enable ? "Enabled" : "Disabled");
						}
						else {

							LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) through %s [%s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, enable ? "Enabled" : "Disabled");
							log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) through %s [%s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, enable ? "Enabled" : "Disabled");
						}

						send_notice_to_user(s_RootServ, callerUser, "Bot \2%s\2 has been \2%s\2.", bot->nick, enable ? "enabled" : "disabled");
					}
				}
				else if (str_equals_nocase(opt, "MODE")) {

					char *modes;
					BOOL add = TRUE;


					TRACE_MAIN();
					modes = val;

					bot->modes_on = 0;
					bot->modes_off = 0;

					while (*modes) {

						switch (*modes++) {

						case '+':
							add = TRUE;
							break;
						case '-':
							add = FALSE;
							break;

						case 'x':
							if (add) {

								AddFlag(bot->modes_on, UMODE_x);
								RemoveFlag(bot->modes_off, UMODE_x);
							}
							else {

								RemoveFlag(bot->modes_on, UMODE_x);
								AddFlag(bot->modes_off, UMODE_x);
							}
							break;

						case 'z':
							if (add) {

								AddFlag(bot->modes_on, UMODE_z);
								RemoveFlag(bot->modes_off, UMODE_z);
							}
							else {

								RemoveFlag(bot->modes_on, UMODE_z);
								AddFlag(bot->modes_off, UMODE_z);
							}
							break;

						}
					}

					modes = get_user_modes(bot->modes_on, bot->modes_off);

					if (data->operMatch) {

						LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) [Modes: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, modes);
						log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) [Modes: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, modes);
					}
					else {

						LOG_SNOOP(s_OperServ, "RS B %s -- by %s (%s@%s) through %s [Modes: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, modes);
						log_services(LOG_SERVICES_ROOTSERV, "B %s -- by %s (%s@%s) through %s [Modes: %s]", bot->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, modes);
					}

					send_notice_to_user(s_RootServ, callerUser, "Modes for bot \2%s\2 have been set to: %s", bot->nick, modes);
				}
				else {

					send_notice_to_user(s_RootServ, callerUser, "Syntax: \2BOT SET\2 nick [USER|HOST|HOST2|MODE|SERVER|SERVER2|ENABLED|DISABLED] value");
					send_notice_to_user(s_RootServ, callerUser, "Type \2/rs OHELP BOT\2 for more information.");
				}

				if (serverBotListLoadComplete != 1)
					send_notice_to_user(s_RootServ, callerUser, "\2Warning:\2 Not all bots on the list have been loaded at startup. Changes will \2NOT\2 be saved.");
			}
			else {

				if (data->operMatch)
					LOG_SNOOP(s_OperServ, "RS *B %s -- by %s (%s@%s) [Not Registered]", botnick, callerUser->nick, callerUser->username, callerUser->host);
				else
					LOG_SNOOP(s_OperServ, "RS *B %s -- by %s (%s@%s) through %s [Not Registered]", botnick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_notice_to_user(s_RootServ, callerUser, "Bot \2%s\2 is not registered.", botnick);
			}
		}
		else {

			send_notice_to_user(s_RootServ, callerUser, "Syntax: \2BOT SET\2 nick [USER|HOST|HOST2|MODE|SERVER|SERVER2|ENABLED|DISABLED] value");
			send_notice_to_user(s_RootServ, callerUser, "Type \2/rs OHELP BOT\2 for more information.");
		}
	}
	else if (str_equals_nocase(command, "LIST")) {

		send_notice_to_user(s_RootServ, callerUser, "Current \2Bot\2 list:");

		send_access_list(serverBotList, s_RootServ, callerUser);

		if (serverBotListLoadComplete != 1)
			send_notice_to_user(s_RootServ, callerUser, "\2Warning:\2 Not all bots on the list have been loaded at startup. Changes will \2NOT\2 be saved.");
	}
	else if (str_equals_nocase(command, "INFO")) {

		char *botnick;


		if (IS_NOT_NULL(botnick = strtok(NULL, " "))) {

			if (!send_access_info(serverBotList, botnick, s_RootServ, callerUser)) {

				send_notice_to_user(s_RootServ, callerUser, "Bot \2%s\2 is not registered.", botnick);
				LOG_SNOOP(s_OperServ, "RS *B %s -- by %s (%s@%s) [Not Registered]",	botnick, callerUser->nick, callerUser->username, callerUser->host);
			}
		}
		else {

			send_notice_to_user(s_RootServ, callerUser, "Syntax: \2BOT INFO\2 nick");
			send_notice_to_user(s_RootServ, callerUser, "Type \2/rs OHELP BOT\2 for more information.");
		}
	}
	else {

		send_notice_to_user(s_RootServ, callerUser, "Syntax: \2BOT\2 [ADD|DEL|SET|LIST|INFO] nick [value]");
		send_notice_to_user(s_RootServ, callerUser, "Type \2/rs OHELP BOT\2 for more information.");
	}
}

/*********************************************************/

static void do_dynconf(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *command;


	TRACE_MAIN_FCLT(FACILITY_ROOTSERV_HANDLE_DYNCONF);

	if (IS_NULL(command = strtok(NULL, " "))) {

		send_notice_to_user(s_RootServ, callerUser, "Syntax: \2CONF\2 [SET|SHOW] [CSLIMIT|NSLIMIT|WNOTICE] [value]");
		send_notice_to_user(s_RootServ, callerUser, "Type \2/rs OHELP CONF\2 for more information.");
	}
	else if (str_equals_nocase(command, "SET")) {

		char *option;


		TRACE_MAIN();
		if (IS_NOT_NULL(option = strtok(NULL, " "))) {

			str_toupper(option);

			if (str_equals(option, "NSLIMIT") || str_equals(option, "CSLIMIT")) {

				char *param;


				if (IS_NOT_NULL(param = strtok(NULL, " "))) {

					char				*err;
					unsigned long int	value;


					value = strtoul(param, &err, 10);

					if ((value > 0) && (*err == '\0')) {

						TRACE_MAIN();
						if (option[0] == 'N') {

							if (value > (ns_regCount + 25)) {

								TRACE_MAIN();
								dynConf.ns_regLimit = value;

								if (data->operMatch) {

									LOG_SNOOP(s_OperServ, "RS D NS -- by %s (%s@%s) [%d]", callerUser->nick, callerUser->username, callerUser->host, value);
									log_services(LOG_SERVICES_ROOTSERV, "D NS -- by %s (%s@%s) [%d]", callerUser->nick, callerUser->username, callerUser->host, value);

									send_globops(s_RootServ, "\2%s\2 set nick registration limit to \2%d\2", source, value);
								}
								else {

									LOG_SNOOP(s_OperServ, "RS D NS -- by %s (%s@%s) through %s [%d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, value);
									log_services(LOG_SERVICES_ROOTSERV, "D NS -- by %s (%s@%s) through %s [%d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, value);

									send_globops(s_RootServ, "\2%s\2 (through \2%s\2) set nick registration limit to \2%d\2", source, data->operName, value);
								}

								send_notice_to_user(s_RootServ, callerUser, "\2%s\2 e' stato impostato a \2%d\2", option, value);
							}
							else {

								TRACE_MAIN();
								if (data->operMatch)
									LOG_SNOOP(s_OperServ, "RS *D NS -- by %s (%s@%s) [%d < %d]", callerUser->nick, callerUser->username, callerUser->host, value, (ns_regCount + 25));
								else
									LOG_SNOOP(s_OperServ, "RS *D NS -- by %s (%s@%s) through %s [%d < %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, value, (ns_regCount + 25));

								send_notice_to_user(s_RootServ, callerUser, "The given value is less than the current number of registered nicks! [%d < %d]", value, (ns_regCount + 25));
							}
						}
						else {

							if (value > (cs_regCount + 25)) {

								TRACE_MAIN();
								dynConf.cs_regLimit = value;

								if (data->operMatch) {

									LOG_SNOOP(s_OperServ, "RS D CS -- by %s (%s@%s) [%d]", callerUser->nick, callerUser->username, callerUser->host, value);
									log_services(LOG_SERVICES_ROOTSERV, "D CS -- by %s (%s@%s) [%d]", callerUser->nick, callerUser->username, callerUser->host, value);

									send_globops(s_RootServ, "\2%s\2 set channel registration limit to \2%d\2", source, value);
								}
								else {

									LOG_SNOOP(s_OperServ, "RS D CS -- by %s (%s@%s) through %s [%d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, value);
									log_services(LOG_SERVICES_ROOTSERV, "D CS -- by %s (%s@%s) through %s [%d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, value);

									send_globops(s_RootServ, "\2%s\2 (through \2%s\2) set channel registration limit to \2%d\2", source, data->operName, value);
								}

								send_notice_to_user(s_RootServ, callerUser, "\2%s\2 e' stato impostato a \2%d\2", option, value);
							}
							else {

								TRACE_MAIN();
								if (data->operMatch)
									LOG_SNOOP(s_OperServ, "RS *D CS -- by %s (%s@%s) [%d < %d]", callerUser->nick, callerUser->username, callerUser->host, value, (cs_regCount + 25));
								else
									LOG_SNOOP(s_OperServ, "RS *D CS -- by %s (%s@%s) through %s [%d < %d]", callerUser->nick, callerUser->username, callerUser->host, data->operName, value, (cs_regCount + 25));

								send_notice_to_user(s_RootServ, callerUser, "The given value is less than the current number of registered channels! [%d < %d]", value, (cs_regCount + 25));
							}
						}
					}
					else {

						if (data->operMatch)
							LOG_SNOOP(s_OperServ, "RS *D %cS -- by %s (%s@%s) [%d < 0]", option[0], callerUser->nick, callerUser->username, callerUser->host, value);
						else
							LOG_SNOOP(s_OperServ, "RS *D %cS -- by %s (%s@%s) through %s [%d < 0]", option[0], callerUser->nick, callerUser->username, callerUser->host, data->operName, value);

						send_notice_to_user(s_RootServ, callerUser, "Value must be a positive number.");
					}
				}
				else {

					send_notice_to_user(s_RootServ, callerUser, "Syntax: \2CONF\2 SET %cSLIMIT value", option[0]);
					send_notice_to_user(s_RootServ, callerUser, "Type \2/rs OHELP CONF\2 for more information.");
				}
			}
			else if (str_equals_nocase(option, "WNOTICE")) {

				char *message;


				TRACE_MAIN();
				if (IS_NOT_NULL(message = strtok(NULL, ""))) {

					size_t len;


					if (str_equals_nocase(message, "NONE")) {

						TRACE_MAIN();
						if (IS_NOT_NULL(dynConf.welcomeNotice))
							mem_free(dynConf.welcomeNotice);

						dynConf.welcomeNotice = NULL;

						if (data->operMatch) {

							LOG_SNOOP(s_OperServ, "RS -W -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
							log_services(LOG_SERVICES_ROOTSERV, "-W -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);

							send_globops(s_RootServ, "\2%s\2 disabled the Welcome Notice", source);
						}
						else {

							LOG_SNOOP(s_OperServ, "RS -W -- by %s (%s@%s) through %s", callerUser->nick, callerUser->username, callerUser->host, data->operName);
							log_services(LOG_SERVICES_ROOTSERV, "-W -- by %s (%s@%s) through %s", callerUser->nick, callerUser->username, callerUser->host, data->operName);

							send_globops(s_RootServ, "\2%s\2 (through \2%s\2) disabled the Welcome Notice", source, data->operName);
						}

						send_notice_to_user(s_RootServ, callerUser, "Welcome Notice has been disabled.");
					}
					else if ((len = str_len(message)) > 400)
						send_notice_to_user(s_RootServ, callerUser, "Welcome Notice cannot be longer than 400 characters (yours has: %d).", len);

					else {

						terminate_string_ccodes(message);

						TRACE_MAIN();
						if (IS_NOT_NULL(dynConf.welcomeNotice))
							mem_free(dynConf.welcomeNotice);

						dynConf.welcomeNotice = str_duplicate(message);

						if (data->operMatch) {

							LOG_SNOOP(s_OperServ, "RS +W -- by %s (%s@%s) [%s]", callerUser->nick, callerUser->username, callerUser->host, dynConf.welcomeNotice);
							log_services(LOG_SERVICES_ROOTSERV, "+W -- by %s (%s@%s) [%s]", callerUser->nick, callerUser->username, callerUser->host, dynConf.welcomeNotice);

							send_globops(s_RootServ, "\2%s\2 set the Welcome Notice to: %s", source, dynConf.welcomeNotice);
						}
						else {

							LOG_SNOOP(s_OperServ, "RS +W -- by %s (%s@%s) through %s [%s]", callerUser->nick, callerUser->username, callerUser->host, data->operName, dynConf.welcomeNotice);
							log_services(LOG_SERVICES_ROOTSERV, "+W -- by %s (%s@%s) through %s [%s]", callerUser->nick, callerUser->username, callerUser->host, data->operName, dynConf.welcomeNotice);

							send_globops(s_RootServ, "\2%s\2 (through \2%s\2) set the Welcome Notice to: %s", source, data->operName, dynConf.welcomeNotice);
						}

						send_notice_to_user(s_RootServ, callerUser, "Welcome Notice has been set to: %s", dynConf.welcomeNotice);
					}
				}
				else {

					send_notice_to_user(s_RootServ, callerUser, "Syntax: \2CONF SET\2 WNOTICE message");
					send_notice_to_user(s_RootServ, callerUser, "Type \2/rs OHELP CONF\2 for more information.");
				}
			}
			else
				send_notice_to_user(s_RootServ, callerUser, "Unknown option: \2%s\2. Type \2/rs OHELP CONF\2 for more information.", option);
		}
		else {

			send_notice_to_user(s_RootServ, callerUser, "Syntax: \2CONF SET\2 option value");
			send_notice_to_user(s_RootServ, callerUser, "Type \2/rs OHELP CONF\2 for more information.");
		}
	}
	else if (str_equals_nocase(command, "SHOW")) {

		TRACE_MAIN();
		send_notice_to_user(s_RootServ, callerUser, "Current \2DynConf\2 settings:");
		send_notice_to_user(s_RootServ, callerUser, "Registration limits: NS: \2%d\2 - CS: \2%d\2", dynConf.ns_regLimit, dynConf.cs_regLimit);
		send_notice_to_user(s_RootServ, callerUser, "Welcome Notice: %s", dynConf.welcomeNotice ? dynConf.welcomeNotice : "<not set>");
		send_notice_to_user(s_RootServ, callerUser, "*** \2End of List\2 ***");
	}
	else {

		send_notice_to_user(s_RootServ, callerUser, "Syntax: \2CONF\2 [SET|SHOW] [CSLIMIT|NSLIMIT|WNOTICE] [value]");
		send_notice_to_user(s_RootServ, callerUser, "Type \2/rs OHELP CONF\2 for more information.");
	}
}


/*********************************************************
 * DebugServ dump routines                               *
 *********************************************************/

void rootserv_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	char *command;
	BOOL needSyntax = FALSE;


	if (IS_NULL(command = strtok(NULL, s_SPACE)))
		needSyntax = TRUE;

	else if (str_equals_nocase(command, "BOT")) {

		char *value;


		if (IS_NULL(value = strtok(NULL, s_SPACE)))
			needSyntax = TRUE;

		else if (str_equals_nocase(value, "LIST")) {

			access_ds_dump(serverBotList, sourceNick, callerUser, TRUE);

			LOG_DEBUG_SNOOP("Command: DUMP ROOTSERV BOT LIST -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
		}
		else if (str_equals_nocase(value, "FULL")) {

			access_ds_dump(serverBotList, sourceNick, callerUser, FALSE);

			LOG_DEBUG_SNOOP("Command: DUMP ROOTSERV BOT FULL -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
		}
		else {

			Access *bot;


			if (IS_NOT_NULL(bot = find_access(serverBotList, value))) {

				send_notice_to_user(sourceNick, callerUser, "DUMP: Bot \2%s\2", value);

				access_send_dump(bot, sourceNick, callerUser);

				LOG_DEBUG_SNOOP("Command: DUMP ROOTSERV BOT %s -- by %s (%s@%s)", value, callerUser->nick, callerUser->username, callerUser->host);
			}
			else
				send_notice_to_user(sourceNick, callerUser, "DUMP: Bot \2%s\2 not found.", value);
		}
	}
	else if (str_equals_nocase(command, "DYNCONF")) {

		send_notice_to_user(sourceNick, callerUser, "DUMP: DynConf");

		send_notice_to_user(sourceNick, callerUser, "ChanServ Registration Limit: %d", dynConf.cs_regLimit);
		send_notice_to_user(sourceNick, callerUser, "NickServ Registration Limit: %d", dynConf.ns_regLimit);
		send_notice_to_user(sourceNick, callerUser, "Welcome Notice: 0x%08X \2[\2%s\2]\2", (unsigned long)dynConf.welcomeNotice, str_get_valid_display_value(dynConf.welcomeNotice));

		LOG_DEBUG_SNOOP("Command: DUMP ROOTSERV DYNCONF -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
	}
	else
		needSyntax = TRUE;

	if (needSyntax) {

		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 ROOTSERV BOT nickname");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 ROOTSERV BOT LIST|FULL");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 ROOTSERV DYNCONF");
	}
}


/*********************************************************
 * DebugServ memory report routines                      *
 *********************************************************/

unsigned long int rootserv_mem_report(CSTR sourceNick, const User *callerUser) {

	unsigned long int	mem = 0;
	int					count;


	TRACE_FCLT(FACILITY_ROOTSERV_GET_STATS);

	send_notice_to_user(sourceNick, callerUser, "\2%s\2:", s_RootServ);

	/* DynConf */
	mem += sizeof(dynConfig);

	if (IS_NOT_NULL(dynConf.welcomeNotice))
		mem += (str_len(dynConf.welcomeNotice) + 1);

	/* Server bot list */
	mem = access_mem_report(serverBotList, &count);

	send_notice_to_user(sourceNick, callerUser, "Server BOT-list: \2%lu\2 -> \2%lu\2 KB (\2%lu\2 B)", count, mem / 1024, mem);

	return mem;
}

#endif /* USE_SERVICES */
