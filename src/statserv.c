/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* statserv.c - StatServ service
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
#include "../inc/storage.h"
#include "../inc/conf.h"
#include "../inc/main.h"
#include "../inc/helpserv.h"
#include "../inc/misc.h"
#include "../inc/send.h"
#include "../inc/crypt_userhost.h"
#include "../inc/servers.h"
#include "../inc/seenserv.h"
#include "../inc/statserv.h"
#include "../inc/cidr.h"


/*********************************************************
 * Global variables                                      *
 *********************************************************/

RecordStats		records;
GlobalStats		total;
GlobalStats		monthly;
GlobalStats		weekly;
GlobalStats		daily;

unsigned int	stats_daily_maxusers = 0;
unsigned int	stats_daily_maxchans = 0;


/*********************************************************
 * Local variables                                       *
 *********************************************************/

/* Average statistics. */
static float uavg, oavg, savg, cavg;

/* Hourly statistics. */
static float huser, hoper, hchan, hserv;

/* Stuff to pass to the command handler. */
static Agent a_StatServ;

#ifdef	FIX_USE_MPOOL
/* Memory Pool support. */
MemoryPool *stats_chan_mempool = NULL;
#endif


/*********************************************************
 * List hashing support                                  *
 *********************************************************/

static ServerStats	*list_serverstats = NULL;

#define HASH_DATA_MODIFIER			static
#define HASH_FUNCTIONS_MODIFIER		
#undef  LIST_USE_MY_HASH

#undef  HASH_KEY_OFFSET
#define HASH_KEY_OFFSET		1

#include "../inc/list.h"


#define CHANSTATS_HASHSIZE	1024

// ChannelStats *hashtable_chanstats[CHANSTATS_HASHSIZE];
CREATE_HASHTABLE(chanstats, ChannelStats, CHANSTATS_HASHSIZE)

// void hash_chanstats_add(ChannelStats *node);
static CREATE_HASH_ADD(chanstats, ChannelStats, name)

// void hash_chanstats_add_tail(ChannelStats *node);
static CREATE_HASH_ADD_TAIL(chanstats, ChannelStats, name)

// void hash_chanstats_remove(ChannelStats *node);
static CREATE_HASH_REMOVE(chanstats, ChannelStats, name)

// ChannelStats *hash_chanstats_find(const char *value);
CREATE_HASH_FIND(chanstats, ChannelStats, name)


/*********************************************************
 * Prototypes                                            *
 *********************************************************/

static void delete_channel_stats(ChannelStats *cs);
static void delete_server_stats(ServerStats *ss);

static void do_chanstats(const char *source, User *callerUser, ServiceCommandData *data);
static void do_delete(const char *source, User *callerUser, ServiceCommandData *data);
static void do_listreg(const char *source, User *callerUser, ServiceCommandData *data);
static void do_map(const char *source, User *callerUser, ServiceCommandData *data);
static void do_netstats(const char *source, User *callerUser, ServiceCommandData *data);
static void do_records(const char *source, User *callerUser, ServiceCommandData *data);
static void do_server(const char *source, User *callerUser, ServiceCommandData *data);
static void do_who(const char *source, User *callerUser, ServiceCommandData *data);


/*********************************************************
 * Initialization/cleanup routines                       *
 *********************************************************/

void statserv_init(const time_t now) {

	int hashIdx;

	for (hashIdx = 0; hashIdx < CHANSTATS_HASHSIZE; ++hashIdx) {

		hashtable_chanstats[hashIdx] = NULL;
		hashtable_chanstats_tails[hashIdx] = NULL;
	}

	list_serverstats = NULL;


	#ifdef FIX_USE_MPOOL
	stats_chan_mempool = mempool_create(MEMPOOL_ID_STATS_CHANDB, sizeof(ChannelStats), MP_IPB_STATS_CHANDB, MB_IBC_STATS_CHANDB);
	#endif

	/* Overall Stats variables */
	memset(&total, 0, sizeof(total));

	/* Monthly variables */
	memset(&monthly, 0, sizeof(monthly));
	monthly.last_update = now;

	/* Weekly variables. */
	memset(&weekly, 0, sizeof(weekly));
	weekly.last_update = now;

	/* Daily variables. */
	memset(&daily, 0, sizeof(daily));
	daily.last_update = now;

	uavg = oavg = savg = cavg = 0;
	huser = hoper = hchan = hserv = 0;

	/* Initialize this struct. */
	a_StatServ.nick = s_StatServ;
	a_StatServ.shortNick = s_ST;
	a_StatServ.agentID = AGENTID_STATSERV;
	a_StatServ.logID = logid_from_agentid(AGENTID_STATSERV);
}


void statserv_terminate(void) {
	
	#ifdef FIX_USE_MPOOL
	mempool_destroy(stats_chan_mempool);
	stats_chan_mempool = NULL;
	#endif
}


/*********************************************************
 * Command handlers                                      *
 *********************************************************/

// 'A' (65 / 0)
// 'B' (66 / 1)
// 'C' (67 / 2)
static ServiceCommand	statserv_commands_C[] = {
	{ "CHANSTATS",	ULEVEL_USER,	0, do_chanstats },
	{ NULL,			0,				0, NULL }
};
// 'D' (68 / 3)
static ServiceCommand	statserv_commands_D[] = {
	{ "DELETE",		ULEVEL_SOP,		0, do_delete },
	{ NULL,			0,				0, NULL }
};
// 'E' (69 / 4)
// 'F' (70 / 5)
// 'G' (71 / 6)
// 'H' (72 / 7)
static ServiceCommand	statserv_commands_H[] = {
	{ "HELP",		ULEVEL_USER,	0, handle_help },
	{ NULL,			0,				0, NULL }
};
// 'I' (73 / 8)
// 'J' (74 / 9)
// 'K' (75 / 10)
// 'L' (76 / 11)
static ServiceCommand	statserv_commands_L[] = {
	{ "LIST",		ULEVEL_SOP,		0, handle_list },
	{ "LISTREG",	ULEVEL_SOP,		0, do_listreg },
	{ NULL,			0,				0, NULL }
};
// 'M' (77 / 12)
static ServiceCommand	statserv_commands_M[] = {
	{ "MAP",		ULEVEL_OPER,	0, do_map },
	{ NULL,			0,				0, NULL }
};
// 'N' (78 / 13)
static ServiceCommand	statserv_commands_N[] = {
	{ "NETSTATS",	ULEVEL_OPER,	0, do_netstats },
	{ NULL,			0,				0, NULL }
};
// 'O' (79 / 14)
static ServiceCommand	statserv_commands_O[] = {
	{ "OHELP",		ULEVEL_OPER,	0, handle_help },
	{ NULL,			0,				0, NULL }
};
// 'P' (80 / 15)
// 'Q' (81 / 16)
// 'R' (82 / 17)
static ServiceCommand	statserv_commands_R[] = {
	{ "RECORDS",	ULEVEL_OPER,	0, do_records },
	{ NULL,			0,				0, NULL }
};
// 'S' (83 / 18)
static ServiceCommand	statserv_commands_S[] = {
	{ "SERVER",		ULEVEL_OPER,	0, do_server },
	{ NULL,			0,				0, NULL }
};
// 'T' (84 / 19)
// 'U' (85 / 20)
// 'V' (86 / 21)
// 'W' (87 / 22)
static ServiceCommand	statserv_commands_W[] = {
	{ "WHO",		ULEVEL_SOP,		0, do_who },
	{ NULL,			0,				0, NULL }
};
// 'X' (88 / 23)
// 'Y' (89 / 24)
// 'Z' (90 / 25)

ServiceCommand	*statserv_commands[26] = {
	NULL,					NULL,
	statserv_commands_C,	statserv_commands_D,
	NULL,					NULL,
	NULL,					statserv_commands_H,
	NULL,					NULL,
	NULL,					statserv_commands_L,
	statserv_commands_M,	statserv_commands_N,
	statserv_commands_O,	NULL,
	NULL,					statserv_commands_R,
	statserv_commands_S,	NULL,
	NULL,					NULL,
	statserv_commands_W,	NULL,
	NULL,					NULL
};


/*********************************************************
 * Main routine                                          *
 *********************************************************/

void statserv(const char *source, User *callerUser, char *buf) {

	char *cmd;

	TRACE_MAIN_FCLT(FACILITY_STATSERV);

	cmd = strtok(buf, " ");

	if (!cmd)
		return;

	else if (cmd[0] == '\001') {

		++cmd;

		TRACE_MAIN();
		if (IS_EMPTY_STR(cmd))
			LOG_SNOOP(s_StatServ, "Invalid CTCP from \2%s\2", source);

		if (str_equals_nocase(cmd, "PING")) {

			send_notice_to_user(s_StatServ, callerUser, "\001PING\001");
			LOG_SNOOP(s_StatServ, "CTCP: PING from \2%s\2", source);
		}
		else {

			char *action = strtok(NULL, "");

			if (action) {

				action[str_len(action) - 1] = '\0';
				LOG_SNOOP(s_StatServ, "CTCP: %s %s from \2%s\2", cmd, action, source);
			}
			else {

				cmd[str_len(cmd) - 1] = '\0';
				LOG_SNOOP(s_StatServ, "CTCP: %s from \2%s\2", cmd, source);
			}
		}
	}
	else
		oper_invoke_agent_command(cmd, statserv_commands, callerUser, &a_StatServ);
}


/*********************************************************
 * Database functions                                    *
 *********************************************************/

BOOL statserv_chanstats_db_load(void) {

	STGHANDLE		stg = 0;
	STG_RESULT		result;
	int				idx;

	#ifdef	FIX_USE_MPOOL
	MEMORYBLOCK_ID	mblock_id;
	#endif


	TRACE_FCLT(FACILITY_STATSERV_CHANSTATS_DB_LOAD);

	result = stg_open(STATSERV_DB, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version;
			BOOL		in_section;


			version = stg_data_version(stg);

			switch (version) {

				case STATSERV_DB_CURRENT_VERSION: {

					ChannelStats_V10	*cs;

					// Load global statistics

					if (stg_read_record(stg, NULL, 0) != stgBeginOfSection ||
						stg_read_record(stg, (PBYTE)&total,   sizeof(GlobalStats_V10)) != stgSuccess ||
						stg_read_record(stg, (PBYTE)&monthly, sizeof(GlobalStats_V10)) != stgSuccess ||
						stg_read_record(stg, (PBYTE)&weekly,  sizeof(GlobalStats_V10)) != stgSuccess ||
						stg_read_record(stg, (PBYTE)&daily,   sizeof(GlobalStats_V10)) != stgSuccess ||
						stg_read_record(stg, (PBYTE)&records, sizeof(RecordStats_V10)) != stgSuccess ||
						stg_read_record(stg, NULL, 0) != stgEndOfSection) {

						stg_close(stg, STATSERV_DB);
						fatal_error(FACILITY_STATSERV_CHANSTATS_DB_LOAD, __LINE__, "Read error on %s - %s", STATSERV_DB, stg_result_to_string(stg_get_last_error()));
					}


					// channels stats
					for (idx = 0; idx < CHANSTATS_HASHSIZE; ++idx) {

						// start-of-section marker
						if (stg_read_record(stg, NULL, 0) == stgBeginOfSection) {

							in_section = TRUE;

							while (in_section) {
								
								#ifdef	FIX_USE_MPOOL
								cs = mempool_alloc2(ChannelStats_V10*, stats_chan_mempool, FALSE, &mblock_id);
								#else
								cs = mem_malloc(sizeof(ChannelStats_V10));
								#endif

								result = stg_read_record(stg, (PBYTE)cs, sizeof(ChannelStats_V10));

								switch (result) {

									case stgEndOfSection: // end-of-section

										in_section = FALSE;

										#ifdef	FIX_USE_MPOOL
										mempool_free2(stats_chan_mempool, cs, mblock_id);
										#else
										mem_free(cs);
										#endif

										break;

									case stgSuccess: // a valid region

										#ifdef	FIX_USE_MPOOL
										cs->mblock_id = mblock_id;
										#endif

										if (cs->name && stg_read_string(stg, &(cs->name), NULL) != stgSuccess)
											fatal_error(FACILITY_STATSERV_CHANSTATS_DB_LOAD, __LINE__, "Read error on %s (2) - %s", STATSERV_DB, stg_result_to_string(stg_get_last_error()));

										cs->next = cs->prev = NULL;

										hash_chanstats_add_tail(cs);

										break;

									default: // some error
										fatal_error(FACILITY_STATSERV_CHANSTATS_DB_LOAD, __LINE__, "Read error on %s - %s", STATSERV_DB, stg_result_to_string(stg_get_last_error()));
								}
							}
						}
						else
							fatal_error(FACILITY_STATSERV_CHANSTATS_DB_LOAD, __LINE__, "Read error on %s : invalid format", STATSERV_DB);

					} // for

					stg_close(stg, STATSERV_DB);
					return TRUE;
				}

				default:
					fatal_error(FACILITY_STATSERV_CHANSTATS_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, STATSERV_DB);
			}
		}

		case stgNotFound: // no data to load
			return TRUE;

		default: // error!
			stg_close(stg, STATSERV_DB);

			fatal_error(FACILITY_STATSERV_CHANSTATS_DB_LOAD, __LINE__, "Error opening %s - %s", STATSERV_DB, stg_result_to_string(stg_get_last_error()));
			return FALSE;
	}
}


BOOL statserv_servstats_db_load(void) {

	STGHANDLE		stg = 0;
	STG_RESULT		result;


	TRACE_FCLT(FACILITY_STATSERV_SERVSTATS_DB_LOAD);

	result = stg_open(SERVSTATS_DB, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version = stg_data_version(stg);

			switch (version) {

				case STATSERV_DB_CURRENT_VERSION: {

					ServerStats_V10	*ss;

					// start-of-section marker
					if (stg_read_record(stg, NULL, 0) == stgBeginOfSection) {

						while (1) {
							
							ss = mem_malloc(sizeof(ServerStats_V10));

							if (stg_read_record(stg, (PBYTE)ss, sizeof(ServerStats_V10)) == stgSuccess) {

								if (IS_NOT_NULL(ss->name) && (stg_read_string(stg, &(ss->name), NULL) != stgSuccess))
									fatal_error(FACILITY_STATSERV_SERVSTATS_DB_LOAD, __LINE__, "Read error on %s (2) - %s", SEENSERV_DB, stg_result_to_string(result));

								ss->clients = 0;
								ss->opers = 0;
								RemoveFlag(ss->flags, STATS_SERVER_ONLINE);

								LIST_INSERT_ORDERED(ss, list_serverstats, str_compare_nocase, name);
							}
							else {

								mem_free(ss);
								break;
							}
						}
					}
					else
						fatal_error(FACILITY_STATSERV_SERVSTATS_DB_LOAD, __LINE__, "Read error on %s : invalid format", SERVSTATS_DB);

					stg_close(stg, SERVSTATS_DB);
					return TRUE;
				}

				default:
					fatal_error(FACILITY_STATSERV_SERVSTATS_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, SERVSTATS_DB);
			}
		}

		case stgNotFound: // no data to load
			return TRUE;

		default: // error!
			stg_close(stg, SERVSTATS_DB);

			fatal_error(FACILITY_STATSERV_SERVSTATS_DB_LOAD, __LINE__, "Error opening %s - %s", SERVSTATS_DB, stg_result_to_string(stg_get_last_error()));
			return FALSE;
	}
}


BOOL statserv_chanstats_db_save(void) {

	STGHANDLE		stg;
	STG_RESULT		result;
	ChannelStats	*cs;
	int				idx;


	TRACE_FCLT(FACILITY_STATSERV_CHANSTATS_DB_SAVE);

	result = stg_create(STATSERV_DB, SF_NOFLAGS, STATSERV_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_STATSERV_CHANSTATS_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"statserv_chanstats_db_save(): Could not create database file %s: %s [Error %d: %s]", STATSERV_DB, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	// saving global statistics

	if (stg_start_section(stg) != stgSuccess ||
		stg_write_record(stg, (PBYTE)&total, sizeof(GlobalStats)) != stgSuccess ||
		stg_write_record(stg, (PBYTE)&monthly, sizeof(GlobalStats)) != stgSuccess ||
		stg_write_record(stg, (PBYTE)&weekly, sizeof(GlobalStats)) != stgSuccess ||
		stg_write_record(stg, (PBYTE)&daily, sizeof(GlobalStats)) != stgSuccess ||
		stg_write_record(stg, (PBYTE)&records, sizeof(RecordStats)) != stgSuccess ||
		stg_end_section(stg) != stgSuccess)
		fatal_error(FACILITY_STATSERV_CHANSTATS_DB_SAVE, __LINE__, "Write error on %s - %s", STATSERV_DB, stg_result_to_string(stg_get_last_error()));


	// Now for the channels database...
	HASH_FOREACH_BRANCH(idx, CHANSTATS_HASHSIZE) {

		if (stg_start_section(stg) != stgSuccess)
			fatal_error(FACILITY_STATSERV_CHANSTATS_DB_SAVE, __LINE__, "Write error on %s - %s", STATSERV_DB, stg_result_to_string(stg_get_last_error()));

		HASH_FOREACH_BRANCH_ITEM(chanstats, idx, cs) {

			if (stg_write_record(stg, (PBYTE)cs, sizeof(ChannelStats)) != stgSuccess ||
				(cs->name && (stg_write_string(stg, cs->name) != stgSuccess)))
				fatal_error(FACILITY_STATSERV_CHANSTATS_DB_SAVE, __LINE__, "Write error on %s - %s", STATSERV_DB, stg_result_to_string(stg_get_last_error()));
		}

		if (stg_end_section(stg) != stgSuccess)
			fatal_error(FACILITY_STATSERV_CHANSTATS_DB_SAVE, __LINE__, "Write error on %s - %s", STATSERV_DB, stg_result_to_string(stg_get_last_error()));
	}

	stg_close(stg, STATSERV_DB);

	return TRUE;
}


BOOL statserv_servstats_db_save(void) {

	STGHANDLE		stg;
	STG_RESULT		result;
	ServerStats		*ss;


	result = stg_create(SERVSTATS_DB, SF_NOFLAGS, STATSERV_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_STATSERV_SERVSTATS_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"statserv_servstats_db_save(): Could not create database file %s: %s [Error %d: %s]", SERVSTATS_DB, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	if (stg_start_section(stg) != stgSuccess)
		fatal_error(FACILITY_STATSERV_CHANSTATS_DB_SAVE, __LINE__, "Write error on %s - %s", SERVSTATS_DB, stg_result_to_string(stg_get_last_error()));


	LIST_FOREACH(ss, list_serverstats) {

		if (stg_write_record(stg, (PBYTE)ss, sizeof(ServerStats)) != stgSuccess ||
			(ss->name && (stg_write_string(stg, ss->name) != stgSuccess)))
			fatal_error(FACILITY_STATSERV_CHANSTATS_DB_SAVE, __LINE__, "Write error on %s - %s", SERVSTATS_DB, stg_result_to_string(stg_get_last_error()));
	}

	if (stg_end_section(stg) != stgSuccess)
		fatal_error(FACILITY_STATSERV_CHANSTATS_DB_SAVE, __LINE__, "Write error on %s - %s", SERVSTATS_DB, stg_result_to_string(stg_get_last_error()));

	stg_close(stg, SERVSTATS_DB);

	return TRUE;
}


/*********************************************************
 * Expiration routines.                                  *
 *********************************************************/

void expire_stats() {

	Channel *chan;
	ChannelStats *cs, *next;
	const time_t expire_time = (NOW - (CONF_STATS_EXPIRE * ONE_DAY));
	int hashIdx, count = 0, xcount = 0;

	TRACE_FCLT(FACILITY_STATSERV_EXPIRE_STATS);

	if (!CONF_STATS_EXPIRE || !CONF_SET_NOEXPIRE)
		return;

	HASH_FOREACH_BRANCH(hashIdx, CHANSTATS_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM_SAFE(chanstats, hashIdx, cs, next) {

			TRACE();
			++count;

			if ((cs->last_change < expire_time) && (IS_NULL(chan = hash_channel_find(cs->name)))) {

				TRACE();
				++xcount;
				LOG_DEBUG("Expiring channel stats record %s", cs->name);
				delete_channel_stats(cs);
			}
		}
	}

	TRACE();
	if (CONF_DISPLAY_UPDATES)
		send_globops(NULL, "Completed Channel Expire (%d/%d)", xcount, count);
}

/*********************************************************/

void statserv_daily_expire() {

	ChannelStats *cs;
	ServerStats *ss;
	int hashIdx, count = 0, scount = 0;


	HASH_FOREACH_BRANCH(hashIdx, CHANSTATS_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM(chanstats, hashIdx, cs) {

			TRACE();
			++count;
			cs->dailypeak = 0;
			cs->dailyjoins = 0;
			cs->dailyparts = 0;
			cs->dailykicks = 0;
			cs->dailybans = 0;
			cs->dailyoppings = 0;
			cs->dailydeoppings = 0;
			cs->dailyvoicings = 0;
			cs->dailydevoicings = 0;
			cs->dailytopics = 0;
			cs->dailydelcmodes = 0;
			cs->dailyaddcmodes = 0;
		}
	}

	LIST_FOREACH(ss, list_serverstats) {

		++scount;
		ss->dailysplits = 0;
	}

	if (daily.connections > records.maxconn) {

		records.maxconn = daily.connections;
		records.maxconn_time = NOW;
	}

	TRACE();
	memset(&daily, 0, sizeof(GlobalStats));
	daily.last_update = NOW;

	stats_daily_maxusers = 0;
	stats_daily_maxchans = 0;

	if (CONF_DISPLAY_UPDATES)
		send_globops(NULL, "Completed Daily Stats Expire (Channels/Servers in DataBase: %d/%d)", count, scount);
}

/*********************************************************/

void statserv_weekly_expire() {

	ChannelStats *cs;
	ServerStats *ss;
	int hashIdx, count = 0, scount = 0;


	HASH_FOREACH_BRANCH(hashIdx, CHANSTATS_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM(chanstats, hashIdx, cs) {

			TRACE();
			++count;
			cs->weeklypeak = 0;
			cs->weeklyjoins = 0;
			cs->weeklyparts = 0;
			cs->weeklykicks = 0;
			cs->weeklybans = 0;
			cs->weeklyoppings = 0;
			cs->weeklydeoppings = 0;
			cs->weeklyvoicings = 0;
			cs->weeklydevoicings = 0;
			cs->weeklytopics = 0;
			cs->weeklydelcmodes = 0;
			cs->weeklyaddcmodes = 0;
		}		
	}

	LIST_FOREACH(ss, list_serverstats) {

		++scount;
		ss->weeklysplits = 0;
	}

	TRACE();
	memset(&weekly, 0, sizeof(GlobalStats));
	weekly.last_update = NOW;

	if (CONF_DISPLAY_UPDATES)
		send_globops(NULL, "Completed Weekly Stats Expire (Channels in DataBase: %d)", count);
}

/*********************************************************/

void statserv_monthly_expire() {

	ChannelStats *cs;
	ServerStats *ss;
	int hashIdx, count = 0, scount = 0;


	HASH_FOREACH_BRANCH(hashIdx, CHANSTATS_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM(chanstats, hashIdx, cs) {

			TRACE();
			++count;
			cs->monthlypeak = 0;
			cs->monthlyjoins = 0;
			cs->monthlyparts = 0;
			cs->monthlykicks = 0;
			cs->monthlybans = 0;
			cs->monthlyoppings = 0;
			cs->monthlydeoppings = 0;
			cs->monthlyvoicings = 0;
			cs->monthlydevoicings = 0;
			cs->monthlytopics = 0;
			cs->monthlydelcmodes = 0;
			cs->monthlyaddcmodes = 0;
		}		
	}

	LIST_FOREACH(ss, list_serverstats) {

		++scount;
		ss->monthlysplits = 0;
	}

	TRACE();
	memset(&monthly, 0, sizeof(GlobalStats));
	monthly.last_update = NOW;

	if (CONF_DISPLAY_UPDATES)
		send_globops(NULL, "Completed Monthly Stats Expire (Channels in DataBase: %d)", count);
}


/*********************************************************
 * Channel stats private routines.                       *
 *********************************************************/

static ChannelStats *make_channel_stats(CSTR name) {

	ChannelStats *cs;


	TRACE_FCLT(FACILITY_STATSERV_MAKE_CHANNEL_STATS);

	#ifdef	FIX_USE_MPOOL
	cs = mempool_alloc(ChannelStats*, stats_chan_mempool, TRUE);
	#else
	cs = mem_calloc(1, sizeof(ChannelStats));
	#endif

	cs->name = str_duplicate(name);

	cs->time_added = NOW;

	hash_chanstats_add(cs);

	return cs;
}

/*********************************************************/

static void delete_channel_stats(ChannelStats *cs) {

	TRACE_FCLT(FACILITY_STATSERV_DELETE_CHANNEL_STATS);

	hash_chanstats_remove(cs);

	TRACE();
	mem_free(cs->name);

	#ifdef	FIX_USE_MPOOL
	mempool_free(stats_chan_mempool, cs);
	#else
	mem_free(cs);
	#endif
}

/*********************************************************/

void add_channel_stats(CSTR channel) {

	ChannelStats *cs;


	TRACE_FCLT(FACILITY_STATSERV_ADD_CHANNEL_STATS);

	if (IS_NULL(channel)) {

		log_error(FACILITY_STATSERV_ADD_CHANNEL_STATS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "statserv_add_channel_stats()", s_LOG_NULL, "channel");

		return;
	}

	if (IS_NOT_NULL(hash_chanstats_find(channel))) {

		log_error(FACILITY_STATSERV_ADD_CHANNEL_STATS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"statserv_add_channel_stats(): Channel %s is already being tracked", channel);

		return;
	}

	TRACE();
	cs = make_channel_stats(channel);

	cs->last_change = NOW;

	if (CONF_SET_EXTRASNOOP)
		LOG_SNOOP(s_StatServ, "ST R %s", channel);
}

/*********************************************************/

void update_averages() {

	TRACE_FCLT(FACILITY_STATSERV_UPDATE_AVERAGES);

	if (!uavg)
		uavg = user_online_user_count;

	if (!oavg)
		oavg = user_online_operator_count;

	if (!savg)
		savg = nservers;

	if (!huser && uavg)
		huser = uavg;

	TRACE();
	if (!hoper && oavg)
		hoper = oavg;

	TRACE();
	if (!hserv && savg)
		hserv = savg;

	TRACE();
	if (!hchan && stats_open_channels_count)
		hchan = stats_open_channels_count;

	TRACE();
	if (uavg)
		uavg = (uavg + user_online_user_count + huser) / 3;

	if (oavg)
		oavg = (oavg + user_online_operator_count + hoper) / 3;

	if (savg)
		savg = (savg + (nservers) + hserv) / 3;

	if (stats_open_channels_count)
		cavg = (cavg + stats_open_channels_count + hchan) / 3;
}

/*********************************************************/

void update_hour() {

	TRACE_FCLT(FACILITY_STATSERV_UPDATE_HOUR);

	if (stats_open_channels_count && !hchan)
		hchan = stats_open_channels_count;

	TRACE();
	huser = (huser + user_online_user_count) / 2;
	hchan = (hchan + stats_open_channels_count) / 2;
	hserv = (hserv + (nservers + 1)) / 2;
	hoper = (hoper + user_online_operator_count) / 2;
}


/*********************************************************
 * Server stats private routines.                        *
 *********************************************************/

ServerStats *findserverstats(CSTR server) {

	ServerStats *stats;


	TRACE_FCLT(FACILITY_STATSERV_FINDSERVERSTATS);

	if (IS_NULL(server)) {

		log_error(FACILITY_STATSERV_FINDSERVERSTATS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "findserverstats()", s_LOG_NULL, "server");

		return NULL;
	}

	LIST_SEARCH_ORDERED(list_serverstats, name, server, str_compare_nocase, stats);

	return stats;
}

/*********************************************************/

ServerStats *make_server_stats(CSTR server) {

	ServerStats *stats;


	TRACE_FCLT(FACILITY_STATSERV_MAKE_SERVER_STATS);

	stats = mem_calloc(1, sizeof(ServerStats));

	stats->name = str_duplicate(server);

	TRACE();
	stats->time_added = NOW;
	stats->connect = NOW;

	LIST_INSERT_ORDERED(stats, list_serverstats, str_compare_nocase, name);

	TRACE();
	return stats;
}

/*********************************************************/

static void delete_server_stats(ServerStats *stats) {

	TRACE_FCLT(FACILITY_STATSERV_DELETE_SERVER_STATS);

	LIST_REMOVE(stats, list_serverstats);

	TRACE();
	mem_free(stats->name);
	mem_free(stats);
}

/*********************************************************/

void update_server_averages() {

	ServerStats *stats;


	TRACE_FCLT(FACILITY_STATSERV_UPDATE_SERVER_AVERAGES);

	LIST_FOREACH(stats, list_serverstats) {

		TRACE();
		if (stats->users_average == 0)
			stats->users_average = stats->clients;

		if ((stats->clients > 0) || (stats->users_average > 0))
			stats->users_average = (stats->users_average + stats->clients) / 2;

		if (stats->opers_average == 0)
			stats->opers_average = stats->opers;

		if ((stats->opers > 0) || (stats->opers_average > 0))
			stats->opers_average = (stats->opers_average + stats->opers) / 2;
	}
}


/*********************************************************
 * StatServ command routines.                            *
 *********************************************************/

static void do_map(CSTR source, User *callerUser, ServiceCommandData *data) {

	ServerStats *ss;
	const char *action;


	TRACE_MAIN_FCLT(FACILITY_STATSERV_HANDLE_MAP);

	if (IS_NULL(action = strtok(NULL, " ")) || str_equals_nocase(action, "ALL")) {

		int count = 0;

		send_notice_to_user(s_StatServ, callerUser, "\2Server Listing:\2");
		send_notice_to_user(s_StatServ, callerUser, s_SPACE);

		TRACE_MAIN();

		LIST_FOREACH(ss, list_serverstats) {

			if (IS_NULL(action) && FlagSet(ss->flags, STATS_SERVER_HIDDEN))
				continue;

			send_notice_to_user(s_StatServ, callerUser, "%d) \2%s\2 [Status: %s] [Clients/Max: %d/%d] [Opers/Max: %d/%d]",
				++count, ss->name, FlagSet(ss->flags, STATS_SERVER_ONLINE) ? "Online" : "\2Offline\2", ss->clients, ss->maxclients, ss->opers, ss->maxopers);
		}

		TRACE_MAIN();
		send_notice_to_user(s_StatServ, callerUser, s_SPACE);
		send_notice_to_user(s_StatServ, callerUser, "*** \2End of List\2 ***");
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SOP))
		send_notice_to_user(s_StatServ, callerUser, "Permission denied.");

	else if (str_equals_nocase(action, "DEL")) {

		const char *server;

		if (IS_NULL(server = strtok(NULL, " "))) {

			send_notice_to_user(s_StatServ, callerUser, "Syntax: \2MAP\2 [ALL|DEL|HIDE|SHOW] [server]");
			return;
		}

		LIST_FOREACH(ss, list_serverstats) {

			if (str_equals_nocase(server, ss->name)) {

				if (FlagSet(ss->flags, STATS_SERVER_ONLINE)) {

					send_notice_to_user(s_StatServ, callerUser, "Server \2%s\2 is currently online and cannot be deleted.", ss->name);
					return;
				}
				else {

					if (data->operMatch) {

						send_globops(s_StatServ, "\2%s\2 deleted server stats for \2%s\2", source, ss->name);

						LOG_SNOOP(s_StatServ, "ST -M %s -- by %s (%s@%s)", ss->name, source, callerUser->username, callerUser->host);
						log_services(LOG_SERVICES_STATSERV, "-M %s -- by %s (%s@%s)", ss->name, source, callerUser->username, callerUser->host);
					}
					else {

						send_globops(s_StatServ, "\2%s\2 (through \2%s\2) deleted server stats for \2%s\2", source, data->operName, ss->name);

						LOG_SNOOP(s_StatServ, "ST -M %s -- by %s (%s@%s) through %s", ss->name, source, callerUser->username, callerUser->host, data->operName);
						log_services(LOG_SERVICES_STATSERV, "-M %s -- by %s (%s@%s) through %s", ss->name, source, callerUser->username, callerUser->host, data->operName);
					}

					send_notice_to_user(s_StatServ, callerUser, "Stats for \2%s\2 have been deleted.", ss->name);

					delete_server_stats(ss);
					return;
				}
			}
		}

		send_notice_to_user(s_StatServ, callerUser, "Server \2%s\2 not found.", server);
	}
	else if (str_equals_nocase(action, "HIDE")) {

		const char *server;

		if (IS_NULL(server = strtok(NULL, " "))) {

			send_notice_to_user(s_StatServ, callerUser, "Syntax: \2MAP\2 [ALL|DEL|HIDE|SHOW] [server]");
			return;
		}

		LIST_FOREACH(ss, list_serverstats) {

			if (str_equals_nocase(server, ss->name)) {

				if (FlagSet(ss->flags, STATS_SERVER_HIDDEN)) {

					send_notice_to_user(s_StatServ, callerUser, "Server \2%s\2 is already hidden.", ss->name);
					return;
				}
				else {

					AddFlag(ss->flags, STATS_SERVER_HIDDEN);

					if (data->operMatch) {

						send_globops(s_StatServ, "\2%s\2 hid server stats for \2%s\2", source, ss->name);

						LOG_SNOOP(s_StatServ, "ST M %s -- by %s (%s@%s) [Hide]", ss->name, source, callerUser->username, callerUser->host);
						log_services(LOG_SERVICES_STATSERV, "M %s -- by %s (%s@%s) [Hide]", ss->name, source, callerUser->username, callerUser->host);
					}
					else {

						send_globops(s_StatServ, "\2%s\2 (through \2%s\2) hid server stats for \2%s\2", source, data->operName, ss->name);

						LOG_SNOOP(s_StatServ, "ST M %s -- by %s (%s@%s) through %s [Hide]", ss->name, source, callerUser->username, callerUser->host, data->operName);
						log_services(LOG_SERVICES_STATSERV, "M %s -- by %s (%s@%s) through %s [Hide]", ss->name, source, callerUser->username, callerUser->host, data->operName);
					}

					send_notice_to_user(s_StatServ, callerUser, "Stats for server \2%s\2 are now hidden.", ss->name);
					return;
				}
			}
		}

		send_notice_to_user(s_StatServ, callerUser, "Server \2%s\2 not found.", server);
	}
	else if (str_equals_nocase(action, "SHOW")) {

		const char *server;

		if (IS_NULL(server = strtok(NULL, " "))) {

			send_notice_to_user(s_StatServ, callerUser, "Syntax: \2MAP\2 [ALL|DEL|HIDE|SHOW] [server]");
			return;
		}

		LIST_FOREACH(ss, list_serverstats) {

			if (str_equals_nocase(server, ss->name)) {

				if (FlagUnset(ss->flags, STATS_SERVER_HIDDEN)) {

					send_notice_to_user(s_StatServ, callerUser, "Server \2%s\2 is not hidden.", ss->name);
					return;
				}
				else {

					RemoveFlag(ss->flags, STATS_SERVER_HIDDEN);

					if (data->operMatch) {

						LOG_SNOOP(s_StatServ, "ST M %s -- by %s (%s@%s) [Show]", ss->name, source, callerUser->username, callerUser->host);
						log_services(LOG_SERVICES_STATSERV, "M %s -- by %s (%s@%s) [Hide]", ss->name, source, callerUser->username, callerUser->host);

						send_globops(s_StatServ, "\2%s\2 unhid server stats for \2%s\2", source, ss->name);
					}
					else {

						LOG_SNOOP(s_StatServ, "ST M %s -- by %s (%s@%s) through %s [Show]", ss->name, source, callerUser->username, callerUser->host, data->operName);
						log_services(LOG_SERVICES_STATSERV, "M %s -- by %s (%s@%s) through %s [Show]", ss->name, source, callerUser->username, callerUser->host, data->operName);

						send_globops(s_StatServ, "\2%s\2 (through \2%s\2) unhid server stats for \2%s\2", source, data->operName, ss->name);
					}

					send_notice_to_user(s_StatServ, callerUser, "Stats for server \2%s\2 are now visible.", ss->name);
					return;
				}
			}
		}

		send_notice_to_user(s_StatServ, callerUser, "Server \2%s\2 not found.", server);
	}
	else
		send_notice_to_user(s_StatServ, callerUser, "Syntax: \2MAP\2 [ALL|DEL|HIDE|SHOW] [server]");
}

/*********************************************************/

static void do_netstats(CSTR source, User *callerUser, ServiceCommandData *data) {

	TRACE_MAIN_FCLT(FACILITY_STATSERV_HANDLE_NETSTATS);

	send_notice_to_user(s_StatServ, callerUser, "\2*** Global Network Statistics ***\2");
	send_notice_to_user(s_StatServ, callerUser, s_SPACE);

	send_notice_to_user(s_StatServ, callerUser, "Nick Changes: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D:\2%ld\2", total.nicks, monthly.nicks, weekly.nicks, daily.nicks);
	send_notice_to_user(s_StatServ, callerUser, "Kills: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D:\2%ld\2", total.kills, monthly.kills, weekly.kills, daily.kills);
	send_notice_to_user(s_StatServ, callerUser, "Service Kills: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D:\2%ld\2", total.skills, monthly.skills, weekly.skills, daily.skills);
	send_notice_to_user(s_StatServ, callerUser, "Channel Joins: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D:\2%ld\2", total.joins, monthly.joins, weekly.joins, daily.joins);
	send_notice_to_user(s_StatServ, callerUser, "Channel Parts: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D:\2%ld\2", total.parts, monthly.parts, weekly.parts, daily.parts);
	send_notice_to_user(s_StatServ, callerUser, "Quits: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D:\2%ld\2", total.quits, monthly.quits, weekly.quits, daily.quits);
	send_notice_to_user(s_StatServ, callerUser, "Kicks: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D:\2%ld\2", total.kicks, monthly.kicks, weekly.kicks, daily.kicks);
	send_notice_to_user(s_StatServ, callerUser, "Bans: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D:\2%ld\2", total.bans, monthly.bans, weekly.bans, daily.bans);
	send_notice_to_user(s_StatServ, callerUser, "Channel Modes: T: \2%ld\2 (\2%d\2+, \2%d\2-), M: \2%ld\2 (\2%d\2+, \2%d\2-), W: \2%ld\2 (\2%d\2+, \2%d\2-), D:\2%ld\2 (\2%d\2+, \2%d\2-)", (total.addcmodes + total.delcmodes), total.addcmodes, total.delcmodes, (monthly.addcmodes + monthly.delcmodes), monthly.addcmodes, monthly.delcmodes, (weekly.addcmodes + weekly.delcmodes), weekly.addcmodes, weekly.delcmodes, (daily.addcmodes + daily.delcmodes), daily.addcmodes, daily.delcmodes);
	send_notice_to_user(s_StatServ, callerUser, "Connections: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D:\2%ld\2", total.connections, monthly.connections, weekly.connections, daily.connections);
	send_notice_to_user(s_StatServ, callerUser, "Oppings: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D:\2%ld\2", total.oppings, monthly.oppings, weekly.oppings, daily.oppings);
	send_notice_to_user(s_StatServ, callerUser, "Deoppings: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D:\2%ld\2", total.deoppings, monthly.deoppings, weekly.deoppings, daily.deoppings);
	send_notice_to_user(s_StatServ, callerUser, "Voicings: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D:\2%ld\2", total.voicings, monthly.voicings, weekly.voicings, daily.voicings);
	send_notice_to_user(s_StatServ, callerUser, "Devoicings: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D:\2%ld\2", total.devoicings, monthly.devoicings, weekly.devoicings, daily.devoicings);
	send_notice_to_user(s_StatServ, callerUser, "Topics: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D:\2%ld\2", total.topics, monthly.topics, weekly.topics, daily.topics);

	send_notice_to_user(s_StatServ, callerUser, s_SPACE);
	send_notice_to_user(s_StatServ, callerUser, "*** \2End of Net Stats\2 ***");
}

/*********************************************************/

static void do_records(CSTR source, User *callerUser, ServiceCommandData *data) {

	char timebuf[64];
	struct tm tm;


	TRACE_MAIN_FCLT(FACILITY_STATSERV_HANDLE_RECORDS);

	send_notice_to_user(s_StatServ, callerUser, "\2Network Records\2:");

	tm = *localtime(&records.started);
	strftime(timebuf, sizeof(timebuf), "%a %d/%m/%Y %H:%M:%S %Z", &tm);
	send_notice_to_user(s_StatServ, callerUser, "Stats From: %s", timebuf);

	tm = *localtime(&NOW);
	strftime(timebuf, sizeof(timebuf), "%a %d/%m/%Y %H:%M:%S %Z", &tm);
	send_notice_to_user(s_StatServ, callerUser, "Current time: %s", timebuf);

	send_notice_to_user(s_StatServ, callerUser, s_SPACE);

	tm = *localtime(&records.maxusers_time);
	strftime(timebuf, sizeof(timebuf), "%a %d/%m/%Y %H:%M:%S %Z", &tm);
	send_notice_to_user(s_StatServ, callerUser, "Current Users: \2%u\2 [Record: \2%u\2 on %s]", user_online_user_count, records.maxusers, timebuf);

	tm = *localtime(&records.maxchannels_time);
	strftime(timebuf, sizeof(timebuf), "%a %d/%m/%Y %H:%M:%S %Z", &tm);
	send_notice_to_user(s_StatServ, callerUser, "Current Chans: \2%u\2 [Record: \2%u\2 on %s]", stats_open_channels_count, records.maxchannels, timebuf);

	tm = *localtime(&records.maxopers_time);
	strftime(timebuf, sizeof(timebuf), "%a %d/%m/%Y %H:%M:%S %Z", &tm);
	send_notice_to_user(s_StatServ, callerUser, "Current Opers: \2%u\2 [Record: \2%u\2 on %s]", user_online_operator_count, records.maxopers, timebuf);

	tm = *localtime(&records.maxservers_time);
	strftime(timebuf, sizeof(timebuf), "%a %d/%m/%Y %H:%M:%S %Z", &tm);
	send_notice_to_user(s_StatServ, callerUser, "Current Servers: \2%u\2 [Record: \2%u\2 on %s]", nservers, records.maxservers, timebuf);

	tm = *localtime(&records.maxconn_time);
	strftime(timebuf, sizeof(timebuf), "%a %d/%m/%Y", &tm);
	send_notice_to_user(s_StatServ, callerUser, "Current Connections: \2%u\2 [Record: \2%u\2 on %s]", daily.connections, records.maxconn, timebuf);

	TRACE_MAIN();

	send_notice_to_user(s_StatServ, callerUser, s_SPACE);
	send_notice_to_user(s_StatServ, callerUser, "\2Average Statistics\2:");
	send_notice_to_user(s_StatServ, callerUser, "Average Users/Chans: %.2f/%.2f", uavg, cavg);
	send_notice_to_user(s_StatServ, callerUser, "Average Servers/Opers: %.2f/%.2f", savg, oavg);
	send_notice_to_user(s_StatServ, callerUser, s_SPACE);

	tm = *localtime(&NOW);
	strftime(timebuf, sizeof(timebuf), "%d/%m/%Y", &tm);

	send_notice_to_user(s_StatServ, callerUser, "\2Daily Statistics\2: (%s)", timebuf);
	send_notice_to_user(s_StatServ, callerUser, "Max Users: \2%u\2", stats_daily_maxusers);
	send_notice_to_user(s_StatServ, callerUser, "Max Chans: \2%u\2", stats_daily_maxchans);

	send_notice_to_user(s_StatServ, callerUser, "*** \2End of Records\2 ***");
}

/*********************************************************/

static void do_listreg(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelStats		*cs;
	char				*prms[3] = { NULL, NULL, NULL };
	char				*start	= "0";
	char				*end	= "+50";
	char				*search	= NULL;
	int					hashIdx, paramIdx = 0;
	unsigned long int	start_line, end_line, line = 0, count = 0;


	TRACE_MAIN_FCLT(FACILITY_STATSERV_HANDLE_LISTREG);

	while ((paramIdx < 3) && IS_NOT_NULL( (prms[paramIdx] = strtok(NULL, s_SPACE)) ))
		++paramIdx;

	if (paramIdx < 1) {

		send_notice_to_user(s_StatServ, callerUser, "Syntax error.");
		return;
	}
	else {

		--paramIdx;
		search = prms[paramIdx];

		TRACE_MAIN();
		if (paramIdx > 0) {

			start = prms[0];
			--paramIdx;

			if (paramIdx >= 0) {

				end = prms[1];
				--paramIdx;
			}
		}
	}

	if (IS_NOT_NULL(search) && str_equals(search, s_STAR)) {

		send_notice_to_user(s_StatServ, callerUser, "\2ERROR\2: Search pattern too broad.");
		return;
	}

	/* Intervallo */
	
	start_line = strtoul(start, NULL, 10);

	if (end[0] == c_PLUS)
		end_line = start_line + strtoul(end + 1, NULL, 10);
	else
		end_line = strtoul(end, NULL, 10);

	TRACE_MAIN();

	/* Ricerca */

	if (end_line == 0)
		end_line = start_line + 50;

	HASH_FOREACH_BRANCH(hashIdx, CHANSTATS_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM(chanstats, hashIdx, cs) {

			if (str_match_wild(search, cs->name)) {

				TRACE_MAIN();
				++line;

				if (line < start_line)
					continue;

				send_notice_to_user(s_StatServ, callerUser, "%d) %s", line, cs->name);
				++count;

				if (line >= end_line)
					break;
			}
		}
	}

	TRACE_MAIN();
	send_notice_to_user(s_StatServ, callerUser, "\2*** End of Search. Channel%s found: %d ***\2", count == 1 ? "" : "s", count);
}

/*********************************************************/

static void do_delete(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *channel;
	ChannelStats *cs;


	TRACE_MAIN_FCLT(FACILITY_STATSERV_HANDLE_DELETE);

	if (CONF_SET_READONLY) {

		send_notice_to_user(s_StatServ, callerUser, "Sorry, channel deletion is temporarily disabled.");
		return;
	}

	if (IS_NULL(channel = strtok(NULL, " "))) {

		send_notice_to_user(s_StatServ, callerUser, "Syntax: \2DELETE\2 #channel");
		send_notice_to_user(s_StatServ, callerUser, "Type \2/st OHELP %s\2 for more information.");
		return;
	}

	if (channel[0] != '#') {

		send_notice_to_user(s_StatServ, callerUser, "\2%s\2 is not a valid channel. Try again using \2#%s\2", channel, channel);
		return;
	}

	TRACE_MAIN();
	if (IS_NULL(cs = hash_chanstats_find(channel))) {

		if (data->operMatch) {

			LOG_SNOOP(s_StatServ, "ST *De %s -- by %s (%s@%s)", channel, source, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_STATSERV, "*De %s -- by %s (%s@%s)", channel, source, callerUser->username, callerUser->host);
		}
		else {

			LOG_SNOOP(s_StatServ, "ST *De %s -- by %s (%s@%s) through %s", channel, source, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_STATSERV, "*De %s -- by %s (%s@%s) through %s", channel, source, callerUser->username, callerUser->host, data->operName);
		}

		send_notice_to_user(s_StatServ, callerUser, "Channel \2%s\2 is not registered.", channel);
		return;
	}

	if (data->operMatch) {

		LOG_SNOOP(s_StatServ, "ST De %s -- by %s (%s@%s)", cs->name, source, callerUser->username, callerUser->host);
		log_services(LOG_SERVICES_STATSERV, "De %s -- by %s (%s@%s)", cs->name, source, callerUser->username, callerUser->host);

		send_globops(s_StatServ, "\2%s\2 deleted stats for channel \2%s\2", source, cs->name);
	}
	else {

		LOG_SNOOP(s_StatServ, "ST De %s -- by %s (%s@%s) through %s", cs->name, source, callerUser->username, callerUser->host, data->operName);
		log_services(LOG_SERVICES_STATSERV, "De %s -- by %s (%s@%s) through %s", cs->name, source, callerUser->username, callerUser->host, data->operName);

		send_globops(s_StatServ, "\2%s\2 (through \2%s\2) deleted stats for channel \2%s\2", source, data->operName, cs->name);
	}

	send_notice_to_user(s_StatServ, callerUser, "Channel \2%s\2 has been deleted.", cs->name);

	TRACE_MAIN();
	delete_channel_stats(cs);
}

/*********************************************************/

static void do_server(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *server, timebuf[64];
	struct tm tm;
	ServerStats *ss;


	TRACE_MAIN_FCLT(FACILITY_STATSERV_HANDLE_SERVER);

	if (IS_NULL(server = strtok(NULL, " "))) {

		send_notice_to_user(s_StatServ, callerUser, "Syntax: SERVER irc.servername.org");
		return;
	}

	TRACE_MAIN();

	if (IS_NULL(ss = findserverstats(server))) {

		send_notice_to_user(s_StatServ, callerUser, "Server stats for \2%s\2 not found.", server);
		return;
	}

	TRACE_MAIN();

	send_notice_to_user(s_StatServ, callerUser, "\2Server Information\2 for \2%s\2:", ss->name);
	send_notice_to_user(s_StatServ, callerUser, s_SPACE);

	tm = *localtime(&NOW);
	strftime(timebuf, sizeof(timebuf), "%a %m/%d/%Y %H:%M:%S %Z", &tm);
	send_notice_to_user(s_StatServ, callerUser, "Current time: %s", timebuf);

	tm = *localtime(&ss->time_added);
	strftime(timebuf, sizeof(timebuf), "%a %m/%d/%Y %H:%M:%S %Z", &tm);
	send_notice_to_user(s_StatServ, callerUser, "Stats From: %s", timebuf);
	send_notice_to_user(s_StatServ, callerUser, s_SPACE);

	if (FlagUnset(ss->flags, STATS_SERVER_ONLINE)) {

		tm = *localtime(&ss->squit);
		strftime(timebuf, sizeof(timebuf), "%a %m/%d/%Y %H:%M:%S %Z", &tm);
		send_notice_to_user(s_StatServ, callerUser, "Server is \2Offline\2. [Disconnected on %s]", timebuf);
	}
	else {

		tm = *localtime(&ss->connect);
		strftime(timebuf, sizeof(timebuf), "%a %m/%d/%Y %H:%M:%S %Z", &tm);
		send_notice_to_user(s_StatServ, callerUser, "Server is \2Online\2. [Connected on %s]", timebuf);
	}

	send_notice_to_user(s_StatServ, callerUser, s_SPACE);

	tm = *localtime(&ss->maxclients_time);
	strftime(timebuf, sizeof(timebuf), "%a %m/%d/%Y %H:%M:%S %Z", &tm);
	send_notice_to_user(s_StatServ, callerUser, "Current Clients: \2%d\2 (Record: \2%d\2 on %s)",
		ss->clients, ss->maxclients, timebuf);

	tm = *localtime(&ss->maxopers_time);
	strftime(timebuf, sizeof(timebuf), "%a %m/%d/%Y %H:%M:%S %Z", &tm);
	send_notice_to_user(s_StatServ, callerUser, "Current Opers: \2%d\2 (Record: \2%d\2 on %s)",
		ss->opers, ss->maxopers, timebuf);

	send_notice_to_user(s_StatServ, callerUser, "Average Users/Opers: \2%.2f\2/\2%.2f\2",
		ss->users_average, ss->opers_average);

	send_notice_to_user(s_StatServ, callerUser, s_SPACE);
	send_notice_to_user(s_StatServ, callerUser, "Server Hits: \2%d\2", ss->hits);
	send_notice_to_user(s_StatServ, callerUser, "Server Messages: \2%d\2", ss->msgs);
	send_notice_to_user(s_StatServ, callerUser, "Oper/Server Kills: \2%d\2/\2%d\2", ss->operkills, ss->servkills);
	send_notice_to_user(s_StatServ, callerUser, "Splits: T: \2%d\2, M: \2%d\2, W: \2%d\2, D: \2%d\2", ss->totalsplits, ss->monthlysplits, ss->weeklysplits, ss->dailysplits);

	send_notice_to_user(s_StatServ, callerUser, s_SPACE);
	send_notice_to_user(s_StatServ, callerUser, "\2*** End of Server Information ***\2");
}

/*********************************************************/

static void do_chanstats(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelStats *cs;
	Channel *chan;
	char *channel;


	TRACE_MAIN_FCLT(FACILITY_STATSERV_HANDLE_CHANSTATS);

	if (IS_NULL(channel = strtok(NULL, " "))) {

		send_notice_to_user(s_StatServ, callerUser, "Sintassi: \2CHANSTATS\2 #canale");
		send_notice_to_user(s_StatServ, callerUser, "Digita \2/st HELP CHANSTATS\2 per maggiori informazioni.");
		return;
	}

	if (!user_is_services_agent(callerUser) && !user_is_ircop(callerUser) &&
		(IS_NULL(chan = hash_channel_find(channel)) || !user_is_chanop(source, channel, chan))) {

		send_notice_to_user(s_StatServ, callerUser, "Devi essere operatore in %s per poter utilizzare questo comando.", channel);
		return;
	}

	if (IS_NOT_NULL(cs = hash_chanstats_find(channel))) {

		struct tm tm;
		char timebuf[64];


		tm = *localtime(&cs->time_added);
		strftime(timebuf, sizeof(timebuf), "%d/%m/%Y %H:%M:%S", &tm);

		TRACE_MAIN();
		send_notice_to_user(s_StatServ, callerUser, "Statistiche di \2%s\2:", cs->name);
		send_notice_to_user(s_StatServ, callerUser, s_SPACE);

		send_notice_to_user(s_StatServ, callerUser, "Data di inizio: %s", timebuf);

		tm = *localtime(&cs->last_change);
		strftime(timebuf, sizeof(timebuf), "%d/%m/%Y %H:%M:%S", &tm);
		send_notice_to_user(s_StatServ, callerUser, "Ultimo aggiornamento: %s", timebuf);

		tm = *localtime(&NOW);
		strftime(timebuf, sizeof(timebuf), "%d/%m/%Y %H:%M:%S", &tm);
		send_notice_to_user(s_StatServ, callerUser, "Ora corrente: %s", timebuf);

		send_notice_to_user(s_StatServ, callerUser, s_SPACE);

		send_notice_to_user(s_StatServ, callerUser, "Peak: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D: \2%ld\2",
			cs->totalpeak, cs->monthlypeak, cs->weeklypeak, cs->dailypeak);
		send_notice_to_user(s_StatServ, callerUser, "Joins: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D: \2%ld\2",
			cs->totaljoins, cs->monthlyjoins, cs->weeklyjoins, cs->dailyjoins);
		send_notice_to_user(s_StatServ, callerUser, "Parts: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D: \2%ld\2",
			cs->totalparts, cs->monthlyparts, cs->weeklyparts, cs->dailyparts);
		send_notice_to_user(s_StatServ, callerUser, "Kicks: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D: \2%ld\2",
			cs->totalkicks, cs->monthlykicks, cs->weeklykicks, cs->dailykicks);
		send_notice_to_user(s_StatServ, callerUser, "Bans: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D: \2%ld\2",
			cs->totalbans, cs->monthlybans, cs->weeklybans, cs->dailybans);
		send_notice_to_user(s_StatServ, callerUser, "Oppings: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D: \2%ld\2",
			cs->totaloppings, cs->monthlyoppings, cs->weeklyoppings, cs->dailyoppings);
		send_notice_to_user(s_StatServ, callerUser, "Deoppings: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D: \2%ld\2",
			cs->totaldeoppings, cs->monthlydeoppings, cs->weeklydeoppings, cs->dailydeoppings);
		send_notice_to_user(s_StatServ, callerUser, "Voicings: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D: \2%ld\2",
			cs->totalvoicings, cs->monthlyvoicings, cs->weeklyvoicings, cs->dailyvoicings);
		send_notice_to_user(s_StatServ, callerUser, "Devoicings: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D: \2%ld\2",
			cs->totaldevoicings, cs->monthlydevoicings, cs->weeklydevoicings, cs->dailydevoicings);
		send_notice_to_user(s_StatServ, callerUser, "Topics: T: \2%ld\2, M: \2%ld\2, W: \2%ld\2, D: \2%ld\2",
			cs->totaltopics, cs->monthlytopics, cs->weeklytopics, cs->dailytopics);
		send_notice_to_user(s_StatServ, callerUser, "Modes: T: \2%ld\2 (\2%ld\2+, \2%ld\2-), M: \2%ld\2 (\2%ld\2+, \2%ld\2-), W: \2%ld\2 (\2%ld\2+, \2%ld\2-), D: \2%ld\2 (\2%ld\2+, \2%ld\2-)",
			(cs->totaladdcmodes + cs->totaldelcmodes), cs->totaladdcmodes, cs->totaldelcmodes, (cs->monthlyaddcmodes + cs->monthlydelcmodes), cs->monthlyaddcmodes, cs->monthlydelcmodes, (cs->weeklyaddcmodes + cs->weeklydelcmodes), cs->weeklyaddcmodes, cs->weeklydelcmodes, (cs->dailyaddcmodes + cs->dailydelcmodes), cs->dailyaddcmodes, cs->dailydelcmodes);
		send_notice_to_user(s_StatServ, callerUser, s_SPACE);
		send_notice_to_user(s_StatServ, callerUser, "\2*** Fine delle Statistiche ***\2");
	}
	else
		send_notice_to_user(s_StatServ, callerUser, "Nessuna statistica disponibile per \2%s\2.", channel);
}

/*********************************************************/

/* Stuff needed by do_who() */

#ifdef ENABLE_CAPAB_NICKIP
#define WHO_HOST(x) showIP ? get_ip((x)->ip) : (x)->host
#else
#define WHO_HOST(x) (x)->host
#endif

#define WHO_CHANNEL(x) (firstChannel && IS_NOT_NULL((x)->chans)) ? (x)->chans->chan->name : "*"

static __inline__ BOOL match_regex(CSTR string, CSTR pattern, size_t size) {

	unsigned int idx;

	for (idx = 0; idx < size; ++idx) {

		if ((string[idx] == '\0') ||
			(isdigit(pattern[idx]) && !isdigit(string[idx])) ||
			(islower(pattern[idx]) && !islower(string[idx])) ||
			(isupper(pattern[idx]) && !isupper(string[idx])) ||
			(pattern[idx] != string[idx]))
			return FALSE;
	}

	/* String and pattern lengths do not match? */
	if (string[idx] != '\0')
		return FALSE;

	return TRUE;
}

/*********************************************************/

static void do_who(CSTR source, User *callerUser, ServiceCommandData *data) {

	/* Idea and layout comes from bahamut. */

	char *what, *token, g, status[4];
	User *user = NULL;
	int hashIdx, shown = 0;
	BOOL add = TRUE;

	Channel *search_chan = NULL;
	char *search_nick = NULL, *search_username = NULL, *search_host = NULL, *search_realname = NULL, *search_server = NULL;
	long int search_modes = 0;
	BOOL noChannels = FALSE, matchRealname = FALSE, matchHost = FALSE, matchNick = FALSE, matchServer = FALSE;
	BOOL matchUsername = FALSE, matchModes = FALSE, wantOps = FALSE, wantVoices = FALSE, positiveTS = FALSE;
	BOOL firstChannel = FALSE, wantRegex = FALSE;
	time_t wantTS = 0;
	size_t nick_len = 0, username_len = 0, realname_len = 0;

#ifdef ENABLE_CAPAB_NICKIP
	CIDR_IP cidr;
	int matchCIDR = -1;
	BOOL showIP = FALSE;
#endif


	TRACE_MAIN_FCLT(FACILITY_STATSERV_HANDLE_WHO);

	if (IS_NULL(what = strtok(NULL, " ")) || (what[0] == '?')) {

		send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
		return;
	}
	else if ((what[0] != '+') && (what[0] != '-')) {

		TRACE_MAIN();

		if (what[0] == '#') {

			/* This is a channel */

			if (IS_NULL(search_chan = hash_channel_find(what))) {

				send_notice_to_user(s_StatServ, callerUser, "Channel \2%s\2 does not exist.", what);
				return;
			}
			else {

				UserListItem *item;

				TRACE_MAIN();
				for (item = search_chan->users; IS_NOT_NULL(item); item = item->next) {

					status[0] = 'H';
					status[1] = (user_is_ircop(item->user) ? '*' : (FlagSet(item->user->mode, UMODE_i) ? '%' : '\0'));
					status[((status[1] == '\0') ? 1 : 2)] = (user_is_chanop(item->user->nick, search_chan->name, search_chan) ? '@' : (user_is_chanvoice(item->user->nick, search_chan->name, search_chan) ? '+' : '\0'));
					status[3] = '\0';

					send_cmd("352 %s %s %s %s %s %s %s :%d %s", source, search_chan->name,
						item->user->username, WHO_HOST(item->user), item->user->server->name,
						item->user->nick, status, 2, item->user->realname);
				}

				send_cmd("315 %s %s :End of /WHO list.", source, search_chan->name);
				return;
			}
		}
		else if (strchr(what, '.')) {

			/* This is a host/IP */

			TRACE_MAIN();

			HASH_FOREACH_BRANCH(hashIdx, ONLINEUSER_HASHSIZE) {

				HASH_FOREACH_BRANCH_ITEM(onlineuser, hashIdx, user) {

					status[0] = 'H';
					status[1] = (user_is_ircop(user) ? '*' : (FlagSet(user->mode, UMODE_i) ? '%' : '\0'));
					status[2] = '\0';

					send_cmd("352 %s %s %s %s %s %s %s :%d %s", source, WHO_CHANNEL(user), user->username,
						WHO_HOST(user), user->server->name, user->nick, status, 2, user->realname);
				}
			}

			send_cmd("315 %s %s :End of /WHO list.", source, what);
			return;
		}
		else {

			/* This is a nick */

			if (IS_NOT_NULL(user = hash_onlineuser_find(what))) {

				size_t			prefixLen, len = 0;
				char			buffer[IRCBUFSIZE];
				ChanListItem	*item;


				status[0] = 'H';
				status[1] = (user_is_ircop(user) ? '*' : (FlagSet(user->mode, UMODE_i) ? '%' : '\0'));
				status[2] = '\0';

				send_cmd("352 %s %s %s %s %s %s %s :%d %s", source, WHO_CHANNEL(user), user->username,
					WHO_HOST(user), user->server->name, user->nick, status, 2, user->realname);

				prefixLen = (str_len(CONF_SERVICES_NAME) + str_len(source) + str_len(user->nick) + 6);

				for (*buffer = '\0', item = user->chans; IS_NOT_NULL(item); item = item->next) {

					if ((len + str_len(item->chan->name)) > (size_t) (MISC_BUFFER_SIZE - prefixLen - 4)) {

						send_cmd("883 %s %s :%s", source, user->nick, buffer);

						*buffer = '\0';
						len = 0;
					}

					if (FlagSet(item->chan->mode, CMODE_p) || FlagSet(item->chan->mode, CMODE_s))
						*(buffer + len++) = '%';

					if (user_is_chanop(user->nick, item->chan->name, item->chan))
						*(buffer + len++) = '@';
					else if (user_is_chanvoice(user->nick, item->chan->name, item->chan))
						*(buffer + len++) = '+';

					if (len)
						*(buffer + len) = '\0';

					len += str_copy_checked(item->chan->name, (buffer + len), (sizeof(buffer) - len));
					buffer[len++] = c_SPACE;
				}

				if (buffer[0] != '\0')
					send_cmd("883 %s %s :%s", source, user->nick, buffer);
			}

			send_cmd("315 %s %s :End of /WHO list.", source, what);
			return;
		}
	}

	TRACE_MAIN();
	while (*what) {

		switch (g = *what++) {

			case '+':
				add = TRUE;
				break;


			case '-':
				add = FALSE;
				break;


			case 'c':
				if (!add) {

					noChannels = TRUE;
					break;
				}

				if (IS_NULL(token = strtok(NULL, " "))) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				if (token[0] == '@') {

					if (*(token + 1) == '+') {

						wantOps = 1;
						wantVoices = 1;
						token += 2;
					}
					else {

						wantOps = 1;
						++token;
					}
				}
				else if (token[0] == '+') {

					wantVoices = 1;
					++token;
				}

				if (IS_NULL(search_chan = hash_channel_find(token))) {

					send_notice_to_user(s_StatServ, callerUser, "No such channel.");
					goto done;
				}

				break;


			case 'C':
				if (add)
					firstChannel = TRUE;

				else {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				break;


			case 'g':
				if (IS_NULL(token = strtok(NULL, " "))) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				search_realname = str_duplicate(token);
				matchRealname = add;
				break;


			case 'h':
				if (IS_NULL(token = strtok(NULL, " "))) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				search_host = str_duplicate(token);
				matchHost = add;
				break;


#ifdef ENABLE_CAPAB_NICKIP
			case 'i':
				if (IS_NULL(token = strtok(NULL, " "))) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				if (cidr_ip_fill(token, &cidr, FALSE) != cidrSuccess) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				matchCIDR = add;
				break;

			case 'I':
				showIP = TRUE;
				break;
#endif


			case 'm':
				if (IS_NULL(token = strtok(NULL, " "))) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				while (*token) {

					switch (*token++) {

						case 'a': AddFlag(search_modes, UMODE_a); break;
						case 'A': AddFlag(search_modes, UMODE_A); break;
						case 'h': AddFlag(search_modes, UMODE_h); break;
						case 'i': AddFlag(search_modes, UMODE_i); break;
						case 'I': AddFlag(search_modes, UMODE_I); break;
						case 'o': AddFlag(search_modes, UMODE_o); break;
						case 'r': AddFlag(search_modes, UMODE_r); break;
						case 'R': AddFlag(search_modes, UMODE_R); break;
						case 'S': AddFlag(search_modes, UMODE_S); break;
						case 'x': AddFlag(search_modes, UMODE_x); break;
						case 'y': AddFlag(search_modes, UMODE_y); break;
						case 'z': AddFlag(search_modes, UMODE_z); break;
					}
				}

				if (!search_modes) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				matchModes = add;
				break;


			case 'n':
				if (IS_NULL(token = strtok(NULL, " "))) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				search_nick = str_duplicate(token);
				matchNick = add;
				break;


			case 'r':
				if (add)
					wantRegex = TRUE;

				break;


			case 's': {

				Server *server;

				if (IS_NULL(token = strtok(NULL, " "))) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				if (IS_NULL(server = findserver(token))) {

					send_notice_to_user(s_StatServ, callerUser, "No such server \2%s\2", token);
					goto done;
				}

				search_server = str_duplicate(token);
				matchServer = add;
				break;
			}


			case 't': {

				char *err;
				time_t ts;

				if (IS_NULL(token = strtok(NULL, " ")) || ((ts = strtol(token, &err, 10)) == 0) || (*err != 0)) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				wantTS = ts;
				positiveTS = add;
				break;
			}


			case 'u':
				if (IS_NULL(token = strtok(NULL, " "))) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				search_username = str_duplicate(token);
				matchUsername = add;
				break;

			default:
				send_notice_to_user(s_StatServ, callerUser, "Unknown flag: %c", g);
				goto done;
		}
	}

	if (wantRegex) {

		if (search_nick)
			nick_len = str_len(search_nick);

		if (search_username)
			username_len = str_len(search_username);

		if (search_realname)
			realname_len = str_len(search_realname);
	}

	TRACE_MAIN();
	if (IS_NOT_NULL(search_chan)) {

		UserListItem *item;


		TRACE_MAIN();
		for (item = search_chan->users; IS_NOT_NULL(item); item = item->next) {

			if (search_modes != 0) {

				if (matchModes != ((item->user->mode & search_modes) == search_modes))
					continue;
			}

			if (IS_NOT_NULL(search_server)) {

				if (matchServer != str_equals_nocase(item->user->server->name, search_server))
					continue;
			}

			if (IS_NOT_NULL(search_username)) {

				if (wantRegex == FALSE) {

					if (matchUsername != str_match_wild_nocase(search_username, item->user->username))
						continue;
				}
				else {

					if (match_regex(item->user->username, search_username, username_len) == FALSE)
						continue;
				}
			}

			if (IS_NOT_NULL(search_host)) {

				if (matchHost != str_match_wild_nocase(search_host, item->user->host))
					continue;
			}

			if (IS_NOT_NULL(search_realname)) {

				if (wantRegex == FALSE) {

					if (matchRealname != str_match_wild_nocase(search_realname, item->user->realname))
						continue;
				}
				else {

					if (match_regex(item->user->realname, search_realname, realname_len) == FALSE)
						continue;
				}
			}

			if (IS_NOT_NULL(search_nick)) {

				if (wantRegex == FALSE) {

					if (matchNick != str_match_wild_nocase(search_nick, item->user->nick))
						continue;
				}
				else {

					if (match_regex(item->user->nick, search_nick, nick_len) == FALSE)
						continue;
				}
			}

			if (wantTS && (positiveTS ? (NOW - item->user->signon < wantTS) : (NOW - item->user->signon > wantTS)))
				continue;

			if (wantOps && !user_is_chanop(item->user->nick, search_chan->name, search_chan))
				continue;

			if (wantVoices && !user_is_chanvoice(item->user->nick, search_chan->name, search_chan))
				continue;

#ifdef ENABLE_CAPAB_NICKIP
			if ((matchCIDR != -1) && ((item->user->ip == 0) ||
				(matchCIDR != cidr_match(&cidr, item->user->ip))))
				continue;
#endif

			TRACE_MAIN();
			status[0] = 'H';
			status[1] = (user_is_ircop(item->user) ? '*' : (FlagSet(item->user->mode, UMODE_i) ? '%' : '\0'));
			status[((status[1] == '\0') ? 1 : 2)] = (user_is_chanop(item->user->nick, search_chan->name, search_chan) ? '@' : (user_is_chanvoice(item->user->nick, search_chan->name, search_chan) ? '+' : '\0'));
			status[3] = '\0';

			send_cmd("352 %s %s %s %s %s %s %s :%d %s", source, search_chan->name,
				item->user->username, WHO_HOST(item->user), item->user->server->name,
				item->user->nick, status, 2, item->user->realname);
		}

		TRACE_MAIN();
		send_cmd("315 %s %s :End of /WHO list.", source, search_chan->name);
		goto done;
	}
	else if (IS_NOT_NULL(search_nick) && !strchr(search_nick, '?') && !strchr(search_nick, '*')) {

		/* Niente canale, +n senza wildcard */

		TRACE_MAIN();
		if (IS_NOT_NULL(user = hash_onlineuser_find(search_nick))) {

			if (search_modes != 0) {

				if (matchModes != ((user->mode & search_modes) == search_modes))
					goto end;
			}

			if (IS_NOT_NULL(search_server)) {

				if (matchServer != str_equals_nocase(user->server->name, search_server))
					goto end;
			}

			if (IS_NOT_NULL(search_username)) {

				if (wantRegex == FALSE) {

					if (matchUsername != str_match_wild_nocase(search_username, user->username))
						goto end;
				}
				else {

					if (match_regex(user->username, search_username, username_len) == FALSE)
						goto end;
				}
			}

			if (IS_NOT_NULL(search_host)) {

				if (matchHost != str_match_wild_nocase(search_host, user->host))
					goto end;
			}

			if (IS_NOT_NULL(search_realname)) {

				if (wantRegex == FALSE) {

					if (matchRealname != str_match_wild_nocase(search_realname, user->realname))
						goto end;
				}
				else {

					if (match_regex(user->realname, search_realname, realname_len) == FALSE)
						goto end;
				}
			}

			if (IS_NOT_NULL(search_nick)) {

				if (wantRegex == FALSE) {

					if (matchNick != str_match_wild_nocase(search_nick, user->nick))
						goto end;
				}
				else {

					if (match_regex(user->nick, search_nick, nick_len) == FALSE)
						goto end;
				}
			}

			if (wantTS && (positiveTS ? (NOW - user->signon < wantTS) : (NOW - user->signon > wantTS)))
				goto end;

			if (noChannels && IS_NOT_NULL(user->chans))
				goto end;

#ifdef ENABLE_CAPAB_NICKIP
			if ((matchCIDR != -1) && ((user->ip == 0) || (matchCIDR != cidr_match(&cidr, user->ip))))
				goto end;
#endif

			TRACE_MAIN();
			status[0] = 'H';
			status[1] = (user_is_ircop(user) ? '*' : (FlagSet(user->mode, UMODE_i) ? '%' : '\0'));
			status[2] = '\0';

			send_cmd("352 %s %s %s %s %s %s %s :%d %s", source, WHO_CHANNEL(user), user->username,
				WHO_HOST(user), user->server->name, user->nick, status, 2, user->realname);
		}
		
		goto end;
	}

	TRACE_MAIN();

	HASH_FOREACH_BRANCH(hashIdx, ONLINEUSER_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM(onlineuser, hashIdx, user) {

			if (search_modes != 0) {

				if (matchModes != ((user->mode & search_modes) == search_modes))
					continue;
			}

			if (IS_NOT_NULL(search_server)) {

				if (matchServer != str_equals_nocase(user->server->name, search_server))
					continue;
			}

			if (IS_NOT_NULL(search_username)) {

				if (wantRegex == FALSE) {

					if (matchUsername != str_match_wild_nocase(search_username, user->username))
						continue;
				}
				else {

					if (match_regex(user->username, search_username, username_len) == FALSE)
						continue;
				}
			}

			if (IS_NOT_NULL(search_host)) {

				if (matchHost != str_match_wild_nocase(search_host, user->host))
					continue;
			}

			if (IS_NOT_NULL(search_realname)) {

				if (wantRegex == FALSE) {

					if (matchRealname != str_match_wild_nocase(search_realname, user->realname))
						continue;
				}
				else {

					if (match_regex(user->realname, search_realname, realname_len) == FALSE)
						continue;
				}
			}

			if (IS_NOT_NULL(search_nick)) {

				if (wantRegex == FALSE) {

					if (matchNick != str_match_wild_nocase(search_nick, user->nick))
						continue;
				}
				else {

					if (match_regex(user->nick, search_nick, nick_len) == FALSE)
						continue;
				}
			}

			if (wantTS && (positiveTS ? (NOW - user->signon < wantTS) : (NOW - user->signon > wantTS)))
				continue;

			if (noChannels && IS_NOT_NULL(user->chans))
				continue;

#ifdef ENABLE_CAPAB_NICKIP
			if ((matchCIDR != -1) && ((user->ip == 0) || (matchCIDR != cidr_match(&cidr, user->ip))))
				continue;
#endif

			TRACE_MAIN();
			if (shown++ >= 200) {

				send_cmd("523 %s :Error, /who limit of %d exceed. Please narrow your search down and try again", source, 200);
				break;
			}

			status[0] = 'H';
			status[1] = (user_is_ircop(user) ? '*' : (FlagSet(user->mode, UMODE_i) ? '%' : '\0'));
			status[2] = '\0';

			send_cmd("352 %s %s %s %s %s %s %s :%d %s", source, WHO_CHANNEL(user), user->username,
				WHO_HOST(user), user->server->name, user->nick, status, 2, user->realname);
		}
	}

end:
	send_cmd("315 %s %s :End of /WHO list.", source,
		(IS_NOT_NULL(search_host) ? search_host :
		(IS_NOT_NULL(search_nick) ? search_nick :
		(IS_NOT_NULL(search_username) ? search_username :
		(IS_NOT_NULL(search_realname) ? search_realname :
		(IS_NOT_NULL(search_server) ? search_server : "*"))))));

done:

	TRACE_MAIN();
	if (search_nick)
		mem_free(search_nick);
	if (search_realname)
		mem_free(search_realname);
	if (search_host)
		mem_free(search_host);
	if (search_username)
		mem_free(search_username);
	if (search_server)
		mem_free(search_server);
}


/*********************************************************
 * DebugServ dump support                                *
 *********************************************************/

void statserv_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	STR		command;
	BOOL	needSyntax = FALSE;


	if (IS_NULL(command = strtok(request, s_SPACE)))
		needSyntax = TRUE;

	else if (str_equals_nocase(command, "CHAN")) {

		char			*chan_name;
		ChannelStats	*cs;


		if (IS_NOT_NULL(chan_name = strtok(NULL, s_SPACE))) {

			if (IS_NOT_NULL(cs = hash_chanstats_find(chan_name))) {

				send_notice_to_user(sourceNick, callerUser, "DUMP: Stats record for \2%s\2:", chan_name);

				send_notice_to_user(sourceNick, callerUser, "Address 0x%08X, size %d B",						(unsigned long)cs, sizeof(ChannelStats) + str_len(cs->name) + 1);
				send_notice_to_user(sourceNick, callerUser, "Name: 0x%08X \2[\2%s\2]\2",						(unsigned long)cs->name, str_get_valid_display_value(cs->name));
				send_notice_to_user(sourceNick, callerUser, "Time Added C-time: %d",							cs->time_added);
				send_notice_to_user(sourceNick, callerUser, "Last Change C-time: %d",							cs->last_change);
				send_notice_to_user(sourceNick, callerUser, "Next / previous record: 0x%08X / 0x%08X",			(unsigned long)cs->next, (unsigned long)cs->prev);

				LOG_DEBUG_SNOOP("Command: DUMP STATSERV CHAN %s -- by %s (%s@%s)", chan_name, callerUser->nick, callerUser->username, callerUser->host);
			}
			else
				send_notice_to_user(sourceNick, callerUser, "DUMP: Stats record for \2%s\2 not found.", chan_name);
		}
		else
			needSyntax = TRUE;
	}
	else if (str_equals_nocase(command, "HASHTABLE")) {

		long int		hashIdx = -1, startIdx = 0, endIdx = 50, idx;
		char			*ptr;
		ChannelStats	*cs;


		if (IS_NOT_NULL(ptr = strtok(NULL, s_SPACE))) {

			char *err;
			long int value;

			value = strtol(ptr, &err, 10);

			if ((value >= 0) && (value < CHANSTATS_HASHSIZE) && (*err == '\0')) {

				hashIdx = value;

				if (IS_NOT_NULL(ptr = strtok(NULL, " "))) {

					value = strtol(ptr, &err, 10);

					if ((value >= 0) && (*err == '\0')) {

						startIdx = value;

						if (IS_NOT_NULL(ptr = strtok(NULL, " "))) {

							value = strtol(ptr, &err, 10);

							if ((value >= 0) && (*err == '\0'))
								endIdx = value;
						}
					}
				}
			}
		}

		if (hashIdx >= 0) {

			if (endIdx < startIdx)
				endIdx = (startIdx + 50);

			for (idx = 0, cs = hashtable_chanstats[hashIdx]; IS_NOT_NULL(cs) && (idx <= endIdx); ++idx, cs = cs->next) {

				if (idx >= startIdx)
					send_notice_to_user(sourceNick, callerUser, "%05d) ADR\2 0x%08X\2 - NXT\2 0x%08X\2 - PRV\2 0x%08X\2 - KEY \2%s\2", idx, (unsigned long)cs, (unsigned long)cs->next, (unsigned long)cs->prev, str_get_valid_display_value(cs->name));
			}

			LOG_DEBUG_SNOOP("Command: DUMP STATSERV HASHTABLE %d %d %d -- by %s (%s@%s)", hashIdx, startIdx, endIdx, callerUser->nick, callerUser->username, callerUser->host);
		}
		else
			needSyntax = TRUE;
	}

	#ifdef FIX_USE_MPOOL
	else if (str_equals_nocase(command, "POOLSTAT")) {

		MemoryPoolStats pstats;

		mempool_stats(stats_chan_mempool, &pstats);
		send_notice_to_user(sourceNick, callerUser, "DUMP: StatServ chanstat memory pool - Address 0x%08X, ID: %d",	(unsigned long)stats_chan_mempool, pstats.id);
		send_notice_to_user(sourceNick, callerUser, "Memory allocated / free: %d B / %d B",							pstats.memory_allocated, pstats.memory_free);
		send_notice_to_user(sourceNick, callerUser, "Items allocated / free: %d / %d",								pstats.items_allocated, pstats.items_free);
		send_notice_to_user(sourceNick, callerUser, "Items per block / block count: %d / %d",						pstats.items_per_block, pstats.block_count);
		//send_notice_to_user(sourceNick, callerUser, "Avarage use: %.2f%%",										pstats.block_avg_usage);

		LOG_DEBUG_SNOOP("Command: DUMP STATSERV POOLSTAT -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
	}
	#endif

	else
		needSyntax = TRUE;

	if (needSyntax) {

		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 STATSERV CHAN #channel");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 STATSERV HASHTABLE index [start [end]]");

		#ifdef FIX_USE_MPOOL
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 STATSERV POOLSTAT");
		#endif
	}
}


/*********************************************************
 * DebugServ memory support                              *
 *********************************************************/

unsigned long statserv_mem_report(CSTR sourceNick, const User *callerUser) {

	ChannelStats		*cs;
	ServerStats			*ss;
	unsigned long int	count = 0, mem = 0, mem_total;
	int					hashIdx;


	TRACE_FCLT(FACILITY_STATSERV_MEM_REPORT);

	send_notice_to_user(sourceNick, callerUser, "\2STATSERV\2:");


	/* Global stats */
	mem_total = (sizeof(GlobalStats) * 4);
	send_notice_to_user(sourceNick, callerUser, "Global stats: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", 4, mem_total / 1024, mem_total);


	/* Channel stats */
	HASH_FOREACH_BRANCH(hashIdx, CHANSTATS_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM(chanstats, hashIdx, cs) {

			TRACE();
			++count;
		}
	}

	mem += (sizeof(ChannelStats) * count);

	TRACE();
	send_notice_to_user(sourceNick, callerUser, "Channel stats records: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", count, mem / 1024, mem);
	mem_total += mem;


	/* Server stats */
	count = mem = 0;

	LIST_FOREACH(ss, list_serverstats) {

		TRACE();
		++count;
		mem += sizeof(ServerStats);
	}

	TRACE();
	send_notice_to_user(sourceNick, callerUser, "Server records: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", count, mem / 1024, mem);
	mem_total += mem;

	return mem_total;
}

