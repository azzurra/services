/*
*
* Azzurra IRC Services
* 
* chanserv.c - Channel Services
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
#include "../inc/datafiles.h"
#include "../inc/oper.h"
#include "../inc/users.h"
#include "../inc/timeout.h"
#include "../inc/misc.h"
#include "../inc/main.h"
#include "../inc/conf.h"
#include "../inc/cidr.h"
#include "../inc/helpserv.h"
#include "../inc/rootserv.h"
#include "../inc/chanserv.h"
#include "../inc/memoserv.h"
#include "../inc/reserved.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _channelsuspenddata ChannelSuspendData;

struct _channelsuspenddata {

	ChannelSuspendData *next;

	char name[CHANMAX];
	char who[NICKMAX];
	time_t expires;
};


/*********************************************************
 * Global variables                                      *
 *********************************************************/

#ifdef	FIX_USE_MPOOL
MemoryPool			*chandb_mempool;
//MemoryPool		*chandb_access_mempool;
//MemoryPool		*chandb_akick_mempool;
#endif


/*********************************************************
 * Local variables                                       *
 *********************************************************/

/* Channel Information (hashed by first character of chan). */
static ChannelInfo *chanlists[256];

/* Stuff to pass to the command handler. */
static Agent a_ChanServ;

/* Suspend list. */
static ChannelSuspendData *ChannelSuspendList = NULL;

/* Total number of registered channels. */
unsigned long int cs_regCount;


/*********************************************************
 * Prototypes                                            *
 *********************************************************/

static void database_insert_chan(ChannelInfo *ci);
static void delchan(ChannelInfo *ci);

static void do_set_bantype(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch);
static void do_set_desc(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch);
static void do_set_email(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch);
static void do_set_founder(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch);
static void do_set_lang(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch);
static void do_set_memolevel(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch);
static void do_set_mlock(User *callerUser, ChannelInfo *ci, char *param, CSTR accessName, const int accessMatch);
static void do_set_password(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch);
static void do_set_successor(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch);
static void do_set_topic(User *callerUser, ChannelInfo *ci, CSTR param, const int accessLevel, CSTR accessName, const int accessMatch);
static void do_set_topiclock(User *callerUser, ChannelInfo *ci, CSTR param, const int accessLevel, CSTR accessName, const int accessMatch);
static void do_set_url(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch);
static void do_set_verbose(User *callerUser, ChannelInfo *ci, CSTR param, const int accessLevel, CSTR accessName, const int accessMatch);
static void do_set_welcome(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch);

static void do_set_option(User *callerUser, ChannelInfo *ci, CSTR option, CSTR param, CSTR accessName, const int accessMatch);

static void do_akick(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_count(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_drop(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_sendcode(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_identify(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_info(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_invite(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_register(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_remove(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_set(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_unban(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_why(CSTR source, User *callerUser, ServiceCommandData *data);

static void do_ischanop(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_ischanhalfop(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_ischanvoice(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_isonchan(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_show_cmode(CSTR source, User *callerUser, ServiceCommandData *data);

static void do_authreset(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_chanset(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_close(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_delete(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_forbid(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_freeze(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_getpass(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_hold(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_level(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_listreg(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_mark(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_open(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_sendpass(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_suspend(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_unforbid(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_unfreeze(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_unhold(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_unmark(CSTR source, User *callerUser, ServiceCommandData *data);
static void do_wipe(CSTR source, User *callerUser, ServiceCommandData *data);

static void handle_voice_devoice(User *callerUser, Channel *chan, User *user_list[], int user_count, const char action);
static void handle_halfop_dehalfop(User *callerUser, Channel *chan, User *user_list[], int user_count, const char action);
static void handle_op_deop(User *callerUser, Channel *chan, User *user_list[], int user_count, const char action);
static void handle_op_voice(CSTR source, User *callerUser, ServiceCommandData *data);
static void handle_xop(CSTR source, User *callerUser, ServiceCommandData *data);

static void compact_chan_access_list(ChannelInfo *ci, const int removed);
static const char *get_chan_access_name(const int listLevel);
static void do_chan_access_LIST(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci, CSTR nick, BOOL isHelper);
static void do_chan_access_FIND(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci, CSTR mask);
static void do_chan_access_ADD(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci, CSTR nick);
static void do_chan_access_DEL(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci, CSTR nick);
static void do_chan_access_CLEAN(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci);
static void do_chan_access_explist(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci);

static void do_chan_access_WIPE(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci);
static void do_chan_access_LOCK(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci, CSTR mask, const BOOL lock);


/*********************************************************
 * Initialization/cleanup routines                       *
 *********************************************************/

void chanserv_init(void) {

	#ifdef FIX_USE_MPOOL
	chandb_mempool = mempool_create(MEMPOOL_ID_CHANDB, sizeof(ChannelInfo), MP_IPB_CHANDB, MB_IBC_CHANDB);
	//chandb_access_mempool = mempool_create(MEMPOOL_ID_CHANDB_ACCESS, sizeof(ChanAccess), MP_IPB_CHANDB_ACCESS, MB_IBC_CHANDB_ACCESS);
	//chandb_akick_mempool = mempool_create(MEMPOOL_ID_CHANDB_AKICK, sizeof(AutoKick), MP_IPB_CHANDB_AKICK, MB_IBC_CHANDB_AKICK);
	#endif

	/* Initialize the Agent info. */
	a_ChanServ.nick = s_ChanServ;
	a_ChanServ.shortNick = s_CS;
	a_ChanServ.agentID = AGENTID_CHANSERV;
	a_ChanServ.logID = logid_from_agentid(AGENTID_CHANSERV);
}

void chanserv_terminate(void) {

	#ifdef FIX_USE_MPOOL
	mempool_destroy(chandb_mempool);
	//mempool_destroy(chandb_access_mempool);
	//mempool_destroy(chandb_akick_mempool);

	chandb_mempool = NULL;
	#endif
}


/*********************************************************
 * Command handlers                                      *
 *********************************************************/

// 'A' (65 / 0)
static ServiceCommand	chanserv_commands_A[] = {
	{ "AOP",		ULEVEL_USER,			0, handle_xop },
	{ "AKICK",		ULEVEL_USER,			0, do_akick },
	{ "AUTHRESET",	ULEVEL_HOP,				0, do_authreset },
	{ NULL,			0,						0, NULL }
};
// 'B' (66 / 1)
// 'C' (67 / 2)
static ServiceCommand	chanserv_commands_C[] = {
	{ "CFOUNDER",	ULEVEL_USER,			0, handle_xop },
	{ "CF",			ULEVEL_USER,			0, handle_xop },
	{ "COFOUNDER",	ULEVEL_USER,			0, handle_xop },
	{ "COUNT",		ULEVEL_USER,			0, do_count },
	{ "CMODE",		ULEVEL_HOP,				0, do_show_cmode },
	{ "CHANSET",	ULEVEL_SRA,				0, do_chanset },
	{ "CLOSE",		ULEVEL_SA,				0, do_close },
	{ NULL,			0,						0, NULL }
};
// 'D' (68 / 3)
static ServiceCommand	chanserv_commands_D[] = {
	{ "DEOP",		ULEVEL_USER,			0, handle_op_voice },
	{ "DEHALFOP",	ULEVEL_USER,			0, handle_op_voice },
	{ "DEVOICE",	ULEVEL_USER,			0, handle_op_voice },
	{ "DROP",		ULEVEL_USER,			0, do_drop },
	{ "DELETE",		ULEVEL_SRA,				0, do_delete },
	{ NULL,			0,						0, NULL }
};
// 'E' (69 / 4)
// 'F' (70 / 5)
static ServiceCommand	chanserv_commands_F[] = {
	{ "FREEZE",		ULEVEL_SOP,				0, do_freeze },
	{ "FORBID",		ULEVEL_SA,				0, do_forbid },
	{ NULL,			0,						0, NULL }
};
// 'G' (71 / 6)
static ServiceCommand	chanserv_commands_G[] = {
	{ "GETPASS",	ULEVEL_SA,				0, do_getpass },
	{ NULL,			0,						0, NULL }
};
// 'H' (72 / 7)
static ServiceCommand	chanserv_commands_H[] = {
	{ "HELP",		ULEVEL_USER,			0, handle_help },
	{ "HALFOP",		ULEVEL_USER,			0, handle_op_voice },
	{ "HOP",		ULEVEL_USER,			0, handle_xop },
	{ "HHELP",		ULEVEL_HOP,				0, handle_help },
	{ "HOLD",		ULEVEL_SA,				0, do_hold },
	{ NULL,			0,						0, NULL }
};
// 'I' (73 / 8)
static ServiceCommand	chanserv_commands_I[] = {
	{ "IDENTIFY",	ULEVEL_USER,			0, do_identify },
	{ "INFO",		ULEVEL_USER,			0, do_info },
	{ "INVITE",		ULEVEL_USER,			0, do_invite },
	{ "ID",			ULEVEL_USER,			0, do_identify },
	{ "ISOP",		ULEVEL_HOP,				0, do_ischanop },
	{ "ISHALFOP",	ULEVEL_HOP,				0, do_ischanhalfop },
	{ "ISVOICE",	ULEVEL_HOP,				0, do_ischanvoice },
	{ "ISON",		ULEVEL_HOP,				0, do_isonchan },
	{ NULL,			0,						0, NULL }
};
// 'J' (74 / 9)
// 'K' (75 / 10)
// 'L' (76 / 11)
static ServiceCommand	chanserv_commands_L[] = {
	{ "LISTREG",	ULEVEL_SOP,				0, do_listreg },
	{ "LEVEL",		ULEVEL_SOP,				0, do_level },
	{ NULL,			0,						0, NULL }
};
// 'M' (77 / 12)
static ServiceCommand	chanserv_commands_M[] = {
	{ "MUNBAN",		ULEVEL_USER,			0, handle_masscmds },
	{ "MDEOP",		ULEVEL_USER,			0, handle_masscmds },
	{ "MDEHALFOP",	ULEVEL_USER,			0, handle_masscmds },
	{ "MODE",		ULEVEL_USER,			0, handle_mode },
	{ "MKICK",		ULEVEL_USER,			0, handle_masscmds },
	{ "MDEVOICE",	ULEVEL_USER,			0, handle_masscmds },
	{ "MARK",		ULEVEL_SRA,				0, do_mark },
	{ NULL,			0,						0, NULL }
};
// 'N' (78 / 13)
// 'O' (79 / 14)
static ServiceCommand	chanserv_commands_O[] = {
	{ "OP",			ULEVEL_USER,			0, handle_op_voice },
	{ "OHELP",		ULEVEL_OPER,			0, handle_help },
	{ "OPEN",		ULEVEL_SA,				0, do_open },
	{ NULL,			0,						0, NULL }
};
// 'P' (80 / 15)
// 'Q' (81 / 16)
// 'R' (82 / 17)
static ServiceCommand	chanserv_commands_R[] = {
	{ "REGISTER",	ULEVEL_USER,			0, do_register },
	{ "REMOVE",		ULEVEL_USER,			0, do_remove },
	{ "RESETMODES",	ULEVEL_USER,			0, handle_masscmds },
	{ NULL,			0,						0, NULL }
};
// 'S' (83 / 18)
static ServiceCommand	chanserv_commands_S[] = {
	{ "SET",		ULEVEL_USER,			0, do_set },
	{ "SOP",		ULEVEL_USER,			0, handle_xop },
	{ "SENDPASS",	ULEVEL_HOP,				0, do_sendpass },
	{ "SENDCODE",   ULEVEL_HOP,				0, do_sendcode },
	{ "SUSPEND",	ULEVEL_OPER,			0, do_suspend },	/* Opers only get to LIST */
	{ NULL,			0,						0, NULL }
};
// 'T' (84 / 19)
// 'U' (85 / 20)
static ServiceCommand	chanserv_commands_U[] = {
	{ "UNBAN",		ULEVEL_USER,			0, do_unban },
	{ "UNFREEZE",	ULEVEL_SOP,				0, do_unfreeze },
	{ "UNFORBID",	ULEVEL_SA,				0, do_unforbid },
	{ "UNMARK",		ULEVEL_SRA,				0, do_unmark },
	{ "UNHOLD",		ULEVEL_SA,				0, do_unhold },
	{ NULL,			0,						0, NULL }
};
// 'V' (86 / 21)
static ServiceCommand	chanserv_commands_V[] = {
	{ "VOP",		ULEVEL_USER,			0, handle_xop },
	{ "VOICE",		ULEVEL_USER,			0, handle_op_voice },
	{ NULL,			0,						0, NULL }
};
// 'W' (87 / 22)
static ServiceCommand	chanserv_commands_W[] = {
	{ "WHY",		ULEVEL_USER,			0, do_why },
	{ "WIPE",		ULEVEL_SA,				0, do_wipe },
	{ NULL,			0,						0, NULL }
};
// 'X' (88 / 23)
// 'Y' (89 / 24)
// 'Z' (90 / 25)

ServiceCommand	*chanserv_commands[26] = {
	chanserv_commands_A,	NULL,
	chanserv_commands_C,	chanserv_commands_D,
	NULL,					chanserv_commands_F,
	chanserv_commands_G,	chanserv_commands_H,
	chanserv_commands_I,	NULL,
	NULL,					chanserv_commands_L,
	chanserv_commands_M,	NULL,
	chanserv_commands_O,	NULL,
	NULL,					chanserv_commands_R,
	chanserv_commands_S,	NULL,
	chanserv_commands_U,	chanserv_commands_V,
	chanserv_commands_W,	NULL,
	NULL,					NULL
};


/*********************************************************
 * Public code                                           *
 *********************************************************/

/* Main ChanServ routine. */

void chanserv(CSTR source, User *callerUser, char *buf) {

	char *cmd = strtok(buf, " ");

	TRACE_MAIN_FCLT(FACILITY_CHANSERV);

	if (IS_NULL(cmd))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

	else if (cmd[0] == '\001') {

		++cmd;

		if (IS_EMPTY_STR(cmd))
			LOG_SNOOP(s_ChanServ, "Invalid CTCP from \2%s\2", source);

		else if (str_equals_nocase(cmd, "PING")) {

			send_notice_to_user(s_ChanServ, callerUser, "\001PING\001");
			LOG_SNOOP(s_ChanServ, "CTCP: PING from \2%s\2", source);
		}
		else {

			char *action = strtok(NULL, "");

			if (action) {

				action[str_len(action) - 1] = '\0';
				LOG_SNOOP(s_ChanServ, "CTCP: %s %s from \2%s\2", cmd, action, source);
			}
			else {

				cmd[str_len(cmd) - 1] = '\0';
				LOG_SNOOP(s_ChanServ, "CTCP: %s from \2%s\2", cmd, source);
			}
		}
	}
	else
		oper_invoke_agent_command(cmd, chanserv_commands, callerUser, &a_ChanServ);
}

/*********************************************************/

static void cs_translate_entry(void *chan, ChannelInfo *new_chan, int ver)
{
    switch (ver) {
	case 7:
	    {
		ChannelInfo_V7 *ci;
		ci = (ChannelInfo_V7 *)chan;

		TRACE();
		
		str_copy_checked(ci->name, new_chan->name, CHANMAX);
		str_copy_checked(ci->founder, new_chan->founder, NICKMAX);
		str_copy_checked(ci->founderpass, new_chan->founderpass, PASSMAX);
		new_chan->desc = ci->desc;
		new_chan->time_registered = ci->time_registered;
		new_chan->last_used = ci->last_used;
		new_chan->accesscount = ci->accesscount;
		new_chan->access = ci->access;
		new_chan->akickcount = ci->akickcount;
		new_chan->akick = ci->akick;
		new_chan->mlock_on = ci->mlock_on;
		new_chan->mlock_off = ci->mlock_off;
		new_chan->mlock_key = ci->mlock_key;
		new_chan->last_topic = ci->last_topic;
		str_copy_checked (ci->last_topic_setter, new_chan->last_topic_setter, NICKMAX);
		new_chan-> last_topic_time = ci->last_topic_time;
		new_chan->flags = ci->flags;
		new_chan->successor = ci->successor;
		new_chan->url = ci->url;
		new_chan->email = ci->email;
		new_chan->welcome = ci->welcome;
		new_chan->hold = ci->hold;
		new_chan->mark = ci->mark;
		new_chan->freeze = ci->freeze;
		new_chan->forbid = ci->forbid;
		new_chan->topic_allow = ci->topic_allow;
		new_chan->auth = ci->auth;
		new_chan->settings = ci->settings;
		new_chan->real_founder = ci->real_founder;
		new_chan->last_drop_request = ci->last_drop_request;
		new_chan->langID = ci->langID;
		new_chan->banType = ci->banType;
		memset(new_chan->reserved, 0, sizeof(new_chan->reserved));
	    }
	    break;

	default:
	    break;
    }
}

/* Load/save data files. */
void load_cs_dbase(void) {

	FILE *f;
	int ver, i;
	ChannelInfo *ci = NULL;
	ChannelInfo_V7 *ci_old = NULL;
	NickInfo *ni;


	TRACE_FCLT(FACILITY_CHANSERV_LOAD_CS_DB);

	cs_regCount = 0;

	if (IS_NULL(f = open_db_read(s_ChanServ, CHANSERV_DB)))
		return;

	for (i = 0; i < 256; ++i)
		chanlists[i] = NULL;

	TRACE();

	switch (ver = get_file_version(f, CHANSERV_DB)) {

	/* Backward compatibility stuff, KEEP IT */
	case 7:

		/* No need to waste time with mem_malloc/mem_free for each channel we read in */
		ci_old = mem_malloc(sizeof(ChannelInfo_V7));

		for (i = 0; i < 256; ++i) {

			while (fgetc(f) == 1) {

				#ifdef FIX_PASSWORD_SPACE
				char	*space;
				#endif

				TRACE();

				#ifdef FIX_USE_MPOOL
				ci = mempool_alloc(ChannelInfo *, chandb_mempool, FALSE);
				#else
				ci = mem_malloc(sizeof(ChannelInfo));
				#endif

				if (fread(ci_old, sizeof(ChannelInfo_V7), 1, f) != 1)
					fatal_error(FACILITY_CHANSERV_LOAD_CS_DB, __LINE__, "Read error on %s", CHANSERV_DB);

				RemoveFlag(ci_old->flags, CI_NOENTRY);
				RemoveFlag(ci_old->flags, CI_TIMEOUT);

				// Fix
				RemoveFlag(ci_old->settings, CI_ACCCESS_CFOUNDER_LOCK);

				// crashfix
				if (ci_old->langID == LANG_DE)
					ci_old->langID = LANG_ES;

				#ifdef FIX_FLAGS
				RemoveFlag(ci_old->flags, CI_NEVEROP);
				#endif

				TRACE();

				/* Fix vari */

				#ifdef FIX_BANTYPE
				ci_old->banType = 2;
				#endif

				memset(ci_old->reserved, 0, sizeof(ci_old->reserved));

				if (ci_old->accesscount == 0)
					ci_old->access = NULL;

				#ifdef FIX_PASSWORD_SPACE
				space = ci_old->founderpass;

				while (IS_NOT_NULL(space = strchr(space, ' '))) {

					*space = '_';
					++space;
				}
				#endif

				TRACE();

				ci_old->desc = read_string(f, CHANSERV_DB);

				if (ci_old->successor)
					ci_old->successor = read_string(f, CHANSERV_DB);

				if (ci_old->url)
					ci_old->url = read_string(f, CHANSERV_DB);

				if (ci_old->email)
					ci_old->email = read_string(f, CHANSERV_DB);

				if (ci_old->mlock_key)
					ci_old->mlock_key = read_string(f, CHANSERV_DB);

				if (ci_old->last_topic)
					ci_old->last_topic = read_string(f, CHANSERV_DB);

				if (ci_old->welcome)
					ci_old->welcome = read_string(f, CHANSERV_DB);

				if (ci_old->hold)
					ci_old->hold = read_string(f, CHANSERV_DB);

				if (ci_old->mark)
					ci_old->mark = read_string(f, CHANSERV_DB);

				if (ci_old->freeze)
					ci_old->freeze = read_string(f, CHANSERV_DB);

				if (ci_old->forbid)
					ci_old->forbid = read_string(f, CHANSERV_DB);

				if (ci_old->real_founder)
					ci_old->real_founder = read_string(f, CHANSERV_DB);

				#ifdef FIX_RF
				if (IS_NULL(ci_old->real_founder))
					ci_old->real_founder = str_duplicate(ci_old->founder);
				#endif

				#ifdef FIX_NICKNAME_ACCESS_COUNT
				if (IS_NOT_NULL(ni = findnick(ci_old->founder)))
					++(ni->channelcount);
				#endif

				/* Update to current version */
				cs_translate_entry(ci_old, ci, ver);

				database_insert_chan(ci);
				++cs_regCount;

				TRACE();
				if (ci->accesscount) {

					ChanAccess	*anAccess;
					int			unused_access, accessIdx;

					TRACE();
					anAccess = mem_malloc(sizeof(ChanAccess) * ci->accesscount);
					ci->access = anAccess;

					TRACE();
					if ((signed)fread(anAccess, sizeof(ChanAccess), ci->accesscount, f) != ci->accesscount)
						fatal_error(FACILITY_CHANSERV_LOAD_CS_DB, __LINE__, "Read error on %s", CHANSERV_DB);

					for (accessIdx = 0; accessIdx < ci->accesscount; ++accessIdx, ++anAccess) {

						anAccess->name = read_string(f, CHANSERV_DB);
						anAccess->creator = read_string(f, CHANSERV_DB);

						#ifdef FIX_CHANNEL_ACCESS_TYPE
						if ((anAccess->status == ACCESS_ENTRY_NICK) && (strchr(anAccess->name, '!') || strchr(anAccess->name, '@')))
							anAccess->status = ACCESS_ENTRY_MASK;
						#endif
					}

					TRACE();
					accessIdx = 0;
					anAccess = ci->access;

					unused_access = 0;

					while (accessIdx < ci->accesscount) {

						TRACE();

						#ifdef FIX_NICKNAME_ACCESS_COUNT
						ni = NULL;
						#endif

						switch (anAccess->status) {

							case ACCESS_ENTRY_FREE:
							case ACCESS_ENTRY_EXPIRED:

								TRACE();
								if (IS_NOT_NULL(anAccess->name)) {

									mem_free(anAccess->name);
									anAccess->name = NULL;
								}

								TRACE();
								if (IS_NOT_NULL(anAccess->creator)) {

									mem_free(anAccess->creator);
									anAccess->creator = NULL;
								}

								anAccess->status = ACCESS_ENTRY_FREE;
								anAccess->flags = 0;
								++unused_access;
								break;

							case ACCESS_ENTRY_NICK:

								TRACE();
								if (IS_NOT_NULL(anAccess->name)) {

									ni = findnick(anAccess->name);

									TRACE();
									if (IS_NULL(ni) || str_equals_nocase(ni->nick, ci->founder)) {

										mem_free(anAccess->name);
										anAccess->name = NULL;

										TRACE();
										if (IS_NOT_NULL(anAccess->creator)) {

											mem_free(anAccess->creator);
											anAccess->creator = NULL;
										}

										anAccess->status = ACCESS_ENTRY_FREE;
										anAccess->flags = 0;
										++unused_access;
									}
									#ifdef FIX_NICKNAME_ACCESS_COUNT
									else
										++(ni->channelcount);
									#endif
								}
								break;
						}

						++accessIdx;
						++anAccess;
					}

					if (unused_access > 0)
						compact_chan_access_list(ci, unused_access);

				} /* if (ci->accesscount) */

				TRACE();
				if (ci->akickcount) {

					AutoKick *anAkick;
					int akickIdx;

					TRACE();
					anAkick = mem_malloc(sizeof(AutoKick) * ci->akickcount);
					ci->akick = anAkick;

					if ((signed)fread(anAkick, sizeof(AutoKick), ci->akickcount, f) != ci->akickcount)
						fatal_error(FACILITY_CHANSERV_LOAD_CS_DB, __LINE__, "Read error on %s", CHANSERV_DB);

					TRACE();
					for (akickIdx = 0; akickIdx < ci->akickcount; ++akickIdx, ++anAkick) {

						anAkick->name = read_string(f, CHANSERV_DB);

						if (anAkick->reason)
							anAkick->reason = read_string(f, CHANSERV_DB);

						if (anAkick->creator)
							anAkick->creator = read_string(f, CHANSERV_DB);

						#ifdef FIX_BANTYPE
						if (anAkick->isNick > 0)
							anAkick->banType = 2;
						else
							anAkick->banType = -1;
						#endif
					}

					#ifdef SUX
					akickIdx = 0;
					anAkick = ci->akick;

					TRACE();
					while (akickIdx < ci->akickcount) {

						if (anAkick->isNick < 0) {

							TRACE();
							--(ci->akickcount);

							mem_free(anAkick->name);

							if (anAkick->reason)
								mem_free(anAkick->reason);

							if (anAkick->creator)
								mem_free(anAkick->creator);

							if (akickIdx < ci->akickcount)
								memmove(anAkick, (anAkick + 1), sizeof(AutoKick) * (ci->akickcount - akickIdx));
						}
						else {

							TRACE();
							++akickIdx;
							++anAkick;
						}
					}

					TRACE();
					if (ci->akickcount)
						ci->akick = mem_realloc(ci->akick, sizeof(AutoKick) * ci->akickcount);

					else {

						TRACE();
						mem_free(ci->akick);
						ci->akick = NULL;
					}
					#endif /* SUX */
				}		/* if (ci->akickcount) */
			}		/* while (fgetc(f) == 1) */
		}			/* for (i) */
		mem_free(ci_old);
		break;		/* case 1, etc. */

	case CHANSERV_DB_CURRENT_VERSION:

		for (i = 0; i < 256; ++i) {

			while (fgetc(f) == 1) {

				#ifdef FIX_PASSWORD_SPACE
				char	*space;
				#endif

				TRACE();
				#ifdef FIX_USE_MPOOL
				ci = mempool_alloc(ChannelInfo *, chandb_mempool, FALSE);
				#else
				ci = mem_malloc(sizeof(ChannelInfo));
				#endif

				if (fread(ci, sizeof(ChannelInfo), 1, f) != 1)
					fatal_error(FACILITY_CHANSERV_LOAD_CS_DB, __LINE__, "Read error on %s", CHANSERV_DB);

				RemoveFlag(ci->flags, CI_NOENTRY);
				RemoveFlag(ci->flags, CI_TIMEOUT);

				// Fix
				RemoveFlag(ci->settings, CI_ACCCESS_CFOUNDER_LOCK);

				// crashfix
				if (ci->langID == LANG_DE)
					ci->langID = LANG_ES;

				#ifdef FIX_FLAGS
				RemoveFlag(ci->flags, CI_NEVEROP);
				#endif

				TRACE();
				/*
				 * Password encription is currently no longer supported -int
				#ifdef USE_ENCRYPTION

				if (FlagUnset(ci->flags, CI_ENCRYPTEDPW) && FlagUnset(ci->flags, CI_FORBIDDEN)) {

					LOG_DEBUG("%s: encrypting password for %s on load", s_ChanServ, ci->name);
					
					if (encrypt_in_place(ci->founderpass, PASSSIZE) < 0)
						fatal_error(FACILITY_CHANSERV_LOAD_CS_DB, __LINE__, "%s: load database: Can't encrypt %s password!", s_ChanServ, ci->name);

					AddFlag(ci->flags, CI_ENCRYPTEDPW);
				}

				#else

				if (FlagSet(ci->flags, CI_ENCRYPTEDPW)) {

					// Bail: it makes no sense to continue with encrypted
					// passwords, since we won't be able to verify them
					fatal_error(FACILITY_CHANSERV_LOAD_CS_DB, __LINE__, "%s: load database: password for %s encrypted but encryption disabled, aborting",	s_ChanServ, ci->name);
				}

				#endif
				*/

				/* Fix vari */

				#ifdef FIX_BANTYPE
				ci->banType = 2;
				#endif

				memset(ci->reserved, 0, sizeof(ci->reserved));

				if (ci->accesscount == 0)
					ci->access = NULL;

				/* Can't guarantee the file is in a particular order...
				 * (Well, we can, but we don't have to depend on it.) */

				database_insert_chan(ci);

				#ifdef FIX_PASSWORD_SPACE
				space = ci->founderpass;

				while (IS_NOT_NULL(space = strchr(space, ' '))) {

					*space = '_';
					++space;
				}
				#endif

				TRACE();
				++cs_regCount;

				ci->desc = read_string(f, CHANSERV_DB);

				if (ci->successor)
					ci->successor = read_string(f, CHANSERV_DB);

				if (ci->url)
					ci->url = read_string(f, CHANSERV_DB);

				if (ci->email)
					ci->email = read_string(f, CHANSERV_DB);

				if (ci->mlock_key)
					ci->mlock_key = read_string(f, CHANSERV_DB);

				if (ci->last_topic)
					ci->last_topic = read_string(f, CHANSERV_DB);

				if (ci->welcome)
					ci->welcome = read_string(f, CHANSERV_DB);

				if (ci->hold)
					ci->hold = read_string(f, CHANSERV_DB);

				if (ci->mark)
					ci->mark = read_string(f, CHANSERV_DB);

				if (ci->freeze)
					ci->freeze = read_string(f, CHANSERV_DB);

				if (ci->forbid)
					ci->forbid = read_string(f, CHANSERV_DB);

				if (ci->real_founder)
					ci->real_founder = read_string(f, CHANSERV_DB);

				#ifdef FIX_RF
				if (IS_NULL(ci->real_founder))
					ci->real_founder = str_duplicate(ci->founder);
				#endif

				#ifdef FIX_NICKNAME_ACCESS_COUNT
				if (IS_NOT_NULL(ni = findnick(ci->founder)))
					++(ni->channelcount);
				#endif

				TRACE();
				if (ci->accesscount) {

					ChanAccess	*anAccess;
					int			unused_access, accessIdx;

					TRACE();
					anAccess = mem_malloc(sizeof(ChanAccess) * ci->accesscount);
					ci->access = anAccess;

					TRACE();
					if ((signed)fread(anAccess, sizeof(ChanAccess), ci->accesscount, f) != ci->accesscount)
						fatal_error(FACILITY_CHANSERV_LOAD_CS_DB, __LINE__, "Read error on %s", CHANSERV_DB);

					for (accessIdx = 0; accessIdx < ci->accesscount; ++accessIdx, ++anAccess) {

						anAccess->name = read_string(f, CHANSERV_DB);
						anAccess->creator = read_string(f, CHANSERV_DB);

						#ifdef FIX_CHANNEL_ACCESS_TYPE
						if ((anAccess->status == ACCESS_ENTRY_NICK) && (strchr(anAccess->name, '!') || strchr(anAccess->name, '@')))
							anAccess->status = ACCESS_ENTRY_MASK;
						#endif
					}

					TRACE();
					accessIdx = 0;
					anAccess = ci->access;

					unused_access = 0;

					while (accessIdx < ci->accesscount) {

						TRACE();

						#ifdef FIX_NICKNAME_ACCESS_COUNT
						ni = NULL;
						#endif

						switch (anAccess->status) {

							case ACCESS_ENTRY_FREE:
							case ACCESS_ENTRY_EXPIRED:

								TRACE();
								if (IS_NOT_NULL(anAccess->name)) {

									mem_free(anAccess->name);
									anAccess->name = NULL;
								}

								TRACE();
								if (IS_NOT_NULL(anAccess->creator)) {

									mem_free(anAccess->creator);
									anAccess->creator = NULL;
								}

								anAccess->status = ACCESS_ENTRY_FREE;
								anAccess->flags = 0;
								++unused_access;
								break;

							case ACCESS_ENTRY_NICK:

								TRACE();
								if (IS_NOT_NULL(anAccess->name)) {

									ni = findnick(anAccess->name);

									TRACE();
									if (IS_NULL(ni) || str_equals_nocase(ni->nick, ci->founder)) {

										mem_free(anAccess->name);
										anAccess->name = NULL;

										TRACE();
										if (IS_NOT_NULL(anAccess->creator)) {

											mem_free(anAccess->creator);
											anAccess->creator = NULL;
										}

										anAccess->status = ACCESS_ENTRY_FREE;
										anAccess->flags = 0;
										++unused_access;
									}
									#ifdef FIX_NICKNAME_ACCESS_COUNT
									else
										++(ni->channelcount);
									#endif
								}
								break;
						}

						++accessIdx;
						++anAccess;
					}

					if (unused_access > 0)
						compact_chan_access_list(ci, unused_access);

				} /* if (ci->accesscount) */

				TRACE();
				if (ci->akickcount) {

					AutoKick *anAkick;
					int akickIdx;

					TRACE();
					anAkick = mem_malloc(sizeof(AutoKick) * ci->akickcount);
					ci->akick = anAkick;

					if ((signed)fread(anAkick, sizeof(AutoKick), ci->akickcount, f) != ci->akickcount)
						fatal_error(FACILITY_CHANSERV_LOAD_CS_DB, __LINE__, "Read error on %s", CHANSERV_DB);

					TRACE();
					for (akickIdx = 0; akickIdx < ci->akickcount; ++akickIdx, ++anAkick) {

						anAkick->name = read_string(f, CHANSERV_DB);

						if (anAkick->reason)
							anAkick->reason = read_string(f, CHANSERV_DB);

						if (anAkick->creator)
							anAkick->creator = read_string(f, CHANSERV_DB);

						#ifdef FIX_BANTYPE
						if (anAkick->isNick > 0)
							anAkick->banType = 2;
						else
							anAkick->banType = -1;
						#endif
					}

					#ifdef SUX
					akickIdx = 0;
					anAkick = ci->akick;

					TRACE();
					while (akickIdx < ci->akickcount) {

						if (anAkick->isNick < 0) {

							TRACE();
							--(ci->akickcount);

							mem_free(anAkick->name);

							if (anAkick->reason)
								mem_free(anAkick->reason);

							if (anAkick->creator)
								mem_free(anAkick->creator);

							if (akickIdx < ci->akickcount)
								memmove(anAkick, (anAkick + 1), sizeof(AutoKick) * (ci->akickcount - akickIdx));
						}
						else {

							TRACE();
							++akickIdx;
							++anAkick;
						}
					}

					TRACE();
					if (ci->akickcount)
						ci->akick = mem_realloc(ci->akick, sizeof(AutoKick) * ci->akickcount);

					else {

						TRACE();
						mem_free(ci->akick);
						ci->akick = NULL;
					}
					#endif /* SUX */
				}		/* if (ci->akickcount) */
			}		/* while (fgetc(f) == 1) */
		}			/* for (i) */
		break;		/* case 1, etc. */

	default:
		fatal_error(FACILITY_CHANSERV_LOAD_CS_DB, __LINE__, "Unsupported version number (%d) on %s", i, CHANSERV_DB);

	}	/* switch (version) */

	TRACE();
	close_db(f, CHANSERV_DB);
}

/*********************************************************/

void save_single_chanlist(int idx, FILE *f) {

	ChannelInfo *ci;
	int accessIdx, akickIdx;


	TRACE_FCLT(FACILITY_CHANSERV_SAVE_SINGLE_CHANLIST);

	for (ci = chanlists[idx]; IS_NOT_NULL(ci); ci = ci->next) {

		TRACE();
		fputc(1, f);

		if (fwrite(ci, sizeof(ChannelInfo), 1, f) != 1)
			fatal_error(FACILITY_CHANSERV_SAVE_SINGLE_CHANLIST, __LINE__, "Write error on %s", CHANSERV_DB);

		TRACE();
		write_string(ci->desc ? ci->desc : "", f, CHANSERV_DB);

		if (ci->successor)
			write_string(ci->successor, f, CHANSERV_DB);

		if (ci->url)
			write_string(ci->url, f, CHANSERV_DB);

		if (ci->email)
			write_string(ci->email, f, CHANSERV_DB);

		if (ci->mlock_key)
			write_string(ci->mlock_key, f, CHANSERV_DB);

		if (ci->last_topic)
			write_string(ci->last_topic, f, CHANSERV_DB);

		if (ci->welcome)
			write_string(ci->welcome, f, CHANSERV_DB);

		if (ci->hold)
			write_string(ci->hold, f, CHANSERV_DB);

		if (ci->mark)
			write_string(ci->mark, f, CHANSERV_DB);

		if (ci->freeze)
			write_string(ci->freeze, f, CHANSERV_DB);

		if (ci->forbid)
			write_string(ci->forbid, f, CHANSERV_DB);

		if (ci->real_founder)
			write_string(ci->real_founder, f, CHANSERV_DB);

		if (ci->accesscount) {

			ChanAccess *anAccess = ci->access;

			TRACE();
			if ((signed)fwrite(anAccess, sizeof(ChanAccess), ci->accesscount, f) != ci->accesscount)
				fatal_error(FACILITY_CHANSERV_SAVE_SINGLE_CHANLIST, __LINE__, "Write error on %s", CHANSERV_DB);

			for (accessIdx = 0; accessIdx < ci->accesscount; ++accessIdx, ++anAccess) {

				TRACE();
				if (anAccess->status != ACCESS_ENTRY_FREE) {

					write_string(anAccess->name, f, CHANSERV_DB);
					write_string(anAccess->creator, f, CHANSERV_DB);
				}
				else {

					write_string("", f, CHANSERV_DB);
					write_string("", f, CHANSERV_DB);
				}
			}
		}

		TRACE();
		if (ci->akickcount) {

			AutoKick *anAkick = ci->akick;

			TRACE();
			if ((signed)fwrite(anAkick, sizeof(AutoKick), ci->akickcount, f) != ci->akickcount)
				fatal_error(FACILITY_CHANSERV_SAVE_SINGLE_CHANLIST, __LINE__, "Write error on %s", CHANSERV_DB);

			for (akickIdx = 0; akickIdx < ci->akickcount; ++akickIdx, ++anAkick) {

				TRACE();
				write_string(anAkick->name, f, CHANSERV_DB);

				TRACE();
				if (anAkick->reason)
					write_string(anAkick->reason, f, CHANSERV_DB);

				if (anAkick->creator)
					write_string(anAkick->creator, f, CHANSERV_DB);
			}
		}
	}		/* for (chanlists[i]) */

	TRACE();
	fputc(0, f);
}

/*********************************************************/

void save_cs_dbase(void) {

	FILE *f;
	int idx;

	TRACE_FCLT(FACILITY_CHANSERV_SAVE_CS_DB);

	if (!(f = open_db_write(s_ChanServ, CHANSERV_DB, CHANSERV_DB_CURRENT_VERSION))) {

		LOG_SNOOP(s_OperServ, "Error creating database %s", CHANSERV_DB);
		LOG_DEBUG("Error creating database %s", CHANSERV_DB);
		return;
	}

	TRACE();
	for (idx = 0; idx < 256; ++idx)
		save_single_chanlist(idx, f);

	TRACE();
	close_db(f, CHANSERV_DB);
}

/*********************************************************/

void load_suspend_db(void) {

	FILE *f;
	ChannelSuspendData *name;
	int i;

	TRACE_FCLT(FACILITY_CHANSERV_LOAD_SUSPEND_DB);

	ChannelSuspendList = NULL;
	
	TRACE();
	if (!(f = open_db_read(s_OperServ, SUSPEND_DB))) {

		LOG_DEBUG("OS Rsv - impossibile aprire il database %s", SUSPEND_DB);
		return;
	}

	if ((i = get_file_version(f, SUSPEND_DB)) > FILE_VERSION_MAX)
		fatal_error(FACILITY_CHANSERV_LOAD_SUSPEND_DB, __LINE__, "Unsupported version number (%d) on %s", i, SUSPEND_DB);

	i = 0;
	while (fgetc(f) == 1) {

		++i;
		name = mem_malloc(sizeof(ChannelSuspendData));

		TRACE();
		if (fread(name, sizeof(ChannelSuspendData), 1, f) != 1)
			fatal_error(FACILITY_CHANSERV_LOAD_SUSPEND_DB, __LINE__, "Read error on %s at entry %d", SUSPEND_DB, i);

		TRACE();
		name->next = ChannelSuspendList;
		ChannelSuspendList = name;
	}
	
	TRACE();
	close_db(f, SUSPEND_DB);
}

/*********************************************************/

void save_suspend_db(void) {

	FILE *f;
	ChannelSuspendData *name;
	int version;

	TRACE_FCLT(FACILITY_CHANSERV_SAVE_SUSPEND_DB);

	if (!(f = open_db_read(s_OperServ, SUSPEND_DB))) {
		version = FILE_VERSION_MAX;
	} else {
		version = get_file_version(f, SUSPEND_DB);
		close_db(f, SUSPEND_DB);
	}

	if (!(f = open_db_write(s_OperServ, SUSPEND_DB, version))) {

		LOG_SNOOP(s_OperServ, "Error creating database %s", SUSPEND_DB);
		LOG_DEBUG("Error creating database %s", SUSPEND_DB);
		return;
	}

	name = ChannelSuspendList;

	TRACE();
	while (IS_NOT_NULL(name)) {

		fputc(1, f);
		if (fwrite(name, sizeof(ChannelSuspendData), 1, f) != 1)
			fatal_error(FACILITY_CHANSERV_LOAD_SUSPEND_DB, __LINE__, "Error writing on %s", SUSPEND_DB);

		TRACE();

		name = name->next;
	}

	TRACE();
	fputc(0, f);
	close_db(f, SUSPEND_DB);
}

/*********************************************************/

/* Remove all channels which have expired. */
void expire_chans() {

	ChannelInfo *ci, *next;
	NickInfo *ni;
	int i;
	const time_t expire_limit = (NOW - (CONF_CHANNEL_EXPIRE * ONE_DAY));
	long count = 0, rcount = 0, xcount = 0;

	TRACE_FCLT(FACILITY_CHANSERV_EXPIRE_CHANS);

	if (CONF_SET_NOEXPIRE)
		return;

	for (i = 0; i < 256; ++i) {

		for (ci = chanlists[i]; ci; ci = next) {

			TRACE();
			++count;
			next = ci->next;

			if ((ci->last_used < expire_limit) && FlagUnset(ci->flags, CI_FORBIDDEN) && FlagUnset(ci->flags, CI_HELDCHAN)) {

				if (FlagSet(ci->flags, CI_CLOSED)) {

					RemoveFlag(ci->flags, CI_CLOSED);

					if (IS_NOT_NULL(ni = findnick(ci->founder))) {

						if (ni->channelcount > 0)
							--(ni->channelcount);
						else
							log_error(FACILITY_CHANSERV_DELCHAN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED,
								"%s in expire_chans(): Nickname record %s (founder) has a negative channelcount value", s_ChanServ, ni->nick);
					}

					memset(&(ci->founder), 0, sizeof(ci->founder));
					memset(&(ci->founderpass), 0, sizeof(ci->founderpass));
					memset(&(ci->last_topic_setter), 0, sizeof(ci->last_topic_setter));

					if (ci->desc)
						mem_free(ci->desc);
					ci->desc = NULL;

					if (ci->successor)
						mem_free(ci->successor);
					ci->successor = NULL;

					if (ci->url)
						mem_free(ci->url);
					ci->url = NULL;

					if (ci->email)
						mem_free(ci->email);
					ci->email = NULL;

					if (ci->real_founder)
						mem_free(ci->real_founder);
					ci->real_founder = NULL;

					if (ci->mlock_key)
						mem_free(ci->mlock_key);
					ci->mlock_key = NULL;

					if (ci->last_topic)
						mem_free(ci->last_topic);
					ci->last_topic = NULL;

					if (ci->access) {

						ChanAccess *anAccess;

						for (anAccess = ci->access, i = 0; (i < ci->accesscount) && IS_NOT_NULL(anAccess); ++anAccess, ++i) {

							TRACE();
							if ((anAccess->status != ACCESS_ENTRY_EXPIRED) && (ni = findnick(anAccess->name))) {

								if (ni->channelcount > 0)
									--(ni->channelcount);
								else
									log_error(FACILITY_CHANSERV_DELCHAN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED,
										"%s in delchan(): Nickname record %s has a negative channelcount value", s_ChanServ, ni->nick);
							}

							if (anAccess->name)
								mem_free(anAccess->name);

							if (anAccess->creator)
								mem_free(anAccess->creator);
						}

						mem_free(ci->access);

						ci->access = NULL;
					}

					ci->accesscount = 0;

					TRACE();
					for (i = 0; i < ci->akickcount; ++i) {

						mem_free(ci->akick[i].name);

						if (ci->akick[i].reason)
							mem_free(ci->akick[i].reason);

						if (ci->akick[i].creator)
							mem_free(ci->akick[i].creator);
					}

					ci->akickcount = 0;

					if (ci->akick)
						mem_free(ci->akick);
					ci->akick = NULL;

					if (ci->welcome)
						mem_free(ci->welcome);
					ci->welcome = NULL;

					if (ci->hold)
						mem_free(ci->hold);
					ci->hold = NULL;

					if (ci->mark)
						mem_free(ci->mark);
					ci->mark = NULL;

					if (ci->freeze)
						mem_free(ci->freeze);
					ci->freeze = NULL;

					ci->mlock_on = 0;
					ci->mlock_off = 0;
					ci->mlock_limit = 0;
					ci->last_topic_time = 0;
					ci->auth = 0;
					ci->topic_allow = 0;
					ci->last_drop_request = 0;
					ci->settings = 0;

					ci->flags = CI_FORBIDDEN;

					if (ci->forbid)
						mem_free(ci->forbid);
					ci->forbid = str_duplicate(s_ChanServ);

					continue;
				}

				++xcount;

				TRACE();
				LOG_SNOOP(s_OperServ, "CS X %s [Founder: %s]", ci->name, ci->founder);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "X %s [Founder: %s]", ci->name, ci->founder);
				LOG_DEBUG("Expiring channel %s", ci->name); 

				delchan(ci);
			}
			else if (CONF_SEND_REMINDER && CONF_USE_EMAIL && FlagUnset(ci->flags, CI_REMIND) && ((ni = findnick(ci->founder)))
				&& FlagUnset(ci->flags, CI_FORBIDDEN) && ni->email
				&& (expire_limit >= ci->last_used - (ONE_DAY * CONF_SEND_REMINDER)) && FlagUnset(ci->flags, CI_CLOSED)
				&& FlagUnset(ci->flags, CI_HELDCHAN) && FlagUnset(ci->flags, CI_FROZEN)) {

				FILE *mailfile;

				AddFlag(ci->flags, CI_REMIND);

				LOG_SNOOP(s_OperServ, "CS X+ %s", ci->name);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "X+ %s", ci->name);
				++rcount;

				if (IS_NOT_NULL(mailfile = fopen("csremind.txt", "w"))) {

					fprintf(mailfile, "From: %s <%s>\n", CONF_NETWORK_NAME, CONF_RETURN_EMAIL);
					fprintf(mailfile, "To: %s\n", ni->email);

					fprintf(mailfile, lang_msg(GetNickLang(ni), CS_REMIND_EMAIL_SUBJECT), CONF_NETWORK_NAME);

					fprintf(mailfile, lang_msg(GetNickLang(ni), CS_REMIND_EMAIL_TEXT), ci->name, CONF_SEND_REMINDER, CONF_NETWORK_NAME);

					fclose(mailfile);

					snprintf(misc_buffer, MISC_BUFFER_SIZE, "%s -f %s -t < csremind.txt", CONF_SENDMAIL_PATH, CONF_RETURN_EMAIL);
					system(misc_buffer);

					snprintf(misc_buffer, MISC_BUFFER_SIZE, "rm -f csremind.txt");
					system(misc_buffer);
				}
				else
					log_error(FACILITY_CHANSERV_EXPIRE_CHANS, __LINE__, LOG_TYPE_ERROR_RTL, LOG_SEVERITY_ERROR_SKIPPED, "expire_chans(): unable to create csremind.txt");
			}
		}
	}

	TRACE();
	if (CONF_DISPLAY_UPDATES)
		send_globops(NULL, "Completed Channel Expire (\2%d\2/\2%d\2/\2%d\2)", xcount, rcount, count);
}

/*********************************************************/

void chanserv_daily_expire() {

	ChannelInfo *ci, *next;
	NickInfo *ni;
	int i;
	const time_t expire_limit = (NOW - (CONF_CHANNEL_EXPIRE * ONE_DAY));
	const time_t expire_drop = (NOW - ONE_DAY);
	long count = 0;

	TRACE_FCLT(FACILITY_CHANSERV_EXPIRE_CHANS);

	for (i = 0; i < 256; ++i) {

		for (ci = chanlists[i]; ci; ci = next) {

			++count;
			next = ci->next;

			if (FlagSet(ci->flags, CI_FORBIDDEN))
				continue;

			if (IS_NOT_NULL(ni = findnick(ci->founder))) {

				/* Se non c'e' il founder il chan verra' droppato, inutile controllare il real founder. */

				if ((ci->time_registered < expire_limit) &&
					(strstr(ci->real_founder, ci->founder) != ci->real_founder)) {

					size_t	size;

					TRACE();
					mem_free(ci->real_founder);
					size = (str_len(ci->founder) + str_len(ni->last_usermask) + 4) * sizeof(char);
					ci->real_founder = mem_calloc(1, size);

					snprintf(ci->real_founder, size, "%s (%s)", ci->founder, ni->last_usermask);
				}
			}

			if ((ci->last_drop_request != 0) && (expire_drop >= ci->last_drop_request)) {

				ci->last_drop_request = 0;
				ci->auth = 0;
			}
		}
	}

	TRACE();
	if (CONF_DISPLAY_UPDATES)
		send_globops(NULL, "Completed Daily Channel Expire (Channels in database: \2%d\2)", count);
}


/*********************************************************
 * ChanServ private routines.                            *
 *********************************************************/

/* Insert a channel into the database. */
static void database_insert_chan(ChannelInfo *item) {

	ChannelInfo	*branch_head;
	int			branch_name;

	TRACE_FCLT(FACILITY_CHANSERV_DATABASE_INSERT_CHAN);

	if (IS_NULL(item)) {

		log_error(FACILITY_CHANSERV_DATABASE_INSERT_CHAN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "database_insert_chan()", s_LOG_NULL, "item");

		return;
	}

	branch_name = str_char_tolower(item->name[1]);
	TRACE();
	branch_head = chanlists[branch_name];
	chanlists[branch_name] = item;

	TRACE();
	item->next = branch_head;
	item->prev = NULL;

	if (IS_NOT_NULL(branch_head))
		branch_head->prev = item;
}

/*********************************************************/

/* Add a channel to the database. Returns a pointer to the new ChannelInfo
 * structure if the channel was successfully registered, NULL otherwise.
 * Assumes channel does not already exist. */

static ChannelInfo *makechan(CSTR chan) {
	
	ChannelInfo *ci;
	
	TRACE_FCLT(FACILITY_CHANSERV_MAKECHAN);

	#ifdef FIX_USE_MPOOL
	ci = mempool_alloc(ChannelInfo*, chandb_mempool, TRUE);
	#else
	ci = mem_calloc(1, sizeof(ChannelInfo));
	#endif

	TRACE();
	str_copy_checked(chan, ci->name, CHANMAX);
	ci->time_registered = NOW;
	ci->banType = 2;

	database_insert_chan(ci);
	++cs_regCount;
	return ci;
}

/*********************************************************/

/* Remove a channel from the ChanServ database. Return 1 on success, 0 otherwise. */
static void delchan(ChannelInfo *ci) {

	Channel *chan;
	NickInfo *ni;
	int i;

	TRACE_FCLT(FACILITY_CHANSERV_DELCHAN);

	if (IS_NOT_NULL(ni = findnick(ci->founder))) {

		if (ni->channelcount > 0)
			--(ni->channelcount);
		else
			log_error(FACILITY_CHANSERV_DELCHAN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED,
				"%s in delchan(): Nickname record %s (founder) has a negative channelcount value", s_ChanServ, ni->nick);
	}

	if (IS_NOT_NULL(chan = hash_channel_find(ci->name))) {

		if (FlagSet(chan->mode, CMODE_r)) {

			send_cmd(":%s MODE %s -r", s_ChanServ, ci->name);
			RemoveFlag(chan->mode, CMODE_r);
		}

		chan->ci = NULL;
	}

	if (FlagSet(ci->flags, CI_TIMEOUT)) {

		if (!timeout_remove(toChanServ, TOTYPE_ANYSUBTYPE, (unsigned long) ci))
			log_error(FACILITY_CHANSERV_DELCHAN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING, 
				"delchan(): Timeout not found for %s (ChanServ/Any)", ci->name);

		if (IS_NOT_NULL(chan)) {

			send_cmd(":%s MODE %s -b *!*@*", s_ChanServ, ci->name);
			chan_remove_ban(chan, "*!*@*");

			send_PART(s_ChanServ, ci->name);
		}
	}

	user_remove_chanid(ci);

	TRACE();
	if (ci->next)
		ci->next->prev = ci->prev;

	if (ci->prev)
		ci->prev->next = ci->next;
	else
		chanlists[str_char_tolower(ci->name[1])] = ci->next;

	if (ci->desc)
		mem_free(ci->desc);

	if (ci->successor)
		mem_free(ci->successor);

	if (ci->url)
		mem_free(ci->url);

	if (ci->email)
		mem_free(ci->email);

	if (ci->real_founder)
		mem_free(ci->real_founder);

	if (ci->mlock_key)
		mem_free(ci->mlock_key);

	if (ci->last_topic)
		mem_free(ci->last_topic);

	if (ci->access) {

		ChanAccess *anAccess;

		for (anAccess = ci->access, i = 0; (i < ci->accesscount) && IS_NOT_NULL(anAccess); ++anAccess, ++i) {

			TRACE();
			if ((anAccess->status != ACCESS_ENTRY_EXPIRED) && (ni = findnick(anAccess->name))) {

				if (ni->channelcount > 0)
					--(ni->channelcount);
				else
					log_error(FACILITY_CHANSERV_DELCHAN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED,
						"%s in delchan(): Nickname record %s has a negative channelcount value", s_ChanServ, ni->nick);
			}

			if (anAccess->name)
				mem_free(anAccess->name);

			if (anAccess->creator)
				mem_free(anAccess->creator);
		}

		mem_free(ci->access);
	}	

	TRACE();
	for (i = 0; i < ci->akickcount; ++i) {

		mem_free(ci->akick[i].name);

		if (ci->akick[i].reason)
			mem_free(ci->akick[i].reason);

		if (ci->akick[i].creator)
			mem_free(ci->akick[i].creator);
	}

	if (ci->akick)
		mem_free(ci->akick);

	if (ci->welcome)
		mem_free(ci->welcome);

	if (ci->hold)
		mem_free(ci->hold);

	if (ci->mark)
		mem_free(ci->mark);

	if (ci->freeze)
		mem_free(ci->freeze);

	if (ci->forbid)
		mem_free(ci->forbid);

	TRACE();
	#ifdef FIX_USE_MPOOL
	mempool_free(chandb_mempool, ci);
	#else
	mem_free(ci);
	#endif

	--cs_regCount;
}

/*********************************************************/

/* Return the ChannelInfo structure for the given channel, or NULL if the channel isn't registered. */
ChannelInfo *cs_findchan(CSTR chan) {

	ChannelInfo *ci;

	TRACE_FCLT(FACILITY_CHANSERV_CS_FINDCHAN);

	if (chan) {

		for (ci = chanlists[str_char_tolower(chan[1])]; ci; ci = ci->next) {

			if (str_equals_nocase(ci->name, chan))
				return ci;
		}
	}

	return NULL;
}

/*********************************************************/

static __inline__ void link_channel(User *user, ChannelInfo *ci) {

	ChanInfoListItem *item;


	item = mem_malloc(sizeof(ChanInfoListItem));

	item->next = user->founder_chans;
	item->prev = NULL;

	if (user->founder_chans)
		user->founder_chans->prev = item;

	user->founder_chans = item;

	item->ci = ci;
}

/*********************************************************/

/* Tiny helper routine to get ChanServ out of a channel after it went in. */
__inline__ void timeout_leave(Timeout *to) {

	ChannelTimeoutData	*data;

	TRACE_FCLT(FACILITY_CHANSERV_TIMEOUT_LEAVE);

	data = (ChannelTimeoutData*) to->data;

	if (IS_NOT_NULL(data)) {

		if (data->type == CTOD_CHAN_RECORD) {

			ChannelInfo	*ci = data->info.record;

			if (IS_NOT_NULL(ci)) {

				send_PART(s_ChanServ, ci->name);
				RemoveFlag(ci->flags, CI_NOENTRY);
				RemoveFlag(ci->flags, CI_TIMEOUT);
			}
		}
		else
			send_PART(s_ChanServ, data->info.name);
	}
}

/*********************************************************/

__inline__ void timeout_unban(Timeout *to) {

	ChannelTimeoutData	*data;

	TRACE_FCLT(FACILITY_CHANSERV_TIMEOUT_UNBAN);

	data = (ChannelTimeoutData*) to->data;

	if (IS_NOT_NULL(data)) {

		Channel *chan;

		if (data->type == CTOD_CHAN_RECORD) {

			ChannelInfo	*ci = data->info.record;

			if (IS_NOT_NULL(ci))
				send_cmd(":%s MODE %s -b *!*@*", s_ChanServ, ci->name);

			/* non togliere CI_TIMEOUT -> lo toglie timeout_leave() */

			chan = hash_channel_find(ci->name);
		}
		else {

			send_cmd(":%s MODE %s -b *!*@*", s_ChanServ, data->info.name);

			chan = hash_channel_find(data->info.name);
		}

		if (IS_NOT_NULL(chan))
			chan_remove_ban(chan, "*!*@*");
	}
}

/*********************************************************/

void chanserv_dispose_timeout_data(void *data) {

	ChannelTimeoutData	*ctd;

	ctd = (ChannelTimeoutData*) data;

	if (IS_NOT_NULL(ctd)) {

		if (ctd->type == CTOD_CHAN_NAME)
			mem_free(ctd->info.name);

		mem_free(ctd);
	}
}

/*********************************************************/

static int masskick_channel(CSTR chan_name, LANG_MSG_ID reason) {

	Channel *chan;
	int userCount = 0;


	if (IS_NOT_NULL(chan = hash_channel_find(chan_name))) {

		UserListItem		*item, *next_item;
		ChannelTimeoutData	*data1, *data2;
		ChannelInfo			*ci = chan->ci;

		if (FlagUnset(chan->mode, CMODE_CS)) {

			send_SJOIN(s_ChanServ, chan_name);
			AddFlag(chan->mode, CMODE_CS);
		}

		send_cmd(":%s MODE %s +b *!*@* %lu", s_ChanServ, chan_name, NOW);

		for (item = chan->users; item; item = next_item) {

			next_item = item->next;

			TRACE_MAIN();
			if (user_is_services_agent(item->user))
				continue;

			++userCount;

			TRACE_MAIN();
			send_cmd(":%s KICK %s %s :%s", s_ChanServ, chan_name, item->user->nick, lang_msg(item->user->current_lang, reason));
			user_handle_services_kick(chan_name, item->user);
		}

		TRACE_MAIN();
		data1 = mem_malloc(sizeof(ChannelTimeoutData));
		data2 = mem_malloc(sizeof(ChannelTimeoutData));

		if (IS_NOT_NULL(ci)) {

			data1->type = data2->type = CTOD_CHAN_RECORD;
			data1->info.record = data2->info.record = ci;
			AddFlag(ci->flags, CI_TIMEOUT);

			user_remove_chanid(ci);

			AddFlag(ci->flags, CI_TIMEOUT);
		}
		else {

			data1->type = data2->type = CTOD_CHAN_NAME;
			data1->info.name = str_duplicate(chan_name);
			data2->info.name = str_duplicate(chan_name);
		}

		TRACE_MAIN();
		timeout_add(toChanServ, TOTYPE_CHANSERV_UNBAN, ci ? (unsigned long)ci : (unsigned long)data1->info.name, CONF_CHANNEL_INHABIT, FALSE, timeout_unban, (void *)data1);
		timeout_add(toChanServ, TOTYPE_CHANSERV_LEAVE, ci ? (unsigned long)ci : (unsigned long)data2->info.name, CONF_CHANNEL_INHABIT + 1, FALSE, timeout_leave, (void *)data2);
	}

	return userCount;
}

/*********************************************************/

/* Check the current modes on a channel; if they conflict with a mode lock, fix them. */
void check_modelock(Channel *chan, User *changedBy) {

	char modebuf[48];
	unsigned int idx, modeIdx = 0;
	long int modes;
	BOOL addKey = FALSE, removeKey = FALSE, addLimit = FALSE;
	ChannelInfo *ci;

	TRACE_FCLT(FACILITY_CHANSERV_CHECK_MODELOCK);

	if (IS_NULL(chan) || IS_NULL((ci = chan->ci)) || FlagSet(ci->flags, CI_FROZEN))
		return;

	TRACE();

	if (changedBy) {

		if (user_is_services_agent(changedBy) || user_is_services_client(changedBy))
			return;

		else {

			int accessLevel;

			accessLevel = get_access(changedBy, ci, NULL, NULL, NULL);

			if (accessLevel >= CS_ACCESS_COFOUNDER)
				return;
		}
	}

	/* Compute modes to be removed. */
	modes = chan->mode & ci->mlock_off;

	if (modes) {

		modebuf[modeIdx++] = '-';

		/* Loop through the modes, remove flags as necessary. */
		for (idx = 0; idx < known_cmodes_count; ++idx) {

			if (FlagSet(modes, known_cmodes[idx].mode)) {

				if (known_cmodes[idx].letter == 'k')
					removeKey = TRUE;

				RemoveFlag(chan->mode, known_cmodes[idx].mode);

				modebuf[modeIdx++] = known_cmodes[idx].letter;
			}
		}

		if (modebuf[modeIdx - 1] == '-')
			modeIdx = 0;
	}

	/* Compute modes to add. */
	modes = ~chan->mode & ci->mlock_on;

	/* Make sure we update the key if one was set and a new (different) one is mlocked. */
	if (FlagUnset(modes, CMODE_k) && IS_NOT_NULL(ci->mlock_key) && IS_NOT_NULL(chan->key) && str_not_equals(chan->key, ci->mlock_key))
		AddFlag(modes, CMODE_k);

	/* Also make sure we update the limit. */
	if (FlagUnset(modes, CMODE_l) && (ci->mlock_limit > 0) && (ci->mlock_limit != chan->limit))
		AddFlag(modes, CMODE_l);

	if (modes) {

		modebuf[modeIdx++] = '+';

		/* Loop through the modes, add flags as necessary. */
		for (idx = 0; idx < known_cmodes_count; ++idx) {

			if (FlagSet(modes, known_cmodes[idx].mode)) {

				switch (known_cmodes[idx].letter) {

					case 'l':
						chan->limit = ci->mlock_limit;
						addLimit = TRUE;
						break;

					case 'k':
						addKey = TRUE;
						break;
				}

				AddFlag(chan->mode, known_cmodes[idx].mode);

				modebuf[modeIdx++] = known_cmodes[idx].letter;
			}
		}

		if (modebuf[modeIdx - 1] == '+')
			--modeIdx;
	}

	/* Some sanity checks (to be removed?). */
	if (addKey && removeKey)
		LOG_DEBUG_SNOOP("check_modelock() for channel %s has both addKey and removeKey!");

	/* No changes? Don't do anything. */
	if (modeIdx == 0)
		return;

	modebuf[modeIdx] = '\0';

	if (FlagUnset(chan->mode, CMODE_l))
		chan->limit = 0;

	send_chan_MODE(s_ChanServ, chan->name, modebuf, (addLimit ? chan->limit : 0), (removeKey ? chan->key : (addKey ? ci->mlock_key : NULL)));

	/* Take care of the key. */
	if (removeKey) {

		if (chan->key)
			mem_free(chan->key);
		chan->key = NULL;
	}
	else if (addKey) {

		if (chan->key)
			mem_free(chan->key);

		chan->key = str_duplicate(ci->mlock_key);
	}
}

/*********************************************************/

/* Check whether a user is allowed to be opped on a channel; if they
* aren't, deop them. If serverop is 1, the +o was done by a server.
* Return 1 if the user is allowed to be opped, 0 otherwise. */

BOOL check_valid_op(const User *user, ChannelInfo *ci, int serverop) {

	int accessLevel;

	TRACE_FCLT(FACILITY_CHANSERV_CHECK_VALID_OP);

	if (IS_NULL(user))
		return FALSE;

	if (IS_NULL(ci) || user_is_services_agent(user))
		return TRUE;

	/* Shouldn't happen because of chanserv_check_user_join(), but you never know. */
	if (FlagSet(ci->flags, CI_FORBIDDEN) || FlagSet(ci->flags, CI_CLOSED) || FlagSet(ci->flags, CI_FROZEN))
		return FALSE;

	accessLevel = get_access(user, ci, NULL, NULL, NULL);

	if (IS_NOT_NULL(user->ni) && FlagSet(user->ni->flags, NI_NEVEROP) && user_is_identified_to(user, user->nick)) {
		/* Update this, as the SJOIN will not since we return FALSE. */
		if (accessLevel >= CS_ACCESS_VOP)
		    ci->last_used = NOW;
		return FALSE;
	}

	if (FlagSet(ci->flags, CI_AUTOOP) && FlagUnset(ci->flags, CI_OPGUARD))
		return TRUE;

	if ((accessLevel < CS_ACCESS_AOP) && FlagUnset(ci->flags, CI_OPGUARD) && !serverop)
		return TRUE;

	if (FlagSet(ci->flags, CI_OPGUARD)) {

		if ((accessLevel >= CS_ACCESS_AOP) || (!serverop && is_services_admin(user)))
			return TRUE;

		return FALSE;
	}

	TRACE();
	if (accessLevel < CS_ACCESS_AOP)
		return FALSE;

	/* All else fails, let the user keep the ops. */

	return TRUE;
}

/*********************************************************/

void check_welcome(const User *user, ChannelInfo *ci) {

	TRACE_FCLT(FACILITY_CHANSERV_CHECK_WELCOME);

	if (IS_NULL(user) || IS_NULL(ci)) {

		log_error(FACILITY_CHANSERV_CHECK_WELCOME, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, s_LOG_ERR_PARAMETER, "check_welcome()", s_LOG_NULL, IS_NULL(ci) ? "ci" : "user");
		return;
	}

	if (IS_NULL(ci->welcome) || user_is_services_client(user))
		return;

	if (IS_NULL(user->ni) || !user_is_identified_to(user, user->nick) || FlagUnset(user->ni->flags, NI_NOWELCOME))
		send_notice_to_user(s_ChanServ, user, "[ \2%s\2 ]: %s", ci->name, ci->welcome);
}

/*********************************************************/

/* Check whether a user should be opped on a channel, and if so, do it.
 * Return 1 if the user was opped, 0 otherwise. (Updates the channel's
 * last used time if the user was opped.) */

BOOL check_should_op(const User *user, ChannelInfo *ci) {

	int accessLevel;

	TRACE_FCLT(FACILITY_CHANSERV_CHECK_SHOULD_OP);

	if (IS_NULL(ci))
		return FALSE;

	if (FlagSet(ci->flags, CI_FORBIDDEN) || FlagSet(ci->flags, CI_FROZEN) ||
		FlagSet(ci->flags, CI_CLOSED) || FlagSet(ci->flags, CI_SUSPENDED))
		return FALSE;

	accessLevel = get_access(user, ci, NULL, NULL, NULL);
	
	if (accessLevel >= CS_ACCESS_AOP) {

		TRACE();
		ci->last_used = NOW;
		
		if (FlagSet(ci->flags, CI_NEVEROP))
			return FALSE;

		if (CONF_SEND_REMINDER && FlagSet(ci->flags, CI_REMIND))
			RemoveFlag(ci->flags, CI_REMIND);

		if ((user->ni) && FlagSet(user->ni->flags, NI_NEVEROP))
			return FALSE;

		return TRUE;
	}
	else {

		if (FlagSet(ci->flags, CI_AUTOOP) && FlagUnset(ci->flags, CI_OPGUARD))
			return TRUE;
	}

	return FALSE;
}

/*********************************************************/

/* Check whether a user should be halfopped on a channel, and if so, do it.
 * Return 1 if the user was halfopped, 0 otherwise. */
BOOL check_should_halfop(const User *user, ChannelInfo *ci) {

	int accessLevel;

	TRACE_FCLT(FACILITY_CHANSERV_CHECK_SHOULD_HALFOP);

	if (IS_NULL(ci) || FlagSet(ci->flags, CI_FORBIDDEN) ||
		FlagSet(ci->flags, CI_FROZEN) || FlagSet(ci->flags, CI_CLOSED))
		return FALSE;

	if (FlagSet(ci->flags, CI_AUTOHALFOP))
		return TRUE;

	accessLevel = get_access(user, ci, NULL, NULL, NULL);

	if (accessLevel == CS_ACCESS_HOP) {

		ci->last_used = NOW;

		if (CONF_SEND_REMINDER && FlagSet(ci->flags, CI_REMIND))
			RemoveFlag(ci->flags, CI_REMIND);

		return TRUE;
	}

	return FALSE;
}

/*********************************************************/

/* Check whether a user should be voiced on a channel, and if so, do it.
 * Return 1 if the user was voiced, 0 otherwise. */
BOOL check_should_voice(const User *user, ChannelInfo *ci) {

	int accessLevel;

	TRACE_FCLT(FACILITY_CHANSERV_CHECK_SHOULD_VOICE);

	if (IS_NULL(ci) || FlagSet(ci->flags, CI_FORBIDDEN) ||
		FlagSet(ci->flags, CI_FROZEN) || FlagSet(ci->flags, CI_CLOSED))
		return FALSE;

	if (FlagSet(ci->flags, CI_AUTOVOICE))
		return TRUE;

	accessLevel = get_access(user, ci, NULL, NULL, NULL);

	if (accessLevel == CS_ACCESS_VOP) {

		ci->last_used = NOW;

		if (CONF_SEND_REMINDER && FlagSet(ci->flags, CI_REMIND))
			RemoveFlag(ci->flags, CI_REMIND);

		return TRUE;
	}

	return FALSE;
}

/*********************************************************
 * add_suspend()                                         *
 *                                                       *
 * Add a channel to the suspend list for the next        *
 * 'delta' seconds.                                      *
 *********************************************************/

static ChannelSuspendData *add_suspend(CSTR channel) {

	ChannelSuspendData	*data;
	ChannelInfo			*ci;


	TRACE_FCLT(FACILITY_CHANSERV_ADD_SUSPEND);

	data = mem_malloc(sizeof(ChannelSuspendData));

	TRACE();
	str_copy_checked(channel, data->name, CHANMAX);

	TRACE();
	data->next = ChannelSuspendList;
	ChannelSuspendList = data;

	if (IS_NOT_NULL(ci = cs_findchan(channel)))
		AddFlag(ci->flags, CI_SUSPENDED);

	return data;
}


/*********************************************************
 * find_suspend()                                        *
 *                                                       *
 * Retrieve a suspend record for a chan.                 *
 *********************************************************/

static ChannelSuspendData *find_suspend(CSTR channel) {

	ChannelSuspendData *name = ChannelSuspendList;

	TRACE_FCLT(FACILITY_CHANSERV_FIND_SUSPEND);

	if (channel) {

		while (IS_NOT_NULL(name)) {

			if (str_equals_nocase(name->name, channel))
				return name;

			TRACE();
			name = name->next;
		}
	}

	return NULL;
}


/*********************************************************
 * del_suspend()                                         *
 *                                                       *
 * Remove a suspend record for a chan.                   *
 *********************************************************/

static void del_suspend(CSTR channel) {

	ChannelSuspendData *name, *namePrev;

	TRACE_FCLT(FACILITY_CHANSERV_DEL_SUSPEND);

	if (IS_NULL(channel)) {

		log_error(FACILITY_CHANSERV_DEL_SUSPEND, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, s_LOG_ERR_PARAMETER, "del_suspend()", s_LOG_NULL, "chan");
		return;
	}

	TRACE();
	namePrev = NULL;
	name = ChannelSuspendList;

	while (IS_NOT_NULL(name)) {

		if (str_equals_nocase(channel, name->name)) {

			ChannelInfo *ci;

			if (IS_NOT_NULL(namePrev))
				namePrev->next = name->next;
			else
				ChannelSuspendList = name->next;

			if (IS_NOT_NULL(ci = cs_findchan(channel)))
				RemoveFlag(ci->flags, CI_SUSPENDED);

			TRACE();
			mem_free(name);
			return;
		}

		TRACE();
		namePrev = name;
		name = name->next;
	}
}


/*********************************************************
 * chanserv_check_user_join                              *
 *                                                       *
 * Controlla se l'utente indicato ha il permesso di      *
 * entrare nel canale indicato. Se si restituisce TRUE   *
 * altrimenti kick-banna l'utente con il messaggio       *
 * appropriato e restituisce FALSE.                      *
 * Viene chiamata PRIMA che l'utente sia inserito nella  *
 * lista degli utenti del canale.                        * 
 *********************************************************/

BOOL chanserv_check_user_join(const User *user, Channel *chan) {

	ChannelSuspendData	*csd;
	AutoKick			*anAkick;
	ChannelInfo			*ci;
	int					idx, accessLevel;
	char 				*mask, *reason;
	BOOL				isAdmin, isExempt;

	TRACE_FCLT(FACILITY_CHANSERV_CHECK_USER_JOIN);

	if (IS_NULL(user) || IS_NULL(chan))
		return FALSE;

	if (user_is_services_agent(user))
		return TRUE;

	ci = chan->ci;

	isAdmin = is_services_admin(user);
	/* straight from nickserv.c */
	isExempt = IS_NOT_NULL(user->oper) || user_is_ircop(user) || user_is_admin(user) || user_is_services_agent(user) || isAdmin;

	/* Channel suspension check must come first because if the channel is
	 * not registered, services will not be able to kick because !ci returns 0. */

	TRACE();
	if ((IS_NULL(ci) || (FlagSet(ci->flags, CI_SUSPENDED))) && IS_NOT_NULL(csd = find_suspend(chan->name))) {

		if (csd->expires <= NOW)
			del_suspend(chan->name);

		else if (!isAdmin) {

			mask = user_usermask_create(user, 2);
			reason = lang_msg(GetCallerLang(), CS_SUSPENDED_KICK_REASON);
			goto kick;
		}
	}

	switch (reserved_match(chan->name + 1, RESERVED_CHAN, 0, s_ChanServ, user->nick, user->username, user->host, user->ip, isExempt, user->current_lang)) {

		case reservedKill:
			send_KILL(s_ChanServ, user->nick, lang_msg(GetCallerLang(), RESERVED_NAME_KILL_REASON_USE), TRUE);
			/* Fall... */

		case reservedAutoKill:
			return FALSE;

		case reservedBlock:
			if (!isExempt) {
				mask = user_usermask_create(user, 2);
				reason = lang_msg(GetCallerLang(), CS_RESERVED_KICK_REASON);
				goto kick;
			}
			/* Fall if exempt... */

		case reservedValid:
			/* Don't do anything. */
			break;
	}

	TRACE();
	if (IS_NULL(ci))
		return TRUE;

	if (FlagSet(ci->flags, CI_CODERONLY) && !is_services_coder(user)) {

		mask = user_usermask_create(user, 2);
		reason = lang_msg(GetCallerLang(), CS_LEVEL_CODERONLY_KICK_REASON);
		goto kick;
	}

	TRACE();
	if (FlagSet(ci->flags, CI_SRAONLY) && !is_services_root(user)) {

		mask = user_usermask_create(user, 2);
		reason = lang_msg(GetCallerLang(), CS_LEVEL_SRAONLY_KICK_REASON);
		goto kick;
	}

	if (isAdmin)
		return TRUE;

	if (FlagSet(ci->flags, CI_SAONLY)) {

		mask = user_usermask_create(user, 2);
		reason = lang_msg(GetCallerLang(), CS_LEVEL_SAONLY_KICK_REASON);
		goto kick;
	}

	if (FlagSet(ci->flags, CI_SOPONLY) && !is_services_oper(user)) {

		mask = user_usermask_create(user, 2);
		reason = lang_msg(GetCallerLang(), CS_LEVEL_SOPONLY_KICK_REASON);
		goto kick;
	}

	if (FlagSet(ci->flags, CI_CLOSED)) {

		mask = user_usermask_create(user, 2);
		reason = lang_msg(GetCallerLang(), CS_CLOSED_KICK_REASON);
		goto kick;
	}

	if (FlagSet(ci->flags, CI_FORBIDDEN)) {

		mask = user_usermask_create(user, 2);
		reason = lang_msg(GetCallerLang(), CS_FORBIDDEN_KICK_REASON);
		goto kick;
	}

	if (FlagSet(ci->flags, CI_SUSPENDED)) {

		mask = user_usermask_create(user, 2);
		reason = lang_msg(GetCallerLang(), CS_SUSPENDED_KICK_REASON);
		goto kick;
	}

	TRACE();
	if (FlagSet(ci->flags, CI_FROZEN))
		return TRUE;

	accessLevel = get_access(user, ci, NULL, NULL, NULL);

	if (!isAdmin && (accessLevel < CS_ACCESS_VOP) && FlagSet(ci->flags, CI_RESTRICTED)) {

		mask = user_usermask_create(user, ci->banType);
		reason = lang_msg(GetCallerLang(), CS_RESTRICTED_KICK_REASON);
		goto kick;
	}

	TRACE();
	if (accessLevel > CS_ACCESS_NONE)
		return TRUE;

	for (anAkick = ci->akick, idx = 0; idx < ci->akickcount; ++anAkick, ++idx) {

		if (anAkick->isNick > 0) {

			int j;
			char **idnicks;

			TRACE_MAIN();
			for (idnicks = user->id_nicks, j = 0; j < user->idcount; ++idnicks, ++j) {

				if (str_equals_nocase(*idnicks, anAkick->name)) {

					TRACE();
					if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_CLEAR))
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_USER_AKICKED), s_ChanServ, ci->name, user->nick, anAkick->name);

					mask = user_usermask_create(user, anAkick->banType);
					reason = anAkick->reason ? anAkick->reason : lang_msg(GetCallerLang(), CS_AKICK_KICK_REASON);
					goto kick;
				}
			}

			if (str_match_wild_nocase(anAkick->name, user->nick)) {

				TRACE();
				if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_CLEAR))
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_USER_AKICKED), s_ChanServ, ci->name, user->nick, anAkick->name);

				mask = user_usermask_create(user, anAkick->banType);
				reason = anAkick->reason ? anAkick->reason : lang_msg(GetCallerLang(), CS_AKICK_KICK_REASON);
				goto kick;
			}
		}
		else {

			if (user_usermask_match(anAkick->name, user, TRUE, TRUE)) {

				TRACE();
				if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_CLEAR))
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_USER_AKICKED), s_ChanServ, ci->name, user->nick, anAkick->name);

				//mask = (anAkick->banType == -1) ? str_duplicate(anAkick->name) : user_usermask_create(user, anAkick->banType);
				if (anAkick->banType == -1) {
					char	*host;
					host = strchr(anAkick->name, '@');
					if (host != NULL)
						host++;

					if (FlagUnset(user->flags, USER_FLAG_TEREDO | USER_FLAG_6TO4) || (host != NULL && (str_match_wild_nocase(host, user->host) || str_match_wild_nocase(host, user->maskedHost) || str_match_wild_nocase(host, get_ip6(user->ipv6))))) {
						mask = str_duplicate(anAkick->name);
					} else {
						mask = user_usermask_create(user, 2);
					}
				} else {
					mask = user_usermask_create(user, anAkick->banType);
				}
				reason = anAkick->reason ? anAkick->reason : lang_msg(GetCallerLang(), CS_AKICK_KICK_REASON);
				goto kick;
			}
		}
	}

	return TRUE;

kick:

	LOG_DEBUG("channels: AutoKicking %s!%s@%s from %s", user->nick, user->username, user->host, chan->name);

	if ((chan->userCount <= 1) && (IS_NULL(ci) || FlagUnset(ci->flags, CI_TIMEOUT))) {

		ChannelTimeoutData	*data;


		data = mem_malloc(sizeof(ChannelTimeoutData));

		if (IS_NOT_NULL(ci)) {

			data->type = CTOD_CHAN_RECORD;
			data->info.record = ci;
			AddFlag(ci->flags, CI_TIMEOUT);
		}
		else {

			data->type = CTOD_CHAN_NAME;
			data->info.name = str_duplicate(chan->name);
		}

		TRACE();
		if (FlagUnset(chan->mode, CMODE_CS)) {

			send_SJOIN(s_ChanServ, chan->name);
			AddFlag(chan->mode, CMODE_CS);
		}

		timeout_add(toChanServ, TOTYPE_CHANSERV_LEAVE, ci ? (unsigned long)data->info.record : (unsigned long)data->info.name, CONF_CHANNEL_INHABIT, FALSE, timeout_leave, (void *)data);
	}

	/* Should be fine to leave out timeout_unban since the empty channel will remove the mode anyway. */

	TRACE();

	/* If this ban is not already present and can be added (i.e. banlist is not full) send it. */
	if (!chan_has_ban(chan, mask, NULL) && chan_add_ban(chan, mask))
		send_cmd(":%s MODE %s +b %s %lu", s_ChanServ, chan->name, mask, NOW);

	TRACE();
	send_cmd(":%s KICK %s %s :%s", s_ChanServ, chan->name, user->nick, reason);

	TRACE();
	if (mask)
		mem_free(mask);

	return FALSE;
}

/*********************************************************/

/* Record the current channel topic in the ChannelInfo structure. */
void record_topic(Channel *chan) {

	ChannelInfo *ci;

	TRACE_FCLT(FACILITY_CHANSERV_RECORD_TOPIC);

	if (CONF_SET_READONLY)
		return;

	if (IS_NULL(chan) || IS_NULL((ci = chan->ci)) || FlagSet(ci->flags, CI_FROZEN))
		return;

	TRACE();
	if (ci->last_topic)
		mem_free(ci->last_topic);

	if (chan->topic)
		ci->last_topic = str_duplicate(chan->topic);
	else
		ci->last_topic = NULL;

	TRACE();
	str_copy_checked(chan->topic_setter, ci->last_topic_setter, NICKMAX);
	ci->last_topic_time = chan->topic_time;
}

/*********************************************************/

/* Restore the topic in a channel when it's created, if we should. */
void restore_topic(Channel *chan) {

	ChannelInfo *ci;

	TRACE_FCLT(FACILITY_CHANSERV_RESTORE_TOPIC);

	if (IS_NULL(chan) || IS_NULL(ci = chan->ci) || FlagUnset(ci->flags, CI_KEEPTOPIC))
		return;

	TRACE();
	if (chan->topic)
		mem_free(chan->topic);

	if (ci->last_topic) {

		chan->topic = str_duplicate(ci->last_topic);
		str_copy_checked(ci->last_topic_setter, chan->topic_setter, NICKMAX);
		chan->topic_time = ci->last_topic_time;
	}
	else {

		chan->topic = NULL;
		str_copy_checked(s_ChanServ, chan->topic_setter, NICKMAX);
	}

	TRACE();
	if (IS_NOT_NULL(chan->topic))
		send_cmd(":%s TOPIC %s %s %lu :%s", s_ChanServ, chan->name, chan->topic_setter, chan->topic_time, chan->topic ? chan->topic : "");
}

/*********************************************************/

/* See if the topic is locked on the given channel, and return 1 (and fix the topic) if so. */
BOOL check_topiclock(const User *user, Channel *chan) {

	ChannelInfo *ci;
	int accessLevel;

	TRACE_FCLT(FACILITY_CHANSERV_CHECK_TOPICLOCK);

	if (IS_NULL(ci = chan->ci) || FlagUnset(ci->flags, CI_TOPICLOCK))
		return FALSE;

	accessLevel = get_access(user, ci, NULL, NULL, NULL);

	TRACE();
	if ((ci->topic_allow <= accessLevel) && FlagUnset(ci->flags, CI_FROZEN))
		return FALSE;

	TRACE();
	if (chan->topic)
		mem_free(chan->topic);

	if (ci->last_topic)
		chan->topic = str_duplicate(ci->last_topic);
	else
		chan->topic = NULL;

	TRACE();
	str_copy_checked(ci->last_topic_setter, chan->topic_setter, NICKMAX);
	chan->topic_time = ci->last_topic_time;

	send_cmd(":%s TOPIC %s %s %lu :%s", s_ChanServ, chan->name, chan->topic_setter, chan->topic_time, chan->topic ? chan->topic : "");
	return TRUE;
}

/*********************************************************/

/* Remove a (deleted or expired) nickname from all channel access lists. */
void cs_remove_nick(CSTR nick) {

	int i, j;
	ChannelInfo *ci, *next;
	ChanAccess *anAccess;

	TRACE_FCLT(FACILITY_CHANSERV_CS_REMOVE_NICK);

	for (i = 0; i < 256; ++i) {

		for (ci = chanlists[i]; ci; ci = next) {

			next = ci->next;

			for (anAccess = ci->access, j = ci->accesscount; j > 0; ++anAccess, --j) {

				TRACE();
				if ((anAccess->status == ACCESS_ENTRY_NICK) && str_equals_nocase(anAccess->name, nick))
					anAccess->status = ACCESS_ENTRY_EXPIRED;
			}

			if (IS_NOT_NULL(ci->successor) && str_equals_nocase(ci->successor, nick)) {

				mem_free(ci->successor);
				ci->successor = NULL;
			}
			else if (str_equals_nocase(ci->founder, nick)) {

				if (IS_NULL(ci->successor)) {

					if (FlagSet(ci->flags, CI_HELDCHAN)) {

						TRACE();
						LOG_SNOOP(s_OperServ, "CS X! %s [Founder: %s]", ci->name, ci->founder);
						log_services(LOG_SERVICES_CHANSERV_GENERAL, "X! %s [Founder: %s]", ci->name, ci->founder);

						str_copy_checked("AzzurraRoot", ci->founder, NICKMAX);
					}
					else {

						LOG_SNOOP(s_OperServ, "CS XF %s [Founder: %s]", ci->name, ci->founder);
						log_services(LOG_SERVICES_CHANSERV_GENERAL, "XF %s [Founder: %s]", ci->name, ci->founder);

						delchan(ci);
					}
				}
				else {

					unsigned long int randID;
					char memoText[512];
					NickInfo *ni;


					if (IS_NULL(ni = findnick(ci->successor))) {

						log_error(FACILITY_CHANSERV_CS_REMOVE_NICK, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED,
							"%s in cs_remove_nick(): Successor %s for channel %s has no NickInfo record", s_ChanServ, ci->successor, ci->name);

						if (FlagSet(ci->flags, CI_HELDCHAN)) {

							TRACE();
							LOG_SNOOP(s_OperServ, "CS X! %s [Founder: %s]", ci->name, ci->founder);
							log_services(LOG_SERVICES_CHANSERV_GENERAL, "X! %s [Founder: %s]", ci->name, ci->founder);

							str_copy_checked("AzzurraRoot", ci->founder, NICKMAX);
						}
						else {

							LOG_SNOOP(s_OperServ, "CS XF %s [Founder: %s]", ci->name, ci->founder);
							log_services(LOG_SERVICES_CHANSERV_GENERAL, "XF %s [Founder: %s]", ci->name, ci->founder);

							delchan(ci);
						}

						continue;
					}

					/* Generate a random password. */
					srand(randomseed());
					randID = (NOW + getrandom(1, 99999) * getrandom(1, 9999));

					/* Log this action. */
					LOG_SNOOP(s_OperServ, "CS XF! %s [%s -> %s] [P: %s -> %s-%lu]", ci->name, ci->founder, ci->successor, ci->founderpass, CRYPT_NETNAME, randID);
					log_services(LOG_SERVICES_CHANSERV_GENERAL, "XF! %s [%s -> %s] [P: %s -> %lu]", ci->name, ci->founder, ci->successor, ci->founderpass, CRYPT_NETNAME, randID);

					/* Change the channel password to the new (random) one. */
					snprintf(ci->founderpass, sizeof(ci->founderpass), "%s-%lu", CRYPT_NETNAME, randID);

					/* Notify the new owner about it via memo. */
					snprintf(memoText, sizeof(memoText), lang_msg(EXTRACT_LANG_ID(ni->langID), CS_SET_FOUNDER_SUCCESSOR), ci->name, CRYPT_NETNAME, randID);
					send_memo_internal(ni, memoText);

					/* Now actually change the founder. */
					str_copy_checked(ci->successor, ci->founder, NICKMAX);

					/* Remove identification to this channel from all users. */
					user_remove_chanid(ci);

					/* Clear the successor entry. */
					mem_free(ci->successor);
					ci->successor = NULL;

					for (anAccess = ci->access, j = 0; (j < ci->accesscount) && IS_NOT_NULL(anAccess); ++anAccess, ++j) {

						if ((anAccess->status == ACCESS_ENTRY_NICK) && (anAccess->level == CS_ACCESS_COFOUNDER)
							&& str_equals_nocase(ci->founder, anAccess->name)) {

							mem_free(anAccess->name);
							anAccess->name = NULL;

							mem_free(anAccess->creator);
							anAccess->creator = NULL;

							anAccess->status = ACCESS_ENTRY_FREE;
							anAccess->flags = 0;
							anAccess->creationTime = 0;

							compact_chan_access_list(ci, 1);
							break;
						}
					}
				}
			}
		}
	}
}

/*********************************************************/

/* Has the given user password-identified as founder for the channel? */

static BOOL is_identified(const User *user, const ChannelInfo *ci) {

	ChanInfoListItem *item;


	TRACE_FCLT(FACILITY_CHANSERV_IS_IDENTIFIED);

	for (item = user->founder_chans; IS_NOT_NULL(item); item = item->next) {

		TRACE();

		if (item->ci == ci)
			return TRUE;
	}

	return FALSE;
}

/*********************************************************/

/* Return the access level the given user has on the channel. If the
 * channel doesn't exist, the user isn't on the access list, or the channel
 * is CS_IDENT and the user hasn't IDENTIFY'd with NickServ, return 0. */

/* 
	Valori restituiti (level):

	CS_ACCESS_NONE		 (0): No access
	CS_ACCESS_VOP		 (3): VOP access
	CS_ACCESS_HOP		 (4): HOP access
	CS_ACCESS_AOP		 (5): AOP access
	CS_ACCESS_SOP		(10): SOP access
	CS_ACCESS_COFOUNDER (13): Co-Founder access
	CS_ACCESS_FOUNDER	(15): Founder access
*/

int get_access(const User *user, const ChannelInfo *ci, char *accessName, int *accessMatch, int *accessStatus) {

	ChanAccess	*anAccess;
	int			i, level, accessIdx;
	BOOL		gotmynick = FALSE;
	char		**idnicks;

	TRACE_FCLT(FACILITY_CHANSERV_GET_ACCESS);

	if (IS_NULL(ci) || FlagSet(ci->flags, CI_FORBIDDEN)) {

		if (accessName)
			str_copy_checked(user->nick, accessName, NICKSIZE);

		if (accessMatch)
			*accessMatch = TRUE;

		if (accessStatus)
			*accessStatus = CS_STATUS_NONE;

		return CS_ACCESS_NONE;
	}

	if (user_is_identified_to(user, ci->founder)) {

		if (accessName)
			str_copy_checked(ci->founder, accessName, NICKSIZE);

		if (accessMatch)
			*accessMatch = str_equals_nocase(user->nick, accessName);

		if (accessStatus)
			*accessStatus = CS_STATUS_IDNICK;

		return CS_ACCESS_FOUNDER;
	}

	if (is_identified(user, ci)) {

		if (accessName)
			str_copy_checked(user->nick, accessName, NICKSIZE);

		if (accessMatch)
			*accessMatch = TRUE;

		if (accessStatus)
			*accessStatus = CS_STATUS_IDCHAN;

		return CS_ACCESS_FOUNDER;
	}

	level = CS_ACCESS_NONE;

	if (FlagUnset(ci->flags, CI_IDENT)) {

		NickInfo *ni;
		int on_access, is_id;

		if (IS_NOT_NULL(ni = findnick(ci->founder)) && is_on_access(user, ni)) {

			if (accessName)
				str_copy_checked(ci->founder, accessName, NICKSIZE);

			if (accessMatch)
				*accessMatch = str_equals_nocase(user->nick, accessName);

			if (accessStatus)
				*accessStatus = CS_STATUS_ACCLIST;

			return CS_ACCESS_FOUNDER;
		}

		on_access = user->ni ? is_on_access(user, user->ni) : 0;
		is_id = user->ni ? user_is_identified_to(user, user->ni->nick) : 0;

		for (anAccess = ci->access, accessIdx = 0; (accessIdx < ci->accesscount) && IS_NOT_NULL(anAccess); ++anAccess, ++accessIdx) {

			if (on_access && (anAccess->status == ACCESS_ENTRY_NICK) && !is_id
				&& (anAccess->level > level) && str_equals_nocase(user->ni->nick, anAccess->name)) {

				level = anAccess->level;

				if (accessName)
					str_copy_checked(anAccess->name, accessName, NICKSIZE);

				if (accessStatus)
					*accessStatus = CS_STATUS_ACCLIST;
			}
			else {

				if ((anAccess->status == ACCESS_ENTRY_MASK) && (anAccess->level > level)
					&& user_usermask_match(anAccess->name, user, FALSE, FALSE)) {

					level = anAccess->level;

					if (accessName)
						str_copy_checked(user->nick, accessName, NICKSIZE);

					if (accessStatus)
						*accessStatus = CS_STATUS_MASK;
				}
				else {

					if ((anAccess->status == ACCESS_ENTRY_NICK) && (anAccess->level > level)
						&& (ni = findnick(anAccess->name)) && is_on_access(user, ni)) {

						level = anAccess->level;

						if (accessName)
							str_copy_checked(anAccess->name, accessName, NICKSIZE);

						if (accessStatus)
							*accessStatus = CS_STATUS_ACCLIST;
					}
				}
			}
		}
	}

	for (idnicks = user->id_nicks, i = 0; i < user->idcount; ++idnicks, ++i) {

		for (anAccess = ci->access, accessIdx = 0; (accessIdx < ci->accesscount) && IS_NOT_NULL(anAccess); ++anAccess, ++accessIdx) {

			if ((anAccess->status == ACCESS_ENTRY_NICK) &&
				(gotmynick ? (anAccess->level > level) : (anAccess->level >= level))
				&& str_equals_nocase(*idnicks, anAccess->name)) {

				level = anAccess->level;

				if (accessName)
					str_copy_checked(anAccess->name, accessName, NICKSIZE);

				if (accessStatus)
					*accessStatus = CS_STATUS_IDNICK;

				/* Give precedence to the user's nick if the access level is the same. */
				if (str_equals_nocase(anAccess->name, user->nick))
					gotmynick = TRUE;
			}
		}
	}

	TRACE();

	if (level > CS_ACCESS_NONE) {

		if (accessMatch)
			*accessMatch = str_equals_nocase(user->nick, accessName);

		return level;
	}
	else {

		if (accessName)
			str_copy_checked(user->nick, accessName, NICKSIZE);

		if (accessMatch)
			*accessMatch = TRUE;

		return CS_ACCESS_NONE;
	}
}

/*********************************************************/

static char cs_get_verbose_level_name(const ChannelInfo *ci) {

	if (ci)
		return (char) 48 + ((ci->settings & CI_NOTICE_VERBOSE_MASK) >> 8);
	else
		return '0';
}


/*********************************************************
 * ChanServ public command routines.                     *
 *********************************************************/

static void do_register(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *chan, *pass, *desc;
	ChannelInfo *ci;
	Channel *channel;
	RESERVED_RESULT reserved;


	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_REGISTER);

	if (CONF_SET_READONLY) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_ERROR_READONLY);
		return;
	}

	if (dynConf.cs_regLimit > 0) {

		if (dynConf.cs_regLimit <= cs_regCount) {

			send_globops(NULL, "\2%s\2 hit the maximum number of registrations allowed (\2%d\2/\2%d\2)",
				s_ChanServ, cs_regCount, dynConf.cs_regLimit);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_MAX_REG_REACHED);
			return;
		}
		else if (dynConf.cs_regLimit <= (cs_regCount + 10)) {

			send_globops(NULL, "\2%s\2 is about to hit the maximum number of registrations allowed (\2%d\2/\2%d\2)",
				s_ChanServ, cs_regCount, dynConf.cs_regLimit);
		}
	}

	TRACE_MAIN();

	if ((NOW < callerUser->lastchanreg + CONF_REGISTER_DELAY) && !is_services_oper(callerUser)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), NS_REGISTER_REG_DELAY, CONF_REGISTER_DELAY);
		callerUser->lastchanreg = NOW;
	}
	else if (IS_NULL(chan = strtok(NULL, " ")) || IS_NULL(pass = strtok(NULL, " ")) || IS_NULL(desc = strtok(NULL, ""))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "REGISTER");
	}
	else if (*chan == '&')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_ERROR_CANT_REG_LOCAL);

	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_ERROR_NICK_NOT_REG_1);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_ERROR_NICK_NOT_REG_2);
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
	}
	else if (CONF_FORCE_AUTH && (FlagSet(callerUser->ni->flags, NI_AUTH) || !callerUser->ni->email)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_ERROR_MUST_AUTH_NICK);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
	}
	else if (IS_NOT_NULL(ci = cs_findchan(chan))) {

		TRACE_MAIN();
		if (FlagSet(ci->flags, CI_FORBIDDEN)) {
			
			LOG_SNOOP(s_OperServ, "CS *R %s -- by %s (%s@%s) [Forbidden]", ci->name, source, callerUser->username, callerUser->host);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS *R %s -- by %s (%s@%s) [Already Registered]", ci->name, source, callerUser->username, callerUser->host);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_ERROR_ALREADY_REG, ci->name);
		}
	}
	else if (IS_NOT_NULL(find_suspend(chan)))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_ERROR_CHAN_SUSPENDED, chan);

	else if (IS_NULL(channel = hash_channel_find(chan)))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHAN_DOES_NOT_EXIST, chan);

	else if (!user_is_chanop(source, chan, channel))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_ERROR_MUST_BE_OP, chan);

	else if ((CONF_USER_CHAN_ACCESS_MAX > 0) && (callerUser->ni->channelcount >= CONF_USER_CHAN_ACCESS_MAX) && !(is_services_admin(callerUser))) {

		TRACE_MAIN();
		LOG_SNOOP(s_OperServ, "CS *R %s -- by %s (%s@%s) [Limit %s]", chan, source, callerUser->username, callerUser->host, callerUser->ni->channelcount > CONF_USER_CHAN_ACCESS_MAX ? "Surpassed" : "Reached");

		if (callerUser->ni->channelcount > CONF_USER_CHAN_ACCESS_MAX)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_ERROR_OVER_MAXREG, CONF_USER_CHAN_ACCESS_MAX);
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_ERROR_HIT_MAXREG, CONF_USER_CHAN_ACCESS_MAX);
	}
	else if ((reserved = reserved_match(chan + 1, RESERVED_CHAN, 1, s_ChanServ, source, callerUser->username, callerUser->host, callerUser->ip, (IS_NOT_NULL(callerUser->oper) || user_is_ircop(callerUser) || user_is_admin(callerUser) || user_is_services_agent(callerUser)), callerUser->current_lang)) == reservedKill)
		send_KILL(s_ChanServ, source, lang_msg(GetCallerLang(), RESERVED_NAME_KILL_REASON_REG), TRUE);

	else if (reserved == reservedAutoKill)
		return;

	else if (reserved == reservedBlock) {

		LOG_SNOOP(s_OperServ, "CS *R %s -- by %s (%s@%s) [Reserved]", chan, source, callerUser->username, callerUser->host);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_ERROR_CHAN_RESERVED, chan);
	}
	else if (strpbrk(pass, "<>"))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_BRAKES_IN_PASS, "<", ">");

	else if (string_has_ccodes(pass))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_WITH_CCODES);

	else if (str_equals_nocase(pass, callerUser->ni->pass))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_ERROR_SAME_PASS_AS_NICK);

	else if (str_equals_nocase(pass, "password"))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_AS_PASS);

	else if ((str_len(pass) < 5) || str_equals_nocase(pass, chan) || str_equals_nocase(pass, chan+1)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_INSECURE_PASSWORD);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "REGISTER");
	}
	else if (str_len(pass) > PASSMAX)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_MAX_LENGTH, PASSMAX);

	else {

		size_t	size;

		ci = makechan(chan);

		TRACE_MAIN();
		callerUser->lastchanreg = NOW;

		AddFlag(ci->flags, CI_KEEPTOPIC);
		AddFlag(ci->flags, CI_IDENT);
		AddFlag(ci->flags, CI_NOMKICK);
		AddFlag(ci->flags, CI_MEMO_VOP);

		ci->last_used = ci->time_registered;
		str_copy_checked(source, ci->founder, NICKMAX);

		TRACE_MAIN();
		size = (str_len(source) + str_len(callerUser->username) + str_len(callerUser->host) + 5) * sizeof(char);
		ci->real_founder = mem_calloc(1, size);

		snprintf(ci->real_founder, size, "%s (%s@%s)", source, callerUser->username, callerUser->host);

		str_copy_checked(pass, ci->founderpass, PASSMAX);
		ci->desc = str_duplicate(desc);

		ci->langID = callerUser->ni->langID;
		ci->mlock_on = CONF_DEF_MLOCKON;
		ci->mlock_off = CONF_DEF_MLOCKOFF;

		TRACE_MAIN();
		if (channel->topic) {

			ci->last_topic = str_duplicate(channel->topic);
			str_copy_checked(channel->topic_setter, ci->last_topic_setter, NICKMAX);
			ci->last_topic_time = channel->topic_time;
		}

		TRACE_MAIN();
		++(callerUser->ni->channelcount);

		LOG_SNOOP(s_OperServ, "CS R %s -- by %s (%s@%s)", chan, callerUser->nick, callerUser->username, callerUser->host);
		log_services(LOG_SERVICES_CHANSERV_GENERAL, "R %s -- by %s (%s@%s) [Password: %s ]", chan, callerUser->nick, callerUser->username, callerUser->host, ci->founderpass);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_REG_OK_1, chan, source);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_REG_OK_2, pass);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REGISTER_REG_OK_4);

		TRACE_MAIN();

		/* Link this channel to the user's identified channels list. */
		link_channel(callerUser, ci);

		/* Link it to the channel struct. */
		channel->ci = ci;

		TRACE_MAIN();

		/* Send +r and the default modelock modes. */
		check_modelock(channel, NULL);
	}
}

/*********************************************************/

static void do_identify(CSTR source, User *callerUser, ServiceCommandData *data) {
	
	const char *chan, *pass;
	ChannelInfo *ci;
	NickInfo *ni;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_IDENTIFY);

	if (IS_NULL(chan = strtok(NULL, " ")) || IS_NULL(pass = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_IDENTIFY_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "IDENTIFY");
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan)))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, chan);

	else if (FlagSet(ci->flags, CI_FORBIDDEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

	else if (FlagSet(ci->flags, CI_FROZEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FROZEN, ci->name);

	else if (FlagSet(ci->flags, CI_CLOSED))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_CLOSED, ci->name);

	else if (FlagSet(ci->flags, CI_SUSPENDED))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_SUSPENDED, ci->name);

	else if (IS_NOT_NULL(ni = findnick(ci->founder)) && FlagSet(ni->flags, NI_FROZEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_FOUNDER_FROZEN, ci->name);

	else {

		if (str_equals(pass, ci->founderpass)) {

			TRACE_MAIN();
			if (!is_identified(callerUser, ci))
				link_channel(callerUser, ci);

			if (CONF_SEND_REMINDER && FlagSet(ci->flags, CI_REMIND))
				RemoveFlag(ci->flags, CI_REMIND);

			if (CONF_SET_EXTRASNOOP)
				LOG_SNOOP(s_OperServ, "CS I %s -- by %s (%s@%s) [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, pass);

			log_services(LOG_SERVICES_CHANSERV_ID, "I %s -- by %s (%s@%s) [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, pass);

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_IDENTIFY_ID_OK, chan);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS *I %s -- by %s (%s@%s) [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, pass);
			log_services(LOG_SERVICES_CHANSERV_ID, "*I %s -- by %s (%s@%s) [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, pass);

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_BAD_PASS, ci->name);

			update_invalid_password_count(callerUser, s_NickServ, chan);
		}
	}
}

static void do_sendcode(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *chan;
	ChannelInfo *ci;
	FILE *mailfile;
	NickInfo *ni;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SENDCODE);

	if (IS_NULL(chan = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SENDCODE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "SENDCODE");
		return;
	}
	 if (*chan != '#') {
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);
		return;
	}	
	if (IS_NULL(ci = cs_findchan(chan))) {

		LOG_SNOOP(s_OperServ, "CS *SC %s -- by %s (%s@%s) [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, chan);
		return;
	}
	
	if(!ci->auth) {
		
		LOG_SNOOP(s_OperServ, "CS *SC -- by %s (%s@%s) [NO Dropping requests]", callerUser->nick, callerUser->username, callerUser->host, data->operName, NICKMAX);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_DROP_ERROR_NOT_DROPPING, ci->name);
		return;
	}	
	
	if(FlagSet(ci->flags,  CI_MARKCHAN)) {
		
		LOG_SNOOP(s_OperServ, "CS *SC -- by %s (%s@%s) [Marked]", callerUser->nick, callerUser->username, callerUser->host, data->operName, NICKMAX);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_ERROR_CHAN_MARKED, ci->name);
		return;
	}
	
	
	if (IS_NULL(ni = findnick(ci->founder))) {

		log_error(FACILITY_CHANSERV_HANDLE_DROP, __LINE__, LOG_TYPE_ERROR_RTL, LOG_SEVERITY_ERROR_HALTED,"do_drop(): could not find nick record (%s) for channel %s", ci->founder, ci->name);

		return;
		
	}

	
	if (IS_NOT_NULL(mailfile = fopen("senddrop.txt", "w"))) {

		fprintf(mailfile, "From: %s <%s>\n", CONF_NETWORK_NAME, CONF_RETURN_EMAIL);
		fprintf(mailfile, "To: %s\n", ni->email);

		fprintf(mailfile, lang_msg(GetNickLang(ni), CS_DROP_EMAIL_SUBJECT), CONF_NETWORK_NAME);
		fprintf(mailfile, lang_msg(GetNickLang(ni), CS_DROP_EMAIL_TEXT), ci->auth, CONF_NETWORK_NAME, ci->name, s_ChanServ, ci->name, ci->auth);
		fprintf(mailfile, lang_msg(GetNickLang(ni), CSNS_EMAIL_TEXT_ABUSE), MAIL_ABUSE, CONF_NETWORK_NAME);
		fclose(mailfile);

		snprintf(misc_buffer, MISC_BUFFER_SIZE, "%s -f %s -t < senddrop.txt", CONF_SENDMAIL_PATH, CONF_RETURN_EMAIL);
		system(misc_buffer);

		snprintf(misc_buffer, MISC_BUFFER_SIZE, "rm -f senddrop.txt");
		system(misc_buffer);
		
	
			
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_SENDCODE_CODE_SENT, ni->nick, ni->email);
		send_globops(s_ChanServ, "\2%s\2 used SENDCODE on channel \2%s\2 [DROP]", callerUser->nick, ci->name);
		LOG_SNOOP(s_OperServ, "CS SC %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
		log_services(LOG_SERVICES_CHANSERV_GENERAL, "SC %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
	
	}	
	else
		log_error(FACILITY_CHANSERV_HANDLE_DROP, __LINE__, LOG_TYPE_ERROR_RTL, LOG_SEVERITY_ERROR_HALTED,
						"do_sendcode(): unable to create senddrop.txt");
						
}						
/*********************************************************/

static void do_drop(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *chan;
	ChannelInfo *ci;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_DROP);

	if (CONF_SET_READONLY)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_DROP_ERROR_READONLY);

	else if (IS_NULL(chan = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_DROP_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "DROP");
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan))) {

		LOG_SNOOP(s_OperServ, "CS *D %s -- by %s (%s@%s) [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, chan);
	}
	else if (FlagSet(ci->flags, CI_FORBIDDEN)) {

		LOG_SNOOP(s_OperServ, "CS *D %s -- by %s (%s@%s) [Forbidden]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);
	}
	else if (FlagSet(ci->flags, CI_FROZEN)) {

		LOG_SNOOP(s_OperServ, "CS *D %s -- by %s (%s@%s) [Frozen]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FROZEN, ci->name);
	}
	else if (FlagSet(ci->flags, CI_CLOSED)) {

		LOG_SNOOP(s_OperServ, "CS *D %s -- by %s (%s@%s) [Closed]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_CLOSED, ci->name);
	}
	else if (FlagSet(ci->flags, CI_SUSPENDED)) {

		LOG_SNOOP(s_OperServ, "CS *D %s -- by %s (%s@%s) [Suspended]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_DROP_ERROR_CHAN_SUSPENDED, ci->name);
	}
	else if (!is_identified(callerUser, ci)) {

		LOG_SNOOP(s_OperServ, "CS *D %s -- by %s (%s@%s) [Not Identified to Channel]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_MUST_IDENTIFY, ci->name);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_CS, ci->name);
	}
	else if (!user_is_identified_to(callerUser, ci->founder)) {

		LOG_SNOOP(s_OperServ, "CS *D %s -- by %s (%s@%s) [Not Identified to Founder's Nick]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, ci->founder);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, ci->founder);
	}
	else {

		const char *auth;

		if (IS_NULL(auth = strtok(NULL, " "))) {

			if (ci->auth != 0) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_DROP_CODE_ALREADY_SENT);
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
			}
			else if ((NOW - ci->last_drop_request) < ONE_DAY)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_DROP_ERROR_WAIT);

			else {

				FILE *mailfile;
				NickInfo *ni;

				if (IS_NULL(ni = findnick(ci->founder))) {

					log_error(FACILITY_CHANSERV_HANDLE_DROP, __LINE__, LOG_TYPE_ERROR_RTL, LOG_SEVERITY_ERROR_HALTED,
						"do_drop(): could not find nick record (%s) for channel %s", ci->founder, ci->name);

					return;
				}

				srand(randomseed());

				ci->auth = ci->time_registered + (getrandom(1, 99999) * getrandom(1, 9999));
				ci->last_drop_request = NOW;

				LOG_SNOOP(s_OperServ, "CS D %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "D %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_DROP_CODE_SENT);

				if (IS_NOT_NULL(mailfile = fopen("chandrop.txt", "w"))) {

					fprintf(mailfile, "From: %s <%s>\n", CONF_NETWORK_NAME, CONF_RETURN_EMAIL);
					fprintf(mailfile, "To: %s\n", ni->email);

					fprintf(mailfile, lang_msg(GetNickLang(ni), CS_DROP_EMAIL_SUBJECT), CONF_NETWORK_NAME);
					fprintf(mailfile, lang_msg(GetNickLang(ni), CS_DROP_EMAIL_TEXT), ci->auth, CONF_NETWORK_NAME, ci->name, s_ChanServ, ci->name, ci->auth);
					fprintf(mailfile, lang_msg(GetNickLang(ni), CSNS_EMAIL_TEXT_ABUSE), MAIL_ABUSE, CONF_NETWORK_NAME);
					fclose(mailfile);

					snprintf(misc_buffer, MISC_BUFFER_SIZE, "%s -f %s -t < chandrop.txt", CONF_SENDMAIL_PATH, CONF_RETURN_EMAIL);
					system(misc_buffer);

					snprintf(misc_buffer, MISC_BUFFER_SIZE, "rm -f chandrop.txt");
					system(misc_buffer);
				}
				else
					log_error(FACILITY_CHANSERV_HANDLE_DROP, __LINE__, LOG_TYPE_ERROR_RTL, LOG_SEVERITY_ERROR_HALTED,
						"do_drop(): unable to create chandrop.txt");
			}
		}
		else if (ci->auth == 0)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_DROP_ERROR_NOT_DROPPING, ci->name);

		else {

			/* The user supplied an auth code. Check whether he wants to undo the request or proceed with it. */

			if (str_equals_nocase(auth, "UNDO")) {

				ci->auth = 0;
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_DROP_REQUEST_UNDONE, ci->name);
			}
			else {

				char *err;
				unsigned long int authcode = 0;

				authcode = strtoul(auth, &err, 10);

				if ((*err != '\0') || (authcode == 0) || (authcode != ci->auth)) {

					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_WRONG_DROP_CODE);
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);
				}
				else {

					user_remove_chanid(ci);

					LOG_SNOOP(s_OperServ, "CS D! %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
					log_services(LOG_SERVICES_CHANSERV_GENERAL, "D! %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);

					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_DROP_CHAN_DROPPED, ci->name);

					delchan(ci);
				}
			}
		}
	}
}

/*********************************************************/

/* Main SET routine. Calls other routines as follows:
 * do_set_command(User *command-sender, ChannelInfo *ci, char *param);
 * Additional parameters can be retrieved using strtok(NULL, toks). */

static void do_set(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo	*ci;
	const char *chan;
	char *cmd = NULL, *param = NULL;
	int accessLevel, accessMatch, accessStatus;
	char accessName[NICKSIZE];
	BOOL idNick, idChan;
	void (*funcptr)(User *, ChannelInfo *, CSTR, CSTR, const int) = NULL;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SET);

	if (CONF_SET_READONLY) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_ERROR_READONLY);
		return;
	}

	if (IS_NOT_NULL(chan = strtok(NULL, " "))) {

		if (IS_NOT_NULL(cmd = strtok(NULL, " "))) {

			str_toupper(cmd);

			if (str_equals(cmd, "DESC") || str_equals(cmd, "TOPIC") || str_equals(cmd, "WELCOME") ||
				str_equals(cmd, "GREETING") || str_equals(cmd, "MOTD") || str_equals(cmd, "PASSWD"))

				param = strtok(NULL, "");

			else
				param = strtok(NULL, " ");
		}
	}

	TRACE_MAIN();

	if (IS_NULL(cmd) || IS_NULL(param)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "SET");
		return;
	}

	if (*chan != '#') {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);
		return;
	}

	if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, chan);
		return;
	}

	if (FlagSet(ci->flags, CI_FORBIDDEN)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);
		return;
	}

	if (FlagSet(ci->flags, CI_FROZEN)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FROZEN, ci->name);
		return;
	}

	if (FlagSet(ci->flags, CI_CLOSED)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_CLOSED, ci->name);
		return;
	}

	if (FlagSet(ci->flags, CI_SUSPENDED)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_SUSPENDED, ci->name);
		return;
	}

	accessLevel = get_access(callerUser, ci, accessName, &accessMatch, &accessStatus);

	if ((accessLevel < CS_ACCESS_COFOUNDER) || (accessStatus == CS_STATUS_ACCLIST)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_MUST_IDENTIFY, ci->name);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_CS, ci->name);
		return;
	}
	else if (str_equals(cmd, "FOUNDER"))
		funcptr = do_set_founder;

	else if (str_equals(cmd, "PASSWORD") || str_equals(cmd, "PASSWD"))
		funcptr = do_set_password;

	else if (str_equals(cmd, "SUCCESSOR"))
		funcptr = do_set_successor;

	else if (str_equals(cmd, "MEMO") || str_equals(cmd, "MEMOLEVEL"))
		funcptr = do_set_memolevel;

	else if (str_equals(cmd, "VERBOSE")) {

		do_set_verbose(callerUser, ci, param, accessLevel, accessName, accessMatch);
		return;
	}
	else if (str_equals(cmd, "TOPICLOCK")) {

		do_set_topiclock(callerUser, ci, param, accessLevel, accessName, accessMatch);
		return;
	}
	else if (str_equals(cmd, "TOPIC")) {

		do_set_topic(callerUser, ci, param, accessLevel, accessName, accessMatch);
		return;
	}
	else if (str_equals(cmd, "LANG")) {

		do_set_lang(callerUser, ci, param, accessName, accessMatch);
		return;
	}
	else if (str_equals(cmd, "GREETING") || str_equals(cmd, "MOTD") || str_equals(cmd, "WELCOME")) {

		do_set_welcome(callerUser, ci, param, accessName, accessMatch);
		return;
	}
	else if (str_equals(cmd, "DESC")) {

		do_set_desc(callerUser, ci, param, accessName, accessMatch);
		return;
	}
	else if (str_equals(cmd, "URL")) {

		do_set_url(callerUser, ci, param, accessName, accessMatch);
		return;
	}
	else if (str_equals(cmd, "EMAIL")) {

		do_set_email(callerUser, ci, param, accessName, accessMatch);
		return;
	}
	else if (str_equals(cmd, "MLOCK")) {

		do_set_mlock(callerUser, ci, param, accessName, accessMatch);
		return;
	}
	else if (str_equals(cmd, "BANTYPE")) {

		do_set_bantype(callerUser, ci, param, accessName, accessMatch);
		return;
	}
	else if (str_not_equals(cmd, "NOMKICK") && str_not_equals(cmd, "NEVEROP")) {

		do_set_option(callerUser, ci, cmd, param, accessName, accessMatch);
		return;
	}

	idNick = (accessLevel == CS_ACCESS_FOUNDER && accessStatus == CS_STATUS_IDNICK);
	idChan = is_identified(callerUser, ci);

	TRACE_MAIN();
	if (idNick && idChan) {

		if (IS_NOT_NULL(funcptr))
			funcptr(callerUser, ci, param, accessName, accessMatch);
		else
			do_set_option(callerUser, ci, cmd, param, accessName, accessMatch);
	}
	else if (!idChan) {	

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_MUST_IDENTIFY, ci->name);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_CS, ci->name);
	}
	else {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, ci->founder);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, ci->founder);
	}
}

/*********************************************************/

static void do_set_option(User *callerUser, ChannelInfo *ci, CSTR option, CSTR param, CSTR accessName, const int accessMatch) {

	long flag;
	char *optname, *logtype;
	int enable = -1;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SET);

	if (str_equals_nocase(param, "ON"))
		enable = TRUE;

	else if (str_equals_nocase(param, "OFF"))
		enable = FALSE;

	if (str_equals(option, "KEEPTOPIC")) {

		flag = CI_KEEPTOPIC;
		optname = "Topic Retention";
		logtype = "K";
	}
	else if (str_equals(option, "OPGUARD")) {

		flag = CI_OPGUARD;
		optname = "Op Guard";
		logtype = "O";

		if ((enable == TRUE) && FlagSet(ci->flags, CI_AUTOOP)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_ERROR_OTHER_ON, optname, "Auto Op");
			return;
		}
	}
	else if (str_equals(option, "RESTRICT")) {

		flag = CI_RESTRICTED;
		optname = "Restrict";
		logtype = "R";
	}
	else if (str_equals(option, "PROTECT")) {

		flag = CI_PROTECTED;
		optname = "Protect";
		logtype = "P";
	}
	else if (str_equals(option, "NOMKICK")) {

		flag = CI_NOMKICK;
		optname = "No MassKick";
		logtype = "N";
	}
	else if (str_equals(option, "IDENT")) {

		flag = CI_IDENT;
		optname = "Ident";
		logtype = "I";
	}
	else if (str_equals(option, "AUTOOP")) {

		flag = CI_AUTOOP;
		optname = "Auto Op";
		logtype = "AO";

		if (enable == TRUE) {

			if (FlagSet(ci->flags, CI_OPGUARD)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_ERROR_OTHER_ON, optname, "Op Guard");
				return;
			}

			if (FlagSet(ci->flags, CI_AUTOHALFOP)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_PICK_ONE, optname, "Auto HalfOp");
				return;
			}
			
			if (FlagSet(ci->flags, CI_AUTOVOICE)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_PICK_ONE, optname, "Auto Voice");
				return;
			}

			if (FlagSet(ci->flags, CI_NEVEROP)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_PICK_ONE, optname, "Never Op");
				return;
			}
		}
	}
	else if (str_equals(option, "AUTOHALFOP")) {

		flag = CI_AUTOHALFOP;
		optname = "Auto HalfOp";
		logtype = "AH";

		if ((enable == TRUE) && FlagSet(ci->flags, CI_AUTOOP)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_PICK_ONE, optname, "Auto Op");
			return;
		}
		
		if ((enable == TRUE) && FlagSet(ci->flags, CI_AUTOVOICE)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_PICK_ONE, optname, "Auto Voice");
			return;
		}
	}
	else if (str_equals(option, "AUTOVOICE")) {

		flag = CI_AUTOVOICE;
		optname = "Auto Voice";
		logtype = "AV";

		if ((enable == TRUE) && FlagSet(ci->flags, CI_AUTOOP)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_PICK_ONE, optname, "Auto Op");
			return;
		}
		
		if ((enable == TRUE) && FlagSet(ci->flags, CI_AUTOHALFOP)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_PICK_ONE, optname, "Auto HalfOp");
			return;
		}
	}
	else if (str_equals(option, "NEVEROP")) {

		flag = CI_NEVEROP;
		optname = "Never Op";
		logtype = "R";

		if (enable == TRUE) {

			if (FlagSet(ci->flags, CI_AUTOOP)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_ERROR_OTHER_ON, optname, "Auto Op");
				return;
			}
		}
	}
	else {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_UNKNOWN_SET_COMMAND, option);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "SET");
		return;
	}

	if (enable == -1) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_OPTION_SYNTAX_ERROR, option);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_SET_COMMAND, s_CS, option);
	}
	else if (enable == TRUE) {

		if (FlagSet(ci->flags, flag)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_ERROR_OPTION_ALREADY_ON, optname, ci->name);
			return;
		}

		TRACE_MAIN();
		AddFlag(ci->flags, flag);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_OPTION_ON, optname, ci->name);

		if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

			if (accessMatch)
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_OPTION_ON), s_ChanServ, ci->name, callerUser->nick, option);
			else
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_OPTION_ON_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName, option);
		}

		if (accessMatch)
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET %s %s ON -- by %s (%s@%s)", logtype, ci->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET %s %s ON -- by %s (%s@%s) through %s", logtype, ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName);
	}
	else {

		TRACE_MAIN();
		if (FlagUnset(ci->flags, flag)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_ERROR_OPTION_ALREADY_OFF, optname, ci->name);
			return;
		}

		RemoveFlag(ci->flags, flag);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_OPTION_OFF, optname, ci->name);

		if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

			if (accessMatch)
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_OPTION_OFF), s_ChanServ, ci->name, callerUser->nick, option);
			else
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_OPTION_OFF_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName, option);
		}

		if (accessMatch)
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET %s %s OFF -- by %s (%s@%s)", logtype, ci->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET %s %s OFF -- by %s (%s@%s) through %s", logtype, ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName);
	}
}

/*********************************************************/

static void do_set_founder(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch) {

	NickInfo *newFounder;
	User *newUser;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SET_FOUNDER);

	if (IS_NULL(newFounder = findnick(param)))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_NICK_NOT_REG, param);

	else if (str_equals_nocase(ci->founder, newFounder->nick))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_FOUNDER_ERROR_ALREADY_FOUNDER, newFounder->nick, ci->name);

	else if (FlagSet(newFounder->flags, NI_NOOP))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_FOUNDER_ERROR_NOOP_ON, newFounder->nick);

	else if (CONF_FORCE_AUTH && FlagSet(newFounder->flags, NI_AUTH))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_FOUNDER_ERROR_NICK_NOT_AUTH, newFounder->nick);

	else if (IS_NULL(newUser = hash_onlineuser_find(param)) || !user_is_identified_to(newUser, newFounder->nick))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_FOUNDER_ERROR_NICK_OFFLINE, newFounder->nick);

	else {

		NickInfo *ni;
		ChanAccess *anAccess;
		int idx;
		unsigned long int randID;
		char memoText[512];


		TRACE_MAIN();

		if (IS_NOT_NULL(ni = findnick(ci->founder))) {

			if (ni->channelcount > 0)
				--(ni->channelcount);
			else		
				log_error(FACILITY_CHANSERV_HANDLE_SET_FOUNDER, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
					"%s in do_set_founder(): Nickname record %s has a negative channelcount value", s_ChanServ, ni->nick);
		}
		else
			log_error(FACILITY_CHANSERV_HANDLE_SET_FOUNDER, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
				"%s in do_set_founder(): Could not find NickInfo record for %s founder %s", s_ChanServ, ci->name, ci->founder);

		++(newFounder->channelcount);

		/* Notify the old owner of the successful change. */
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_FOUNDER_CHANGED, ci->name, param);

		/* Change the password to a random one. */
		srand(randomseed());
		randID = (NOW + getrandom(1, 99999) * getrandom(1, 9999));

		/* Log this action. */
		LOG_SNOOP(s_OperServ, "CS F %s -- by %s (%s@%s) [%s -> %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->founder, newFounder->nick);
		log_services(LOG_SERVICES_CHANSERV_GENERAL, "F %s -- by %s (%s@%s) [%s -> %s] [P: %s -> %s-%lu]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->founder, newFounder->nick, ci->founderpass, CRYPT_NETNAME, randID);

		/* Change the channel password to the new (random) one. */
		snprintf(ci->founderpass, sizeof(ci->founderpass), "%s-%lu", CRYPT_NETNAME, randID);

		/* Notify the new owner about it via memo. */
		snprintf(memoText, sizeof(memoText), lang_msg(EXTRACT_LANG_ID(newFounder->langID), CS_SET_FOUNDER_CHANGED_NEW), ci->founder, ci->name, CRYPT_NETNAME, randID);
		send_memo_internal(newFounder, memoText);

		/* Now actually change the founder. */
		str_copy_checked(newFounder->nick, ci->founder, NICKMAX);

		/* Remove identification to this channel from all users. */
		user_remove_chanid(ci);

		if (str_equals_nocase(ci->founder, ci->successor)) {

			mem_free(ci->successor);
			ci->successor = NULL;
		}

		for (anAccess = ci->access, idx = 0; (idx < ci->accesscount); ++anAccess, ++idx) {

			if ((anAccess->status == ACCESS_ENTRY_NICK) && str_equals_nocase(anAccess->name, ci->founder)) {

				TRACE_MAIN();
				mem_free(anAccess->name);
				anAccess->name = NULL;

				mem_free(anAccess->creator);
				anAccess->creator = NULL;

				anAccess->status = ACCESS_ENTRY_FREE;
				anAccess->flags = 0;
				anAccess->creationTime = 0;

 				/* E' possibile chiamarla direttamente qua poiché il for() termina al successivo break. */
				compact_chan_access_list(ci, 1);

				TRACE_MAIN();
				if (newFounder->channelcount > 0)
					--(newFounder->channelcount);
				else
					log_error(FACILITY_CHANSERV_HANDLE_REMOVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
						"%s in do_set_founder(): Nickname record %s has a negative channelcount value", s_ChanServ, newFounder->nick);

				break;
			}
		}

		if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET))
			send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_FOUNDER_CHANGED), s_ChanServ, ci->name, callerUser->nick, param);
	}
}

/*********************************************************/

static void do_set_password(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch) {
	
	char	*newpass;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SET_PASSWORD);

	if (param && (newpass = strchr(param, ' '))) {

		*newpass++ = 0;

		TRACE_MAIN();
		if (strchr(newpass, ' '))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_WITH_SPACES);

		else if (strpbrk(newpass, "<>"))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_BRAKES_IN_PASS, "<", ">");

		else if (string_has_ccodes(newpass))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_WITH_CCODES);

		else if ((str_len(newpass) < 5) || str_equals_nocase(newpass, ci->name) || str_equals_nocase(newpass, ci->name+1))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_INSECURE_PASSWORD);

		else if (str_equals_nocase(newpass, "PASSWORD"))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_AS_PASS);

		else if (str_len(newpass) > PASSMAX)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_MAX_LENGTH, PASSMAX);

		else {

			/* param == vecchia password */

			if (str_equals(param, ci->founderpass)) {

				if (str_not_equals(param, newpass)) {

					TRACE_MAIN();
					if (CONF_SET_EXTRASNOOP)
						LOG_SNOOP(s_OperServ, "CS P %s -- by %s (%s@%s) [%s -> %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->founderpass, newpass);
					else
						LOG_SNOOP(s_OperServ, "CS P %s -- by %s (%s@%s) [Logged]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

					log_services(LOG_SERVICES_CHANSERV_GENERAL, "P %s -- by %s (%s@%s) [%s -> %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->founderpass, newpass);
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_PASSWD_PASSWORD_CHANGED, ci->name, newpass);

					str_copy_checked(newpass, ci->founderpass, PASSMAX);

					user_remove_chanid(ci);

					TRACE_MAIN();
					link_channel(callerUser, ci);

					if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET))
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_PASSWD), s_ChanServ, ci->name, callerUser->nick);
				}
				else
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_SAME_PASSWORD);
			}
			else {

				TRACE_MAIN();
				LOG_SNOOP(s_OperServ, "CS *P %s -- by %s (%s@%s) [Wrong Old Pass: %s ]", ci->name, callerUser->nick, callerUser->username, callerUser->host, param);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "*P %s -- by %s (%s@%s) [Old Pass: %s - Given: %s ]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->founderpass, param);

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_PASSWD_ERROR_WRONG_OLD_PASS, ci->name);

				update_invalid_password_count(callerUser, s_NickServ, ci->name);
			}
		} 
	}
	else {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_PASSWD_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "SET PASSWD");
	}
}

/*********************************************************/

static void do_set_successor(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch) {

	NickInfo *ni;
	ChanAccess *anAccess;
	int i, found = 0;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SET_FOUNDER);

	if (str_equals_nocase(param, "None")) {

		if (IS_NULL(ci->successor))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_SUCCESSOR_ERROR_EMPTY, ci->name);

		else {

			mem_free(ci->successor);
			ci->successor = NULL;
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_SUCCESSOR_REMOVED, ci->name);

			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

				if (accessMatch)
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_SUCCESSOR_REMOVED), s_ChanServ, ci->name, callerUser->nick);
				else
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_SUCCESSOR_REMOVED_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName);
			}
		}
		return;
	}

	if (IS_NULL(ni = findnick(param))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_NICK_NOT_REG, param);
		return;
	}

	if (str_equals_nocase(ci->founder, ni->nick)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_SUCCESSOR_ERROR_FOUNDER, ni->nick, ci->name);
		return;
	}

	for (anAccess = ci->access, i = 0; (i < ci->accesscount) && IS_NOT_NULL(anAccess); ++anAccess, ++i) {

		if ((anAccess->status == ACCESS_ENTRY_NICK) && (anAccess->level == CS_ACCESS_COFOUNDER)
			&& str_equals_nocase(ni->nick, anAccess->name)) {

			found = 1;
			break;
		}
	}

	if (found != 1)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_SUCCESSOR_ERROR_NOT_CF, ci->name);

	else {

		TRACE_MAIN();

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_SUCCESSOR_CHANGED, ni->nick, ci->name);

		if (ci->successor)
			mem_free(ci->successor);
		ci->successor = str_duplicate(ni->nick);

		if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

			if (accessMatch)
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_SUCCESSOR_CHANGED), s_ChanServ, ci->name, callerUser->nick, param);
			else
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_SUCCESSOR_CHANGED_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName, param);
		}
		if (accessMatch)
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET S %s -- by %s (%s@%s) [%s -> %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->successor ? ci->successor : "None", ni->nick);
		else
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET S %s -- by %s (%s@%s) through %s [%s -> %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName, ci->successor ? ci->successor : "None", ni->nick);
	}
}

/*********************************************************/

static void do_set_welcome(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch) {

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SET_WELCOME);

	if (str_equals_nocase(param, "none")) {

		if (ci->welcome) {

			TRACE_MAIN();
			mem_free(ci->welcome);
			ci->welcome = NULL;

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_WELCOME_DELETED, ci->name);

			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

				if (accessMatch)
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_WELCOME_DELETED), s_ChanServ, ci->name, callerUser->nick);
				else
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_WELCOME_DELETED_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName);
			}

			if (accessMatch)
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET -W %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			else
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET -W %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName);
		}
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_WELCOME_ERROR_NO_WELCOME, ci->name);
	}

	else if (str_len(param) > 400)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_WELCOME_ERROR_TOO_LONG, 400);

	else {

		TRACE_MAIN();
		if (ci->welcome)
			mem_free(ci->welcome);
		ci->welcome = str_duplicate(param);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_WELCOME_CHANGED, ci->name, ci->welcome);

		if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

			if (accessMatch)
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_WELCOME_CHANGED), s_ChanServ, ci->name, callerUser->nick);
			else
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_WELCOME_CHANGED_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName);
		}

		if (accessMatch)
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET W %s -- by %s (%s@%s) [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->welcome);
		else
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET W %s -- by %s (%s@%s) through %s [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName, ci->welcome);
	}
}

/*********************************************************/

static void do_set_lang(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch) {

	LANG_ID lang_id;
	char *err;


	TRACE_MAIN_FCLT(FACILITY_NICKSERV_HANDLE_SET_LANG);

	if (str_equals_nocase(param, "LIST")) {

		lang_send_list(s_ChanServ, callerUser);
		return;
	}

	lang_id = strtoul(param, &err, 10);

	if ((lang_id <= 0) || (*err != '\0')) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_LANG_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "SET LANG");
		return;
	}
	else {

		TRACE_MAIN();
		--lang_id;

		if (lang_is_active_language(lang_id)) {

			ci->langID = COMPACT_LANG_ID(lang_id);

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_LANG_CHANGED, ci->name, lang_get_name(lang_id, TRUE), lang_get_name(lang_id, FALSE));

			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

				if (accessMatch)
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_LANG_CHANGED), s_ChanServ, ci->name, callerUser->nick);
				else
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_LANG_CHANGED_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName);
			}

			if (accessMatch)
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET L %s -- by %s (%s@%s) [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, lang_get_name(lang_id, FALSE));
			else
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET L %s -- by %s (%s@%s) through %s [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName, lang_get_name(lang_id, FALSE));
		}
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_LANG_ERROR_INVALID);
	}
}

/*********************************************************/

static void do_set_desc(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch) {

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SET_DESC);

	if (str_len(param) > 400) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_DESC_ERROR_MAX_LENGTH, 400);
		return;
	}

	mem_free(ci->desc);
	ci->desc = str_duplicate(param);
	send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_DESC_CHANGED, ci->name, param);

	TRACE_MAIN();
	if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

		if (accessMatch)
			send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_DESC), s_ChanServ, ci->name, callerUser->nick);
		else
			send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_DESC_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName);
	}

	if (accessMatch)
		log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET D %s -- by %s (%s@%s) [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->desc);
	else
		log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET D %s -- by %s (%s@%s) through %s [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName, ci->desc);
}

/*********************************************************/

static void do_set_url(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch) {

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SET_URL);

	if (str_equals_nocase(param, "NONE")) {

		if (ci->url) {

			TRACE_MAIN();
			mem_free(ci->url);
			ci->url = NULL;
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_URL_DELETED, ci->name);

			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

				if (accessMatch)
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_URL_DELETED), s_ChanServ, ci->name, callerUser->nick);
				else
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_URL_DELETED_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName);
			}

			if (accessMatch)
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET -U %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			else
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET -U %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName);
		}
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_URL_ERROR_NO_URL, ci->name);
	}
	else if (str_len(param) > URLMAX)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_URL_MAX_LENGTH, URLMAX);

	else if (string_has_ccodes(param))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_URL_FORMAT);

	else {

		TRACE_MAIN();
		if (ci->url)
			mem_free(ci->url);

		ci->url = str_duplicate(param);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_URL_CHANGED, ci->name, param);

		TRACE_MAIN();
		if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

			if (accessMatch)
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_URL_CHANGED), s_ChanServ, ci->name, callerUser->nick);
			else
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_URL_CHANGED_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName);
		}

		if (accessMatch)
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET U %s -- by %s (%s@%s) [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->url);
		else
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET U %s -- by %s (%s@%s) through %s [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName, ci->url);
	}
}

/*********************************************************/

static void do_set_email(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch) {

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SET_EMAIL);

	if (str_equals_nocase(param, "NONE")) {

		if (ci->email) {

			TRACE_MAIN();
			mem_free(ci->email);
			ci->email = NULL;

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_EMAIL_DELETED, ci->name);

			TRACE_MAIN();
			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

				if (accessMatch)
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_EMAIL_DELETED), s_ChanServ, ci->name, callerUser->nick);
				else
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_EMAIL_DELETED_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName);
			}

			if (accessMatch)
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET -E %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			else
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET -E %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName);
		}
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_EMAIL_ERROR_NO_EMAIL, ci->name);
	}
	else if (str_len(param) > MAILMAX)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_MAIL_MAX_LENGTH, MAILMAX);

	else if (string_has_ccodes(param) || !validate_email(param, FALSE))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_EMAIL, param);

	else {

		TRACE_MAIN();
		if (ci->email)
			mem_free(ci->email);

		ci->email = str_duplicate(param);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_EMAIL_CHANGED, ci->name, param);

		TRACE_MAIN();
		if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

			if (accessMatch)
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_EMAIL_CHANGED), s_ChanServ, ci->name, callerUser->nick);
			else
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_EMAIL_CHANGED_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName);
		}

		if (accessMatch)
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET E %s -- by %s (%s@%s) [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->email);
		else
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET E %s -- by %s (%s@%s) through %s [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName, ci->email);
	}
}

/*********************************************************/

static void do_set_topic(User *callerUser, ChannelInfo *ci, CSTR param, const int accessLevel, CSTR accessName, const int accessMatch) {

	Channel *chan;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SET_TOPIC);

	if (IS_NULL(chan = hash_channel_find(ci->name)))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHAN_DOES_NOT_EXIST, ci->name);

	else if ((ci->topic_allow == CS_ACCESS_FOUNDER) && (accessLevel != CS_ACCESS_FOUNDER))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

	else if (str_len(param) > TOPICMAX)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_TOPIC_MAX_LENGTH, TOPICMAX);

	else {

		TRACE_MAIN();
		if (ci->last_topic)
			mem_free(ci->last_topic);
		ci->last_topic = str_duplicate(param);

		str_copy_checked(accessName, ci->last_topic_setter, NICKMAX);
		ci->last_topic_time = NOW;

		TRACE_MAIN();
		if (chan->topic)
			mem_free(chan->topic);
		chan->topic = str_duplicate(param);

		str_copy_checked(accessName, chan->topic_setter, NICKMAX);
		chan->topic_time = NOW;

		send_cmd(":%s TOPIC %s %s %lu :%s", s_ChanServ, ci->name, accessName, NOW, param);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPIC_CHANGED, ci->name);

		if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

			if (accessMatch)
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_TOPIC_CHANGED), s_ChanServ, ci->name, callerUser->nick);
			else
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_TOPIC_CHANGED_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName);
		}

		if (accessMatch)
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET T %s -- by %s (%s@%s) [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->last_topic);
		else
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET T %s -- by %s (%s@%s) through %s [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName, ci->last_topic);
	}
}

/*********************************************************/

#define MLOCK(mode) \
	if (add) { \
		if (FlagSet(ci->mlock_off, (mode))) \
			RemoveFlag(ci->mlock_off, (mode)); \
		AddFlag(ci->mlock_on, (mode)); \
	} \
	else { \
		if (FlagSet(ci->mlock_on, (mode))) \
			RemoveFlag(ci->mlock_on, (mode)); \
		AddFlag(ci->mlock_off, (mode)); \
	}

static void do_set_mlock(User *callerUser, ChannelInfo *ci, char *param, CSTR accessName, const int accessMatch) {

	char invalid[256], unknown[256];
	char *token, *ptr;
	char c;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SET_MLOCK);

	if (str_not_equals_nocase(param, "NONE") && (str_len(param) <= 1)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_SYNTAX_ERROR, ci->name);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "SET MLOCK");
		return;
	}

	ci->mlock_on = ci->mlock_off = ci->mlock_limit = 0;

	TRACE_MAIN();
	if (ci->mlock_key) {

		mem_free(ci->mlock_key);
		ci->mlock_key = NULL;
	}

	if (str_equals_nocase(param, "NONE")) {

		TRACE_MAIN();
		AddFlag(ci->mlock_on, CMODE_r);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_NONE, ci->name);

		if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

			if (accessMatch)
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_MLOCK_NONE), s_ChanServ, ci->name, callerUser->nick);
			else
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_MLOCK_NONE_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName);
		}

		if (accessMatch)
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET -M %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET -M %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName);

		return;
	}
	else {

		int add = -1;			/* 1 if adding, 0 if deleting, -1 if neither */
		int send_l = 0, send_l2 = 0, send_k = 0, send_k2 = 0, send_O = 0;

		TRACE_MAIN();
		if ((param[0] != '+') && (param[0] != '-')) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_SYNTAX_ERROR, ci->name);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "SET MLOCK");
			return;
		}

		memset(invalid, 0, sizeof(invalid));
		memset(unknown, 0, sizeof(unknown));

		while (*param) {

			switch (c = *param++) {

				case '+':
					add = 1;
					break;

				case '-':
					add = 0;
					break;

				case 'b':
					if (!strchr(invalid, 'b'))
						strcat(invalid, "b");
					break;

				case 'c':
					MLOCK(CMODE_c)
					break;

				case 'C':
					MLOCK(CMODE_C)
					break;

				case 'd':
					MLOCK(CMODE_d)
					break;

				case 'h':
					if (!strchr(invalid, 'h'))
						strcat(invalid, "h");
					break;
					
				case 'i':
					MLOCK(CMODE_i)
					break;

				case 'j':
					MLOCK(CMODE_j)
					break;

				case 'k':
					if (add) {

						if (FlagSet(ci->mlock_on, CMODE_k))
							break;

						if (FlagSet(ci->mlock_off, CMODE_k))
							RemoveFlag(ci->mlock_off, CMODE_k);

						if (IS_NULL(token = strtok(NULL, " "))) {

							if (send_k == 0) {

								send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_MISSING_PARAM, 'k');
								send_k = 1;
							}
							break;
						}

						if (strchr(token, '*')) {

							if (send_k2 == 0) {

								send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_KEY_HAS_STAR);
								send_k2 = 1;
							}
							break;
						}

						while (*token == ':')
							++token;

						if (*token == '\0') {

							if (send_k2 == 0) {

								send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_KEY);
								send_k2 = 1;
							}
							break;
						}

						if (str_len(token) > KEYMAX)
							token[KEYMAX] = '\0';

						ci->mlock_key = str_duplicate(token);

						AddFlag(ci->mlock_on, CMODE_k);
					}
					else {

						if (FlagSet(ci->mlock_on, CMODE_k)) {

							mem_free(ci->mlock_key);
							ci->mlock_key = NULL;

							RemoveFlag(ci->mlock_on, CMODE_k);
						}

						AddFlag(ci->mlock_off, CMODE_k);
					}
					break;

				case 'l':
					if (add) {

						char		*err;
						long int	limit;


						if (ci->mlock_limit > 0)
							break;

						if (FlagSet(ci->mlock_off, CMODE_l))
							RemoveFlag(ci->mlock_off, CMODE_l);

						if (IS_NULL(token = strtok(NULL, " "))) {

							if (send_l == 0) {

								send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_MISSING_PARAM, 'l');
								send_l = 1;
							}
							break;
						}

						limit = strtol(token, &err, 10);

						if ((*err != '\0') || (limit <= 0)) {

							if (send_l2 == 0) {

								send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_NEGATIVE_LIMIT);
								send_l2 = 1;
							}
							break;
						}

						ci->mlock_limit = limit;
						AddFlag(ci->mlock_on, CMODE_l);
					}
					else {

						ci->mlock_limit = 0;

						if (FlagSet(ci->mlock_on, CMODE_l))
							RemoveFlag(ci->mlock_on, CMODE_l);
						AddFlag(ci->mlock_off, CMODE_l);
					}

					break;

				case 'm':
					MLOCK(CMODE_m)
					break;

				case 'M':
					MLOCK(CMODE_M)
					break;

				case 'n':
					MLOCK(CMODE_n)
					break;

				case 'o':
					if (!strchr(invalid, 'o'))
						strcat(invalid, "o");
					break;

				case 'O':
					if (user_is_ircop(callerUser)) {

						MLOCK(CMODE_O)
						break;
					}
					else {

						if (send_O == 0) {

							send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_ERROR_IRCOP_ONLY_MODE, c);
							send_O = 1;
						}
					}
					break;

				case 'p':
					MLOCK(CMODE_p)
					break;

				case 'r':
					if (!strchr(invalid, 'r'))
						strcat(invalid, "r");
					break;

				case 'R':
					MLOCK(CMODE_R)
					break;

				case 's':
					MLOCK(CMODE_s)
					break;

				case 'S':
					MLOCK(CMODE_S)
					break;

				case 't':
					MLOCK(CMODE_t)
					break;

				case 'u':
					MLOCK(CMODE_u)
					break;

				case 'U':
					MLOCK(CMODE_U)
					break;
				
				case 'v':
					if (!strchr(invalid, 'v'))
						strcat(invalid, "v");
					break;

				default:
					TRACE_MAIN();
					if (!strchr(unknown, c)) {

						ptr = unknown;

						while (*ptr != '\0')
							++ptr;

						*ptr = c;
						*(ptr + 1) = '\0';
					}

					break;
			}
		}
	}

	TRACE_MAIN();

	if (*invalid)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_ERROR_INVALID_MODE, invalid);

	if (*unknown)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_ERROR_UNKNOWN_MODE, unknown);

	if ((ci->mlock_on != 0) || (ci->mlock_off != 0)) {

		char	*modebuf, *ptrKey, *ptrLimit;
		BOOL	removeKey = FlagSet(ci->mlock_off, CMODE_k);
		BOOL	removeLimit = FlagSet(ci->mlock_off, CMODE_l);
		Channel	*channel;


		modebuf = get_channel_mode(ci->mlock_on, ci->mlock_off);

		TRACE_MAIN();

		ptrKey = strrchr(modebuf, 'k');
		ptrLimit = strrchr(modebuf, 'l');

		TRACE_MAIN();

		if (ptrKey == ptrLimit)	/* Both are NULL. */
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_CHANGED_NO_KL, ci->name, modebuf);

		else if (ptrKey < ptrLimit) {

			if (ptrKey) {

				if (removeKey && removeLimit)
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_CHANGED_NO_KL, ci->name, modebuf);

				else if (removeKey)
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_CHANGED_L, ci->name, modebuf, ci->mlock_limit);

				else if (removeLimit)
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_CHANGED_K, ci->name, modebuf, ci->mlock_key);

				else
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_CHANGED_KL, ci->name, modebuf, ci->mlock_key, ci->mlock_limit);
			}
			else {

				if (removeLimit)
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_CHANGED_NO_KL, ci->name, modebuf);

				else
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_CHANGED_L, ci->name, modebuf, ci->mlock_limit);
			}
		}
		else {

			if (ptrLimit) {

				if (removeKey && removeLimit)
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_CHANGED_NO_KL, ci->name, modebuf);

				else if (removeKey)
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_CHANGED_L, ci->name, modebuf, ci->mlock_limit);

				else if (removeLimit)
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_CHANGED_K, ci->name, modebuf, ci->mlock_key);

				else
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_CHANGED_LK, ci->name, modebuf, ci->mlock_limit, ci->mlock_key);
			}
			else {

				if (removeKey)
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_CHANGED_NO_KL, ci->name, modebuf);
				else
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_CHANGED_K, ci->name, modebuf, ci->mlock_key);
			}
		}

		TRACE_MAIN();
		if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

			if (accessMatch)
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_MLOCK_CHANGED), s_ChanServ, ci->name, callerUser->nick);
			else
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_MLOCK_CHANGED_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName);
		}

		if (accessMatch)
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET M %s -- by %s (%s@%s) [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, modebuf);
		else
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET M %s -- by %s (%s@%s) through %s [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName, modebuf);

		TRACE_MAIN();
		AddFlag(ci->mlock_on, CMODE_r);

		channel = hash_channel_find(ci->name);

		if (IS_NOT_NULL(channel))
			check_modelock(channel, NULL);
	}
	else {

		AddFlag(ci->mlock_on, CMODE_r);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MLOCK_ERROR_NOTHING_TO_DO);
	}
}

#undef MLOCK

/*********************************************************/

static void do_set_topiclock(User *callerUser, ChannelInfo *ci, CSTR param, const int accessLevel, CSTR accessName, const int accessMatch) {

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SET_TOPICLOCK);

	if ((ci->topic_allow == CS_ACCESS_FOUNDER) && (accessLevel != CS_ACCESS_FOUNDER)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_VALUE_FOUNDER_ONLY);
		return;
	}
	else if (str_equals_nocase(param, "VOP")) {

		if (ci->topic_allow == CS_ACCESS_VOP) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPICLOCK_ERROR_ALREADY_SET, ci->name, "VOP");
			return;
		}

		TRACE_MAIN();
		AddFlag(ci->flags, CI_TOPICLOCK);
		ci->topic_allow = CS_ACCESS_VOP;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPICLOCK_ON, ci->name, "VOP");
	}
	else if (str_equals_nocase(param, "HOP")) {

		if (ci->topic_allow == CS_ACCESS_HOP) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPICLOCK_ERROR_ALREADY_SET, ci->name, "HOP");
			return;
		}

		TRACE_MAIN();
		AddFlag(ci->flags, CI_TOPICLOCK);
		ci->topic_allow = CS_ACCESS_HOP;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPICLOCK_ON, ci->name, "HOP");
	}
	else if (str_equals_nocase(param, "AOP")) {

		if (ci->topic_allow == CS_ACCESS_AOP) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPICLOCK_ERROR_ALREADY_SET, ci->name, "AOP");
			return;
		}

		TRACE_MAIN();
		AddFlag(ci->flags, CI_TOPICLOCK);
		ci->topic_allow = CS_ACCESS_AOP;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPICLOCK_ON, ci->name, "AOP");
	}
	else if (str_equals_nocase(param, "SOP")) {

		if (ci->topic_allow == CS_ACCESS_SOP) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPICLOCK_ERROR_ALREADY_SET, ci->name, "SOP");
			return;
		}

		TRACE_MAIN();
		AddFlag(ci->flags, CI_TOPICLOCK);
		ci->topic_allow = CS_ACCESS_SOP;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPICLOCK_ON, ci->name, "SOP");
	}
	else if (str_equals_nocase(param, "CFOUNDER") || str_equals_nocase(param, "CF") || str_equals_nocase(param, "COFOUNDER")) {

		if (ci->topic_allow == CS_ACCESS_COFOUNDER) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPICLOCK_ERROR_ALREADY_SET, ci->name, "Co-Founder");
			return;
		}

		TRACE_MAIN();
		AddFlag(ci->flags, CI_TOPICLOCK);
		ci->topic_allow = CS_ACCESS_COFOUNDER;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPICLOCK_ON, ci->name, "Co-Founder");
	}
	else if (str_equals_nocase(param, "FOUNDER")) {

		if (access == 0) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_VALUE_FOUNDER_ONLY);
			return;
		}

		if (ci->topic_allow == CS_ACCESS_FOUNDER) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPICLOCK_ERROR_ALREADY_SET, ci->name, "Founder");
			return;
		}

		TRACE_MAIN();
		AddFlag(ci->flags, CI_TOPICLOCK);
		ci->topic_allow = CS_ACCESS_FOUNDER;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPICLOCK_ON, ci->name, "Founder");
	}
	else if (str_equals_nocase(param, "OFF")) {

		if (ci->topic_allow == CS_ACCESS_NONE) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPICLOCK_ERROR_ALREADY_OFF, ci->name);
			return;
		}

		TRACE_MAIN();
		RemoveFlag(ci->flags, CI_TOPICLOCK);
		ci->topic_allow = CS_ACCESS_NONE;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPICLOCK_OFF, ci->name);
	}
	else {

		TRACE_MAIN();
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_TOPICLOCK_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "SET TOPICLOCK");
		return;
	}

	if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

		if (accessMatch)
			send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_TOPICLOCK_CHANGED), s_ChanServ, ci->name, callerUser->nick);
		else
			send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_TOPICLOCK_CHANGED_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName);
	}

	if (accessMatch)
		log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET TL %s -- by %s (%s@%s) [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, param);
	else
		log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET TL %s -- by %s (%s@%s) through %s [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName, param);
}

/*********************************************************/

static void do_set_bantype(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch) {

	long int value;
	char *err;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SET_AUTOVOICE);

	value = strtol(param, &err, 10);

	if (*err != '\0' || value < 0 || value > 9) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_BANTYPE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "SET BANTYPE");
	}
	else if (ci->banType == value)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_BANTYPE_ERROR_ALREADY_SET, ci->name, value);

	else {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_BANTYPE_SET, ci->name, value, ci->banType);
		ci->banType = value;
	}
}

/*********************************************************/

static void do_set_memolevel(User *callerUser, ChannelInfo *ci, CSTR param, CSTR accessName, const int accessMatch) {

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SET_MEMOLEVEL);

	if (IS_NULL(param)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "SET MEMOLEVEL");
		return;
	}

	TRACE_MAIN();

	str_toupper((char *) param);

	TRACE_MAIN();
	if (str_equals(param, "NONE")) {

		if (FlagSet(ci->flags, CI_MEMO_NONE)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_ERROR_ALREADY_NONE, ci->name);
			return;
		}

		RemoveFlag(ci->flags, CI_MEMO_VOP);
		RemoveFlag(ci->flags, CI_MEMO_HOP);
		RemoveFlag(ci->flags, CI_MEMO_AOP);
		RemoveFlag(ci->flags, CI_MEMO_SOP);
		RemoveFlag(ci->flags, CI_MEMO_CF);
		RemoveFlag(ci->flags, CI_MEMO_FR);

		AddFlag(ci->flags, CI_MEMO_NONE);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_NONE, ci->name);
	}
	else if (str_equals(param, "VOP")) {

		if (FlagSet(ci->flags, CI_MEMO_VOP)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_ERROR_ALREADY_SET, ci->name, "VOP");
			return;
		}

		RemoveFlag(ci->flags, CI_MEMO_HOP);
		RemoveFlag(ci->flags, CI_MEMO_AOP);
		RemoveFlag(ci->flags, CI_MEMO_SOP);
		RemoveFlag(ci->flags, CI_MEMO_CF);
		RemoveFlag(ci->flags, CI_MEMO_FR);
		RemoveFlag(ci->flags, CI_MEMO_NONE);

		AddFlag(ci->flags, CI_MEMO_VOP);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_ON, ci->name, "VOP");
	}
	else if (str_equals(param, "HOP")) {

		if (FlagSet(ci->flags, CI_MEMO_HOP)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_ERROR_ALREADY_SET, ci->name, "HOP");
			return;
		}

		RemoveFlag(ci->flags, CI_MEMO_VOP);
		RemoveFlag(ci->flags, CI_MEMO_AOP);
		RemoveFlag(ci->flags, CI_MEMO_SOP);
		RemoveFlag(ci->flags, CI_MEMO_CF);
		RemoveFlag(ci->flags, CI_MEMO_FR);
		RemoveFlag(ci->flags, CI_MEMO_NONE);

		AddFlag(ci->flags, CI_MEMO_HOP);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_ON, ci->name, "HOP");
	}
	else if (str_equals(param, "AOP")) {

		if (FlagSet(ci->flags, CI_MEMO_AOP)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_ERROR_ALREADY_SET, ci->name, "AOP");
			return;
		}

		RemoveFlag(ci->flags, CI_MEMO_VOP);
		RemoveFlag(ci->flags, CI_MEMO_HOP);
		RemoveFlag(ci->flags, CI_MEMO_SOP);
		RemoveFlag(ci->flags, CI_MEMO_CF);
		RemoveFlag(ci->flags, CI_MEMO_FR);
		RemoveFlag(ci->flags, CI_MEMO_NONE);

		AddFlag(ci->flags, CI_MEMO_AOP);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_ON, ci->name, "AOP");
	}
	else if (str_equals(param, "SOP")) {

		if (FlagSet(ci->flags, CI_MEMO_SOP)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_ERROR_ALREADY_SET, ci->name, "SOP");
			return;
		}

		RemoveFlag(ci->flags, CI_MEMO_VOP);
		RemoveFlag(ci->flags, CI_MEMO_HOP);
		RemoveFlag(ci->flags, CI_MEMO_AOP);
		RemoveFlag(ci->flags, CI_MEMO_CF);
		RemoveFlag(ci->flags, CI_MEMO_FR);
		RemoveFlag(ci->flags, CI_MEMO_NONE);

		AddFlag(ci->flags, CI_MEMO_SOP);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_ON, ci->name, "SOP");
	}
	else if (str_equals(param, "CFOUNDER") || str_equals(param, "CF") || str_equals(param, "COFOUNDER")) {

		if (FlagSet(ci->flags, CI_MEMO_CF)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_ERROR_ALREADY_SET, ci->name, "Co-Founder");
			return;
		}

		RemoveFlag(ci->flags, CI_MEMO_VOP);
		RemoveFlag(ci->flags, CI_MEMO_HOP);
		RemoveFlag(ci->flags, CI_MEMO_AOP);
		RemoveFlag(ci->flags, CI_MEMO_SOP);
		RemoveFlag(ci->flags, CI_MEMO_FR);
		RemoveFlag(ci->flags, CI_MEMO_NONE);

		AddFlag(ci->flags, CI_MEMO_CF);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_ON, ci->name, "Co-Founder");
	}
	else if (str_equals(param, "FOUNDER")) {

		if (FlagSet(ci->flags, CI_MEMO_FR)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_ERROR_ALREADY_SET, ci->name, "Founder");
			return;
		}

		RemoveFlag(ci->flags, CI_MEMO_VOP);
		RemoveFlag(ci->flags, CI_MEMO_HOP);
		RemoveFlag(ci->flags, CI_MEMO_AOP);
		RemoveFlag(ci->flags, CI_MEMO_SOP);
		RemoveFlag(ci->flags, CI_MEMO_CF);
		RemoveFlag(ci->flags, CI_MEMO_NONE);

		AddFlag(ci->flags, CI_MEMO_FR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_ON, ci->name, "Founder");
	}
	else {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_MEMOLEVEL_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "SET MEMOLEVEL");
		return;
	}

	if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

		if (accessMatch)
			send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_MEMOLEVEL_CHANGED), s_ChanServ, ci->name, callerUser->nick);
		else
			send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_MEMOLEVEL_CHANGED_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName);
	}

	if (accessMatch)
		log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET ML %s -- by %s (%s@%s) [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, param);
	else
		log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET ML %s -- by %s (%s@%s) through %s [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName, param);
}

/*********************************************************/

static void do_set_verbose(User *callerUser, ChannelInfo *ci, CSTR param, const int accessLevel, CSTR accessName, const int accessMatch) {

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SET_VERBOSE);

	if (IS_NULL(param) || (param[1] != '\0')) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_VERBOSE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "SET VERBOSE");
	}
	else if ((accessLevel != CS_ACCESS_FOUNDER) && (param[0] == '3'))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_VALUE_FOUNDER_ONLY);

	else {

		char old_settings = cs_get_verbose_level_name(ci);
		int new_level;

		if (old_settings == param[0]) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_VERBOSE_ERROR_ALREADY_SET, ci->name, param[0]);
			return;
		}

		TRACE_MAIN();
		switch (param[0]) {

			case '0':
				new_level = CI_NOTICE_VERBOSE_NONE;
				break;

			case '1':
				new_level = CI_NOTICE_VERBOSE_CLEAR;
				break;

			case '2':
				new_level = CI_NOTICE_VERBOSE_ACCESS;
				break;

			case '3':
				new_level = CI_NOTICE_VERBOSE_SET;
				break;

			default:
				new_level = -1;
				break;
		}

		if (new_level != -1) {

			TRACE_MAIN();
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_VERBOSE_CHANGED, ci->name, old_settings, param[0]);

			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_SET)) {

				if (accessMatch)
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_VERBOSE_CHANGED), s_ChanServ, ci->name, callerUser->nick);
				else
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_SET_VERBOSE_CHANGED_THROUGH), s_ChanServ, ci->name, callerUser->nick, accessName);
			}

			if (accessMatch)
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET V %s -- by %s (%s@%s) [%c -> %c]", ci->name, callerUser->nick, callerUser->username, callerUser->host, old_settings, param[0]);
			else
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "SET V %s -- by %s (%s@%s) through %s [%c -> %c]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName, old_settings, param[0]);

			ci->settings = (ci->settings & CI_NOTICE_VERBOSE_RESETMASK) | new_level;
		}
		else {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_VERBOSE_SYNTAX_ERROR);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "SET VERBOSE");
		}
	}
}

/*********************************************************/

static void handle_xop(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *chan, *cmd, *nick, *mask;
	ChannelInfo *ci;
	
	
	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_VOP);

	if (IS_NULL(chan = strtok(NULL, " ")) || IS_NULL(cmd = strtok(NULL, " ")) || (IS_NULL(nick = strtok(NULL, " ")) &&
		str_not_equals_nocase(cmd, "LIST") && str_not_equals_nocase(cmd, "WIPE") && str_not_equals_nocase(cmd, "CLEAN") &&
		str_not_equals_nocase(cmd, "LOCK") && str_not_equals_nocase(cmd, "UNLOCK") && str_not_equals_nocase(cmd, "EXPLIST") && str_not_equals_nocase(cmd, "FIND"))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), (str_char_toupper(data->commandName[0]) == 'C') ? CS_CF_SYNTAX_ERROR : CS_XOP_SYNTAX_ERROR, data->commandName);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, data->commandName);
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan)))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, chan);

	else if (FlagSet(ci->flags, CI_FORBIDDEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

	else {

		BOOL isHelper = is_services_helpop(callerUser);
		BOOL noLock = FALSE;
		int accessList;

		if (!isHelper) {

			if (FlagSet(ci->flags, CI_SUSPENDED)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_SUSPENDED, ci->name);
				return;
			}
			else if (FlagSet(ci->flags, CI_FROZEN)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FROZEN, ci->name);
				return;
			}
			else if (FlagSet(ci->flags, CI_CLOSED)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_CLOSED, ci->name);
				return;
			}
		}

		switch (data->commandName[0]) {

			case 'V':
				accessList = CS_ACCESS_VOP;
				break;

			case 'H':
				accessList = CS_ACCESS_HOP;
				break;

			case 'A':
				accessList = CS_ACCESS_AOP;
				break;

			case 'S':
				accessList = CS_ACCESS_SOP;
				break;

			default:
				accessList = CS_ACCESS_COFOUNDER;
				noLock = TRUE;
				break;
		}

		if (str_equals_nocase(cmd, "LIST"))
			do_chan_access_LIST(accessList, source, callerUser, ci, nick, isHelper);

		else if (str_equals_nocase(cmd, "ADD"))
			do_chan_access_ADD(accessList, source, callerUser, ci, nick);

		else if (str_equals_nocase(cmd, "DEL"))
			do_chan_access_DEL(accessList, source, callerUser, ci, nick);

		else if (str_equals_nocase(cmd, "CLEAN"))
			do_chan_access_CLEAN(accessList, source, callerUser, ci);
	
		else if (str_equals_nocase(cmd, "WIPE"))
			do_chan_access_WIPE(accessList, source, callerUser, ci);
		
		else if (str_equals_nocase(cmd, "EXPLIST"))
			do_chan_access_explist(accessList, source, callerUser, ci);
		
		else if (str_equals_nocase(cmd, "FIND")){
			mask = nick;
			do_chan_access_FIND(accessList, source, callerUser, ci, mask);
		}
		else if ((noLock == FALSE) && str_equals_nocase(cmd, "LOCK"))
			do_chan_access_LOCK(accessList, source, callerUser, ci, nick, TRUE);

		else if ((noLock == FALSE) && str_equals_nocase(cmd, "UNLOCK"))
			do_chan_access_LOCK(accessList, source, callerUser, ci, nick, FALSE);
		else {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), (str_char_toupper(data->commandName[0]) == 'C') ? CS_CF_SYNTAX_ERROR : CS_XOP_SYNTAX_ERROR, data->commandName);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, data->commandName);
		}
	}
}

/*********************************************************/

static void do_akick(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *chan, *cmd;
	ChannelInfo *ci;
	int accessLevel, accessMatch;
	char accessName[NICKSIZE];
	BOOL isHelper;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_AKICK);

	if (IS_NULL(chan = strtok(NULL, " ")) || IS_NULL(cmd = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AKICK_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "AKICK");
		return;
	}

	if (*chan != '#') {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);
		return;
	}

	if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, chan);
		return;
	}

	if (FlagSet(ci->flags, CI_FORBIDDEN)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);
		return;
	}

	isHelper = is_services_helpop(callerUser);

	if (!isHelper) {

		if (FlagSet(ci->flags, CI_SUSPENDED)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_SUSPENDED, ci->name);
			return;
		}

		if (FlagSet(ci->flags, CI_FROZEN)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FROZEN, ci->name);
			return;
		}

		if (FlagSet(ci->flags, CI_CLOSED)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_CLOSED, ci->name);
			return;
		}
	}

	if ((FlagSet(ci->flags, CI_SOPONLY) && !is_services_oper(callerUser)) ||
		((FlagSet(ci->flags, CI_SAONLY) || FlagSet(ci->flags, CI_MARKCHAN)) && !is_services_admin(callerUser)) ||
		(FlagSet(ci->flags, CI_SRAONLY) && !is_services_root(callerUser)) ||
		(FlagSet(ci->flags, CI_CODERONLY) && !is_services_coder(callerUser))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
		return;
	}

	accessLevel = get_access(callerUser, ci, accessName, &accessMatch, NULL);

	if (str_equals_nocase(cmd, "LIST")) {

		if ((accessLevel < CS_ACCESS_VOP) && !isHelper)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

		else {

			NickInfo *ni;
			AutoKick *anAkick;
			char timebuf[64], *usermask;
			const char *mask = strtok(NULL, " ");
			int i;

			TRACE_MAIN();
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AKICK_LIST_HEADER, ci->name, mask ? mask : "*");

			for (anAkick = ci->akick, i = 0; i < ci->akickcount; ++anAkick, ++i) {

				if (mask && !str_match_wild_nocase(mask, anAkick->name))
					continue;

				if (IS_NOT_NULL(ni = findnick(anAkick->name)))
					usermask = ni->last_usermask;
				else
					usermask = NULL;

				lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, anAkick->creationTime);

				TRACE_MAIN();

				if (anAkick->isNick ? (anAkick->banType == 2) : (anAkick->banType == -1))
					send_notice_to_user(s_ChanServ, callerUser, "%d) \2%s\2%s%s%s%s%s%s by %s (%s)%s",
						(i + 1), anAkick->name, usermask ? " (" : "", usermask ? usermask : "", usermask ? ")" : "",
						anAkick->reason ? lang_msg(GetCallerLang(), CS_AKICK_REASON_WRAPPER) : "",
						anAkick->reason ? anAkick->reason : "", anAkick->reason ? "]" : "", anAkick->creator, timebuf,
						FlagSet(anAkick->flags, ACCESS_FLAG_LOCKED) ? " [Locked]" : "");
				else
					send_notice_to_user(s_ChanServ, callerUser, "%d) \2%s\2%s%s%s%s%s%s [Ban Type: %d] by %s (%s)%s",
						(i + 1), anAkick->name, usermask ? " (" : "", usermask ? usermask : "", usermask ? ")" : "",
						anAkick->reason ? lang_msg(GetCallerLang(), CS_AKICK_REASON_WRAPPER) : "",
						anAkick->reason ? anAkick->reason : "", anAkick->reason ? "]" : "", anAkick->banType, anAkick->creator,
						timebuf, FlagSet(anAkick->flags, ACCESS_FLAG_LOCKED) ? " [Locked]" : "");
			}

			if (ci->settings & CI_ACCCESS_AKICK_LOCK)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_LIST_IS_LOCKED);

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), END_OF_LIST);
		}
	}
	else if (accessLevel < CS_ACCESS_SOP)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

	else if (str_equals_nocase(cmd, "WIPE")) {

		int deleted = 0, idx;
		AutoKick *anAkick;

		if ((accessLevel != CS_ACCESS_FOUNDER) && (ci->settings & CI_ACCCESS_AKICK_LOCK)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_LIST_LOCKED, "AKICK", ci->name);
			return;
		}

		if (ci->akickcount <= 0) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AKICK_WIPE_ERROR_LIST_EMPTY, ci->name);
			return;
		}

		anAkick = ci->akick;

		for (idx = 0; (idx < ci->akickcount); ++idx) {

			if (FlagSet(anAkick->flags, ACCESS_FLAG_LOCKED) && (accessLevel != CS_ACCESS_FOUNDER)) {

				++anAkick;
				continue;
			}

			++deleted;

			TRACE_MAIN();
			mem_free(anAkick->name);

			if (anAkick->reason)
				mem_free(anAkick->reason);

			if (anAkick->creator)
				mem_free(anAkick->creator);

			TRACE_MAIN();

			--(ci->akickcount);

			if (idx < ci->akickcount) {

				memmove(anAkick, (anAkick + 1), sizeof(AutoKick) * (ci->akickcount - idx));
				--idx;
			}
		}

		if (ci->akickcount <= 0) {

			mem_free(ci->akick);
			ci->akick = NULL;
		}

		TRACE_MAIN();
		if (deleted == 1)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AKICK_1_MASK_DEL, 1, ci->name);
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AKICK_X_MASKS_DEL, deleted, ci->name);

		if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS)) {

			if (accessMatch)
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_XOP_WIPED), s_ChanServ, ci->name, source, "AKick");
			else
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_XOP_WIPED_THROUGH), s_ChanServ, ci->name, source, accessName, "AKick");
		}

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

		if (accessMatch)
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "AKICK %s WIPE -- by %s (%s@%s) [%d]", ci->name, callerUser->nick, callerUser->username, callerUser->host, deleted);
		else
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "AKICK %s WIPE -- by %s (%s@%s) through %s [%d]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName, deleted);
	}
	else if (str_equals_nocase(cmd, "ADD")) {

		AutoKick	*anAkick;
		int			idx;
		int 		banType = -1;
		char		*mask, *reason;
		BOOL		isMask = FALSE;
		NickInfo	*ni;
		ChanAccess	*anAccess;


		if (CONF_SET_READONLY) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_READONLY);
			return;
		}

		if (IS_NULL(mask = strtok(NULL, " "))) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AKICK_SYNTAX_ERROR);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "AKICK");
			return;
		}

		if ((accessLevel != CS_ACCESS_FOUNDER) && (ci->settings & CI_ACCCESS_AKICK_LOCK)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_LIST_LOCKED, "AKICK", ci->name);
			return;
		}

		if ((CONF_AKICK_MAX > 0) && (ci->akickcount >= CONF_AKICK_MAX)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AKICK_ERROR_MAX_AKICKS, CONF_AKICK_MAX);
			return;
		}

		if (IS_NOT_NULL(reason = strtok(NULL, ""))) {

			if (isdigit(*reason)) {

				if (isspace(*(reason + 1))) {

					banType = (short) (reason[0] - 48);
					reason += 2;
				}
				else if (!*(reason + 1)) {

					banType = (short) (reason[0] - 48);
					reason = NULL;
				}
			}

			if (IS_NOT_NULL(reason)) {

				if (str_len(reason) > 200) {

					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_REASON_MAX_LENGTH, 200);
					return;
				}

				if (!validate_string(reason)) {

					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_REASON);
					return;
				}
			}
		}

		isMask = (strchr(mask, '@') || strchr(mask, '!'));

		if ((isMask == FALSE) && IS_NOT_NULL(ni = findnick(mask)))
			mask = str_duplicate(ni->nick);

		else if ((isMask == FALSE) && (str_len(mask) > NICKMAX)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_MASK);
			return;
		}
		else {

			char *nick, *user, *host;

/*
			if (mask_contains_crypt(mask)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_AKICK);
				return;
			}
*/
			if (!validate_mask(mask, TRUE, TRUE, TRUE)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_MASK);
				return;
			}

			TRACE_MAIN();
			user_usermask_split(mask, &nick, &user, &host);

			if (str_len(user) > USERMAX) {

				user[USERMAX - 1] = c_STAR;
				user[USERMAX] = '\0';
			}

			mask = mem_malloc(str_len(nick) + str_len(user) + str_len(host) + 3);
			sprintf(mask, "%s!%s@%s", nick, user, host);
			mem_free(nick);
			mem_free(user);
			mem_free(host);

			str_compact(mask);

			isMask = TRUE;
		}

		/* Check if it's already AKicked. */
		for (anAkick = ci->akick, idx = 0; idx < ci->akickcount; ++anAkick, ++idx) {

			if (str_match_wild_nocase(anAkick->name, mask)) {

				if (str_equals_nocase(anAkick->name, mask))
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AKICK_ERROR_ALREADY_AKICKED, anAkick->name, ci->name);
				else
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_MASK_ALREADY_COVERED, mask, anAkick->name);

				mem_free(mask);
				return;
			}
		}

		/* Make sure this nick is not on any access list. */
		for (anAccess = ci->access, idx = 0; idx < ci->accesscount; ++anAccess, ++idx) {

			if ((isMask ? (anAccess->status == ACCESS_ENTRY_MASK) : (anAccess->status == ACCESS_ENTRY_NICK))
				&& str_equals_nocase(anAccess->name, mask)) {

				/* Found it. Let the user know, then stop. */
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AKICK_ERROR_ONACCESS, mask, get_chan_access_name(anAccess->level), ci->name);

				mem_free(mask);
				return;
			}
		}

		TRACE_MAIN();
		++(ci->akickcount);

		ci->akick = mem_realloc(ci->akick, sizeof(AutoKick) * ci->akickcount);

		anAkick = &(ci->akick[ci->akickcount - 1]);

		anAkick->name = mask;		/* It has already been allocated. */
		anAkick->isNick = (isMask ? 0 : 1);
		anAkick->banType = ((banType != -1) ? banType : (isMask ? -1 : ci->banType));
		anAkick->flags = 0;

		if (reason)
			anAkick->reason = str_duplicate(terminate_string_ccodes(reason));
		else
			anAkick->reason = NULL;

		TRACE_MAIN();
		anAkick->creator = str_duplicate(accessName);
		anAkick->creationTime = NOW;

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AKICK_MASK_AKICKED, anAkick->name, ci->name);

		if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS)) {

			if (accessMatch)
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_XOP_ADDED), s_ChanServ, ci->name, source, anAkick->name, "AKick");
			else
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_XOP_ADDED_THROUGH), s_ChanServ, ci->name, source, accessName, anAkick->name, "AKick");
		}

		if (accessMatch)
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "AKICK %s ADD %s -- by %s (%s@%s) [Reason: %s]", ci->name, anAkick->name, callerUser->nick, callerUser->username, callerUser->host, reason ? reason : "None");
		else
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "AKICK %s ADD %s -- by %s (%s@%s) through %s [Reason: %s]", ci->name, anAkick->name, callerUser->nick, callerUser->username, callerUser->host, accessName, reason ? reason : "None");
	}
	else if (str_equals_nocase(cmd, "DEL")) {

		char *mask, *err;
		long int akickIdx;
		AutoKick *anAkick;

		TRACE_MAIN();

		if (IS_NULL(mask = strtok(NULL, " "))) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AKICK_SYNTAX_ERROR);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "AKICK");
			return;
		}

		if ((accessLevel != CS_ACCESS_FOUNDER) && (ci->settings & CI_ACCCESS_AKICK_LOCK)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_LIST_LOCKED, "AKICK", ci->name);
			return;
		}

		akickIdx = strtol(mask, &err, 10);

		if ((akickIdx > 0) && (*err == '\0')) {

			if (akickIdx <= ci->akickcount) {

				--akickIdx;
				anAkick = &(ci->akick[akickIdx]);
			}
			else {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AKICK_ERROR_MASK_NOT_PRESENT, mask, ci->name);
				return;
			}
		}
		else {

			for (anAkick = ci->akick, akickIdx = 0; akickIdx < ci->akickcount; ++anAkick, ++akickIdx) {

				if (str_equals_nocase(anAkick->name, mask))
					break;
			}

			if (akickIdx == ci->akickcount) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AKICK_ERROR_MASK_NOT_PRESENT, mask, ci->name);
				return;
			}
		}

		if (IS_NULL(anAkick))
			return;

		if (FlagSet(anAkick->flags, ACCESS_FLAG_LOCKED) && (accessLevel != CS_ACCESS_FOUNDER)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_ENTRY_LOCKED, anAkick->name, "AKick", ci->name);
			return;
		}

		TRACE_MAIN();
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AKICK_MASK_DELETED, anAkick->name, ci->name);

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

		if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS)) {

			if (accessMatch)
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_XOP_DELETED), s_ChanServ, ci->name, source, anAkick->name, "AKick");
			else
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_XOP_DELETED_THROUGH), s_ChanServ, ci->name, source, accessName, anAkick->name, "AKick");
		}

		if (accessMatch)
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "AKICK %s DEL %s -- by %s (%s@%s)", ci->name, anAkick->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "AKICK %s DEL %s -- by %s (%s@%s) through %s", ci->name, anAkick->name, callerUser->nick, callerUser->username, callerUser->host, accessName);

		mem_free(anAkick->name);

		if (anAkick->reason)
			mem_free(anAkick->reason);

		if (anAkick->creator)
			mem_free(anAkick->creator);

		--ci->akickcount;

		if (akickIdx < ci->akickcount)
			memmove(anAkick, (anAkick + 1), sizeof(AutoKick) * (ci->akickcount - akickIdx));

		TRACE_MAIN();

		if (ci->akickcount)
			ci->akick = mem_realloc(ci->akick, sizeof(AutoKick) * ci->akickcount);

		else {

			mem_free(ci->akick);
			ci->akick = NULL;
		}
	}

	else if (str_equals_nocase(cmd, "LOCK") || str_equals_nocase(cmd, "UNLOCK")) {

		BOOL lock = ((cmd[0] == 'L') || (cmd[0] == 'l'));
		const char *name;


		if (accessLevel != CS_ACCESS_FOUNDER) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
			return;
		}

		if (IS_NOT_NULL(name = strtok(NULL, " "))) {

			AutoKick *anAkick;
			int idx;


			for (anAkick = ci->akick, idx = 0; IS_NOT_NULL(anAkick) && (idx < ci->akickcount); ++anAkick, ++idx) {

				if (str_equals_nocase(anAkick->name, name))
					break;
			}

			if (idx == ci->akickcount) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_DEL_ERROR_NOT_FOUND, name, "AKick", ci->name);
				return;
			}

			if (lock) {

				if (FlagSet(anAkick->flags, ACCESS_FLAG_LOCKED)) {

					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_ENTRY_ALREADY_LOCKED, anAkick->name, "AKick", ci->name);
					return;
				}

				AddFlag(anAkick->flags, ACCESS_FLAG_LOCKED);
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ENTRY_LOCKED, anAkick->name, "AKick", ci->name);
			}
			else {

				if (FlagUnset(anAkick->flags, ACCESS_FLAG_LOCKED)) {

					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_ENTRY_ALREADY_UNLOCKED, anAkick->name, "AKick", ci->name);
					return;
				}

				RemoveFlag(anAkick->flags, ACCESS_FLAG_LOCKED);
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ENTRY_UNLOCKED, anAkick->name, "AKick", ci->name);
			}

			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS)) {

				if (accessMatch) {

					if (lock)
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_ENTRY_LOCKED), s_ChanServ, ci->name, source, anAkick->name, "AKick");
					else
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_ENTRY_UNLOCKED), s_ChanServ, ci->name, source, anAkick->name, "AKick");
				}
				else {

					if (lock)
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_ENTRY_LOCKED_THROUGH), s_ChanServ, ci->name, source, accessName, anAkick->name, "AKick");
					else
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_ENTRY_UNLOCKED_THROUGH), s_ChanServ, ci->name, source, accessName, anAkick->name, "AKick");
				}
			}

			log_services(LOG_SERVICES_CHANSERV_ACCESS, "AKick %s %s %s -- by %s (%s@%s)", ci->name, lock ? "LOCK" : "UNLOCK", anAkick->name, source, callerUser->username, callerUser->host);
		}
		else
			do_chan_access_LOCK(CS_ACCESS_AKICK, source, callerUser, ci, NULL, lock);
	}
	else {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AKICK_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "AKICK");
	}
}

/*********************************************************/

static void do_info(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *channel = strtok(NULL, " ");
	ChannelInfo *ci;
	BOOL isHelper = is_services_helpop(callerUser);

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_INFO);

	if (IS_NULL(channel)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "INFO");
	}
	else if (*channel != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, channel, channel);

	else if (IS_NULL(ci = cs_findchan(channel)))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, channel);

	else if (FlagSet(ci->flags, CI_FORBIDDEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

	else if (FlagSet(ci->flags, CI_CLOSED) && !isHelper)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_PUB_CHAN_CLOSED, CONF_NETWORK_NAME);

	else if (FlagSet(ci->flags, CI_SUSPENDED) && !isHelper)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_SUSPENDED, ci->name);

	else {

		NickInfo	*ni;
		time_t		ltime = (NOW - ci->last_used);
		Channel		*chan;
		BOOL		isRoot, privateTopic;
		char		buffer[IRCBUFSIZE];
		LANG_ID		langID = EXTRACT_LANG_ID(ci->langID);
		size_t		len = 0;


		isRoot = is_services_root(callerUser);

		chan = hash_channel_find(channel);

		TRACE_MAIN();
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_LIST_HEADER, ci->name);

		if (IS_NOT_NULL(ni = findnick(ci->founder)))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_FOUNDER, ci->founder, ni->last_usermask);
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_FOUNDER_EXPIRED, ci->founder);

		if (ci->successor)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_SUCCESSOR, ci->successor);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_DESCRIPTION, ci->desc);

		TRACE_MAIN();
		if (ci->welcome)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_WELCOME, ci->welcome);

		lang_format_localtime(buffer, sizeof(buffer), GetCallerLang(), TIME_FORMAT_DATETIME, ci->time_registered);

		TRACE_MAIN();
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_INFO_DATE_REG, buffer);

		lang_format_localtime(buffer, sizeof(buffer), GetCallerLang(), TIME_FORMAT_DATETIME, ci->last_used);
		
		if (ltime > ONE_DAY) {

			if (ltime / ONE_DAY == 1)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_LAST_JOIN_1D, buffer);
			else
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_LAST_JOIN_XD, buffer, ltime / ONE_DAY);
		}
		else if (ltime > ONE_HOUR) {

			if (ltime / ONE_HOUR == 1)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_LAST_JOIN_1H, buffer);
			else
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_LAST_JOIN_XH, buffer, ltime / ONE_HOUR);
		}
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_LAST_JOIN_LESS_THAN_1H, buffer);

		TRACE_MAIN();
		lang_format_localtime(buffer, sizeof(buffer), GetCallerLang(), TIME_FORMAT_DATETIME, NOW);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), INFO_CURRENT_TIME, buffer);

		/* Hide topic if channel is mlocked +p/s or it is open with +p/+s set. */
		privateTopic = (FlagSet(ci->mlock_on, CMODE_p) || FlagSet(ci->mlock_on, CMODE_s) || (IS_NOT_NULL(chan) && (FlagSet(chan->mode, CMODE_p) || FlagSet(chan->mode, CMODE_s))));

		if (ci->last_topic && ((privateTopic == FALSE) || ((FlagUnset(ci->flags, CI_HELDCHAN) && FlagUnset(ci->flags, CI_MARKCHAN)) ? isHelper : is_services_oper(callerUser)))) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_LAST_TOPIC, ci->last_topic);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_LAST_TOPIC_BY, ci->last_topic_setter);
		}

		TRACE_MAIN();
		if (FlagSet(ci->flags, CI_MEMO_NONE))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_MEMOLEV_NONE);
		else if (FlagSet(ci->flags, CI_MEMO_HOP))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_MEMOLEV_HOP);
		else if (FlagSet(ci->flags, CI_MEMO_AOP))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_MEMOLEV_AOP);
		else if (FlagSet(ci->flags, CI_MEMO_SOP))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_MEMOLEV_SOP);
		else if (FlagSet(ci->flags, CI_MEMO_CF))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_MEMOLEV_CF);
		else if (FlagSet(ci->flags, CI_MEMO_FR))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_MEMOLEV_FOUNDER);
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_MEMOLEV_VOP);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_INFO_LANGUAGE, lang_get_name(langID, TRUE), lang_get_name(langID, FALSE));

		/* Send URL, if any. */
		if (ci->url)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_URL, ci->url);

		/* Send E-Mail, if any. */
		if (ci->email)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_INFO_EMAIL_ADDRESS, ci->email);

		TRACE_MAIN();

		/* Send options. */
		if (FlagSet(ci->flags, CI_TOPICLOCK)) {

			if (ci->topic_allow == CS_ACCESS_VOP)
				len += str_copy_checked("Topic Lock (VOP)", buffer, sizeof(buffer));

			else if (ci->topic_allow == CS_ACCESS_HOP)
				len += str_copy_checked("Topic Lock (HOP)", buffer, sizeof(buffer));

			else if (ci->topic_allow == CS_ACCESS_AOP)
				len += str_copy_checked("Topic Lock (AOP)", buffer, sizeof(buffer));

			else if (ci->topic_allow == CS_ACCESS_SOP)
				len += str_copy_checked("Topic Lock (SOP)", buffer, sizeof(buffer));

			else if (ci->topic_allow == CS_ACCESS_COFOUNDER)
				len += str_copy_checked("Topic Lock (Co-Founder)", buffer, sizeof(buffer));

			else if (ci->topic_allow == CS_ACCESS_FOUNDER)
				len += str_copy_checked("Topic Lock (Founder)", buffer, sizeof(buffer));
		}

		APPEND_FLAG(ci->flags, CI_KEEPTOPIC, "Topic Retention")
		APPEND_FLAG(ci->flags, CI_OPGUARD, "Op Guard")
		APPEND_FLAG(ci->flags, CI_RESTRICTED, "Restricted Access")
		APPEND_FLAG(ci->flags, CI_PROTECTED, "Protect Ops")
		APPEND_FLAG(ci->flags, CI_IDENT, "Ident")
		APPEND_FLAG(ci->flags, CI_AUTOOP, "Auto Op")
		APPEND_FLAG(ci->flags, CI_AUTOHALFOP, "Auto HalfOp")
		APPEND_FLAG(ci->flags, CI_AUTOVOICE, "Auto Voice")
		APPEND_FLAG(ci->flags, CI_NEVEROP, "Never Op")
		APPEND_FLAG(ci->flags, CI_NOMKICK, "No MassKick")

		if (((ci->settings & CI_NOTICE_VERBOSE_MASK) >> 8) > CI_NOTICE_VERBOSE_NONE) {

			if (len > 0) {

				*(buffer + len++) = c_COMMA;
				*(buffer + len++) = c_SPACE;
			}

			len += str_copy_checked("Verbose (", (buffer + len), (sizeof(buffer) - len));

			*(buffer + len++) = cs_get_verbose_level_name(ci);
			*(buffer + len++) = ')';
			*(buffer + len) = '\0';
		}

		if (ci->banType != 2) {

			if (len > 0) {

				*(buffer + len++) = c_COMMA;
				*(buffer + len++) = c_SPACE;
			}

			len += str_copy_checked("Ban Type (", (buffer + len), (sizeof(buffer) - len));

			*(buffer + len++) = (char) (ci->banType + 48);
			*(buffer + len++) = ')';
			*(buffer + len) = '\0';
		}

		TRACE_MAIN();

		if (len == 0)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_INFO_NO_OPTIONS_SET);
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_INFO_OPTIONS_LIST_HEADER, buffer);

		/* Send modelock. */
		RemoveFlag(ci->mlock_on, CMODE_r);

		if ((ci->mlock_on != 0) || (ci->mlock_off != 0)) {

			if (isRoot) {

				if (ci->mlock_key) {

					if (ci->mlock_limit)
						send_notice_to_user(s_ChanServ, callerUser, "Modelock: %s %s %d", get_channel_mode(ci->mlock_on, ci->mlock_off), ci->mlock_key, ci->mlock_limit);
					else
						send_notice_to_user(s_ChanServ, callerUser, "Modelock: %s %s", get_channel_mode(ci->mlock_on, ci->mlock_off), ci->mlock_key);
				}
				else {

					if (ci->mlock_limit)
						send_notice_to_user(s_ChanServ, callerUser, "Modelock: %s %d", get_channel_mode(ci->mlock_on, ci->mlock_off), ci->mlock_limit);
					else
						send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_MODELOCK, get_channel_mode(ci->mlock_on, ci->mlock_off));
				}
			}
			else
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_MODELOCK, get_channel_mode(ci->mlock_on, ci->mlock_off));
		}

		AddFlag(ci->mlock_on, CMODE_r);

		TRACE_MAIN();

		/* Send locked lists, if any. */
		if ((ci->settings & CI_NOTICE_VERBOSE_RESETMASK) != CI_ACCCESS_NO_LOCK)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_LOCKED_LISTS, 
									 /* ci->settings & CI_ACCCESS_CFOUNDER_LOCK ? "Co-Founder " : "", */
									 ci->settings & CI_ACCCESS_SOP_LOCK ? "SOP " : "", ci->settings & CI_ACCCESS_AOP_LOCK ? "AOP " : "", 
									 ci->settings & CI_ACCCESS_HOP_LOCK ? "HOP " : "", ci->settings & CI_ACCCESS_VOP_LOCK ? "VOP " : "", 
									 ci->settings & CI_ACCCESS_AKICK_LOCK ? "AKICK" : "");

		/* Send channel key if we should. */
		if (isRoot && chan && chan->key)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_INFO_SRA_KEY, chan->key);

		TRACE_MAIN();
		if (isHelper) {

			if (FlagSet(ci->flags, CI_CLOSED))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_PUB_CHAN_CLOSED, CONF_NETWORK_NAME);

			if (FlagSet(ci->flags, CI_SUSPENDED)) {

				ChannelSuspendData *csd = find_suspend(channel);

				if (IS_NULL(csd))
					LOG_DEBUG_SNOOP("csd for %s is empty!", channel);

				else {

					ltime = csd->expires - NOW;

					if (ltime > 0)
						send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_INFO_CHAN_SUSPENDED_ACTIVE, csd->who, ltime / ONE_MINUTE, ltime / ONE_MINUTE == 1 ? "" : "s", ltime % ONE_MINUTE, ltime % ONE_MINUTE == 1 ? "" : "s");
					else
						send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_INFO_CHAN_SUSPENDED_EXPIRED, csd->who);
				}
			}

			if (FlagSet(ci->flags, CI_MARKCHAN))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_INFO_CHAN_MARKED, ci->mark);

			if (FlagSet(ci->flags, CI_HELDCHAN))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_INFO_CHAN_HELD, ci->hold);

			if (FlagSet(ci->flags, CI_FROZEN))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_INFO_CHAN_FROZEN, ci->freeze);

			if (FlagSet(ci->flags, CI_SOPONLY))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_INFO_CHAN_SOPONLY);

			if (FlagSet(ci->flags, CI_SAONLY))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_INFO_CHAN_SAONLY);

			if (FlagSet(ci->flags, CI_SRAONLY))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_INFO_CHAN_SRAONLY);

			if (FlagSet(ci->flags, CI_CODERONLY))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_INFO_CHAN_CODERONLY);

			if (ci->auth != 0)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_INFO_DROP_REQUESTED, ci->auth);

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_INFO_REAL_FOUNDER, ci->real_founder);
		}
		else {

			int accessLevel;

			accessLevel = get_access(callerUser, ci, NULL, NULL, NULL);

			if ((accessLevel >= CS_ACCESS_VOP) && FlagSet(ci->flags, CI_HELDCHAN))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_PUB_CHAN_HELD);

			if (FlagSet(ci->flags, CI_FROZEN))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INFO_PUB_CHAN_FROZEN);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), END_OF_INFO);
	}
}

/*********************************************************/

static void do_invite(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *chan, *who;
	ChannelInfo *ci;
	BOOL isOper = is_services_admin(callerUser);

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_INVITE);

	if (IS_NULL(chan = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INVITE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "INVITE");
	}
	else if (IS_NOT_NULL(who = strtok(NULL, " ")))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INVITE_ERROR_PARAM_GIVEN);

	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (str_len(chan) > CHANMAX)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_MAX_LENGTH, CHANMAX);

	else if (IS_NULL(ci = cs_findchan(chan))) {

		if (!isOper)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, chan);

		else {

			if (!validate_channel(chan)) {

				send_notice_to_user(s_ChanServ, callerUser, "Channel name contains invalid characters.");
				return;
			}

			if (user_isin_chan(callerUser, chan)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INVITE_ERROR_ALREADY_IN, IS_NOT_NULL(ci) ? ci->name : chan);
				return;
			}

			send_globops(s_ChanServ, "\2%s\2 forced an invite on \2%s\2", source, chan);
			send_cmd(":%s INVITE %s %s", s_ChanServ, source, chan);
		}
	}
	else {

		int accessLevel;

		accessLevel = get_access(callerUser, ci, NULL, NULL, NULL);

		if (!isOper) {

			if (accessLevel < CS_ACCESS_VOP)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

			else if (FlagSet(ci->flags, CI_SUSPENDED))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_SUSPENDED, ci->name);

			else if (FlagSet(ci->flags, CI_FROZEN))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FROZEN, ci->name);

			else if (FlagSet(ci->flags, CI_CLOSED))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_CLOSED, ci->name);

			else if (FlagSet(ci->flags, CI_NOENTRY))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INVITE_ERROR_CHANSERV_ISIN);

			else if (user_isin_chan(callerUser, chan))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INVITE_ERROR_ALREADY_IN, IS_NOT_NULL(ci) ? ci->name : chan);

			else
				send_cmd(":%s INVITE %s %s", s_ChanServ, source, chan);
		}
		else {

			if (user_isin_chan(callerUser, chan)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_INVITE_ERROR_ALREADY_IN, IS_NOT_NULL(ci) ? ci->name : chan);
				return;
			}

			if ((FlagSet(ci->flags, CI_SRAONLY) && !is_services_root(callerUser)) ||
				(FlagSet(ci->flags, CI_CODERONLY) && !is_services_coder(callerUser))) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
				return;
			}

			if ((accessLevel < CS_ACCESS_VOP) || FlagSet(ci->flags, CI_NOENTRY))
				send_globops(s_ChanServ, "\2%s\2 forced an invite on \2%s\2", source, chan);

			send_cmd(":%s INVITE %s %s", s_ChanServ, source, chan);
		}
	}
}

/*********************************************************/

static void do_unban(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *chan_name, *param;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_UNBAN);

	if (IS_NULL(chan_name = strtok(NULL, " ")) || IS_NULL(param = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_UNBAN_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "UNBAN");
	}
	else if (*chan_name != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan_name, chan_name);

	else if (str_equals_nocase(param, "ALL")) {

		/* Ugly hack, but nothing to be done to avoid it. */

		misc_buffer[0] = '\0';

		TRACE_MAIN();
		snprintf(misc_buffer, MISC_BUFFER_SIZE, "MUNBAN %s", chan_name);

		TRACE_MAIN();
		misc_buffer[MISC_BUFFER_SIZE - 1] = '\0';

		chanserv(source, callerUser, misc_buffer);
	}
	else if (str_equals_nocase(param, "ME")) {

		ChannelInfo *ci;
		Channel *chan;

		if (IS_NULL(chan = hash_channel_find(chan_name)))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHAN_DOES_NOT_EXIST, chan_name);

		else if (IS_NULL(ci = chan->ci))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, chan_name);

		else if (FlagSet(ci->flags, CI_FORBIDDEN))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

		else if (FlagSet(ci->flags, CI_SUSPENDED))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_SUSPENDED, ci->name);

		else if (FlagSet(ci->flags, CI_FROZEN))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FROZEN, ci->name);

		else if (FlagSet(ci->flags, CI_CLOSED))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_CLOSED, ci->name);

		else if (FlagSet(ci->flags, CI_NOENTRY))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_NOENTRY_ON, ci->name);

		else {

			int accessLevel, accessMatch;
			char accessName[NICKSIZE];

			accessLevel = get_access(callerUser, ci, accessName, &accessMatch, NULL);

			if (accessLevel < CS_ACCESS_VOP)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

			else if (chan->bancount == 0)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_BANLIST_EMPTY, chan->name);

			else {

				char buf[1024], buf2[16];
				int bcnt = 0, len = 0, i;

				memset(buf, 0, sizeof(buf));
				memset(buf2, 0, sizeof(buf2));

				for (i = 0; i < chan->bancount; ++i) {

					if (!user_usermask_match(chan->bans[i], callerUser, TRUE, TRUE))
						continue;

					TRACE_MAIN();
					if (IS_NOT_EMPTY_STR(buf))
						strcat(buf, " ");
					else
						strcat(buf2, "-");

					strcat(buf, chan->bans[i]);
					strcat(buf2, "b");
					++bcnt;

					len += (str_len(chan->bans[i]) + 2);

					/* 512 - 4 (MODE) - 30 (chan) - 13 ((SERVER_MAX_MODES - 1) + "-")
						- 4 (spaces + \0) - 105 (max length of 1 ban) = 355 */

					chan_remove_ban(chan, chan->bans[i]);
					--i;

					if ((bcnt >= SERVER_MAX_MODES) || (len > 350)) {

						bcnt = 0;
						len = 0;
						send_cmd(":%s MODE %s %s %s", s_ChanServ, chan_name, buf2, buf);
						*buf = 0;
						*buf2 = 0;
					}
				}

				if (*buf)
					send_cmd(":%s MODE %s %s %s", s_ChanServ, chan_name, buf2, buf);

				TRACE_MAIN();

				if (accessLevel < CS_ACCESS_VOP)
					send_globops(s_ChanServ, "\2%s\2 used UNBAN on \2%s\2", source, ci->name);

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_UNBAN_ME_BANS_LIFTED, ci->name);

				if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_CLEAR)) {

					if (accessMatch)
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_UNBAN_ME), s_ChanServ, ci->name, source);
					else
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_UNBAN_ME_THROUGH), s_ChanServ, ci->name, source, accessName);
				}

				if (accessMatch)
					log_services(LOG_SERVICES_CHANSERV_ACCESS, "UNBAN %s ME -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
				else
					log_services(LOG_SERVICES_CHANSERV_ACCESS, "UNBAN %s ME -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName);
			}
		}
	}
	else {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_UNBAN_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "UNBAN");
	}
}

/*********************************************************/

static void do_count(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *chan = strtok(NULL, " ");
	ChannelInfo *ci;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_COUNT);

	if (IS_NULL(chan)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_COUNT_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "COUNT");
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan)))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, chan);

	else if (FlagSet(ci->flags, CI_FORBIDDEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

	else {

		int accessLevel;
		ChanAccess *anAccess;
		BOOL isHelper = is_services_helpop(callerUser);

		if (!isHelper) {

			if (FlagSet(ci->flags, CI_SUSPENDED)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_SUSPENDED, ci->name);
				return;
			}
			else if (FlagSet(ci->flags, CI_FROZEN)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FROZEN, ci->name);
				return;
			}
			else if (FlagSet(ci->flags, CI_CLOSED)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_CLOSED, ci->name);
				return;
			}
		}

		accessLevel = get_access(callerUser, ci, NULL, NULL, NULL);

		if ((accessLevel < CS_ACCESS_VOP) && (!isHelper || FlagSet(ci->flags, CI_MARKCHAN) ||
			(FlagSet(ci->flags, CI_SOPONLY) && !is_services_oper(callerUser)) ||
			(FlagSet(ci->flags, CI_SAONLY) && !is_services_admin(callerUser)) ||
			(FlagSet(ci->flags, CI_SRAONLY) && !is_services_root(callerUser)) ||
			(FlagSet(ci->flags, CI_CODERONLY) && !is_services_coder(callerUser))))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

		else {

			int i, vop = 0, hop = 0, aop = 0, sop = 0, cf = 0;

			for (anAccess = ci->access, i = 0; i < ci->accesscount; ++anAccess, ++i) {

				if ((anAccess->status == ACCESS_ENTRY_FREE) || (anAccess->status == ACCESS_ENTRY_EXPIRED))
					continue;

				switch (anAccess->level) {

					case CS_ACCESS_VOP:
						++vop;
						break;

					case CS_ACCESS_HOP:
						++hop;
						break;

					case CS_ACCESS_AOP:
						++aop;
						break;

					case CS_ACCESS_SOP:
						++sop;
						break;

					case CS_ACCESS_COFOUNDER:
						++cf;
						break;
				}
			}
			
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_COUNT_LIST, ci->name, cf, sop, aop, hop, vop, ci->akickcount);
		}
	}
}

/*********************************************************/

void chanserv_listchans(const User *callerUser, CSTR nick, const BOOL isSelf) {

	ChannelInfo *ci;
	short		acc, accIdx;
	short		accLevels[7] = { CS_ACCESS_FOUNDER, CS_ACCESS_COFOUNDER, CS_ACCESS_SOP, CS_ACCESS_AOP, CS_ACCESS_HOP, CS_ACCESS_VOP, CS_ACCESS_AKICK };
	int			chanTotalCount = 0, idx, checkIndex;
	char		buffer[IRCBUFSIZE];
	int			bufferLen = 0;


	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_LISTCHANS);

	memset(buffer, 0, sizeof(buffer));

	send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_LISTCHANS_LIST_HEADER, nick);

	for (accIdx = 0; accIdx < 7; ++accIdx) {

		acc = accLevels[accIdx];

		TRACE_MAIN();

		switch (acc) {

			case CS_ACCESS_FOUNDER: {

				bufferLen = 0;
				*buffer = 0;

				for (idx = 0; idx < 256; ++idx) {

					for (ci = chanlists[idx]; IS_NOT_NULL(ci); ci = ci->next) {

						if (FlagSet(ci->flags, CI_FORBIDDEN))
							continue;

						if ((isSelf == FALSE) &&
							((FlagSet(ci->flags, CI_SOPONLY) && !is_services_oper(callerUser)) ||
							((FlagSet(ci->flags, CI_SAONLY) || FlagSet(ci->flags, CI_MARKCHAN)) && !is_services_admin(callerUser)) ||
							(FlagSet(ci->flags, CI_SRAONLY) && !is_services_root(callerUser)) ||
							(FlagSet(ci->flags, CI_CODERONLY) && !is_services_coder(callerUser))))
							continue;

						if (str_equals_nocase(ci->founder, nick)) {

							++chanTotalCount;

							if (*buffer)
								strcat(buffer, ", ");
							strcat(buffer, ci->name);

							bufferLen += (str_len(ci->name) + 3);

							if (bufferLen > 400) {

								send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_LISTCHANS_LIST_ENTRIES, get_chan_access_name(acc), buffer);
								bufferLen = 0;
								*buffer = 0;
							}
						}
					}
				}

				if (*buffer)
					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_LISTCHANS_LIST_ENTRIES, get_chan_access_name(acc), buffer);

				break;
			}

			case CS_ACCESS_AKICK: {

				if (is_services_helpop(callerUser)) {

					AutoKick	*anAkick;
					User		*user;

					if (str_equals_nocase(callerUser->nick, nick))
						user = (User *)callerUser;
					else
						user = hash_onlineuser_find(nick);

					bufferLen = 0;
					*buffer = 0;

					for (idx = 0; idx < 256; ++idx) {

						for (ci = chanlists[idx]; IS_NOT_NULL(ci); ci = ci->next) {

							if (FlagSet(ci->flags, CI_FORBIDDEN))
								continue;

							if ((isSelf == FALSE) && 
								((FlagSet(ci->flags, CI_SOPONLY) && !is_services_oper(callerUser)) ||
								((FlagSet(ci->flags, CI_SAONLY) || FlagSet(ci->flags, CI_MARKCHAN)) && !is_services_admin(callerUser)) ||
								(FlagSet(ci->flags, CI_SRAONLY) && !is_services_root(callerUser)) ||
								(FlagSet(ci->flags, CI_CODERONLY) && !is_services_coder(callerUser))))
								continue;

							for (anAkick = ci->akick, checkIndex = 0; checkIndex < ci->akickcount; ++anAkick, ++checkIndex) {

								if (((anAkick->isNick > 0) && str_equals_nocase(anAkick->name, nick)) ||
									(!anAkick->isNick && user && !str_spn(anAkick->name, "*!@.")
									&& (user_usermask_match(anAkick->name, user, TRUE, TRUE)))) {

									++chanTotalCount;

									if (*buffer)
										strcat(buffer, ", ");
									strcat(buffer, ci->name);

									bufferLen += (str_len(ci->name) + 3);

									if (bufferLen > 400) {

										send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_LISTCHANS_LIST_ENTRIES, get_chan_access_name(acc), buffer);
										bufferLen = 0;
										*buffer = 0;
									}
								}
							}
						}
					}

					if (*buffer)
						send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_LISTCHANS_LIST_ENTRIES, get_chan_access_name(acc), buffer);
				}

				break;
			}

			default: {

				ChanAccess *anAccess;

				bufferLen = 0;
				*buffer = 0;

				for (idx = 0; idx < 256; ++idx) {

					for (ci = chanlists[idx]; IS_NOT_NULL(ci); ci = ci->next) {

						if (FlagSet(ci->flags, CI_FORBIDDEN))
							continue;

						if ((isSelf == FALSE) &&
							((FlagSet(ci->flags, CI_SOPONLY) && !is_services_oper(callerUser)) ||
							((FlagSet(ci->flags, CI_SAONLY) || FlagSet(ci->flags, CI_MARKCHAN)) && !is_services_admin(callerUser)) ||
							(FlagSet(ci->flags, CI_SRAONLY) && !is_services_root(callerUser)) ||
							(FlagSet(ci->flags, CI_CODERONLY) && !is_services_coder(callerUser))))
							continue;

						for (anAccess = ci->access, checkIndex = 0; checkIndex < ci->accesscount; ++anAccess, ++checkIndex) {

							if ((anAccess->level == acc) && (anAccess->status == ACCESS_ENTRY_NICK) && str_equals_nocase(anAccess->name, nick)) {

								++chanTotalCount;

								if (*buffer)
									strcat(buffer, ", ");
								strcat(buffer, ci->name);

								bufferLen += (str_len(ci->name) + 3);

								if (bufferLen > 400) {

									send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_LISTCHANS_LIST_ENTRIES, get_chan_access_name(acc), buffer);
									bufferLen = 0;
									*buffer = 0;
								}
							}
						}
					}
				}

				if (*buffer)
					send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_LISTCHANS_LIST_ENTRIES, get_chan_access_name(acc), buffer);

				break;
			}
		}
	}

	TRACE_MAIN();
	send_notice_lang_to_user(s_NickServ, callerUser, GetCallerLang(), NS_LISTCHANS_END_OF_LIST, chanTotalCount);
}

/*********************************************************/

static void do_why(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo *ci;
	char *nick_list[5];
	char *nick, *chan;
	int nick_count = 0;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_ACC);

	chan = strtok(NULL, " ");

	TRACE_MAIN();
	while (IS_NOT_NULL(nick = strtok(NULL, " "))) {

		nick_list[nick_count++] = nick;

		if (nick_count == 5)
			break;
	}

	if (IS_NULL(chan) || (nick_count == 0)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "WHY");
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan)))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, chan);

	else if (FlagSet(ci->flags, CI_FORBIDDEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

	else if (FlagSet(ci->flags, CI_SUSPENDED))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_SUSPENDED, ci->name);

	else if (FlagSet(ci->flags, CI_FROZEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FROZEN, ci->name);

	else if (FlagSet(ci->flags, CI_CLOSED))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_CLOSED, ci->name);

	else {

		int idx;
		int	accessLevel, accessMatch, accessStatus;
		char accessName[NICKSIZE], *accessMask = NULL;
		User *user;

		accessLevel = get_access(callerUser, ci, accessName, &accessMatch, &accessStatus);

		if ((accessLevel < CS_ACCESS_VOP) &&
			(FlagSet(ci->flags, CI_MARKCHAN) || !is_services_helpop(callerUser) ||
			(FlagSet(ci->flags, CI_SOPONLY) && !is_services_oper(callerUser)) ||
			(FlagSet(ci->flags, CI_SAONLY) && !is_services_admin(callerUser)) ||
			(FlagSet(ci->flags, CI_SRAONLY) && !is_services_root(callerUser)) ||
			(FlagSet(ci->flags, CI_CODERONLY) && !is_services_coder(callerUser)))) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
			return;
		}

		TRACE_MAIN();
		for (idx = 0; idx < nick_count; ++idx) {

			TRACE_MAIN();
			nick = nick_list[idx];

			user = hash_onlineuser_find(nick);

			if (IS_NOT_NULL(user)) {

				ChanAccess *anAccess;
				int nickIdx, accessIdx;
				char **idnicks;


				if (user_is_identified_to(user, ci->founder)) {

					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_FOUNDER_ID_NICK, user->nick, ci->name);
					continue;
				}

				if (is_identified(user, ci)) {

					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_FOUNDER_ID_CHAN, user->nick, ci->name);
					continue;
				}

				accessStatus = CS_STATUS_NONE;
				accessLevel = CS_ACCESS_NONE;

				if (FlagUnset(ci->flags, CI_IDENT)) {

					NickInfo *ni;
					BOOL isOnAccess, isIdentified;


					if (IS_NOT_NULL(ni = findnick(ci->founder)) && is_on_access(user, ni)) {

						send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_FOUNDER_ON_ACCESS_LIST, user->nick, ci->name);
						continue;
					}

					isOnAccess = (IS_NOT_NULL(user->ni) ? is_on_access(user, user->ni) : FALSE);

					isIdentified = (IS_NOT_NULL(user->ni) ? user_is_identified_to(user, user->ni->nick) : FALSE);

					for (anAccess = ci->access, accessIdx = 0; (accessIdx < ci->accesscount) && IS_NOT_NULL(anAccess); ++anAccess, ++accessIdx) {

						if (isOnAccess && !isIdentified && (anAccess->status == ACCESS_ENTRY_NICK)
							&& str_equals_nocase(user->ni->nick, anAccess->name)) {

							TRACE();
							if (anAccess->level > accessLevel) {

								accessLevel = anAccess->level;
								str_copy_checked(anAccess->name, accessName, NICKSIZE);
								accessStatus = CS_STATUS_ACCLIST;
							}
						}
						else {

							if ((anAccess->status == ACCESS_ENTRY_MASK)
								&& user_usermask_match(anAccess->name, user, TRUE, TRUE)) {

								if (anAccess->level > accessLevel) {

									accessLevel = anAccess->level;

									if (accessMask)
										mem_free(accessMask);
									accessMask = str_duplicate(anAccess->name);

									accessStatus = CS_STATUS_MASK;
								}
							}
							else {

								if ((anAccess->status == ACCESS_ENTRY_NICK) && (anAccess->level > accessLevel)) {

									if (IS_NOT_NULL(ni = findnick(anAccess->name)) && is_on_access(user, ni)) {

										accessLevel = anAccess->level;
										str_copy_checked(anAccess->name, accessName, NICKSIZE);
										accessStatus = CS_STATUS_ACCLIST;
									}
								}
							}
						}
					}
				}

				for (idnicks = user->id_nicks, nickIdx = 0; nickIdx < user->idcount; ++idnicks, ++nickIdx) {

					for (anAccess = ci->access, accessIdx = 0; (accessIdx < ci->accesscount) && IS_NOT_NULL(anAccess); ++anAccess, ++accessIdx) {

						if ((anAccess->status == ACCESS_ENTRY_NICK) && str_equals_nocase(*idnicks, anAccess->name)) {

							TRACE();
							/* >= to show identified instead of on access list if both are true. */
							if ((accessStatus != CS_STATUS_IDNICK) ? (anAccess->level >= accessLevel) : (anAccess->level > accessLevel)) {

								accessLevel = anAccess->level;
								str_copy_checked(anAccess->name, accessName, NICKSIZE);
								accessStatus = CS_STATUS_IDNICK;
							}
						}
					}
				}

				if (accessLevel < CS_ACCESS_NONE)
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_BANNED_USER, user->nick, ci->name);

				else if (accessLevel == CS_ACCESS_NONE)
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_NORMAL_USER, user->nick, ci->name);

				else {

					switch (accessStatus) {

						case CS_STATUS_MASK:

							switch (accessLevel) {

								case CS_ACCESS_VOP:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_MASK_IN_LIST, user->nick, "VOP", ci->name, accessMask);
									break;

								case CS_ACCESS_HOP:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_MASK_IN_LIST, user->nick, "HOP", ci->name, accessMask);
									break;

								case CS_ACCESS_AOP:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_MASK_IN_LIST, user->nick, "AOP", ci->name, accessMask);
									break;

								case CS_ACCESS_SOP:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_MASK_IN_LIST, user->nick, "SOP", ci->name, accessMask);
									break;

								case CS_ACCESS_COFOUNDER:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_MASK_IN_LIST, user->nick, "Co-Founder", ci->name, accessMask);
									break;

								default:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_MASK_IN_LIST, user->nick, "Unknown", ci->name, accessMask);
									break;
							}
							break;

						case CS_STATUS_IDNICK:

							switch (accessLevel) {

								case CS_ACCESS_VOP:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_IDENTIFIED, user->nick, "VOP", ci->name, accessName);
									break;

								case CS_ACCESS_HOP:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_IDENTIFIED, user->nick, "HOP", ci->name, accessName);
									break;

								case CS_ACCESS_AOP:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_IDENTIFIED, user->nick, "AOP", ci->name, accessName);
									break;

								case CS_ACCESS_SOP:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_IDENTIFIED, user->nick, "SOP", ci->name, accessName);
									break;

								case CS_ACCESS_COFOUNDER:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_IDENTIFIED, user->nick, "Co-Founder", ci->name, accessName);
									break;

								default:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_IDENTIFIED, user->nick, "Unknown", ci->name, accessName);
									break;
							}
							break;

						case CS_STATUS_ACCLIST:

							switch (accessLevel) {

								case CS_ACCESS_VOP:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_ON_ACCESS_LIST, user->nick, "VOP", ci->name, accessName);
									break;
									
								case CS_ACCESS_HOP:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_ON_ACCESS_LIST, user->nick, "HOP", ci->name, accessName);
									break;

								case CS_ACCESS_AOP:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_ON_ACCESS_LIST, user->nick, "AOP", ci->name, accessName);
									break;

								case CS_ACCESS_SOP:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_ON_ACCESS_LIST, user->nick, "SOP", ci->name, accessName);
									break;

								case CS_ACCESS_COFOUNDER:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_ON_ACCESS_LIST, user->nick, "Co-Founder", ci->name, accessName);
									break;

								default:
									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_ON_ACCESS_LIST, user->nick, "Unknown", ci->name, accessName);
									break;
							}
							break;

						default:
							log_error(FACILITY_CHANSERV_HANDLE_WHY, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
								"%s in do_why(): Unknown accessStatus value %d", s_ChanServ, accessStatus);
							break;
					}
				}

				if (accessMask)
					mem_free(accessMask);
			}
			else {

				TRACE_MAIN();
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_NICK_OFFLINE, nick, ci->name);

				if (str_equals_nocase(ci->founder, nick))
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_NICK_IS_FOUNDER, nick, ci->name);

				else {

					ChanAccess *anAccess;
					int accessIdx;


					TRACE_MAIN();
					accessLevel = CS_ACCESS_NONE;

					for (anAccess = ci->access, accessIdx = 0; accessIdx < ci->accesscount; ++anAccess, ++accessIdx) {

						if ((anAccess->status == ACCESS_ENTRY_NICK) && str_equals_nocase(anAccess->name, nick)) {

							accessLevel = anAccess->level;
							break;
						}
					}

					if (accessLevel == CS_ACCESS_NONE)
						send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_NICK_NOT_ON_LIST, nick, ci->name);

					else {

						switch (accessLevel) {

							case CS_ACCESS_VOP:
								send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_ACCESS_LEVEL, nick, ci->name, "VOP");
								break;

							case CS_ACCESS_HOP:
								send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_ACCESS_LEVEL, nick, ci->name, "HOP");
								break;

							case CS_ACCESS_AOP:
								send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_ACCESS_LEVEL, nick, ci->name, "AOP");
								break;

							case CS_ACCESS_SOP:
								send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_ACCESS_LEVEL, nick, ci->name, "SOP");
								break;

							case CS_ACCESS_COFOUNDER:
								send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_ACCESS_LEVEL, nick, ci->name, "Co-Founder");
								break;

							default:
								send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WHY_ACCESS_LEVEL, nick, ci->name, "Unknown");
								break;
						}
					}
				}
			}
		}
	}
}

/*********************************************************/
static void handle_voice_devoice(User *callerUser, Channel *chan, User *user_list[], int user_count, const char action)
{
	/* A user may only voice anyone if he is at least HOP or if he is a SA+/+z.
	 * A user may only voice himself if he is a VOP.
	 * If he use the command as a SA+/+z then the affected nick must be appended to globops_buf.
	 * If he don't have sufficient access then he must be notified of the situation.
	 * If all the user in user_list have the requested status then the user must be notified of the situation.
	 */
	char	accessName[NICKSIZE];
	int		accessLevel, accessMatch, isOper;
	User 	*targetUser;
	
	/* Check for valid parameters */
	if (callerUser == NULL || chan == NULL || chan->ci == NULL || user_list == NULL)
		return;
	
	isOper = is_services_admin(callerUser) || user_is_services_agent(callerUser);
	
	TRACE_MAIN();
	accessLevel = get_access(callerUser, chan->ci, accessName, &accessMatch, NULL);
	
	/* Check if callerUser has access to command */
	if ((accessLevel == CS_ACCESS_VOP) && !isOper) {
		
		/* User is VOP and not SA+/+z: he may only VOICE/DEVOICE himself */
		targetUser = user_list[0];
		
		if (str_not_equals_nocase(callerUser->nick, targetUser->nick)) {
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
			return;
		}
		
		if (!user_isin_chan(targetUser, chan->name) ||
		    ((action == '+') && user_is_chanvoice(targetUser->nick, chan->name, chan)) ||
			((action == '-') && !user_is_chanvoice(targetUser->nick, chan->name, chan))) {
			/* Nothing to be done */
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_OP_DEOP_ERROR_NOTHING_TO_DO);
			return;
		}				
		
		/* Give/take voice to targetUser (which is the same of callerUser, in this case) */
		
		TRACE_MAIN();
		send_cmd(":%s MODE %s %cv %s", s_ChanServ, chan->name, action, targetUser->nick);
		
		if (action == '+')
			chan_add_voice(chan, callerUser);
		else
			chan_remove_voice(chan, callerUser);
		
		if (accessMatch) {
			if (CSMatchVerbose(chan->ci->settings, CI_NOTICE_VERBOSE_CLEAR))
				send_cmd(lang_msg(EXTRACT_LANG_ID(chan->ci->langID), CS_VERBOSE_OPNOTICE_OP_DEOP_USED), s_ChanServ, chan->ci->name, callerUser->nick,
						 (action == '+') ? "VOICE" : "DEVOICE", targetUser->nick);
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "OP/VOICE %s %cv %s -- by %s (%s@%s)", chan->ci->name, action, targetUser->nick,
						 callerUser->nick, callerUser->username, callerUser->host);
		} else {
			if (CSMatchVerbose(chan->ci->settings, CI_NOTICE_VERBOSE_CLEAR))
				send_cmd(lang_msg(EXTRACT_LANG_ID(chan->ci->langID), CS_VERBOSE_OPNOTICE_OP_DEOP_USED_THROUGH), s_ChanServ, chan->ci->name, callerUser->nick,
						 accessName, (action == '+') ? "VOICE" : "DEVOICE", targetUser->nick);
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "OP/VOICE %s %cv %s -- by %s (%s@%s) through %s", chan->ci->name, action, targetUser->nick,
						 callerUser->nick, callerUser->username, callerUser->host, accessName);			
		}
		
	} else if ((accessLevel >= CS_ACCESS_HOP) || isOper) {
		
		/* User is at least HOP or SA+/+z: he may VOICE/DEVOICE anyone */
		char 	nick_list_buf[((NICKMAX + 1) * USER_MAX_MODES) + 1];
		char 	globops_buf[((NICKMAX + 4) * USER_MAX_MODES) + 1];
		char 	modes[SERVER_MAX_MODES + 2];
		int 	i, skip, mIndex = 1;
		
		TRACE_MAIN();
		memset(nick_list_buf, 0, sizeof(nick_list_buf));
		memset(globops_buf, 0, sizeof(globops_buf));
		memset(modes, 0, sizeof(modes));
		
		modes[0] = action;
		
		/* Cycle through user_list[] */
		for (i = 0; i < user_count; ++i) {
			
			TRACE_MAIN();
			
			/* If there is another user with the same nick in one of the next positions
			 * in the list then skip the current one: the user will be processed later.
			 */
			for (skip = i + 1; skip < user_count; ++skip) {
				
				if (user_list[skip] == user_list[i]) {
					
					skip = -1;
					break;
				}
			}
			
			if (skip == -1)
				continue;
			
			targetUser = user_list[i];
			
			/* Check if targetUser needs to be voiced/devoiced. If not go on to next user in user_list */
			if (!user_isin_chan(targetUser, chan->ci->name))
				continue;
			
			if ((action == '+') ? user_is_chanvoice(targetUser->nick, chan->ci->name, chan) : !user_is_chanvoice(targetUser->nick, chan->ci->name, chan))
				continue;
			
			TRACE_MAIN();
			
			if ((accessLevel < CS_ACCESS_VOP) || ((accessLevel == CS_ACCESS_VOP) && (targetUser != callerUser))) {
				/* The user must have used his SA+/+z privileges: prepare GLOBOPS message... */
				if (*globops_buf)
					strcat(globops_buf, "\2, \2");
				strcat(globops_buf, targetUser->nick);
			}
			
			if (action == '+')
				chan_add_voice(chan, targetUser);
			else
				chan_remove_voice(chan, targetUser);
			
			if (*nick_list_buf)
				strcat(nick_list_buf, " ");
			strcat(nick_list_buf, targetUser->nick);
			
			modes[mIndex++] = 'v';
		} /* for */
		
		if (*nick_list_buf) {
			if (*globops_buf) {
				if (IS_NOT_NULL(callerUser->oper) && str_not_equals_nocase(callerUser->oper->nick, callerUser->nick)) {

					accessMatch = FALSE;
					str_copy_checked(callerUser->oper->nick, accessName, NICKSIZE);
				}

				if (accessMatch)
					send_globops(s_ChanServ, "\2%s\2 %s \2%s\2 on \2%s\2", callerUser->nick, 
								 (action == '+') ? "voiced" : "devoiced", globops_buf, chan->ci->name);
				else
					send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) %s \2%s\2 on \2%s\2", callerUser->nick, accessName, 
								 (action == '+') ? "voiced" : "devoiced", globops_buf, chan->ci->name);				
			}
			
			send_cmd(":%s MODE %s %s %s", s_ChanServ, chan->name, modes, nick_list_buf);

			if (accessMatch) {
				if (CSMatchVerbose(chan->ci->settings, CI_NOTICE_VERBOSE_CLEAR))
					send_cmd(lang_msg(EXTRACT_LANG_ID(chan->ci->langID), CS_VERBOSE_OPNOTICE_OP_DEOP_USED), s_ChanServ, chan->ci->name, callerUser->nick,
							 (action == '+') ? "VOICE" : "DEVOICE", nick_list_buf);
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "OP/VOICE %s %s %s -- by %s (%s@%s)", chan->ci->name, modes, nick_list_buf,
							 callerUser->nick, callerUser->username, callerUser->host);
			} else {
				if (CSMatchVerbose(chan->ci->settings, CI_NOTICE_VERBOSE_CLEAR))
					send_cmd(lang_msg(EXTRACT_LANG_ID(chan->ci->langID), CS_VERBOSE_OPNOTICE_OP_DEOP_USED_THROUGH), s_ChanServ, chan->ci->name, callerUser->nick,
							 accessName, (action == '+') ? "VOICE" : "DEVOICE", nick_list_buf);
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "OP/VOICE %s %s %s -- by %s (%s@%s) through %s", chan->ci->name, modes, nick_list_buf,
							 callerUser->nick, callerUser->username, callerUser->host, accessName);			
			}					
		} else {
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_OP_DEOP_ERROR_NOTHING_TO_DO);
		}
	} else {
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
	}
}

static void handle_halfop_dehalfop(User *callerUser, Channel *chan, User *user_list[], int user_count, const char action)
{
	/* A user may only halfop anyone if he is at least AOP or if he is a SA+/+z.
	 * A user may only halfop himself if he is a HOP.
	 * If he use the command as a SA+/+z then the affected nick must be appended to globops_buf.
	 * If he don't have sufficient access then he must be notified of the situation.
	 * If all the user in user_list have the requested status then the user must be notified of the situation.
	 */
	char	accessName[NICKSIZE];
	int		accessLevel, accessMatch, isOper;
	User 	*targetUser;
	
	/* Check for valid parameters */
	if (callerUser == NULL || chan == NULL || chan->ci == NULL || user_list == NULL)
		return;
	
	isOper = is_services_admin(callerUser) || user_is_services_agent(callerUser);
	
	TRACE_MAIN();
	accessLevel = get_access(callerUser, chan->ci, accessName, &accessMatch, NULL);
	
	/* Check if callerUser has access to command */
	if ((accessLevel == CS_ACCESS_HOP) && !isOper) {
		
		/* User is HOP and not SA+/+z: he may only HALFOP/DEHALFOP himself */
		targetUser = user_list[0];
		
		if (str_not_equals_nocase(callerUser->nick, targetUser->nick)) {
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
			return;
		}
		
		if (!user_isin_chan(targetUser, chan->name) ||
			((action == '+') && user_is_chanhalfop(targetUser->nick, chan->name, chan)) ||
			((action == '-') && !user_is_chanhalfop(targetUser->nick, chan->name, chan))) {
			/* Nothing to be done */
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_OP_DEOP_ERROR_NOTHING_TO_DO);
			return;
		}
		
		/* Give/take halfop to targetUser (which is the same of callerUser, in this case) */
		
		TRACE_MAIN();
		send_cmd(":%s MODE %s %ch %s", s_ChanServ, chan->name, action, targetUser->nick);
		
		if (action == '+')
			chan_add_halfop(chan, callerUser);
		else
			chan_remove_halfop(chan, callerUser);
		
		if (accessMatch) {
			if (CSMatchVerbose(chan->ci->settings, CI_NOTICE_VERBOSE_CLEAR))
				send_cmd(lang_msg(EXTRACT_LANG_ID(chan->ci->langID), CS_VERBOSE_OPNOTICE_OP_DEOP_USED), s_ChanServ, chan->ci->name, callerUser->nick,
						 (action == '+') ? "HALFOP" : "DEHALFOP", targetUser->nick);
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "OP/VOICE %s %ch %s -- by %s (%s@%s)", chan->ci->name, action, targetUser->nick,
						 callerUser->nick, callerUser->username, callerUser->host);
		} else {
			if (CSMatchVerbose(chan->ci->settings, CI_NOTICE_VERBOSE_CLEAR))
				send_cmd(lang_msg(EXTRACT_LANG_ID(chan->ci->langID), CS_VERBOSE_OPNOTICE_OP_DEOP_USED_THROUGH), s_ChanServ, chan->ci->name, callerUser->nick,
						 accessName, (action == '+') ? "HALFOP" : "DEHALFOP", targetUser->nick);
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "OP/VOICE %s %ch %s -- by %s (%s@%s) through %s", chan->ci->name, action, targetUser->nick,
						 callerUser->nick, callerUser->username, callerUser->host, accessName);			
		}
		
	} else if ((accessLevel >= CS_ACCESS_AOP) || isOper) {
		
		/* User is at least AOP or SA+/+z: he may HALFOP/DEHALFOP anyone */
		char 	nick_list_buf[((NICKMAX + 1) * USER_MAX_MODES) + 1];
		char 	globops_buf[((NICKMAX + 4) * USER_MAX_MODES) + 1];
		char 	modes[SERVER_MAX_MODES + 2];
		int 	i, skip, mIndex = 1;
		
		TRACE_MAIN();
		memset(nick_list_buf, 0, sizeof(nick_list_buf));
		memset(globops_buf, 0, sizeof(globops_buf));
		memset(modes, 0, sizeof(modes));
		
		modes[0] = action;
		
		/* Cycle through user_list[] */
		for (i = 0; i < user_count; ++i) {
			
			TRACE_MAIN();
			
			/* If there is another user with the same nick in one of the next positions
			 * in the list then skip the current one: the user will be processed later.
			 */
			for (skip = i + 1; skip < user_count; ++skip) {
				
				if (user_list[skip] == user_list[i]) {
					
					skip = -1;
					break;
				}
			}
			
			if (skip == -1)
				continue;
			
			targetUser = user_list[i];
			
			/* Check if targetUser needs to be halfopped/dehalfopped. If not go on to next user in user_list */
			if (!user_isin_chan(targetUser, chan->ci->name))
				continue;
			
			if ((action == '+') ? user_is_chanhalfop(targetUser->nick, chan->ci->name, chan) : !user_is_chanhalfop(targetUser->nick, chan->ci->name, chan))
				continue;
			
			TRACE_MAIN();
			
			if ((accessLevel < CS_ACCESS_HOP) || ((accessLevel == CS_ACCESS_HOP) && (targetUser != callerUser))) {
				/* The user must have used his SA+/+z privileges: prepare GLOBOPS message... */
				if (*globops_buf)
					strcat(globops_buf, "\2, \2");
				strcat(globops_buf, targetUser->nick);
			}
			
			if (action == '+')
				chan_add_halfop(chan, targetUser);
			else
				chan_remove_halfop(chan, targetUser);
			
			if (*nick_list_buf)
				strcat(nick_list_buf, " ");
			strcat(nick_list_buf, targetUser->nick);
			
			modes[mIndex++] = 'h';
		} /* for */
		
		if (*nick_list_buf) {
			if (*globops_buf) {
				if (IS_NOT_NULL(callerUser->oper) && str_not_equals_nocase(callerUser->oper->nick, callerUser->nick)) {

					accessMatch = FALSE;
					str_copy_checked(callerUser->oper->nick, accessName, NICKSIZE);
				}

				if (accessMatch)
					send_globops(s_ChanServ, "\2%s\2 %s \2%s\2 on \2%s\2", callerUser->nick, 
								 (action == '+') ? "halfopped" : "dehalfopped", globops_buf, chan->ci->name);
				else
					send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) %s \2%s\2 on \2%s\2", callerUser->nick, accessName, 
								 (action == '+') ? "halfopped" : "dehalfopped", globops_buf, chan->ci->name);				
			}
			
			send_cmd(":%s MODE %s %s %s", s_ChanServ, chan->name, modes, nick_list_buf);

			if (accessMatch) {
				if (CSMatchVerbose(chan->ci->settings, CI_NOTICE_VERBOSE_CLEAR))
					send_cmd(lang_msg(EXTRACT_LANG_ID(chan->ci->langID), CS_VERBOSE_OPNOTICE_OP_DEOP_USED), s_ChanServ, chan->ci->name, callerUser->nick,
							 (action == '+') ? "HALFOP" : "DEHALFOP", nick_list_buf);
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "OP/VOICE %s %s %s -- by %s (%s@%s)", chan->ci->name, modes, nick_list_buf,
							 callerUser->nick, callerUser->username, callerUser->host);
			} else {
				if (CSMatchVerbose(chan->ci->settings, CI_NOTICE_VERBOSE_CLEAR))
					send_cmd(lang_msg(EXTRACT_LANG_ID(chan->ci->langID), CS_VERBOSE_OPNOTICE_OP_DEOP_USED_THROUGH), s_ChanServ, chan->ci->name, callerUser->nick,
							 accessName, (action == '+') ? "HALFOP" : "DEHALFOP", nick_list_buf);
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "OP/VOICE %s %s %s -- by %s (%s@%s) through %s", chan->ci->name, modes, nick_list_buf,
							 callerUser->nick, callerUser->username, callerUser->host, accessName);			
			}					
		} else {
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_OP_DEOP_ERROR_NOTHING_TO_DO);
		}
	} else {
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
	}
}

static void handle_op_deop(User *callerUser, Channel *chan, User *user_list[], int user_count, const char action)
{
	/* A user may op anyone if he is at least AOP and OPGUARD is not set on the channel or if he is at
	 *   least a COFOUNDER or SA+/+z.
	 * A user may deop anyone if he is at least AOP and PROTECT is not set on the channel or if he is at least a
	 *   COFOUNDER.
	 * Il PROTECT is set then a user which is at least AOP may only be deopped by a COFOUNDER or a FOUNDER.
	 * If he use the command as a SA+/+z then the affected nick must be appended to globops_buf.
	 * If he don't have sufficient access then he must be notified of the situation.
	 * If all the user in user_list have the requested status then the user must be notified of the situation.
	 */
	char	accessName[NICKSIZE];
	int		accessLevel, accessMatch, isOper;
	User 	*targetUser;
	
	/* Check for valid parameters */
	if (callerUser == NULL || chan == NULL || chan->ci == NULL || user_list == NULL)
		return;
	
	isOper = is_services_admin(callerUser) || user_is_services_agent(callerUser);
	
	TRACE_MAIN();
	accessLevel = get_access(callerUser, chan->ci, accessName, &accessMatch, NULL);
	
	/* Check if callerUser has access to command */
	if ((accessLevel >= CS_ACCESS_AOP) || isOper) {
		
		/* User is at least AOP or SA+/+z: he may AOP/DEOP anyone if OPGUARD/PROTECT are not set */
		char 	nick_list_buf[((NICKMAX + 1) * USER_MAX_MODES) + 1];
		char 	globops_buf[((NICKMAX + 4) * USER_MAX_MODES) + 1];
		char 	modes[SERVER_MAX_MODES + 2], targetName[NICKSIZE];
		int 	targetLevel, targetMatch;
		int 	i, skip, mIndex = 1, opguard = 0, neverop = 0, protect = 0;
		int 	cannot_opguard = 0, cannot_neverop = 0, cannot_protect = 0; 
		
		TRACE_MAIN();
		memset(nick_list_buf, 0, sizeof(nick_list_buf));
		memset(globops_buf, 0, sizeof(globops_buf));
		memset(modes, 0, sizeof(modes));
		
		modes[0] = action;
		
		/* Cycle through user_list[] */
		for (i = 0; i < user_count; ++i) {
			
			TRACE_MAIN();
			
			/* If there is another user with the same nick in one of the next positions
			 * in the list then skip the current one: the user will be processed later.
			 */
			for (skip = i + 1; skip < user_count; ++skip) {
				
				if (user_list[skip] == user_list[i]) {
					
					skip = -1;
					break;
				}
			}
			
			if (skip == -1)
				continue;
			
			targetUser = user_list[i];
			
			/* Check if targetUser needs to be opped/deopped. If not go on to next user in user_list */
			if (!user_isin_chan(targetUser, chan->ci->name))
				continue;
			
			if ((action == '+') ? user_is_chanop(targetUser->nick, chan->ci->name, chan) : !user_is_chanop(targetUser->nick, chan->ci->name, chan))
				continue;
			
			TRACE_MAIN();
			
			/* True if OP command should be blocked because targetUser has NEVEROP set and callerUser != targetUser */
			cannot_neverop = targetUser->ni && FlagSet(targetUser->ni->flags, NI_NEVEROP) && (callerUser != targetUser);
			
			/* Check for NEVEROP */
			if ((action == '+') && cannot_neverop && !isOper) {
				
				/* A non-SA+/+z user tried to op a different target who has NEVEROP NickServ option set */
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_OP_DEOP_ERROR_NEVEROP_ON, targetUser->nick);
				++neverop;
				continue;
			}
			
			targetLevel = get_access(targetUser, chan->ci, targetName, &targetMatch, NULL);

			/* True if OP command should be blocked because the channel has OPGUARD set and callerUser is not COFOUNDER+ and
			 * targetUser is not AOP+
			 */
			cannot_opguard = FlagSet(chan->ci->flags, CI_OPGUARD) && (accessLevel < CS_ACCESS_COFOUNDER) && (targetLevel < CS_ACCESS_AOP);
			
			/* Check for OPGUARD */
			if ((action == '+') && cannot_opguard && !isOper) {
				
				/* A non-COFOUNDER/SA+/+z user tried to op a non-AOP+ user on a channel with OPGUARD set.
				 */
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_OP_DEOP_ERROR_OPGUARD_ON, targetUser->nick);
				++opguard;
				continue;
			}
			
			/* True if DEOP command should be blocked because the channel has PROTECTED set and callerUser has an accessLevel
			 * lower than targetUser's level and targetUser is AOP+ and callerUser is deopping a user different from self.
			 */
			cannot_protect = FlagSet(chan->ci->flags, CI_PROTECTED) && (accessLevel <= targetLevel) && (targetLevel >= CS_ACCESS_AOP) && (callerUser != targetUser);
			
			/* Check for PROTECT */
			if ((action == '-') && cannot_protect && !isOper) {
				
				/* A non-COFOUNDER/SA+/+z user tried to deop a different user on a channel with PROTECT set and
				 * the target user is at least AOP on that channel.
				 */
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_OP_DEOP_ERROR_PROTECT_ON, targetUser->nick);
				++protect;
				continue;
			}
			
			/* No more exceptions... */
			TRACE_MAIN();
			
			if ((accessLevel < CS_ACCESS_AOP) || 
				((action == '+') && (cannot_neverop || cannot_opguard)) || 
				((action == '-') && cannot_protect)) {
					 
				/* The user must have used his SA+/+z privileges: prepare GLOBOPS message... */
				if (*globops_buf)
					strcat(globops_buf, "\2, \2");
				strcat(globops_buf, targetUser->nick);
			}
			
			if (action == '+')
				chan_add_op(chan, targetUser);
			else
				chan_remove_op(chan, targetUser);
			
			if (*nick_list_buf)
				strcat(nick_list_buf, " ");
			strcat(nick_list_buf, targetUser->nick);
			
			modes[mIndex++] = 'o';
			
			if (targetLevel >= CS_ACCESS_AOP)
				chan->ci->last_used = NOW;
		} /* for */
		
		if (*nick_list_buf) {
			if (*globops_buf) {
				if (IS_NOT_NULL(callerUser->oper) && str_not_equals_nocase(callerUser->oper->nick, callerUser->nick)) {

					accessMatch = FALSE;
					str_copy_checked(callerUser->oper->nick, accessName, NICKSIZE);
				}

				if (accessMatch)
					send_globops(s_ChanServ, "\2%s\2 %s \2%s\2 on \2%s\2", callerUser->nick, 
								 (action == '+') ? "opped" : "deopped", globops_buf, chan->ci->name);
				else
					send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) %s \2%s\2 on \2%s\2", callerUser->nick, accessName, 
								 (action == '+') ? "opped" : "deopped", globops_buf, chan->ci->name);				
			}
			
			send_cmd(":%s MODE %s %s %s", s_ChanServ, chan->name, modes, nick_list_buf);

			if (accessMatch) {
				if (CSMatchVerbose(chan->ci->settings, CI_NOTICE_VERBOSE_CLEAR))
					send_cmd(lang_msg(EXTRACT_LANG_ID(chan->ci->langID), CS_VERBOSE_OPNOTICE_OP_DEOP_USED), s_ChanServ, chan->ci->name, callerUser->nick,
							 (action == '+') ? "OP" : "DEOP", nick_list_buf);
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "OP/VOICE %s %s %s -- by %s (%s@%s)", chan->ci->name, modes, nick_list_buf,
							 callerUser->nick, callerUser->username, callerUser->host);
			} else {
				if (CSMatchVerbose(chan->ci->settings, CI_NOTICE_VERBOSE_CLEAR))
					send_cmd(lang_msg(EXTRACT_LANG_ID(chan->ci->langID), CS_VERBOSE_OPNOTICE_OP_DEOP_USED_THROUGH), s_ChanServ, chan->ci->name, callerUser->nick,
							 accessName, (action == '+') ? "OP" : "DEOP", nick_list_buf);
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "OP/VOICE %s %s %s -- by %s (%s@%s) through %s", chan->ci->name, modes, nick_list_buf,
							 callerUser->nick, callerUser->username, callerUser->host, accessName);			
			}					
		} else if (user_count - neverop - (opguard + protect) > 0) {
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_OP_DEOP_ERROR_NOTHING_TO_DO);
		}
	} else {
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
	}
}

static void handle_op_voice(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *chan_name = strtok(NULL, " ");
	char action = '+', mode = 'o';
	Channel *chan;
	ChannelInfo *ci;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_OP_VOICE);

	switch (data->commandName[2]) {

		case '\0':	/* OP */
			break;

		case 'O':	/* DEOP */
			action = '-';
			break;
			
		case 'L':	/* HALFOP */
			mode = 'h';
			break;

		case 'H':	/* DEHALFOP */
			action = '-';
			mode = 'h';
			break;

		case 'I':	/* VOICE */
			mode = 'v';
			break;

		case 'V':	/* DEVOICE */
			action = '-';
			mode = 'v';
			break;
	}

	if (IS_NULL(chan_name)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_OP_DEOP_SYNTAX_ERROR, data->commandName);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, data->commandName);
	}
	else if (*chan_name != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan_name, chan_name);

	else if (IS_NULL(chan = hash_channel_find(chan_name)))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_EMPTY, chan_name);

	else if (IS_NULL(ci = chan->ci))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, chan_name);

	else if (FlagSet(ci->flags, CI_FORBIDDEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

	else if (FlagSet(ci->flags, CI_SUSPENDED))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_SUSPENDED, ci->name);

	else if (FlagSet(ci->flags, CI_FROZEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FROZEN, ci->name);

	else if (FlagSet(ci->flags, CI_CLOSED))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_CLOSED, ci->name);

	else if (FlagSet(ci->flags, CI_NOENTRY))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_NOENTRY_ON, ci->name);

	else {
		char *target_nick;
		User *user_list[USER_MAX_MODES];
		User *user;
		int user_count = 0;

		while (IS_NOT_NULL(target_nick = strtok(NULL, " "))) {

			if (IS_NOT_NULL(user = hash_onlineuser_find(target_nick))) {

				user_list[user_count++] = user;

				TRACE_MAIN();
				if (user_count == USER_MAX_MODES)
					break;
			}
		}

		TRACE_MAIN();
		if (user_count == 0) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_OP_DEOP_ERROR_OFFLINE);
			return;
		}

		TRACE_MAIN();
		
		switch (mode) {
			case 'v':
				handle_voice_devoice(callerUser, chan, user_list, user_count, action);
				break;
			case 'h':
				handle_halfop_dehalfop(callerUser, chan, user_list, user_count, action);
				break;
			case 'o':
				handle_op_deop(callerUser, chan, user_list, user_count, action);
				break;			
		}
	}
}


/*********************************************************/

static const char *s_FOUNDER =		"Founder";
static const char *s_COFOUNDER =	"Co-Founder";
static const char *s_SOP =			"SOP";
static const char *s_AOP =			"AOP";
static const char *s_HOP =			"HOP";
static const char *s_VOP =			"VOP";
static const char *s_AKICK =		"AKICK";

static const char *s_SHORT_FOUNDER =	"FND";
static const char *s_SHORT_COFOUNDER =	"COF";
static const char *s_SHORT_SOP =		"SOP";
static const char *s_SHORT_AOP =		"AOP";
static const char *s_SHORT_HOP =		"HOP";
static const char *s_SHORT_VOP =		"VOP";
static const char *s_SHORT_AKICK =		"ACK";


static const char *s_empty_string = "";

/*********************************************************/

static const char *get_chan_access_name(const int listLevel) {

	switch (listLevel) {

		case CS_ACCESS_FOUNDER:
			return s_FOUNDER;

		case CS_ACCESS_COFOUNDER:
			return s_COFOUNDER;

		case CS_ACCESS_SOP:
			return s_SOP;

		case CS_ACCESS_AOP:
			return s_AOP;

		case CS_ACCESS_HOP:
			return s_HOP;

		case CS_ACCESS_VOP:
			return s_VOP;

		case CS_ACCESS_AKICK:
			return s_AKICK;

		default:
			return s_empty_string;
	}
}

static const char *get_short_chan_access_name(const int listLevel) {

	switch (listLevel) {

		case CS_ACCESS_FOUNDER:
			return s_SHORT_FOUNDER;

		case CS_ACCESS_COFOUNDER:
			return s_SHORT_COFOUNDER;

		case CS_ACCESS_SOP:
			return s_SHORT_SOP;

		case CS_ACCESS_AOP:
			return s_SHORT_AOP;

		case CS_ACCESS_HOP:
			return s_SHORT_HOP;

		case CS_ACCESS_VOP:
			return s_SHORT_VOP;

		case CS_ACCESS_AKICK:
			return s_SHORT_AKICK;

		default:
			return s_empty_string;
	}
}

/*********************************************************/

static const long get_chan_list_lock_flag(const int listLevel) {

	switch (listLevel) {

		case CS_ACCESS_COFOUNDER:
			return CI_ACCCESS_CFOUNDER_LOCK;

		case CS_ACCESS_SOP:
			return CI_ACCCESS_SOP_LOCK;

		case CS_ACCESS_AOP:
			return CI_ACCCESS_AOP_LOCK;

		case CS_ACCESS_HOP:
			return CI_ACCCESS_HOP_LOCK;

		case CS_ACCESS_VOP:
			return CI_ACCCESS_VOP_LOCK;

		case CS_ACCESS_AKICK:
			return CI_ACCCESS_AKICK_LOCK;

		default:
			return CI_ACCCESS_NO_LOCK;
	}
}

/*********************************************************/

static void do_chan_access_LIST(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci, CSTR nick, BOOL isHelper) {

	const char *listName = get_chan_access_name(listLevel);

	NickInfo *ni;
	ChanAccess *anAccess;
	char timebuf[64];
	char *usermask;
	int checkIndex, entryIndex;

	int accessLevel;

	TRACE_FCLT(FACILITY_CHANSERV_CHAN_ACCESS_LIST);

	accessLevel = get_access(callerUser, ci, NULL, NULL, NULL);

	if ((accessLevel < CS_ACCESS_VOP) && (!isHelper || FlagSet(ci->flags, CI_MARKCHAN) ||
		(FlagSet(ci->flags, CI_SOPONLY) && !is_services_oper(callerUser)) ||
		(FlagSet(ci->flags, CI_SAONLY) && !is_services_admin(callerUser)) ||
		(FlagSet(ci->flags, CI_SRAONLY) && !is_services_root(callerUser)) ||
		(FlagSet(ci->flags, CI_CODERONLY) && !is_services_coder(callerUser)))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
		return;
	}

	send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_LIST_HEADER, listName, ci->name, nick ? nick : "*");

	TRACE();
	for (anAccess = ci->access, checkIndex = 0, entryIndex = 0; checkIndex < ci->accesscount; ++anAccess, ++checkIndex) {

		if (anAccess->level != listLevel)
			continue;

		++entryIndex;

		if (nick && !str_match_wild_nocase(nick, anAccess->name))
			continue;

		if (anAccess->status == ACCESS_ENTRY_EXPIRED)
			usermask = "Expired";
		else if (IS_NOT_NULL(ni = findnick(anAccess->name)))
			usermask = ni->last_usermask;
		else
			usermask = NULL;

		TRACE();
		lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, anAccess->creationTime);

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_LIST_ENTRIES, entryIndex, anAccess->name,
			usermask ? " (" : "", usermask ? usermask : "", usermask ? ")" : "", anAccess->creator, timebuf,
			FlagSet(anAccess->flags, ACCESS_FLAG_LOCKED) ? " [Locked]" : "");
	}

	if (ci->settings & get_chan_list_lock_flag(listLevel))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_LIST_IS_LOCKED);

	TRACE();
	send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), END_OF_LIST);
}
static void do_chan_access_FIND(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci, CSTR mask)
{

	const char *listName = get_chan_access_name(listLevel);

	NickInfo *ni;
	ChanAccess *anAccess;
	char timebuf[64];
	char nick_mask[MASKSIZE];
	char *nick, *usermask, *host;
	char *user_nick, *user_usermask, *user_host;
	int checkIndex, entryIndex;

	int accessLevel;

	TRACE_FCLT(FACILITY_CHANSERV_CHAN_ACCESS_FIND);

	memset(nick_mask, 0 , sizeof(nick_mask));
	
	accessLevel = get_access(callerUser, ci, NULL, NULL, NULL);
	
	if(IS_NULL(mask) || IS_EMPTY_STR(mask)) {
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_MASK);
		return;
	}
		
	if (!validate_mask(mask, TRUE, TRUE, TRUE)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_MASK);
		return;
	}

	user_usermask_split(mask, &user_nick, &user_usermask, &user_host);

	if ((accessLevel < CS_ACCESS_VOP) && (!is_services_helpop(callerUser) || FlagSet(ci->flags, CI_MARKCHAN) ||
		(FlagSet(ci->flags, CI_SOPONLY) && !is_services_oper(callerUser)) ||
		(FlagSet(ci->flags, CI_SAONLY) && !is_services_admin(callerUser)) ||
		(FlagSet(ci->flags, CI_SRAONLY) && !is_services_root(callerUser)) ||
		(FlagSet(ci->flags, CI_CODERONLY) && !is_services_coder(callerUser)))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
		return;
	}

	send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_LIST_HEADER, listName, ci->name, mask);

	
	for (anAccess = ci->access, checkIndex = 0, entryIndex = 0; checkIndex < ci->accesscount; ++anAccess, ++checkIndex) {

		if (anAccess->level != listLevel)
			continue;


		if (IS_NOT_NULL(ni = findnick(anAccess->name))){
		
			if(IS_NULL(ni->last_usermask))
				continue;
				
			str_copy_checked(ni->last_usermask,nick_mask, MASKSIZE);
			
			user_usermask_split(nick_mask, &nick, &usermask, &host);
			
			
			if((IS_NOT_NULL(user_nick) && str_match_wild_nocase(user_nick, ni->nick)) && str_match_wild_nocase(user_usermask, usermask) && str_match_wild_nocase(user_host, host)) {
				++entryIndex;
		
				TRACE();
		
				lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, anAccess->creationTime);
			
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_LIST_ENTRIES, entryIndex, anAccess->name,
			 " (" , ni->last_usermask, ")" , anAccess->creator, timebuf,
			FlagSet(anAccess->flags, ACCESS_FLAG_LOCKED) ? " [Locked]" : "");	
				
			}
		mem_free(nick);
		mem_free(usermask);
		mem_free(host);
		memset(nick_mask, 0, sizeof(nick_mask));
		}		
	}
	
	if (ci->settings & get_chan_list_lock_flag(listLevel))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_LIST_IS_LOCKED);

	TRACE();
	send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), END_OF_LIST);

	mem_free(user_nick);
	mem_free(user_usermask);
	mem_free(user_host);
}

/*********************************************************
 * Parameters are as follows:                            *
 * 	accessLevel = VOP/HOP/AOP/SOP/CF                     *
 *	source = Caller's nick                               *
 * 	callerUser = Caller's User record                    *
 *	ci = Channel                                         *
 *	nick = nickname to be added                          *
 *********************************************************/

static void do_chan_access_ADD(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci, CSTR nick) {

	const char	*listName;
	int			accessLevel, accessMatch;
	char		accessName[NICKSIZE];
	char		mask[MASKSIZE];
	NickInfo	*ni;
	ChanAccess	*anAccess;
	AutoKick	*anAkick;
	BOOL		isMask = FALSE, wasChanged = FALSE;
	int			idxCheck;


	TRACE_FCLT(FACILITY_CHANSERV_CHAN_ACCESS_ADD);

	if (CONF_SET_READONLY) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_READONLY);
		return;
	}

	accessLevel = get_access(callerUser, ci, accessName, &accessMatch, NULL);

	if ((accessLevel <= listLevel) || (accessLevel < CS_ACCESS_SOP)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
		return;
	}

	listName = get_chan_access_name(listLevel);

	if ((accessLevel != CS_ACCESS_FOUNDER) && (ci->settings & get_chan_list_lock_flag(listLevel))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_LIST_LOCKED, listName, ci->name);
		return;
	}

	str_copy_checked(nick, mask, MASKSIZE);

	if (IS_NULL(accessName) || IS_EMPTY_STR(accessName))
		str_copy_checked(source, accessName, NICKSIZE);

	TRACE();
	if (IS_NULL(ni = findnick(nick))) {

		/* Non e' un nick registrato, che sia una mask? ;) */

		if (str_len(nick) > MASKMAX) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_MASK_MAX_LENGTH, MASKMAX);
			return;
		}
		else if (!strchr(mask, '@') && !strchr(mask, '!')) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_NICK_NOT_REG, nick);
			return;
		}
		else if (FlagSet(ci->flags, CI_IDENT)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_IDENT_ON, ci->name);
			return;
		}
		else if (!validate_mask(mask, TRUE, FALSE, FALSE)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_NO_NICK_AT_USER_AT_HOST_MASK);
			return;
		}
		else if (mask_contains_crypt(mask)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_INVALID_ENTRY);
			return;
		}

		switch (validate_access(mask)) {

			case 3:
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_QUESTION_MARK);
				return;

			case 2:
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_MASK);
				return;

			case 1:
				wasChanged = TRUE;
				break;
		}

		str_compact(mask);
		isMask = 1;
	}
	else {

		if (FlagSet(ni->flags, NI_FORBIDDEN)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_NICK_FORBIDDEN, ni->nick);
			return;
		}

		if (FlagSet(ni->flags, NI_FROZEN)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_NICK_FROZEN, ni->nick);
			return;
		}

		if (str_equals_nocase(ni->nick, ci->founder)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_NICK_IS_FOUNDER, ni->nick, ci->name);
			return;
		}

		if (CONF_FORCE_AUTH && (FlagSet(ni->flags, NI_AUTH) || !ni->email)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_NICK_NOT_AUTH, ni->nick);
			return;
		}
	}

	TRACE();
	for (anAccess = ci->access, idxCheck = 0; idxCheck < ci->accesscount; ++anAccess, ++idxCheck) {

		if ((anAccess->status != ACCESS_ENTRY_FREE) && str_equals_nocase(anAccess->name, mask)) {

			TRACE();
			if (anAccess->level >= accessLevel)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_NICK_IS_SUPERIOR, anAccess->name, ci->name);

			else if ((anAccess->level == listLevel) && (anAccess->status != ACCESS_ENTRY_EXPIRED)) {

				if (wasChanged)
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_ALREADY_ADDED_CHANGED, anAccess->name, listName, ci->name);
				else
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_ALREADY_ADDED, anAccess->name, listName, ci->name);
			}
			else if ((accessLevel != CS_ACCESS_FOUNDER) && FlagSet(ci->settings, get_chan_list_lock_flag(anAccess->level)))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_LIST_LOCKED, get_chan_access_name(anAccess->level), ci->name);

			else if ((accessLevel != CS_ACCESS_FOUNDER) && FlagSet(anAccess->flags, ACCESS_FLAG_LOCKED))
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_ENTRY_LOCKED, anAccess->name, get_chan_access_name(anAccess->level), ci->name);

			else {

				int oldLevel = anAccess->level;

				if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS)) {

					if (accessMatch)
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), (anAccess->status == ACCESS_ENTRY_EXPIRED) ? CS_VERBOSE_OPNOTICE_XOP_ADDED : (((listLevel > oldLevel) ? CS_VERBOSE_OPNOTICE_XOP_RAISED : CS_VERBOSE_OPNOTICE_XOP_DEMOTED))), s_ChanServ, ci->name, source, anAccess->name, listName);
					else
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), (anAccess->status == ACCESS_ENTRY_EXPIRED) ? CS_VERBOSE_OPNOTICE_XOP_ADDED_THROUGH : (((listLevel > oldLevel) ? CS_VERBOSE_OPNOTICE_XOP_RAISED_THROUGH : CS_VERBOSE_OPNOTICE_XOP_DEMOTED_THROUGH))), s_ChanServ, ci->name, source, accessName, anAccess->name, listName);
				}

				TRACE();
				if (anAccess->creator)
					mem_free(anAccess->creator);
				anAccess->creator = str_duplicate(accessName);

				anAccess->creationTime = NOW;
				anAccess->level = listLevel;
				anAccess->flags = 0;

				if (anAccess->status == ACCESS_ENTRY_EXPIRED) {

					if (ni) {

						anAccess->status = ACCESS_ENTRY_NICK;
						++(ni->channelcount);
					}
					else
						anAccess->status = ACCESS_ENTRY_MASK;
				}

				if (ni && FlagSet(ni->flags, NI_NOOP)) {

					if (ci->successor && str_equals_nocase(ni->nick, ci->successor)) {

						send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_JUMP_NOOP_1, ni->nick, ci->name);
						send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_JUMP_NOOP_2_SUCCESSOR, listName);

						mem_free(ci->successor);
						ci->successor = NULL;
					}
					else {

						send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_JUMP_NOOP_1, ni->nick, ci->name);
						send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_JUMP_NOOP_2, listName);
					}
				}
				else {

					if (ni && ci->successor && str_equals_nocase(ni->nick, ci->successor)) {

						send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_LEVEL_CHANGED_SUCCESSOR, anAccess->name, listName, ci->name);

						mem_free(ci->successor);
						ci->successor = NULL;
					}
					else {

						if (wasChanged)
							send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_WARNING_MASK_CHANGED, mask);

						send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_LEVEL_CHANGED, anAccess->name, listName, ci->name);
					}
				}

				if (accessMatch)
					log_services(LOG_SERVICES_CHANSERV_ACCESS, "%s %s ADD %s -- by %s (%s@%s) [Was: %s]", listName, ci->name, anAccess->name, source, callerUser->username, callerUser->host, get_chan_access_name(oldLevel));
				else
					log_services(LOG_SERVICES_CHANSERV_ACCESS, "%s %s ADD %s -- by %s (%s@%s) through %s [Was: %s]", listName, ci->name, anAccess->name, source, callerUser->username, callerUser->host, accessName, get_chan_access_name(oldLevel));
			}

			return;
		}
	}

	/* Nick/mask was not found. Make sure it's not AKicked before adding it. */

	for (anAkick = ci->akick, idxCheck = 0; idxCheck < ci->akickcount; ++anAkick, ++idxCheck) {

		if (anAkick->isNick ? str_equals_nocase(anAkick->name, nick) : str_equals_nocase(anAkick->name, mask)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_AKICKED, anAkick->isNick ? nick : mask, ci->name);
			return;
		}
	}

	TRACE();
	if ((CONF_CHAN_ACCESS_MAX > 0) && (ci->accesscount >= CONF_CHAN_ACCESS_MAX))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_LISTS_FULL, CONF_CHAN_ACCESS_MAX);

	else if (ni && FlagSet(ni->flags, NI_NOOP))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_NOOP_ON, ni->nick);

	else if (ni && (ni->channelcount >= CONF_USER_CHAN_ACCESS_MAX)) {

		if (ni->channelcount > CONF_USER_CHAN_ACCESS_MAX)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_OVER_MAXREG, ni->nick, CONF_USER_CHAN_ACCESS_MAX);
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_ERROR_HIT_MAXREG, ni->nick, CONF_USER_CHAN_ACCESS_MAX);
	}
	else {

		/* Inserimento nuovo nick/mask */

		TRACE();
		for (anAccess = ci->access, idxCheck = 0; idxCheck < ci->accesscount; ++anAccess, ++idxCheck) {

			if (anAccess->status == ACCESS_ENTRY_FREE)
				break;
		}

		if (idxCheck == ci->accesscount) {

			/* Tutte le entry sono usate -> aggiungerne una. */

			TRACE();
			++(ci->accesscount);

			ci->access = mem_realloc(ci->access, sizeof(ChanAccess) * ci->accesscount);

			anAccess = &(ci->access[ci->accesscount - 1]);
			anAccess->creator = NULL;
			anAccess->name = NULL;
		}

		TRACE();
		if (anAccess->name)
			mem_free(anAccess->name);

		if (ni) {

			anAccess->name = str_duplicate(ni->nick);
			++(ni->channelcount);
		}
		else
			anAccess->name = str_duplicate(mask);

		TRACE();
		if (anAccess->creator)
			mem_free(anAccess->creator);
		anAccess->creator = str_duplicate(accessName);

		anAccess->creationTime = NOW;
		anAccess->status = isMask ? ACCESS_ENTRY_MASK : ACCESS_ENTRY_NICK;
		anAccess->level = listLevel;
		anAccess->flags = 0;

		TRACE();
		if (!isMask)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_NICK_ADDED, ni->nick, listName, ci->name);

		else {

			if (wasChanged)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_WARNING_MASK_CHANGED, mask);

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ADD_MASK_ADDED, mask, listName, ci->name);
		}

		if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS)) {

			if (accessMatch)
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_XOP_ADDED), s_ChanServ, ci->name, source, isMask ? mask : ni->nick, listName);
			else
				send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_XOP_ADDED_THROUGH), s_ChanServ, ci->name, source, accessName, isMask ? mask : ni->nick, listName);
		}

		if (accessMatch)
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "%s %s ADD %s -- by %s (%s@%s)", listName, ci->name, anAccess->name, source, callerUser->username, callerUser->host);
		else
			log_services(LOG_SERVICES_CHANSERV_ACCESS, "%s %s ADD %s -- by %s (%s@%s) through %s", listName, ci->name, anAccess->name, source, callerUser->username, callerUser->host, accessName);
	}
}

/*********************************************************/

static void do_chan_access_DEL(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci, CSTR nick) {

	const char *listName = get_chan_access_name(listLevel);
	int accessLevel, accessMatch;
	char accessName[NICKSIZE];
	BOOL nocount = FALSE;

	TRACE_FCLT(FACILITY_CHANSERV_CHAN_ACCESS_DEL);

	accessLevel = get_access(callerUser, ci, accessName, &accessMatch, NULL);

	if ((accessLevel <= listLevel) || (accessLevel < CS_ACCESS_SOP))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

	else if ((accessLevel != CS_ACCESS_FOUNDER) && (ci->settings & get_chan_list_lock_flag(listLevel))) {

		/* La lista è bloccata e il chiamante non è identificato come founder del canale. */
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_LIST_LOCKED, listName, ci->name);
	}
	else {

		ChanAccess *anAccess = NULL;
		int idx, listItemIndex;
		long int itemIndex;
		char *err;


		TRACE();

		itemIndex = strtol(nick, &err, 10);

		if ((itemIndex > 0) && (*err == '\0')) {

			if (itemIndex > ci->accesscount) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_DEL_ERROR_NO_MATCH, itemIndex, listName, ci->name);
				return;
			}

			TRACE();
			for (anAccess = ci->access, idx = 0, listItemIndex = 0; IS_NOT_NULL(anAccess) && (idx < ci->accesscount); ++anAccess, ++idx) {

				if (listLevel != anAccess->level)
					continue;

				++listItemIndex;

				if (listItemIndex == itemIndex) {

					if (anAccess->status == ACCESS_ENTRY_EXPIRED)
						nocount = TRUE;

					anAccess = &(ci->access[idx]);
					break;
				}
			}

			TRACE();
			if ((listItemIndex != itemIndex) || (idx == ci->accesscount) || IS_NULL(anAccess)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_DEL_ERROR_NO_MATCH, itemIndex, listName, ci->name);
				return;
			}
		}
		else {

			/* Ricerca in base al valore dell'elemento. */

			TRACE();
			for (anAccess = ci->access, idx = 0; IS_NOT_NULL(access) && (idx < ci->accesscount); ++anAccess, ++idx) {

				if ((anAccess->level == listLevel) && str_equals_nocase(anAccess->name, nick)) {

					if (anAccess->status == ACCESS_ENTRY_EXPIRED)
						nocount = TRUE;

					break;
				}
			}

			if ((idx == ci->accesscount) || IS_NULL(anAccess)) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_DEL_ERROR_NOT_FOUND, nick, listName, ci->name);
				return;
			}
		}

		/* Il chiamante e' autorizzato a cancellare l'elemento ?
		 * (ie, ha un accesso superiore all'utente da cancellare ?) */

		if (accessLevel <= anAccess->level)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

		else if (FlagSet(anAccess->flags, ACCESS_FLAG_LOCKED) && (accessLevel != CS_ACCESS_FOUNDER) && (anAccess->status != ACCESS_ENTRY_EXPIRED))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_ENTRY_LOCKED, anAccess->name, listName, ci->name);

		else {

			NickInfo *ni;

			TRACE();
			if ((nocount == FALSE) && IS_NOT_NULL(ni = findnick(nick))) {

				if (ni->channelcount > 0)
					--(ni->channelcount);
				else
					log_error(FACILITY_CHANSERV_CHAN_ACCESS_DEL, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED,
						"%s in do_chan_access_DEL(): Nickname record %s has a negative channelcount value", s_ChanServ, ni->nick);
			}

			if (str_equals_nocase(anAccess->name, ci->successor)) {

				mem_free(ci->successor);
				ci->successor = NULL;
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_DEL_NICK_DELETED_SUCCESSOR, anAccess->name, listName, ci->name);
			}
			else
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_DEL_NICK_DELETED, anAccess->name, listName, ci->name);

			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS)) {

				if (accessMatch)
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_XOP_DELETED), s_ChanServ, ci->name, source, anAccess->name, listName);
				else
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_XOP_DELETED_THROUGH), s_ChanServ, ci->name, source, accessName, anAccess->name, listName);
			}

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

			if (accessMatch)
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "%s %s DEL %s -- by %s (%s@%s)", listName, ci->name, anAccess->name, source, callerUser->username, callerUser->host);
			else
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "%s %s DEL %s -- by %s (%s@%s) through %s", listName, ci->name, anAccess->name, source, callerUser->username, callerUser->host, accessName);

			mem_free(anAccess->name);
			anAccess->name = NULL;

			mem_free(anAccess->creator);
			anAccess->creator = NULL;

			anAccess->status = ACCESS_ENTRY_FREE;
			anAccess->flags = 0;
			anAccess->creationTime = 0;

			compact_chan_access_list(ci, 1);
		}
	}
}

/*********************************************************/

static void do_chan_access_CLEAN(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci) {

	const char *listName = get_chan_access_name(listLevel);
	int accessLevel, accessMatch;
	char accessName[NICKSIZE];

	TRACE_FCLT(FACILITY_CHANSERV_CHAN_ACCESS_CLEAN);

	accessLevel = get_access(callerUser, ci, accessName, &accessMatch, NULL);

	if ((accessLevel <= listLevel) || (accessLevel < CS_ACCESS_SOP))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

	else if ((accessLevel != CS_ACCESS_FOUNDER) && (ci->settings & get_chan_list_lock_flag(listLevel))) {

		/* La lista è bloccata e il chiamante non è identificato come founder del canale. */
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_LIST_LOCKED, listName, ci->name);
	}
	else {

		ChanAccess *anAccess;
		int checkIndex;
		int removed = 0;

		TRACE();

		for (anAccess = ci->access, checkIndex = 0; checkIndex < ci->accesscount; ++anAccess, ++checkIndex) {

			/* Eliminazioni dei dati delle entry interessate. */

			if (listLevel == anAccess->level && (anAccess->status == ACCESS_ENTRY_EXPIRED ||
				(anAccess->status == ACCESS_ENTRY_NICK && (!findnick(anAccess->name)))) ) {
				TRACE();
				mem_free(anAccess->name);
				anAccess->name = NULL;

				mem_free(anAccess->creator);
				anAccess->creator = NULL;

				anAccess->status = ACCESS_ENTRY_FREE;
				anAccess->flags = 0;
				anAccess->creationTime = 0;
				
				++removed;
			}
		}

		TRACE();
		if (removed == 0)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_CLEAN_ERROR_NOTHING_TO_CLEAN, listName, ci->name);

		else {

			TRACE();
			compact_chan_access_list(ci, removed);

			if (removed == 1)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_CLEAN_1_ENTRY_CLEANED, listName, ci->name);
			else
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_CLEAN_X_ENTRIES_CLEANED, removed, listName, ci->name);

			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS)) {

				if (accessMatch)
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_XOP_CLEANED), s_ChanServ, ci->name, source, listName);
				else
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_XOP_CLEANED_THROUGH), s_ChanServ, ci->name, source, accessName, listName);
			}

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

			if (accessMatch)
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "%s %s CLEAN -- by %s (%s@%s) [%d entr%s removed]", listName, ci->name, source, callerUser->username, callerUser->host, removed, removed == 1 ? "y" : "ies");
			else
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "%s %s CLEAN -- by %s (%s@%s) through %s [%d entr%s removed]", listName, ci->name, source, callerUser->username, callerUser->host, accessName, removed, removed == 1 ? "y" : "ies");
		}
	}
}

/*********************************************************/

static void do_chan_access_WIPE(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci) {

	const char *listName = get_chan_access_name(listLevel);
	int accessLevel, accessMatch;
	char accessName[NICKSIZE];

	TRACE_FCLT(FACILITY_CHANSERV_CHAN_ACCESS_WIPE);

	accessLevel = get_access(callerUser, ci, accessName, &accessMatch, NULL);

	if ((accessLevel <= listLevel) || (accessLevel < CS_ACCESS_SOP))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

	else if ((accessLevel != CS_ACCESS_FOUNDER) && (ci->settings & get_chan_list_lock_flag(listLevel))) {

		/* La lista è bloccata e il chiamante non è identificato come founder del canale. */
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_LIST_LOCKED, listName, ci->name);
	}
	else {

		ChanAccess *anAccess;
		int checkIndex;
		int removed = 0;
		NickInfo *ni;

		TRACE();
		for (anAccess = ci->access, checkIndex = 0; checkIndex < ci->accesscount; ++anAccess, ++checkIndex) {

			/* Eliminazioni dei dati delle entry interessate. */

			if (listLevel == anAccess->level) {

				if (FlagSet(anAccess->flags, ACCESS_FLAG_LOCKED) && (accessLevel != CS_ACCESS_FOUNDER))
					continue;

				if ((anAccess->status != ACCESS_ENTRY_EXPIRED) && (ni = findnick(anAccess->name))) {

					if (ni->channelcount > 0)
						--(ni->channelcount);
					else
						log_error(FACILITY_CHANSERV_CHAN_ACCESS_WIPE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED,
							"%s in do_chan_access_WIPE(): Nickname record %s has a negative channelcount value", s_ChanServ, ni->nick);
				}

				mem_free(anAccess->name);
				anAccess->name = NULL;

				mem_free(anAccess->creator);
				anAccess->creator = NULL;

				anAccess->status = ACCESS_ENTRY_FREE;
				anAccess->flags = 0;
				anAccess->creationTime = 0;

				++removed;
			}
		}

		if (removed == 0)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_WIPE_ERROR_LIST_EMPTY, ci->name, listName);

		else {

			TRACE();
			compact_chan_access_list(ci, removed);

			if (removed == 1) {

				if ((listLevel == CS_ACCESS_COFOUNDER) && ci->successor) {

					mem_free(ci->successor);
					ci->successor = NULL;
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_WIPE_1_ENTRY_WIPED_SUCCESSOR, 1, listName, ci->name);
				}
				else
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_WIPE_1_ENTRY_WIPED, 1, listName, ci->name);
			}
			else {

				if ((listLevel == CS_ACCESS_COFOUNDER) && ci->successor) {

					mem_free(ci->successor);
					ci->successor = NULL;
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_WIPE_X_ENTRIES_WIPED_SUCCESSOR, removed, listName, ci->name);
				}
				else
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_WIPE_X_ENTRIES_WIPED, removed, listName, ci->name);
			}

			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS)) {

				if (accessMatch)
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_XOP_WIPED), s_ChanServ, ci->name, source, listName);
				else
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_XOP_WIPED_THROUGH), s_ChanServ, ci->name, source, accessName, listName);
			}

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

			if (accessMatch)
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "%s %s WIPE -- by %s (%s@%s) [%d entr%s removed]", listName, ci->name, source, callerUser->username, callerUser->host, removed, removed == 1 ? "y" : "ies");
			else
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "%s %s WIPE -- by %s (%s@%s) through %s [%d entr%s removed]", listName, ci->name, source, callerUser->username, callerUser->host, accessName, removed, removed == 1 ? "y" : "ies");
		}
	}
}

/*********************************************************/

static void do_chan_access_LOCK(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci, CSTR mask, const BOOL lock) {

	int accessLevel, accessMatch;
	char accessName[NICKSIZE];

	TRACE_FCLT(FACILITY_CHANSERV_CHAN_ACCESS_LOCK);

	if (CONF_SET_READONLY) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_READONLY);
		return;
	}

	accessLevel = get_access(callerUser, ci, accessName, &accessMatch, NULL);

	if (accessLevel != CS_ACCESS_FOUNDER)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);

	else {

		const char *listName = get_chan_access_name(listLevel);

		if (IS_NULL(mask)) {

			/* Lock/Unlock the whole list. */

			long flag = get_chan_list_lock_flag(listLevel);

			TRACE();
			if (lock == TRUE) {

				if (FlagSet(ci->settings, flag)) {

					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_LIST_ALREADY_LOCKED, listName, ci->name);
					return;
				}

				AddFlag(ci->settings, flag);
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_LIST_LOCKED, listName, ci->name);
			}
			else {

				if (FlagUnset(ci->settings, flag)) {

					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_LIST_ALREADY_UNLOCKED, listName, ci->name);
					return;
				}

				RemoveFlag(ci->settings, flag);
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_LIST_UNLOCKED, listName, ci->name);
			}

			TRACE();
			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS)) {

				if (accessMatch) {

					if (lock)
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_LIST_LOCKED), s_ChanServ, ci->name, source, listName);
					else
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_LIST_UNLOCKED), s_ChanServ, ci->name, source, listName);
				}
				else {

					if (lock)
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_LIST_LOCKED_THROUGH), s_ChanServ, ci->name, source, accessName, listName);
					else
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_LIST_UNLOCKED_THROUGH), s_ChanServ, ci->name, source, accessName, listName);
				}
			}

			log_services(LOG_SERVICES_CHANSERV_ACCESS, "%s %s %s -- by %s (%s@%s)", listName, ci->name, lock ? "LOCK" : "UNLOCK", source, callerUser->username, callerUser->host);
		}
		else {

			/* Lock/Unlock a single entry on the list. */

			ChanAccess *anAccess;
			int idx;

			for (anAccess = ci->access, idx = 0; IS_NOT_NULL(anAccess) && (idx < ci->accesscount); ++anAccess, ++idx) {

				if ((anAccess->level == listLevel) && str_equals_nocase(anAccess->name, mask))
					break;
			}

			if (idx == ci->accesscount) {

				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_DEL_ERROR_NOT_FOUND, mask, listName, ci->name);
				return;
			}

			if (lock) {

				if (FlagSet(anAccess->flags, ACCESS_FLAG_LOCKED)) {

					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_ENTRY_ALREADY_LOCKED, anAccess->name, listName, ci->name);
					return;
				}

				AddFlag(anAccess->flags, ACCESS_FLAG_LOCKED);
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ENTRY_LOCKED, anAccess->name, listName, ci->name);
			}
			else {

				if (FlagUnset(anAccess->flags, ACCESS_FLAG_LOCKED)) {

					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ERROR_ENTRY_ALREADY_UNLOCKED, anAccess->name, listName, ci->name);
					return;
				}

				RemoveFlag(anAccess->flags, ACCESS_FLAG_LOCKED);
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_XOP_ENTRY_UNLOCKED, anAccess->name, listName, ci->name);
			}

			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS)) {

				if (accessMatch) {

					if (lock)
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_ENTRY_LOCKED), s_ChanServ, ci->name, source, anAccess->name, listName);
					else
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_ENTRY_UNLOCKED), s_ChanServ, ci->name, source, anAccess->name, listName);
				}
				else {

					if (lock)
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_ENTRY_LOCKED_THROUGH), s_ChanServ, ci->name, source, accessName, anAccess->name, listName);
					else
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_ENTRY_UNLOCKED_THROUGH), s_ChanServ, ci->name, source, accessName, anAccess->name, listName);
				}
			}

			log_services(LOG_SERVICES_CHANSERV_ACCESS, "%s %s %s %s -- by %s (%s@%s)", listName, ci->name, lock ? "LOCK" : "UNLOCK", anAccess->name, source, callerUser->username, callerUser->host);
		}
	}
}

/*********************************************************/

static void compact_chan_access_list(ChannelInfo *ci, const int removed) {

	TRACE_FCLT(FACILITY_CHANSERV_COMPACT_CHAN_ACCESS_LIST);

	if (removed == 0) {

		log_error(FACILITY_CHANSERV_COMPACT_CHAN_ACCESS_LIST, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"%s in compact_chan_access_list(): Call with removed == 0 for %s!", s_ChanServ, ci->name);
		return;
	}

	if (removed == ci->accesscount) {

		/* Tutti gli elementi della lista sono stati rimossi. */

		TRACE();
		mem_free(ci->access);
		ci->access = NULL;
		ci->accesscount = 0;
	}
	else {

		/* Solo alcuni elementi della lista sono stati cancellati, compattare la lista. */

		ChanAccess *anAccess, *nextUsed;

		int check = ci->accesscount;
		int checkIndex, nextCheckIndex;

		TRACE();
		for (anAccess = ci->access, checkIndex = 0; checkIndex < check; ++anAccess, ++checkIndex) {

			if (anAccess->status == ACCESS_ENTRY_FREE) {

				/* Entry "vuota". */

				TRACE();
				for (nextUsed = (anAccess + 1), nextCheckIndex = (checkIndex + 1); nextCheckIndex < check; ++nextUsed, ++nextCheckIndex) {

					if (nextUsed->status != ACCESS_ENTRY_FREE) {

						/* Trovata entry utilizzata. */

						TRACE();
						anAccess->level = nextUsed->level;
						anAccess->name = nextUsed->name;
						anAccess->status = nextUsed->status;
						anAccess->creator = nextUsed->creator;
						anAccess->creationTime = nextUsed->creationTime;
						anAccess->flags = nextUsed->flags;

						nextUsed->level = 0;
						nextUsed->name = NULL;
						nextUsed->status = ACCESS_ENTRY_FREE;
						nextUsed->creator = NULL;
						nextUsed->creationTime = 0;
						nextUsed->flags = 0;
						break;
					}
				}

				/* Se l'ultima ricerca di entry utilizzate non ne ha trovate, inutile continuare. */
				if (nextCheckIndex >= check)
					break;
			}
		}

		TRACE();
		ci->accesscount -= removed;

		if (ci->accesscount > 0)
			ci->access = mem_realloc(ci->access, sizeof(ChanAccess) * ci->accesscount);

		else {

			TRACE();
			mem_free(ci->access);
			ci->access = NULL;
		}
	}
}

/*********************************************************/

static void do_remove(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo *ci;
	const char *chan = strtok(NULL, " ");

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_REMOVE);

	if (IS_NULL(chan)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REMOVE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "REMOVE");
	}
	else if (IS_NULL(callerUser->ni)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_OWN_NICK_NOT_REG);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_NS, "REGISTER");
	}
	else if (!user_is_identified_to(callerUser, callerUser->ni->nick)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), NS_ERROR_MUST_IDENTIFY, callerUser->ni->nick);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_HELP_HOW_TO_IDENT, s_NS, callerUser->ni->nick);
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan)))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, chan);

	else if (FlagSet(ci->flags, CI_FORBIDDEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

	else if (str_equals_nocase(source, ci->founder))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REMOVE_ERROR_CANT_REMOVE_FOUNDER);

	else {

		ChanAccess *anAccess;
		int i, oldlevel = 0;

		TRACE_MAIN();
		for (anAccess = ci->access, i = 0; i < ci->accesscount; ++anAccess, ++i) {

			if ((anAccess->status == ACCESS_ENTRY_NICK) && str_equals_nocase(anAccess->name, source)) {

				TRACE_MAIN();
				oldlevel = anAccess->level;

				mem_free(anAccess->name);
				anAccess->name = NULL;

				mem_free(anAccess->creator);
				anAccess->creator = NULL;

				anAccess->status = ACCESS_ENTRY_FREE;
				anAccess->creationTime = 0;
				anAccess->flags = 0;

				compact_chan_access_list(ci, 1); /* e' possibile chiamarla direttamente qua xe' il for() termina al successivo break */

				TRACE_MAIN();
				if (callerUser->ni->channelcount > 0)
					--(callerUser->ni->channelcount);
				else
					log_error(FACILITY_CHANSERV_HANDLE_REMOVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
						"%s in do_remove(): Nickname record %s has a negative channelcount value", s_ChanServ, callerUser->ni->nick);

				break;
			}
		}

		if (oldlevel) {

			switch (oldlevel) {

				case CS_ACCESS_VOP:
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REMOVE_NICK_REMOVED, source, "VOP", ci->name);

					if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS))
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_REMOVE), s_ChanServ, ci->name, source, "VOP");

					log_services(LOG_SERVICES_CHANSERV_ACCESS, "VOP %s REMOVE -- by %s (%s@%s)", ci->name, source, callerUser->username, callerUser->host);
					break;

				case CS_ACCESS_HOP:
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REMOVE_NICK_REMOVED, source, "HOP", ci->name);

					if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS))
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_REMOVE), s_ChanServ, ci->name, source, "HOP");

					log_services(LOG_SERVICES_CHANSERV_ACCESS, "HOP %s REMOVE -- by %s (%s@%s)", ci->name, source, callerUser->username, callerUser->host);
					break;

				case CS_ACCESS_AOP:
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REMOVE_NICK_REMOVED, source, "AOP", ci->name);

					if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS))
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_REMOVE), s_ChanServ, ci->name, source, "AOP");

					log_services(LOG_SERVICES_CHANSERV_ACCESS, "AOP %s REMOVE -- by %s (%s@%s)", ci->name, source, callerUser->username, callerUser->host);
					break;

				case CS_ACCESS_SOP:
					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REMOVE_NICK_REMOVED, source, "SOP", ci->name);

					if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS))
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_REMOVE), s_ChanServ, ci->name, source, "SOP");

					log_services(LOG_SERVICES_CHANSERV_ACCESS, "SOP %s REMOVE -- by %s (%s@%s)", ci->name, source, callerUser->username, callerUser->host);
					break;

				case CS_ACCESS_COFOUNDER:
					if (str_equals_nocase(source, ci->successor)) {

						mem_free(ci->successor);
						ci->successor = NULL;
					}

					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REMOVE_NICK_REMOVED, source, "Co-Founder", ci->name);

					if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_ACCESS))
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_REMOVE), s_ChanServ, ci->name, source, "Co-Founder");

					log_services(LOG_SERVICES_CHANSERV_ACCESS, "CF %s REMOVE -- by %s (%s@%s)", ci->name, source, callerUser->username, callerUser->host);
					break;

				default:
					log_error(FACILITY_CHANSERV_HANDLE_REMOVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
						"%s in do_remove(): Unknown oldlevel value %d", s_ChanServ, oldlevel);
					return;
			}

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
		}
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_REMOVE_ERROR_NOT_ON_LIST, source, ci->name);
	}
}


/*********************************************************
 * ChanServ Operator command routines.                   *
 *********************************************************/

static void do_delete(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *chan = strtok(NULL, " ");
	ChannelInfo *ci;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_DELETE);

	if (IS_NULL(chan)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_DELETE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "DELETE");
		return;
	}

	TRACE_MAIN();
	if (*chan != '#') {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);
		return;
	}

	if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_CHAN_NOT_REG, chan);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS *De %s -- by %s (%s@%s) [Not Registered]", chan, source, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS *De %s -- by %s (%s@%s) through %s [Not Registered]", chan, source, callerUser->username, callerUser->host, data->operName);

		return;
	}

	TRACE_MAIN();

	if (data->operMatch) {

		LOG_SNOOP(s_OperServ, "CS De %s -- by %s (%s@%s)", ci->name, source, callerUser->username, callerUser->host);
		log_services(LOG_SERVICES_CHANSERV_GENERAL, "De %s -- by %s (%s@%s)", ci->name, source, callerUser->username, callerUser->host);

		send_globops(s_ChanServ, "\2%s\2 deleted channel \2%s\2", source, ci->name);
	}
	else {

		LOG_SNOOP(s_OperServ, "CS De %s -- by %s (%s@%s) through %s", ci->name, source, callerUser->username, callerUser->host, data->operName);
		log_services(LOG_SERVICES_CHANSERV_GENERAL, "De %s -- by %s (%s@%s) through %s", ci->name, source, callerUser->username, callerUser->host, data->operName);

		send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) deleted channel \2%s\2", source, data->operName, ci->name);
	}

	send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_DELETE_CHAN_DELETED, ci->name);

	if (CONF_SET_READONLY)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

	delchan(ci);
}

/*********************************************************/

static void do_getpass(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *chan = strtok(NULL, " ");
	ChannelInfo *ci;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_GETPASS);

	if (IS_NULL(chan)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_GETPASS_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "GETPASS");
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_CHAN_NOT_REG, chan);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS *G %s -- by %s (%s@%s) [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS *G %s -- by %s (%s@%s) through %s [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (FlagSet(ci->flags, CI_FORBIDDEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

	else if (FlagSet(ci->flags, CI_MARKCHAN) && !is_services_root(callerUser)) {

		TRACE_MAIN();
		if (data->operMatch) {
	
			LOG_SNOOP(s_OperServ, "CS *G %s -- by %s (%s@%s) [Marked]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			send_globops(s_ChanServ, "\2Warning:\2 \2%s\2 attempted to use GETPASS on MARKED channel \2%s\2", callerUser->nick, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS *G %s -- by %s (%s@%s) through %s [Marked]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			send_globops(s_ChanServ, "\2Warning:\2 \2%s\2 (through \2%s\2) attempted to use GETPASS on MARKED channel \2%s\2", callerUser->nick, data->operName, ci->name);
		}
		
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_ERROR_CHAN_MARKED, ci->name);
	}
	else {

		TRACE_MAIN();
		if (FlagSet(ci->flags, CI_MARKCHAN)) {

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "CS G %s -- by %s (%s@%s) [SRA->MARK]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "G %s -- by %s (%s@%s) [SRA->MARK - Pass: %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->founderpass);

				send_globops(s_ChanServ, "\2%s\2 used GETPASS on MARKED channel \2%s\2", callerUser->nick, ci->name);
			}
			else {

				LOG_SNOOP(s_OperServ, "CS G %s -- by %s (%s@%s) through %s [SRA->MARK]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "G %s -- by %s (%s@%s) through %s [SRA->MARK - Pass: %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName, ci->founderpass);

				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) used GETPASS on MARKED channel \2%s\2", callerUser->nick, data->operName, ci->name);
			}

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_GETPASS_SHOW_PASSWORD, ci->name, ci->founderpass);
			return;
		}

		TRACE_MAIN();

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS G %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "G %s -- by %s (%s@%s) [Pass: %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->founderpass);

			send_globops(s_ChanServ, "\2%s\2 used GETPASS on channel \2%s\2", source, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS G %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "G %s -- by %s (%s@%s) through %s [Pass: %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName, ci->founderpass);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) used GETPASS on channel \2%s\2", source, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_GETPASS_SHOW_PASSWORD, ci->name, ci->founderpass);
	}
}

/*********************************************************/

static void do_sendpass(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *chan = strtok(NULL, " ");
	ChannelInfo *ci;
	NickInfo *ni;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SENDPASS);

	if (IS_NULL(chan)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SENDPASS_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "SENDPASS");
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_CHAN_NOT_REG, chan);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS *S %s -- by %s (%s@%s) [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS *S %s -- by %s (%s@%s) through %s [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (FlagSet(ci->flags, CI_FORBIDDEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

	else if (FlagSet(ci->flags, CI_MARKCHAN)) {

		TRACE_MAIN();
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_ERROR_CHAN_MARKED, ci->name);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS *S %s -- by %s (%s@%s) [Marked]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS *S %s -- by %s (%s@%s) through %s [Marked]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (IS_NULL(ni = findnick(ci->founder)))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_NICK_NOT_REG, ci->founder);

	else if (FlagSet(ni->flags, NI_MARK)) {

		TRACE_MAIN();
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_NS_ERROR_NICK_MARKED, ni->nick);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS *S %s -- by %s (%s@%s) [Marked]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS *S %s -- by %s (%s@%s) through %s [Marked]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (FlagSet(ni->flags, NI_AUTH) || !ni->email)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SENDPASS_ERROR_NO_REGEMAIL, ni->nick);

	else {

		FILE *mailfile;

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS S %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "S %s -- by %s (%s@%s) [Pass: %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->founderpass);

			send_globops(s_ChanServ, "\2%s\2 used SENDPASS on channel \2%s\2", source, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS S %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "S %s -- by %s (%s@%s) through %s [Pass: %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName, ci->founderpass);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) used SENDPASS on channel \2%s\2", source, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_SENDPASS_PASSWORD_SENT, ci->founder, ni->email);

		if (IS_NOT_NULL(mailfile = fopen("sendpass.txt", "w"))) {

			char timebuf[64];

			fprintf(mailfile, "From: %s <%s>\n", CONF_NETWORK_NAME, CONF_RETURN_EMAIL);
			fprintf(mailfile, "To: %s\n", ni->email);

			fprintf(mailfile, lang_msg(GetNickLang(ni), CS_SENDPASS_EMAIL_SUBJECT), ci->name);

			lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, NOW);

			fprintf(mailfile, lang_msg(GetNickLang(ni), CS_SENDPASS_EMAIL_TEXT), data->operName, timebuf, ci->name, ci->founderpass);
			fprintf(mailfile, lang_msg(GetNickLang(ni), CSNS_EMAIL_TEXT_ABUSE), MAIL_ABUSE, CONF_NETWORK_NAME);
			fclose(mailfile);

			snprintf(misc_buffer, MISC_BUFFER_SIZE, "%s -f %s -t < sendpass.txt", CONF_SENDMAIL_PATH, CONF_RETURN_EMAIL);
			system(misc_buffer);

			snprintf(misc_buffer, MISC_BUFFER_SIZE, "rm -f sendpass.txt");
			system(misc_buffer);
		}
		else
			log_error(FACILITY_CHANSERV_HANDLE_SENDPASS, __LINE__, LOG_TYPE_ERROR_RTL, LOG_SEVERITY_ERROR_HALTED, "do_sendpass(): unable to create sendpass.txt");
	}
}

/*********************************************************/

static void do_freeze(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo *ci;
	char *chan;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_FREEZE);

	if (IS_NULL(chan = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_SYNTAX_ERROR, "FREEZE");
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "FREEZE");
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_CHAN_NOT_REG, chan);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS +Z* %s -- by %s (%s@%s) [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS +Z* %s -- by %s (%s@%s) through %s [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (FlagSet(ci->flags, CI_FORBIDDEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

	else if (FlagSet(ci->flags, CI_CLOSED))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_CLOSED, ci->name);

	else if (FlagSet(ci->flags, CI_SUSPENDED))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_SUSPENDED, ci->name);

	else if (FlagSet(ci->flags, CI_FROZEN)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_ERROR_CHAN_ALREADY_FLAGGED, ci->name, "FROZEN");

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS +Z* %s -- by %s (%s@%s) [Already Frozen]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS +Z* %s -- by %s (%s@%s) through %s [Already Frozen]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else {

		TRACE_MAIN();
		AddFlag(ci->flags, CI_FROZEN);

		if (ci->freeze)
			mem_free(ci->freeze);
		ci->freeze = str_duplicate(data->operName);

		user_remove_chanid(ci);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS +Z %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+Z %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_ChanServ, "\2%s\2 FROZE channel \2%s\2", callerUser->nick, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS +Z %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+Z %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) FROZE channel \2%s\2", callerUser->nick, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_CHAN_FLAGGED, ci->name, "FROZEN");

		if (CONF_SET_READONLY) 
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_unfreeze(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *chan;
	ChannelInfo *ci;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_UNFREEZE);

	if (IS_NULL(chan = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_SYNTAX_ERROR, "UNFREEZE");
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "UNFREEZE");
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_CHAN_NOT_REG, chan);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS -Z* %s -- by %s (%s@%s) [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS -Z* %s -- by %s (%s@%s) through %s [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (FlagUnset(ci->flags, CI_FROZEN)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_ERROR_CHAN_NOT_FLAGGED, ci->name, "FROZEN");

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS -Z* %s -- by %s (%s@%s) [Not Frozen]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS -Z* %s -- by %s (%s@%s) through %s [Not Frozen]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else {

		TRACE_MAIN();
		RemoveFlag(ci->flags, CI_FROZEN);

		if (ci->freeze)
			mem_free(ci->freeze);
		ci->freeze = NULL;

		/* Avoid right-away expiration */
		ci->last_used = NOW;

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS -Z %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "-Z %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_ChanServ, "\2%s\2 UNFROZE channel \2%s\2", callerUser->nick, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS -Z %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "-Z %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) UNFROZE channel \2%s\2", callerUser->nick, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_CHAN_FLAGGED, ci->name, "UNFROZEN");

		if (CONF_SET_READONLY) 
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_forbid(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo *ci;
	char *chan_name;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_FORBID);

	if (IS_NULL(chan_name = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_SYNTAX_ERROR, "FORBID");
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "FORBID");
	}
	else if (*chan_name != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan_name, chan_name);

	else if (!validate_channel(chan_name))
		send_notice_to_user(s_ChanServ, callerUser, "Channel name contains invalid characters.");

	else if (str_len(chan_name) > CHANMAX)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_MAX_LENGTH, CHANMAX);

	else if (IS_NOT_NULL(ci = cs_findchan(chan_name))) {

		if (FlagSet(ci->flags, CI_FORBIDDEN)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_ERROR_CHAN_ALREADY_FLAGGED, ci->name, "FORBIDDEN");

			if (data->operMatch)
				LOG_SNOOP(s_OperServ, "CS +F* %s -- by %s (%s@%s) [Already Forbidden]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			else
				LOG_SNOOP(s_OperServ, "CS +F* %s -- by %s (%s@%s) through %s [Already Forbidden]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
		}
		else {

			send_notice_to_user(s_ChanServ, callerUser, "Channel \2%s\2 is registered, please use \2CLOSE\2 instead.", ci->name);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "CLOSE");

			if (data->operMatch)
				LOG_SNOOP(s_OperServ, "CS +F* %s -- by %s (%s@%s) [Registered]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			else
				LOG_SNOOP(s_OperServ, "CS +F* %s -- by %s (%s@%s) through %s [Registered]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
		}
	}
	else {

		int userCount;

		ci = makechan(chan_name);

		TRACE_MAIN();
		AddFlag(ci->flags, CI_FORBIDDEN);

		if (ci->forbid)
			mem_free(ci->forbid);
		ci->forbid = str_duplicate(data->operName);

		user_remove_chanid(ci);

		userCount = masskick_channel(chan_name, CS_FORBIDDEN_KICK_REASON);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS +F %s -- by %s (%s@%s)", chan_name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+F %s -- by %s (%s@%s)", chan_name, callerUser->nick, callerUser->username, callerUser->host);

			if (userCount > 0)
				send_globops(s_ChanServ, "\2%s\2 FORBID channel \2%s\2 [Users inside: \2%d\2]", callerUser->nick, chan_name, userCount);
			else
				send_globops(s_ChanServ, "\2%s\2 FORBID channel \2%s\2", callerUser->nick, chan_name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS +F %s -- by %s (%s@%s) through %s", chan_name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+F %s -- by %s (%s@%s) through %s", chan_name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			if (userCount > 0)
				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) FORBID channel \2%s\2 [Users inside: \2%d\2]", callerUser->nick, data->operName, chan_name, userCount);
			else
				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) FORBID channel \2%s\2", callerUser->nick, data->operName, chan_name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_CHAN_FLAGGED, chan_name, "FORBIDDEN");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_unforbid(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo *ci;
	char *chan;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_UNFORBID);

	if (IS_NULL(chan = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_SYNTAX_ERROR, "UNFORBID");
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "UNFORBID");
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_CHAN_NOT_REG, chan);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS -F* %s -- by %s (%s@%s) [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS -F* %s -- by %s (%s@%s) through %s [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (FlagUnset(ci->flags, CI_FORBIDDEN)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_ERROR_CHAN_NOT_FLAGGED, ci->name, "FORBIDDEN");

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS -F* %s -- by %s (%s@%s) [Not Forbidden]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS -F* %s -- by %s (%s@%s) through %s [Not Forbidden]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else {

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS -F %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "-F %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_ChanServ, "\2%s\2 UNFORBID channel \2%s\2", source, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS -F %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "-F %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) UNFORBID channel \2%s\2", source, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_CHAN_FLAGGED, ci->name, "UNFORBIDDEN");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

		delchan(ci);
	}
}

/*********************************************************/

static void do_hold(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo *ci;
	char *chan;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_HOLD);

	if (IS_NULL(chan = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_SYNTAX_ERROR, "HOLD");
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "HOLD");
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_CHAN_NOT_REG, chan);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS +H* %s -- by %s (%s@%s) [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS +H* %s -- by %s (%s@%s) through %s [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (FlagSet(ci->flags, CI_FORBIDDEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

	else if (FlagSet(ci->flags, CI_HELDCHAN)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_ERROR_CHAN_ALREADY_FLAGGED, ci->name, "HELD");

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS +H* %s -- by %s (%s@%s) [Already Held]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS +H* %s -- by %s (%s@%s) through %s [Already Held]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else {

		TRACE_MAIN();
		AddFlag(ci->flags, CI_HELDCHAN);

		if (ci->hold)
			mem_free(ci->hold);
		ci->hold = str_duplicate(data->operName);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS +H %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+H %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_ChanServ, "\2%s\2 HELD channel \2%s\2", callerUser->nick, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS +H %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+H %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) HELD channel \2%s\2", callerUser->nick, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_CHAN_FLAGGED, ci->name, "HELD");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_unhold(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo *ci;
	char *chan;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_UNHOLD);

	if (IS_NULL(chan = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_SYNTAX_ERROR, "UNHOLD");
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "UNHOLD");
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_CHAN_NOT_REG, chan);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS -H* %s -- by %s (%s@%s) [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS -H* %s -- by %s (%s@%s) through %s [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (FlagUnset(ci->flags, CI_HELDCHAN)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_ERROR_CHAN_NOT_FLAGGED, ci->name, "HELD");

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS -H* %s -- by %s (%s@%s) [Not Held]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS -H* %s -- by %s (%s@%s) through %s [Not Held]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else {

		TRACE_MAIN();
		RemoveFlag(ci->flags, CI_HELDCHAN);

		if (ci->hold)
			mem_free(ci->hold);
		ci->hold = NULL;

		/* Avoid right-away expiration */
		ci->last_used = NOW;

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS -H %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "-H %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_ChanServ, "\2%s\2 UNHELD channel \2%s\2", callerUser->nick, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS -H %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "-H %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) UNHELD channel \2%s\2", callerUser->nick, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_CHAN_FLAGGED, ci->name, "UNHELD");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_mark(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo *ci;
	char *chan;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_MARK);

	if (IS_NULL(chan = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_SYNTAX_ERROR, "MARK");
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "MARK");
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_CHAN_NOT_REG, chan);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS +M* %s -- by %s (%s@%s) [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS +M* %s -- by %s (%s@%s) through %s [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (FlagSet(ci->flags, CI_FORBIDDEN))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

	else if (FlagSet(ci->flags, CI_MARKCHAN)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_ERROR_CHAN_ALREADY_FLAGGED, ci->name, "MARKed");

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS +M* %s -- by %s (%s@%s) [Already Marked]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS +M* %s -- by %s (%s@%s) through %s [Already Marked]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else {

		TRACE_MAIN();
		AddFlag(ci->flags, CI_MARKCHAN);

		if (ci->mark)
			mem_free(ci->mark);
		ci->mark = str_duplicate(data->operName);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS +M %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+M %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_ChanServ, "\2%s\2 MARKed channel \2%s\2", callerUser->nick, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS +M %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+M %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) MARKed channel \2%s\2", callerUser->nick, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_CHAN_FLAGGED, ci->name, "MARKed");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_unmark(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo *ci;
	char *chan;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_UNMARK);

	if (IS_NULL(chan = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_SYNTAX_ERROR, "UNMARK");
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "UNMARK");
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_CHAN_NOT_REG, chan);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS -M* %s -- by %s (%s@%s) [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS -M* %s -- by %s (%s@%s) through %s [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (FlagUnset(ci->flags, CI_MARKCHAN)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_ERROR_CHAN_NOT_FLAGGED, ci->name, "MARKed");

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS -M* %s -- by %s (%s@%s) [Not Marked]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS -M* %s -- by %s (%s@%s) through %s [Not Marked]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else {

		TRACE_MAIN();
		RemoveFlag(ci->flags, CI_MARKCHAN);

		if (ci->mark)
			mem_free(ci->mark);
		ci->mark = NULL;

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS -M %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "-M %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_ChanServ, "\2%s\2 UNMARKED channel \2%s\2", callerUser->nick, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS -M %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "-M %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) UNMARKED channel \2%s\2", callerUser->nick, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_CHAN_FLAGGED, ci->name, "UNMARKed");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_level(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char *chan = strtok(NULL, " ");
	const char *who = strtok(NULL, " ");
	ChannelInfo *ci;

	int channelLevel, canChange;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_LEVEL);

	if (IS_NULL(chan) || IS_NULL(who)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_LEVEL_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "LEVEL");
		return;
	}

	if (*chan != '#') {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);
		return;
	}

	if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_CHAN_NOT_REG, chan);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS +L* %s -- by %s (%s@%s) [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS +L* %s -- by %s (%s@%s) through %s [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		return;
	}

	if (FlagSet(ci->flags, CI_FORBIDDEN)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);
		return;
	}

	TRACE_MAIN();

	if (FlagSet(ci->flags, CI_SOPONLY)) {

		channelLevel = CI_SOPONLY;
		canChange = CheckOperAccess(data->userLevel, CMDLEVEL_SOP);
	}
	else if (FlagSet(ci->flags, CI_SAONLY)) {

		channelLevel = CI_SAONLY;
		canChange = CheckOperAccess(data->userLevel, CMDLEVEL_SA);
	}
	else if (FlagSet(ci->flags, CI_SRAONLY)) {

		channelLevel = CI_SRAONLY;
		canChange = CheckOperAccess(data->userLevel, CMDLEVEL_SRA);
	}
	else if (FlagSet(ci->flags, CI_CODERONLY)) {

		channelLevel = CI_CODERONLY;
		canChange = CheckOperAccess(data->userLevel, CMDLEVEL_CODER);
	}
	else {

		channelLevel = 0;
		canChange = 1;
	}

	TRACE_MAIN();
	if (!canChange) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_ACCESS_DENIED);
		return;
	}

	if (str_equals_nocase(who, "SOP")) {

		TRACE_MAIN();
		RemoveFlag(ci->flags, CI_SAONLY | CI_SRAONLY | CI_CODERONLY);
		AddFlag(ci->flags, CI_SOPONLY);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS +L %s -- by %s (%s@%s) [SOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+L %s -- by %s (%s@%s) [SOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_ChanServ, "\2%s\2 set LEVEL for \2%s\2 to: \2SOP\2", source, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS +L %s -- by %s (%s@%s) through %s [SOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+L %s -- by %s (%s@%s) through %s [SOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) set LEVEL for \2%s\2 to: \2SOP\2", source, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_LEVEL_LEVEL_CHANGED, ci->name, "SOP");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
	else if (str_equals_nocase(who, "SA")) {

		if (!CheckOperAccess(data->userLevel, CMDLEVEL_SA)) {

			send_notice_to_user(s_ChanServ, callerUser, "Access denied.");
			return;
		}

		TRACE_MAIN();
		RemoveFlag(ci->flags, CI_SOPONLY | CI_SRAONLY | CI_CODERONLY);
		AddFlag(ci->flags, CI_SAONLY);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS +L %s -- by %s (%s@%s) [SA]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+L %s -- by %s (%s@%s) [SA]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_ChanServ, "\2%s\2 set LEVEL for \2%s\2 to: \2SA\2", callerUser->nick, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS +L %s -- by %s (%s@%s) through %s [SA]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+L %s -- by %s (%s@%s) through %s [SA]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) set LEVEL for \2%s\2 to: \2SA\2", callerUser->nick, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_LEVEL_LEVEL_CHANGED, ci->name, "SA");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
	else if (str_equals_nocase(who, "SRA")) {

		if (!CheckOperAccess(data->userLevel, CMDLEVEL_SRA)) {

			send_notice_to_user(s_ChanServ, callerUser, "Access denied.");
			return;
		}

		TRACE_MAIN();
		RemoveFlag(ci->flags, CI_SOPONLY | CI_SAONLY | CI_CODERONLY);
		AddFlag(ci->flags, CI_SRAONLY);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS +L %s -- by %s (%s@%s) [SRA]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+L %s -- by %s (%s@%s) [SRA]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_ChanServ, "\2%s\2 set LEVEL for \2%s\2 to: \2SRA\2", source, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS +L %s -- by %s (%s@%s) through %s [SRA]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+L %s -- by %s (%s@%s) through %s [SRA]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) set LEVEL for \2%s\2 to: \2SRA\2", source, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_LEVEL_LEVEL_CHANGED, ci->name, "SRA");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
	else if (str_equals_nocase(who, "CODERS")) {

		if (!CheckOperAccess(data->userLevel, CMDLEVEL_CODER)) {

			send_notice_to_user(s_ChanServ, callerUser, "Access denied.");
			return;
		}

		TRACE_MAIN();
		RemoveFlag(ci->flags, CI_SOPONLY | CI_SAONLY | CI_SRAONLY);
		AddFlag(ci->flags, CI_CODERONLY);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS +L %s -- by %s (%s@%s) [MASTERS]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+L %s -- by %s (%s@%s) [MASTERS]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_ChanServ, "\2%s\2 set LEVEL for \2%s\2 to: \2CODERS\2", source, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS +L %s -- by %s (%s@%s) through %s [MASTERS]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+L %s -- by %s (%s@%s) through %s [MASTERS]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) set LEVEL for \2%s\2 to: \2CODERS\2", source, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_LEVEL_LEVEL_CHANGED, ci->name, "Masters");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
	else if (str_equals_nocase(who, "NONE")) {

		TRACE_MAIN();
		RemoveFlag(ci->flags, CI_SOPONLY | CI_SAONLY | CI_SRAONLY | CI_CODERONLY);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS -L %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "-L %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_ChanServ, "\2%s\2 reset LEVEL for channel \2%s\2", source, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS -L %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "-L %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) reset LEVEL for channel \2%s\2", source, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_LEVEL_LEVEL_RESET, ci->name);

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
	else {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_LEVEL_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "LEVEL");
	}
}

/*********************************************************/

static void do_wipe(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo *ci;
	const char *chan = strtok(NULL, " ");
	const char *what = strtok(NULL, " ");
	int i, deleted = 0, lev;
	NickInfo *ni;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_WIPE);

	if (IS_NULL(chan) || IS_NULL(what)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WIPE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "WIPE");
		return;
	}

	if (*chan != '#') {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);
		return;
	}

	if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_CHAN_NOT_REG, chan);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS *W %s -- by %s (%s@%s) [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS *W %s -- by %s (%s@%s) through %s [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		return;
	}

	if (FlagSet(ci->flags, CI_FORBIDDEN)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);
		return;
	}

	if ((str_equals_nocase(what, "AKICK") || str_equals_nocase(what, "ALL")) && (ci->akickcount > 0)) {

		AutoKick *anAkick = ci->akick;

		for (;;) {

			mem_free(anAkick->name);

			if (anAkick->reason)
				mem_free(anAkick->reason);

			if (anAkick->creator)
				mem_free(anAkick->creator);

			++deleted;

			if (--ci->akickcount <= 0)
				break;

			++anAkick;
		}

		mem_free(ci->akick);
		ci->akick = NULL;
	}

	if (str_equals_nocase(what, "CFOUNDER"))
		lev = CS_ACCESS_COFOUNDER;

	else if (str_equals_nocase(what, "SOP"))
		lev = CS_ACCESS_SOP;

	else if (str_equals_nocase(what, "AOP"))
		lev = CS_ACCESS_AOP;

	else if (str_equals_nocase(what, "HOP"))
		lev = CS_ACCESS_HOP;

	else if (str_equals_nocase(what, "VOP"))
		lev = CS_ACCESS_VOP;

	else if (str_equals_nocase(what, "ALL"))
		lev = 1;

	else if (str_equals_nocase(what, "AKICK"))
		lev = 0;

	else {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WIPE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "WIPE");
		return;
	}

	TRACE_MAIN();
	if (lev != 0) {

		int n = 0;
		ChanAccess *anAccess;

		for (anAccess = ci->access, i = 0; i < ci->accesscount; ++anAccess, ++i) {

			TRACE_MAIN();

			if ((lev != anAccess->level) && (lev != 1))
				continue;

			if ((anAccess->status != ACCESS_ENTRY_EXPIRED) && (ni = findnick(anAccess->name))) {

				if (ni->channelcount > 0)
					--(ni->channelcount);
				else
					log_error(FACILITY_CHANSERV_HANDLE_WIPE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED,
						"%s in do_wipe(): Nickname record %s has a negative channelcount value", s_ChanServ, ni->nick);
			}

			mem_free(anAccess->name);
			anAccess->name = NULL;

			mem_free(anAccess->creator);
			anAccess->creator = NULL;

			anAccess->status = ACCESS_ENTRY_FREE;
			anAccess->creationTime = 0;
			anAccess->flags = 0;

			++deleted;
			++n;
		}

		if (n > 0)
			compact_chan_access_list(ci, n);
	}

	switch (lev) {

		case CS_ACCESS_COFOUNDER:

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "CS W %s -- by %s (%s@%s) [CF]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "W %s -- by %s (%s@%s) [CF]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

				send_globops(s_ChanServ, "\2%s\2 wiped the CFOUNDER list for \2%s\2 [Deleted: \2%d\2]", callerUser->nick, ci->name, deleted);
			}
			else {

				LOG_SNOOP(s_OperServ, "CS W %s -- by %s (%s@%s) through %s [CF]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "W %s -- by %s (%s@%s) through %s [CF]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) wiped the CFOUNDER list for \2%s\2 [Deleted: \2%d\2]", callerUser->nick, data->operName, ci->name, deleted);
			}

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WIPE_LIST_WIPED, "Co-Founder", ci->name);

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

			return;

		case CS_ACCESS_SOP:

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "CS W %s -- by %s (%s@%s) [SOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "W %s -- by %s (%s@%s) [SOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

				send_globops(s_ChanServ, "\2%s\2 wiped the SOP list for \2%s\2 [Deleted: \2%d\2]", callerUser->nick, ci->name, deleted);
			}
			else {

				LOG_SNOOP(s_OperServ, "CS W %s -- by %s (%s@%s) through %s [SOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "W %s -- by %s (%s@%s) through %s [SOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) wiped the SOP list for \2%s\2 [Deleted: \2%d\2]", callerUser->nick, data->operName, ci->name, deleted);
			}

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WIPE_LIST_WIPED, "SOP", ci->name);

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
			return;

		case CS_ACCESS_AOP:

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "CS W %s -- by %s (%s@%s) [AOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "W %s -- by %s (%s@%s) [AOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

				send_globops(s_ChanServ, "\2%s\2 wiped the AOP list for \2%s\2 [Deleted: \2%d\2]", callerUser->nick, chan, deleted);
			}
			else {

				LOG_SNOOP(s_OperServ, "CS W %s -- by %s (%s@%s) through %s [AOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "W %s -- by %s (%s@%s) through %s [AOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) wiped the AOP list for \2%s\2 [Deleted: \2%d\2]", callerUser->nick, data->operName, chan, deleted);
			}

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WIPE_LIST_WIPED, "AOP", ci->name);

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

			return;

		case CS_ACCESS_HOP:

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "CS W %s -- by %s (%s@%s) [HOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "W %s -- by %s (%s@%s) [HOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

				send_globops(s_ChanServ, "\2%s\2 wiped the HOP list for \2%s\2 [Deleted: \2%d\2]", callerUser->nick, ci->name, deleted);
			}
			else {

				LOG_SNOOP(s_OperServ, "CS W %s -- by %s (%s@%s) through %s [HOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "W %s -- by %s (%s@%s) through %s [HOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) wiped the HOP list for \2%s\2 [Deleted: \2%d\2]", callerUser->nick, data->operName, ci->name, deleted);
			}

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WIPE_LIST_WIPED, "HOP", ci->name);

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

			return;

		case CS_ACCESS_VOP:

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "CS W %s -- by %s (%s@%s) [VOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "W %s -- by %s (%s@%s) [VOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

				send_globops(s_ChanServ, "\2%s\2 wiped the VOP list for \2%s\2 [Deleted: \2%d\2]", callerUser->nick, ci->name, deleted);
			}
			else {

				LOG_SNOOP(s_OperServ, "CS W %s -- by %s (%s@%s) through %s [VOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "W %s -- by %s (%s@%s) through %s [VOP]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) wiped the VOP list for \2%s\2 [Deleted: \2%d\2]", callerUser->nick, data->operName, ci->name, deleted);
			}

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WIPE_LIST_WIPED, "VOP", ci->name);

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

			return;

		case 1:

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "CS W %s -- by %s (%s@%s) [ALL]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "W %s -- by %s (%s@%s) [ALL]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

				send_globops(s_ChanServ, "\2%s\2 wiped ALL access lists for \2%s\2 [Deleted: \2%d\2]", callerUser->nick, ci->name, deleted);
			}
			else {

				LOG_SNOOP(s_OperServ, "CS W %s -- by %s (%s@%s) through %s [ALL]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "W %s -- by %s (%s@%s) through %s [ALL]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) wiped ALL access lists for \2%s\2 [Deleted: \2%d\2]", callerUser->nick, data->operName, ci->name, deleted);
			}

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WIPE_ALL_LISTS_WIPED, ci->name);

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

			return;

		case 0:

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "CS W %s -- by %s (%s@%s) [AKICK]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "W %s -- by %s (%s@%s) [AKICK]", ci->name, callerUser->nick, callerUser->username, callerUser->host);

				send_globops(s_ChanServ, "\2%s\2 wiped the AKICK list for \2%s\2 [Deleted: \2%d\2]", callerUser->nick, ci->name, deleted);
			}
			else {

				LOG_SNOOP(s_OperServ, "CS W %s -- by %s (%s@%s) through %s [AKICK]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "W %s -- by %s (%s@%s) through %s [AKICK]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) wiped the AKICK list for \2%s\2 [Deleted: \2%d\2]", callerUser->nick, data->operName, ci->name, deleted);
			}

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_WIPE_LIST_WIPED, "AKICK", ci->name);

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

			return;
	}
}

/*********************************************************/

static void do_authreset(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo *ci;
	const char *chan = strtok(NULL, " ");

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_AUTHRESET);

	if (IS_NULL(chan)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AUTHRESET_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "AUTHRESET");
	}
	else if (*chan != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);

	else if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_CHAN_NOT_REG, chan);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS *AR %s -- by %s (%s@%s) [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS *AR %s -- by %s (%s@%s) through %s [Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else {

		TRACE_MAIN();
		ci->auth = 0;
		ci->last_drop_request = 0;

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS AR %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "AR %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_ChanServ, "\2%s\2 removed AUTH from channel \2%s\2", callerUser->nick, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS AR %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "AR %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) removed AUTH from channel \2%s\2", callerUser->nick, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_AUTHRESET_AUTH_RESET, ci->name);

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_chanset(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *chan = strtok(NULL, " ");
	char *command = strtok(NULL, " ");
	ChannelInfo *ci;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_CHANSET);

	if (IS_NULL(chan) || IS_NULL(command)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHANSET_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "CHANSET");
		return;
	}

	if (*chan != '#') {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan, chan);
		return;
	}

	if (IS_NULL(ci = cs_findchan(chan))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_CHAN_NOT_REG, chan);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS *T %s -- by %s (%s@%s) [Chan Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS *T %s -- by %s (%s@%s) through %s [Chan Not Registered]", chan, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		return;
	}

	if (FlagSet(ci->flags, CI_FORBIDDEN)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);
		return;
	}

	if (FlagSet(ci->flags, CI_MARKCHAN)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_CS_ERROR_CHAN_MARKED, ci->name);
		return;
	}

	if (str_equals_nocase(command, "FOUNDER")) {

		char *new_founder = strtok(NULL, " ");
		NickInfo *ni;

		if (IS_NULL(new_founder)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHANSET_SYNTAX_ERROR);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "CHANSET");
		}
		else if (str_equals_nocase(ci->founder, new_founder))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SET_FOUNDER_ERROR_ALREADY_FOUNDER, new_founder, ci->name);

		else if (IS_NULL(ni = findnick(new_founder))) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_NOT_REG, new_founder);

			if (data->operMatch)
				LOG_SNOOP(s_OperServ, "CS *T %s -- by %s (%s@%s) [Nick Not Registered]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			else
				LOG_SNOOP(s_OperServ, "CS *T %s -- by %s (%s@%s) through %s [Nick Not Registered]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
		}
		else if (FlagSet(ni->flags, NI_FORBIDDEN))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), NS_ACC_NICK_FORBIDDEN, ni->nick);

		else if (FlagSet(ni->flags, NI_FROZEN))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), NS_ACC_NICK_FROZEN, ni->nick);

		else {

			size_t size;
			ChanAccess *anAccess;
			NickInfo *old;
			BOOL was_on_list = FALSE;
			int idx;
			User *newUser;
			long int randID;
			char memoText[512];


			if (IS_NOT_NULL(old = findnick(ci->founder))) {

				if (old->channelcount > 0)
					--(old->channelcount);
				else
					log_error(FACILITY_CHANSERV_HANDLE_CHANSET, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED,
						"%s in do_chanset(): Nickname record %s has a negative channelcount value", s_ChanServ, old->nick);
			}

			TRACE_MAIN();

			newUser = hash_onlineuser_find(new_founder);

			if (IS_NOT_NULL(newUser) && !user_is_identified_to(newUser, ni->nick))
				newUser = NULL;

			/* Change the password to a random one. */
			srand(randomseed());
			randID = (NOW + getrandom(1, 99999) * getrandom(1, 9999));

			/* Log this change. */
			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "CS T %s -- by %s (%s@%s) [F: %s -> %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->founder, ni->nick);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "T %s -- by %s (%s@%s) [F: %s -> %s] [P: %s -> %s-%lu]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->founder, ni->nick, ci->founderpass, CRYPT_NETNAME, randID);

				send_globops(s_ChanServ, "\2%s\2 changed the founder of \2%s\2 to \2%s\2", callerUser->nick, ci->name, ni->nick);
			}
			else {

				LOG_SNOOP(s_OperServ, "CS T %s -- by %s (%s@%s) through %s [F: %s -> %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName, ci->founder, ni->nick);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "T %s -- by %s (%s@%s) through %s [F: %s -> %s] [P: %s -> %lu]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName, ci->founder, ni->nick, ci->founderpass, CRYPT_NETNAME, randID);

				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) changed the founder of \2%s\2 to \2%s\2", callerUser->nick, data->operName, ci->name, ni->nick);
			}

			/* Now actually change the password. */
			snprintf(ci->founderpass, sizeof(ci->founderpass), "%s-%lu", CRYPT_NETNAME, randID);

			/* Update the Real Founder info. */
			mem_free(ci->real_founder);

			size = (str_len(new_founder) + str_len(ni->last_usermask) + 4) * sizeof(char);

			ci->real_founder = mem_calloc(1, size);

			snprintf(ci->real_founder, size, "%s (%s)", ni->nick, ni->last_usermask);

			/* Notify the old owner of the successful change. */
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHANSET_CHANGED_FOUNDER, ni->nick, ci->name); 

			/* Notify the new owner about the change via memo. */
			snprintf(memoText, sizeof(memoText), lang_msg(EXTRACT_LANG_ID(ni->langID), CS_SET_FOUNDER_CHANGED_NEW), CRYPT_NETNAME, ci->name, CRYPT_NETNAME, randID);
			send_memo_internal(ni, memoText);

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

			if (str_equals_nocase(new_founder, ci->successor)) {

				send_notice_to_user(s_ChanServ, callerUser, "\2%s\2 lost the successor position.", ci->successor);
				mem_free(ci->successor);
				ci->successor = NULL;
			}

			for (anAccess = ci->access, idx = 0; (idx < ci->accesscount) && IS_NOT_NULL(anAccess); ++anAccess, ++idx) {

				if ((anAccess->status == ACCESS_ENTRY_NICK) && str_equals_nocase(new_founder, anAccess->name)) {

					send_notice_to_user(s_ChanServ, callerUser, "\2%s\2 was removed from the %s list.", anAccess->name, (anAccess->level == CS_ACCESS_COFOUNDER) ? "Co-Founder" : ((anAccess->level == CS_ACCESS_SOP) ? "SOP" : ((anAccess->level == CS_ACCESS_AOP) ? "AOP" : ((anAccess->level == CS_ACCESS_HOP) ? "HOP" : "VOP"))));

					mem_free(anAccess->name);
					anAccess->name = NULL;

					mem_free(anAccess->creator);
					anAccess->creator = NULL;

					anAccess->status = ACCESS_ENTRY_FREE;
					anAccess->creationTime = 0;
					anAccess->flags = 0;

					compact_chan_access_list(ci, 1);

					was_on_list = TRUE;
					break;
				}
			}

			if (was_on_list == FALSE)
				++(ni->channelcount);

			/* Now actually change the founder. */
			str_copy_checked(ni->nick, ci->founder, NICKMAX);

			/* Remove identification to this channel from all users. */
			user_remove_chanid(ci);
		}
	}
	else if (str_equals_nocase(command, "PASSWD") || str_equals_nocase(command, "PASS") ||
		str_equals_nocase(command, "PASSWORD")) {

		char *newpass = strtok(NULL, " ");

		if (IS_NULL(newpass)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHANSET_SYNTAX_ERROR);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "CHANSET");
		}
		else if (str_len(newpass) > PASSMAX)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_MAX_LENGTH, PASSMAX);

		else if (strchr(newpass, '<') || strchr(newpass, '>'))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_BRAKES_IN_PASS, "<", ">");

		else if (string_has_ccodes(newpass))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_WITH_CCODES);

		else if (str_equals_nocase(newpass, "password"))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_PASSWORD_AS_PASS);

		else if (str_match_wild_nocase(newpass, chan+1) || (str_len(newpass) < 5) || str_equals_nocase(chan, newpass))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_INSECURE_PASSWORD);

		else if (str_equals(newpass, ci->founderpass))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_ERROR_SAME_PASSWORD);

		else {

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "CS T %s -- by %s (%s@%s) [P: %s -> %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->founderpass, newpass);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "T %s -- by %s (%s@%s) [P: %s -> %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->founderpass, newpass);

				send_globops(s_ChanServ, "\2%s\2 changed channel password for \2%s\2", callerUser->nick, ci->name);
			}
			else {

				LOG_SNOOP(s_OperServ, "CS T %s -- by %s (%s@%s) through %s [P: %s -> %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName, ci->founderpass, newpass);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "T %s -- by %s (%s@%s) through %s [P: %s -> %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName, ci->founderpass, newpass);

				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) changed channel password for \2%s\2", callerUser->nick, data->operName, ci->name);
			}

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHANSET_CHANGED_PASSWORD, ci->name, newpass);

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

			str_copy_checked(newpass, ci->founderpass, PASSMAX);

			user_remove_chanid(ci);
		}
	}
	else if (str_equals_nocase(command, "TOPIC")) {

		const char *new_topic = strtok(NULL, s_NULL);

		if (IS_NULL(new_topic)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHANSET_SYNTAX_ERROR);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "CHANSET");
		}
		else if (str_len(new_topic) > TOPICMAX)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_TOPIC_MAX_LENGTH, TOPICMAX);

		else {

			Channel *channel;

			channel = hash_channel_find(chan);

			TRACE_MAIN();

			if (IS_NOT_NULL(ci->last_topic))
				mem_free(ci->last_topic);

			TRACE_MAIN();
			if (*new_topic != c_NULL)
				ci->last_topic = str_duplicate(new_topic);
			else
				ci->last_topic = NULL;

			str_copy_checked(s_ChanServ, ci->last_topic_setter, NICKMAX);
			ci->last_topic_time = NOW;

			if (IS_NOT_NULL(channel)) {

				if (IS_NOT_NULL(channel->topic))
					mem_free(channel->topic);

				TRACE_MAIN();
				if (*new_topic != c_NULL)
					channel->topic = str_duplicate(new_topic);
				else
					channel->topic = NULL;

				str_copy_checked(s_ChanServ, channel->topic_setter, NICKMAX);
				channel->topic_time = NOW;

				send_cmd(":%s TOPIC %s %s %lu :%s", s_ChanServ, chan, s_ChanServ, channel->topic_time, new_topic);
			}

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "CS T %s -- by %s (%s@%s) [T: %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, new_topic);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "T %s -- by %s (%s@%s) [T: %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, new_topic);

				send_globops(s_ChanServ, "\2%s\2 changed the topic for \2%s\2 to: %s", callerUser->nick, ci->name, new_topic);
			}
			else {

				LOG_SNOOP(s_OperServ, "CS T %s -- by %s (%s@%s) through %s [T: %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName, new_topic);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "T %s -- by %s (%s@%s) through %s [T: %s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName, new_topic);

				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) changed the topic for \2%s\2 to: %s", callerUser->nick, data->operName, ci->name, new_topic);
			}

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHANSET_CHANGED_TOPIC, ci->name);
		}
	}
	else if (str_equals_nocase(command, "REGDATE")) {

		char		*date, *err;
		long int	newTime;
		char		timebuf[32], newtimebuf[32];
		struct		tm tm;


		if (!CheckOperAccess(data->userLevel, CMDLEVEL_CODER)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
			return;
		}

		if (IS_NULL(date = strtok(NULL, " "))) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHANSET_SYNTAX_ERROR);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "CHANSET");
			return;
		}

		newTime = strtol(date, &err, 10);

		if ((newTime <= 0) || (*err != '\0')) {

			send_notice_to_user(s_ChanServ, callerUser, "Invalid date supplied.");
			return;
		}

		tm = *localtime(&ci->time_registered);
		strftime(timebuf, sizeof(timebuf), "%d/%m/%Y %H:%M:%S", &tm);

		tm = *localtime(&newTime);
		strftime(newtimebuf, sizeof(newtimebuf), "%d/%m/%Y %H:%M:%S", &tm);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS T %s -- by %s (%s@%s) [R: %lu -> %lu]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->time_registered, newTime);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "T %s -- by %s (%s@%s) [R: %lu -> %lu]", ci->name, callerUser->nick, callerUser->username, callerUser->host, ci->time_registered, newTime);

			send_globops(s_ChanServ, "\2%s\2 changed registration date for \2%s\2 to: %s (was: %s)", callerUser->nick, ci->name, newtimebuf, timebuf);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS T %s -- by %s (%s@%s) through %s [D: %lu -> %lu]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName, ci->time_registered, newTime);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "T %s -- by %s (%s@%s) through %s [D: %lu -> %lu]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName, ci->time_registered, newTime);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) changed registration date for \2%s\2 to: %s (was: %s)", callerUser->nick, data->operName, ci->name, newtimebuf, timebuf);
		}

		ci->time_registered = newTime;
	}
	else {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHANSET_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "CHANSET");
	}
}

/*********************************************************/

static void do_show_cmode(CSTR source, User *callerUser, ServiceCommandData *data) {

	Channel *chan;
	char *chan_name;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_CMODE);

	if (!is_services_helpop(callerUser) && !user_is_ircop(callerUser)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_UNKNOWN_COMMAND, "CMODE");
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_SERVICE_COMMAND_LIST, s_CS);
	}
	else if (IS_NULL(chan_name = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CMODE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, s_CS, "CMODE");
	}
	else if (*chan_name != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan_name, chan_name);

	else if (IS_NOT_NULL(chan = hash_channel_find(chan_name))) {

		char buf[64];

		if (chan->mode == 0) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CMODE_REPLY, chan_name, "No modes set.");
			return;
		}

		if (FlagSet(chan->mode, CMODE_k)) {

			if (FlagSet(chan->mode, CMODE_l))
				snprintf(buf, sizeof(buf), "%s %s %ld", get_channel_mode(chan->mode, 0), (CheckOperAccess(data->userLevel, CMDLEVEL_SRA) ? chan->key : s_NULL), chan->limit);
			else
				snprintf(buf, sizeof(buf), "%s %s", get_channel_mode(chan->mode, 0), (CheckOperAccess(data->userLevel, CMDLEVEL_SRA) ? chan->key : s_NULL));
		}
		else {

			if (FlagSet(chan->mode, CMODE_l))
				snprintf(buf, sizeof(buf), "%s %ld", get_channel_mode(chan->mode, 0), chan->limit);
			else
				snprintf(buf, sizeof(buf), "%s", get_channel_mode(chan->mode, 0));
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CMODE_REPLY, chan_name, buf);
	}
	else
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHAN_DOES_NOT_EXIST, chan_name);
}

/*********************************************************/

static void do_ischanop(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *chan_name = strtok(NULL, " ");
	char *nick = strtok(NULL, " ");
	Channel *chan;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_ISOP);

	if (IS_NULL(chan_name) || IS_NULL(nick)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ISX_SYNTAX_ERROR, "OP");
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "ISOP");
	}
	else if (*chan_name != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan_name, chan_name);

	else if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);

	else if (str_len(chan_name) > CHANMAX)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_MAX_LENGTH, CHANMAX);

	else if (IS_NULL(chan = hash_channel_find(chan_name)))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHAN_DOES_NOT_EXIST, chan_name);

	else {

		TRACE_MAIN();
		if (user_is_chanop(nick, chan_name, chan))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ISX_REPLY, nick, " op ", chan->name);
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ISX_REPLY, nick, " NOT op ", chan->name);
	}
}

/*********************************************************/

static void do_ischanhalfop(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *chan_name, *nick;
	Channel *chan;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_ISHALFOP);

	if (IS_NULL(chan_name = strtok(NULL, " ")) || IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ISX_SYNTAX_ERROR, "HALFOP");
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "ISHALFOP");
	}
	else if (*chan_name != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan_name, chan_name);

	else if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);

	else if (str_len(chan_name) > CHANMAX)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_MAX_LENGTH, CHANMAX);

	else if (IS_NULL(chan = hash_channel_find(chan_name)))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHAN_DOES_NOT_EXIST, chan_name);

	else {

		TRACE_MAIN();
		if (user_is_chanhalfop(nick, chan_name, chan))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ISX_REPLY, nick, " halfop ", chan->name);
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ISX_REPLY, nick, " NOT halfop ", chan->name);
	}
}

/*********************************************************/

static void do_ischanvoice(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *chan_name, *nick;
	Channel *chan;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_ISVOICE);

	if (IS_NULL(chan_name = strtok(NULL, " ")) || IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ISX_SYNTAX_ERROR, "VOICE");
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "ISVOICE");
	}
	else if (*chan_name != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan_name, chan_name);

	else if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);

	else if (str_len(chan_name) > CHANMAX)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_MAX_LENGTH, CHANMAX);

	else if (IS_NULL(chan = hash_channel_find(chan_name)))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CHAN_DOES_NOT_EXIST, chan_name);

	else {

		TRACE_MAIN();
		if (user_is_chanvoice(nick, chan_name, chan))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ISX_REPLY, nick, " voice ", chan->name);
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ISX_REPLY, nick, " NOT voice ", chan->name);
	}
}

/*********************************************************/

static void do_isonchan(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *chan_name = strtok(NULL, " ");
	char *nick = strtok(NULL, " ");

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_ISON);

	if (IS_NULL(chan_name) || IS_NULL(nick)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ISX_SYNTAX_ERROR, "ON");
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "ISON");
	}
	else if (*chan_name != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan_name, chan_name);

	else if (str_len(nick) > NICKMAX)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_MAX_LENGTH, NICKMAX);

	else if (str_len(chan_name) > CHANMAX)
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_MAX_LENGTH, CHANMAX);

	else {

		User *user;

		if (IS_NOT_NULL(user = hash_onlineuser_find(nick)) && user_isin_chan(user, chan_name))
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ISX_REPLY, nick, " on ", chan_name);
		else
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ISX_REPLY, nick, " NOT on ", chan_name);
	}
}

/*********************************************************/

typedef BOOL (*cs_listreg_mach_proc)(const ChannelInfo *ci, CSTR pattern);

static BOOL cs_listreg_match_name(const ChannelInfo *ci, CSTR pattern) {

	str_copy_checked(ci->name, misc_buffer, MISC_BUFFER_SIZE);
	str_tolower(misc_buffer);

	return str_match_wild(pattern, misc_buffer);
}

static BOOL cs_listreg_match_desc(const ChannelInfo *ci, CSTR pattern) {

	if (IS_NOT_NULL(ci->desc)) {

		str_copy_checked(ci->desc, misc_buffer, MISC_BUFFER_SIZE);
		str_tolower(misc_buffer);

		return str_match_wild(pattern, misc_buffer);

	} else
		return FALSE;
}

static BOOL cs_listreg_match_topic(const ChannelInfo *ci, CSTR pattern) {

	if (IS_NOT_NULL(ci->last_topic)) {

		str_copy_checked(ci->last_topic, misc_buffer, MISC_BUFFER_SIZE);
		str_tolower(misc_buffer);

		return str_match_wild(pattern, misc_buffer);

	} else
		return FALSE;
}

static BOOL cs_listreg_match_url(const ChannelInfo *ci, CSTR pattern) {

	if (IS_NOT_NULL(ci->url)) {

		str_copy_checked(ci->url, misc_buffer, MISC_BUFFER_SIZE);
		str_tolower(misc_buffer);

		return str_match_wild(pattern, misc_buffer);

	} else
		return FALSE;
}

static BOOL cs_listreg_match_empty_url(const ChannelInfo *ci, CSTR pattern) {

	return IS_NULL(ci->url);
}

static BOOL cs_listreg_match_is_in_drop(const ChannelInfo *ci, CSTR pattern) {

	return (ci->auth != 0);
}

static BOOL cs_listreg_match_regby(const ChannelInfo *ci, CSTR pattern) {

	if (IS_NOT_NULL(ci->real_founder)) {

		str_copy_checked(ci->real_founder, misc_buffer, MISC_BUFFER_SIZE);
		str_tolower(misc_buffer);

		return str_match_wild(pattern, misc_buffer);
	}

	return FALSE;
}

static BOOL cs_listreg_match_is_held(const ChannelInfo *ci, CSTR pattern) {

	return FlagSet(ci->flags, CI_HELDCHAN);
}

static BOOL cs_listreg_match_is_marked(const ChannelInfo *ci, CSTR pattern) {

	return FlagSet(ci->flags, CI_MARKCHAN);
}

static BOOL cs_listreg_match_is_forbidded(const ChannelInfo *ci, CSTR pattern) {

	return FlagSet(ci->flags, CI_FORBIDDEN);
}

static BOOL cs_listreg_match_is_frozen(const ChannelInfo *ci, CSTR pattern) {

	return FlagSet(ci->flags, CI_FROZEN);
}

static BOOL cs_listreg_match_is_closed(const ChannelInfo *ci, CSTR pattern) {

	return FlagSet(ci->flags, CI_CLOSED);
}


/*
CS LISTREG type pattern page_number

TYPE:

NAME / N : per nome
DESC / D : per descrizione
TOPIC / T : per topic
URL / U : per URL
NOURL / NU : canali senza URL
REGBY / R : registrato da
DROP / DR : con richiesta di drop
HOLD / H : canali con il flag HELD attivo
MARK / K : canali con il flag MARK attivo
FORBID / F : canali con il flag FORBID attivo
FREEZE / Z : canali con il flag FREEZE attivo
CLOSED / C : canali chiusi

*/

static void do_listreg(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo				*ci;
	cs_listreg_mach_proc	compare;
	char					*type, *search, *page;
	int						i;
	unsigned long int		start_line, end_line, line;


	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_LISTREG);

	if (IS_NULL(type = strtok(NULL, " ")) || IS_NULL(search = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_LISTREG_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "LISTREG");
		return;
	}

	TRACE_MAIN();
	if (str_equals_nocase(type, "NAME") || str_equals_nocase(type, "N")) {

		compare = cs_listreg_match_name;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by Name: ", search);
	}
	else if (str_equals_nocase(type, "DESC") || str_equals_nocase(type, "D")) {

		compare = cs_listreg_match_desc;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by Description: ", search);
	}
	else if (str_equals_nocase(type, "TOPIC") || str_equals_nocase(type, "T")) {

		compare = cs_listreg_match_topic;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by Topic: ", search);
	}
	else if (str_equals_nocase(type, "URL") || str_equals_nocase(type, "U")) {

		compare = cs_listreg_match_url;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by URL: ", search);
	}
	else if (str_equals_nocase(type, "NOURL") || str_equals_nocase(type, "NU")) {

		compare = cs_listreg_match_empty_url;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by Empty-URL: ", search);
	}
	else if (str_equals_nocase(type, "REGBY") || str_equals_nocase(type, "R")) {

		compare = cs_listreg_match_regby;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by Real Founder: ", search);
	}
	else if (str_equals_nocase(type, "DROP") || str_equals_nocase(type, "DR")) {

		compare = cs_listreg_match_is_in_drop;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by DROP flag:", s_NULL);
	}
	else if (str_equals_nocase(type, "HOLD") || str_equals_nocase(type, "H")) {

		compare = cs_listreg_match_is_held;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by HELD flag: ", s_NULL);
	}
	else if (str_equals_nocase(type, "MARK") || str_equals_nocase(type, "K")) {

		compare = cs_listreg_match_is_marked;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by MARK flag: ", s_NULL);
	}
	else if (str_equals_nocase(type, "FORBID") || str_equals_nocase(type, "F")) {

		compare = cs_listreg_match_is_forbidded;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by FORBID flag: ", s_NULL);
	}
	else if (str_equals_nocase(type, "FREEZE") || str_equals_nocase(type, "Z")) {

		compare = cs_listreg_match_is_frozen;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by FREEZE flag: ", s_NULL);
	}
	else if (str_equals_nocase(type, "CLOSED") || str_equals_nocase(type, "C")) {

		compare = cs_listreg_match_is_closed;
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CSNS_LISTREG_LIST_HEADER, "by CLOSED flag: ", s_NULL);
	}
	else {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_LISTREG_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "LISTREG");
		return;
	}

	TRACE_MAIN();

	if (IS_NOT_NULL(page = strtok(NULL, s_SPACE))) {

		unsigned long int page_number = strtoul(page, NULL, 10);

		if (page_number == 0) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_LISTREG_SYNTAX_ERROR);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "LISTREG");
			return;
		}

		start_line = (page_number - 1) * 50;
	}
	else
		start_line = 0;

	end_line = start_line + 50;

	str_tolower(search);

	// ricerca

	for (line = i = 0; i < 256; ++i) {

		for (ci = chanlists[i]; IS_NOT_NULL(ci); ci = ci->next) {

			if (compare(ci, search)) {

				TRACE_MAIN();
				++line;

				if (line < start_line)
					continue;

				if (FlagSet(ci->flags, CI_FORBIDDEN))
					send_notice_to_user(s_ChanServ, callerUser, "%d) \2%s\2 [Forbidden by: %s]", line, ci->name, ci->forbid);
				else
					send_notice_to_user(s_ChanServ, callerUser, "%d) \2%s\2 [Founder: %s]", line, ci->name, ci->founder);

				if (line >= end_line) {

					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), END_OF_LIST);
					return;
				}
			}
		}
	}

	send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), END_OF_LIST);
}

/*********************************************************/

static void do_suspend(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *cmd = strtok(NULL, " ");

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_SUSPEND);

	if (IS_NULL(cmd)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SUSPEND_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "SUSPEND");
	}
	else if (str_equals_nocase(cmd, "LIST")) {

		ChannelSuspendData *csd = ChannelSuspendList;
		int x = 0, temp_time;

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SUSPEND_LIST_HEADER);
		TRACE_MAIN();

		while (IS_NOT_NULL(csd)) {

			++x;
			temp_time = csd->expires - NOW;

			if (temp_time > 0)
				send_notice_to_user(s_ChanServ, callerUser, "%d) \2%s\2 (Added by \2%s\2) [Expires in %d minute%s, %d second%s]", x, csd->name, csd->who, temp_time / ONE_MINUTE, temp_time / ONE_MINUTE == 1 ? "" : "s", temp_time % ONE_MINUTE, temp_time % ONE_MINUTE == 1 ? "" : "s");
			else
				send_notice_to_user(s_ChanServ, callerUser, "%d) \2%s\2 (Added by \2%s\2) [Expired]", x, csd->name, csd->who);

			csd = csd->next;
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), END_OF_LIST);
	}
	else if (!CheckOperAccess(data->userLevel, CMDLEVEL_SOP))
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_ACCESS_DENIED);

	else if (str_equals_nocase(cmd, "DEL")) {

		char *chan_name = strtok(NULL, " ");
		ChannelSuspendData *csd;

		if (IS_NULL(chan_name)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SUSPEND_DEL_SYNTAX_ERROR);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "SUSPEND");
			return;
		}

		if (*chan_name != '#') {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan_name, chan_name);
			return;
		}

		if (IS_NOT_NULL(csd = find_suspend(chan_name))) {

			if (data->operMatch) {

				LOG_SNOOP(s_OperServ, "CS -S %s -- by %s (%s@%s)", csd->name, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "-S %s -- by %s (%s@%s)", csd->name, callerUser->nick, callerUser->username, callerUser->host);

				send_globops(s_ChanServ, "\2%s\2 UNSUSPENDED channel \2%s\2", source, csd->name);
			}
			else {

				LOG_SNOOP(s_OperServ, "CS -S %s -- by %s (%s@%s) through %s", csd->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "-S %s -- by %s (%s@%s) through %s", csd->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) UNSUSPENDED channel \2%s\2", source, data->operName, csd->name);
			}

			send_notice_to_user(s_ChanServ, callerUser, "Channel \2%s\2 is no longer suspended.", csd->name);

			if (CONF_SET_READONLY)
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);

			del_suspend(chan_name);
			return;
		}
		else {

			send_notice_to_user(s_ChanServ, callerUser, "Channel \2%s\2 is not suspended.", chan_name);

			if (data->operMatch)
				LOG_SNOOP(s_OperServ, "CS -S* %s -- by %s (%s@%s) [Not Suspended]", chan_name, callerUser->nick, callerUser->username, callerUser->host);
			else
				LOG_SNOOP(s_OperServ, "CS -S* %s -- by %s (%s@%s) through %s [Not Suspended]", chan_name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
		}
	}
	else if (str_equals_nocase(cmd, "ADD")) {

		ChannelSuspendData	*csd;
		char				*chan_name, *expiry;
		long int			expireTime;
		int					userCount;


		if (IS_NULL(chan_name = strtok(NULL, " ")) || IS_NULL(expiry = strtok(NULL, " "))) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SUSPEND_ADD_SYNTAX_ERROR);
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "SUSPEND");
			return;
		}

		if (*chan_name != '#') {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan_name, chan_name);
			return;
		}

		if (!validate_channel(chan_name)) {

			send_notice_to_user(s_ChanServ, callerUser, "Channel name contains invalid characters.");
			return;
		}

		if (str_len(chan_name) > CHANMAX) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_CHAN_MAX_LENGTH, CHANMAX);
			return;
		}

		expireTime = convert_amount(expiry);

		if (expireTime == 0) {

			send_notice_to_user(s_ChanServ, callerUser, "To suspend permanently a channel please use the \2CLOSE\2 command.");
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "CLOSE");
			return;
		}
		else if (expireTime == -1) {

			send_notice_to_user(s_ChanServ, callerUser, "Invalid expiry time supplied.");
			return;
		}
		else if (expireTime > ONE_WEEK) {

			send_notice_to_user(s_ChanServ, callerUser, "Il limite di sospensione per un canale e' di 7 giorni (%d minuti).", 7 * 24 * 60);
			return;
		}

		if (IS_NULL(csd = find_suspend(chan_name)))
			csd = add_suspend(chan_name);

		csd->expires = (NOW + expireTime);
		str_copy_checked(data->operName, csd->who, NICKMAX);

		expiry = convert_time(misc_buffer, MISC_BUFFER_SIZE, expireTime, LANG_DEFAULT);

		userCount = masskick_channel(chan_name, CS_SUSPENDED_KICK_REASON);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS +S %s -- by %s (%s@%s) [Time: %s]", chan_name, callerUser->nick, callerUser->username, callerUser->host, expiry);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+S %s -- by %s (%s@%s) [Time: %s]", chan_name, callerUser->nick, callerUser->username, callerUser->host, expiry);

			if (userCount > 0)
				send_globops(s_ChanServ, "\2%s\2 SUSPENDED channel \2%s\2 for %s [Users inside: \2%d\2]", source, chan_name, expiry, userCount);
			else
				send_globops(s_ChanServ, "\2%s\2 SUSPENDED channel \2%s\2 for %s", source, chan_name, expiry);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS +S %s -- by %s (%s@%s) through %s [Time: %s]", chan_name, callerUser->nick, callerUser->username, callerUser->host, data->operName, expiry);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+S %s -- by %s (%s@%s) through %s [Time: %s]", chan_name, callerUser->nick, callerUser->username, callerUser->host, data->operName, expiry);

			if (userCount > 0)
				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) SUSPENDED channel \2%s\2 for %s [Users inside: \2%d\2]", source, data->operName, chan_name, expiry, userCount);
			else
				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) SUSPENDED channel \2%s\2 for %s", source, data->operName, chan_name, expiry);
		}

		send_notice_to_user(s_ChanServ, callerUser, "Channel \2%s\2 has been suspended for %s.", chan_name, expiry);

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
	else {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_SUSPEND_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "SUSPEND");
	}
}

/*********************************************************/

static void do_close(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo *ci;
	char *chan_name;

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_CLOSE);

	if (IS_NULL(chan_name = strtok(NULL, " "))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CLOSE_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "CLOSE");
	}
	else if (*chan_name != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan_name, chan_name);

	else if (IS_NULL(ci = cs_findchan(chan_name))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CLOSE_ERROR_CHAN_NOT_REG);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "FORBID");
	}
	else if (FlagSet(ci->flags, CI_FORBIDDEN)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_ERROR_CHAN_ALREADY_FLAGGED, ci->name, "forbidden");

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS +C* %s -- by %s (%s@%s) [Already Forbidden]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS +C* %s -- by %s (%s@%s) through %s [Already Forbidden]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (FlagSet(ci->flags, CI_CLOSED)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_ERROR_CHAN_ALREADY_FLAGGED, ci->name, "closed");

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS +C* %s -- by %s (%s@%s) [Already Closed]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS +C* %s -- by %s (%s@%s) through %s [Already Closed]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else {

		int userCount;

		TRACE_MAIN();

		user_remove_chanid(ci);
		AddFlag(ci->flags, CI_CLOSED);

		userCount = masskick_channel(chan_name, CS_CLOSED_KICK_REASON);

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS +C %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+C %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);

			if (userCount > 0)
				send_globops(s_ChanServ, "\2%s\2 CLOSED channel \2%s\2 [Users inside: \2%d\2]", source, ci->name, userCount);
			else
				send_globops(s_ChanServ, "\2%s\2 CLOSED channel \2%s\2", source, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS +C %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "+C %s -- by %s (%s@%s) through %s", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			if (userCount > 0)
				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) CLOSED channel \2%s\2 [Users inside: \2%d\2]", source, data->operName, ci->name, userCount);
			else
				send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) CLOSED channel \2%s\2", source, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_CHAN_FLAGGED, ci->name, "CLOSED");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

static void do_open(CSTR source, User *callerUser, ServiceCommandData *data) {

	ChannelInfo *ci;
	const char *channel = strtok(NULL, " ");

	TRACE_MAIN_FCLT(FACILITY_CHANSERV_HANDLE_OPEN);

	if (IS_NULL(channel)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_OPEN_SYNTAX_ERROR);
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_GET_MORE_INFO_ON_COMMAND, s_CS, "OPEN");
	}
	else if (*channel != '#')
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, channel, channel);

	else if (IS_NULL(ci = cs_findchan(channel))) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), OPER_ERROR_CHAN_NOT_REG, channel);

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS -C* %s -- by %s (%s@%s) [Not Registered]", channel, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS -C* %s -- by %s (%s@%s) through %s [Not Registered]", channel, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else if (FlagUnset(ci->flags, CI_CLOSED)) {

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_ERROR_CHAN_NOT_FLAGGED, ci->name, "CLOSED");

		if (data->operMatch)
			LOG_SNOOP(s_OperServ, "CS -C* %s -- by %s (%s@%s) [Not Closed]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(s_OperServ, "CS -C* %s -- by %s (%s@%s) through %s [Not Closed]", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
	}
	else {

		TRACE_MAIN();
		RemoveFlag(ci->flags, CI_CLOSED);
		RemoveFlag(ci->flags, CI_NOENTRY);

		if (FlagSet(ci->flags, CI_TIMEOUT)) {

			Channel *chan;

			if (!timeout_remove(toChanServ, TOTYPE_ANYSUBTYPE, (unsigned long) ci))
				log_error(FACILITY_CHANSERV_HANDLE_OPEN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING, 
					"do_open(): Timeout not found for %s (ChanServ/Any)", ci->name);

			if (IS_NOT_NULL(chan = hash_channel_find(channel))) {

				send_cmd(":%s MODE %s -b *!*@*", s_ChanServ, ci->name);
				chan_remove_ban(chan, "*!*@*");

				send_PART(s_ChanServ, ci->name);
			}

			RemoveFlag(ci->flags, CI_TIMEOUT);
		}

		if (data->operMatch) {

			LOG_SNOOP(s_OperServ, "CS -C %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "-C %s -- by %s (%s@%s)", ci->name, callerUser->nick, callerUser->username, callerUser->host);

			send_globops(s_ChanServ, "\2%s\2 has re-opened channel \2%s\2", callerUser->nick, ci->name);
		}
		else {

			LOG_SNOOP(s_OperServ, "CS -C %s -- by %s (%s@%s) through %s ", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			log_services(LOG_SERVICES_CHANSERV_GENERAL, "-C %s -- by %s (%s@%s) through %s ", ci->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);

			send_globops(s_ChanServ, "\2%s\2 (through \2%s\2) has re-opened channel \2%s\2", callerUser->nick, data->operName, ci->name);
		}

		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_FLAG_CHAN_FLAGGED, ci->name, "REOPENED");

		if (CONF_SET_READONLY)
			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), WARNING_READONLY);
	}
}

/*********************************************************/

void chanserv_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	STR		cmd = strtok(request, s_SPACE);
	STR		value = strtok(NULL, s_SPACE);
	BOOL	needSyntax = FALSE;
	ChannelInfo		*ci;

	if (IS_NOT_NULL(cmd)) {

		if (str_equals_nocase(cmd, "HELP")) {

			/* HELP ! */
		}
		else if (str_equals_nocase(cmd, "CHAN")) {

			if (IS_NULL(value))
				needSyntax = TRUE;

			else {

				ci = cs_findchan(value);

				if (IS_NULL(ci))
					send_notice_to_user(sourceNick, callerUser, "DUMP: Channel \2%s\2 not found.", value);

				else {

					send_notice_to_user(sourceNick, callerUser, "DUMP: channel \2%s\2", value);

					send_notice_to_user(sourceNick, callerUser, "Address 0x%08X, size %d B",						(unsigned long)ci, sizeof(ChannelInfo));
					send_notice_to_user(sourceNick, callerUser, "Name: %s",											ci->name);
					send_notice_to_user(sourceNick, callerUser, "Founder: %s",										ci->founder);
					send_notice_to_user(sourceNick, callerUser, "Password: %s",										ci->founderpass);
					send_notice_to_user(sourceNick, callerUser, "Description: 0x%08X \2[\2%s\2]\2",					(unsigned long)ci->desc, str_get_valid_display_value(ci->desc));
					send_notice_to_user(sourceNick, callerUser, "Registration C-time: %d",							ci->time_registered);
					send_notice_to_user(sourceNick, callerUser, "Last used C-time: %d",								ci->last_used);
					send_notice_to_user(sourceNick, callerUser, "Access count / list: %d / 0x%08X",					ci->accesscount, (unsigned long)ci->access);
					send_notice_to_user(sourceNick, callerUser, "AKICK count / list: %d / 0x%08X",					ci->akickcount, (unsigned long)ci->akick);
					send_notice_to_user(sourceNick, callerUser, "ModeLock ON/OFF: %d/%d (%s)",						ci->mlock_on, ci->mlock_off, get_channel_mode(ci->mlock_on, ci->mlock_off));
					send_notice_to_user(sourceNick, callerUser, "MLOCK +l/+k values: %d / 0x%08X \2[\2%s\2]\2",		ci->mlock_limit, (unsigned long)ci->mlock_key, str_get_valid_display_value(ci->mlock_key));
					send_notice_to_user(sourceNick, callerUser, "Last topic: 0x%08X \2[\2%s\2]\2",					(unsigned long)ci->last_topic, str_get_valid_display_value(ci->last_topic));
					send_notice_to_user(sourceNick, callerUser, "Last topic setter: %s",							ci->last_topic_setter);
					send_notice_to_user(sourceNick, callerUser, "Last topic C-time: %d",							ci->last_topic_time);
					send_notice_to_user(sourceNick, callerUser, "Flags: %d",										ci->flags);
					send_notice_to_user(sourceNick, callerUser, "Successor: 0x%08X \2[\2%s\2]\2",					(unsigned long)ci->successor, str_get_valid_display_value(ci->successor));
					send_notice_to_user(sourceNick, callerUser, "URL: 0x%08X \2[\2%s\2]\2",							(unsigned long)ci->url, str_get_valid_display_value(ci->url));
					send_notice_to_user(sourceNick, callerUser, "e-mail: 0x%08X \2[\2%s\2]\2",						(unsigned long)ci->email, str_get_valid_display_value(ci->email));
					send_notice_to_user(sourceNick, callerUser, "Welcome notice: 0x%08X \2[\2%s\2]\2",				(unsigned long)ci->welcome, str_get_valid_display_value(ci->welcome));
					send_notice_to_user(sourceNick, callerUser, "Hold by: 0x%08X \2[\2%s\2]\2",						(unsigned long)ci->hold, str_get_valid_display_value(ci->hold));
					send_notice_to_user(sourceNick, callerUser, "Marked by: 0x%08X \2[\2%s\2]\2",					(unsigned long)ci->mark, str_get_valid_display_value(ci->mark));
					send_notice_to_user(sourceNick, callerUser, "Frozen by: 0x%08X \2[\2%s\2]\2",					(unsigned long)ci->freeze, str_get_valid_display_value(ci->freeze));
					send_notice_to_user(sourceNick, callerUser, "Forbidden by: 0x%08X \2[\2%s\2]\2",				(unsigned long)ci->forbid, str_get_valid_display_value(ci->forbid));
					send_notice_to_user(sourceNick, callerUser, "Auth code: %d",									ci->auth);
					send_notice_to_user(sourceNick, callerUser, "Settings: %d",										ci->settings);
					send_notice_to_user(sourceNick, callerUser, "Real founder: 0x%08X \2[\2%s\2]\2",				(unsigned long)ci->real_founder, str_get_valid_display_value(ci->real_founder));
					send_notice_to_user(sourceNick, callerUser, "Ban Type: %d",										(int)ci->banType);
					send_notice_to_user(sourceNick, callerUser, "reserved[2]: %d %d",								ci->reserved[0], ci->reserved[1]);
					send_notice_to_user(sourceNick, callerUser, "Next / previous record: 0x%08X / 0x%08X",			(unsigned long)ci->next, (unsigned long)ci->prev);

					LOG_DEBUG_SNOOP("Command: DUMP CHANSERV CHAN %s -- by %s (%s@%s)", value, callerUser->nick, callerUser->username, callerUser->host);
				}
			}
		}
		else if (str_equals_nocase(cmd, "ACCESS")) {

			ci = cs_findchan(value);

			if (IS_NULL(ci))
				send_notice_to_user(sourceNick, callerUser, "DUMP: Channel \2%s\2 not found.", value);

			else {

				ChanAccess	*anAccess;
				int			i;
				STR			level_name, access_type;

				send_notice_to_user(sourceNick, callerUser, "DUMP: access list of \2%s\2", value);

				for (anAccess = ci->access, i = 0; (i < ci->accesscount) && IS_NOT_NULL(anAccess); ++anAccess, ++i) {

					level_name = (STR) get_short_chan_access_name(anAccess->level);

					switch (anAccess->status) {

						case ACCESS_ENTRY_FREE:
							access_type = "FREE";
							break;

						case ACCESS_ENTRY_NICK:
							access_type = "NICK";
							break;

						case ACCESS_ENTRY_MASK:
							access_type = "MASK";
							break;

						case ACCESS_ENTRY_EXPIRED:
							access_type = "EXPIRED";
							break;

						default:
							access_type = "UNKNOWN";
							break;
					}

					send_notice_to_user(sourceNick, callerUser, "%d) Address 0x%08X, size %d B", i+1,	(unsigned long)anAccess, sizeof(ChanAccess));
					send_notice_to_user(sourceNick, callerUser, "Name: 0x%08X \2[\2%s\2]\2",			(unsigned long)anAccess->name, str_get_valid_display_value(anAccess->name));
					send_notice_to_user(sourceNick, callerUser, "Creator: 0x%08X \2[\2%s\2]\2",			(unsigned long)anAccess->creator, str_get_valid_display_value(anAccess->creator));
					send_notice_to_user(sourceNick, callerUser, "Time Created C-time: %d",				anAccess->creationTime);
					send_notice_to_user(sourceNick, callerUser, "Level: %d \2[\2%s\2]\2",				anAccess->level, level_name);
					send_notice_to_user(sourceNick, callerUser, "Status: %d \2[\2%s\2]\2",				anAccess->status, access_type);
					send_notice_to_user(sourceNick, callerUser, "Flags: %d",							anAccess->flags);
				}

				LOG_DEBUG_SNOOP("Command: DUMP CHANSERV CHAN %s -- by %s (%s@%s) [ACCESS]", value, callerUser->nick, callerUser->username, callerUser->host);
			}
		}
		else if (str_equals_nocase(cmd, "AKICK")) {

			ci = cs_findchan(value);

			if (IS_NULL(ci))
				send_notice_to_user(sourceNick, callerUser, "DUMP: Channel \2%s\2 not found.", value);

			else {

				AutoKick	*anAkick;
				int			i;

				send_notice_to_user(sourceNick, callerUser, "DUMP: AKick list for \2%s\2", value);

				for (anAkick = ci->akick, i = 0; i < ci->akickcount; ++anAkick, ++i) {

					send_notice_to_user(sourceNick, callerUser, "%d) Address 0x%08X, size %d B", i+1,	(unsigned long)anAkick, sizeof(AutoKick));
					send_notice_to_user(sourceNick, callerUser, "Name: 0x%08X \2[\2%s\2]\2",			(unsigned long)anAkick->name, str_get_valid_display_value(anAkick->name));
					send_notice_to_user(sourceNick, callerUser, "Creator: 0x%08X \2[\2%s\2]\2",			(unsigned long)anAkick->creator, str_get_valid_display_value(anAkick->creator));
					send_notice_to_user(sourceNick, callerUser, "Reason: 0x%08X \2[\2%s\2]\2",			(unsigned long)anAkick->reason, str_get_valid_display_value(anAkick->reason));
					send_notice_to_user(sourceNick, callerUser, "Time Created C-time: %d",				anAkick->creationTime);
					send_notice_to_user(sourceNick, callerUser, "banType / isNick: %d/%d",				anAkick->banType, anAkick->isNick);
					send_notice_to_user(sourceNick, callerUser, "Flags: %d",							anAkick->flags);
				}

				LOG_DEBUG_SNOOP("Command: DUMP CHANSERV CHAN %s -- by %s (%s@%s) [AKICK]", value, callerUser->nick, callerUser->username, callerUser->host);
			}

		#ifdef FIX_USE_MPOOL
		} else if (str_equals_nocase(cmd, "POOL")) {

		} else if (str_equals_nocase(cmd, "POOLSTAT")) {

			MemoryPoolStats pstats;

			mempool_stats(chandb_mempool, &pstats);
			send_notice_to_user(sourceNick, callerUser, "DUMP: ChanServ memory pool - Address 0x%08X, ID: %d",	(unsigned long)chandb_mempool, pstats.id);
			send_notice_to_user(sourceNick, callerUser, "Memory allocated / free: %d B / %d B",				pstats.memory_allocated, pstats.memory_free);
			send_notice_to_user(sourceNick, callerUser, "Items allocated / free: %d / %d",					pstats.items_allocated, pstats.items_free);
			send_notice_to_user(sourceNick, callerUser, "Items per block / block count: %d / %d",			pstats.items_per_block, pstats.block_count);
			//send_notice_to_user(sourceNick, callerUser, "Avarage use: %.2f%%",								pstats.block_avg_usage);

		#endif

		} else
			needSyntax = TRUE;
	}
	else
		needSyntax = TRUE;

	if (needSyntax) {

		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 CHANSERV CHAN name");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 CHANSERV ACCESS name");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 CHANSERV AKICK name");
		#ifdef FIX_USE_MPOOL
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 CHANSERV POOLSTAT");
		#endif
	}
}

/*********************************************************/

unsigned long chanserv_mem_report(CSTR sourceNick, const User *callerUser) {

	ChannelInfo			*ci;
	unsigned long		count = 0, mem = 0;
	int					i, j;

	TRACE_FCLT(FACILITY_CHANSERV_GET_STATS);

	send_notice_to_user(sourceNick, callerUser, "\2%s\2:", s_ChanServ);

	for (i = 0; i < 256; ++i) {

		for (ci = chanlists[i]; ci; ci = ci->next) {

			TRACE();
			++count;
			mem += sizeof(*ci);

			if (ci->desc)
				mem += str_len(ci->desc) + 1;

			mem += ci->accesscount * sizeof(ChanAccess);
			mem += ci->akickcount * sizeof(AutoKick);

			TRACE();
			for (j = 0; j < ci->akickcount; ++j) {

				if (ci->akick[j].name)
					mem += str_len(ci->akick[j].name) + 1;

				if (ci->akick[j].reason)
					mem += str_len(ci->akick[j].reason) + 1;

				if (ci->akick[j].creator)
					mem += str_len(ci->akick[j].creator) + 1;
			}

			TRACE();
			if (ci->mlock_key)
				mem += str_len(ci->mlock_key) + 1;
			if (ci->last_topic)
				mem += str_len(ci->last_topic) + 1;
			if (ci->successor)
				mem += str_len(ci->successor) + 1;

			if (ci->url)
				mem += str_len(ci->url) + 1;
			if (ci->email)
				mem += str_len(ci->email) + 1;
			if (ci->welcome)
				mem += str_len(ci->welcome) + 1;
			if (ci->hold)
				mem += str_len(ci->hold) + 1;
			if (ci->mark)
				mem += str_len(ci->mark) + 1;
			if (ci->forbid)
				mem += str_len(ci->forbid) + 1;
			if (ci->freeze)
				mem += str_len(ci->freeze) + 1;
		}
	}

	send_notice_to_user(sourceNick, callerUser, "Record: \2%d\2 [%d] -> \2%d\2 KB (\2%d\2 B)", count, cs_regCount, mem / 1024, mem);

	return mem;
}

static void do_chan_access_explist(const int listLevel, CSTR source, const User *callerUser, ChannelInfo *ci) {

	const char *listName = get_chan_access_name(listLevel);
	int accessLevel, accessMatch;
	char accessName[NICKSIZE];
	
	TRACE_FCLT(FACILITY_CHANSERV_CHAN_ACCESS_EXPLIST);

	accessLevel = get_access(callerUser, ci, accessName, &accessMatch, NULL);

	if ((accessLevel < CS_ACCESS_VOP) && (!is_services_helpop(callerUser) || FlagSet(ci->flags, CI_MARKCHAN) ||
		(FlagSet(ci->flags, CI_SOPONLY) && !is_services_oper(callerUser)) ||
		(FlagSet(ci->flags, CI_SAONLY) && !is_services_admin(callerUser)) ||
		(FlagSet(ci->flags, CI_SRAONLY) && !is_services_root(callerUser)) ||
		(FlagSet(ci->flags, CI_CODERONLY) && !is_services_coder(callerUser)))) {
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
		return;
	}
	else {

		ChanAccess *anAccess;
		int checkIndex;
		int expired = 0;

		TRACE();
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_EXPLIST_HEADER, listName, ci->name);
		for (anAccess = ci->access, checkIndex = 0; checkIndex < ci->accesscount; ++anAccess, ++checkIndex) {
			if (listLevel == anAccess->level && (anAccess->status == ACCESS_ENTRY_EXPIRED ||
				(anAccess->status == ACCESS_ENTRY_NICK && (!findnick(anAccess->name)))) ) {
				expired++;
				send_notice_to_user(s_ChanServ, callerUser, "%d) %s", expired, anAccess->name);
			}
		}
		send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), END_OF_LIST);
	}
}
