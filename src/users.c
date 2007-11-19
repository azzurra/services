/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* users.c - User creation and handling
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/timeout.h"
#include "../inc/regions.h"
#include "../inc/users.h"
#include "../inc/logging.h"
#include "../inc/memory.h"
#include "../inc/send.h"
#include "../inc/conf.h"
#include "../inc/operserv.h"
#include "../inc/memoserv.h"
#include "../inc/rootserv.h"
#include "../inc/servers.h"
#include "../inc/misc.h"
#include "../inc/main.h"
#include "../inc/crypt_userhost.h"
#include "../inc/akill.h"

#ifdef USE_SERVICES
#include "../inc/reserved.h"
#endif

#ifdef USE_STATS
#include "../inc/seenserv.h"
#include "../inc/statserv.h"
#endif

#ifdef USE_SOCKSMONITOR
#include "../inc/cybcop.h"
#endif


/*********************************************************
 * Variabili globali                                     *
 *********************************************************/

#ifdef	FIX_USE_MPOOL
MemoryPool			*user_mempool;
extern MemoryPool	*channels_chan_entry_mempool;
#endif


#define HASH_DATA_MODIFIER
#define HASH_FUNCTIONS_MODIFIER		
#undef  LIST_USE_MY_HASH

#include "../inc/list.h"

// online users

// User *hashtable_onlineuser[ONLINEUSER_HASHSIZE];
CREATE_HASHTABLE_NOTAIL(onlineuser, User, ONLINEUSER_HASHSIZE)

// void hash_onlineuser_add(User *node);
static CREATE_HASH_ADD(onlineuser, User, nick)

// void hash_onlineuser_remove(User *node);
static CREATE_HASH_REMOVE_NOTAIL(onlineuser, User, nick)

// User *hash_onlineuser_find(const char *value);
CREATE_HASH_FIND(onlineuser, User, nick)


// local users

#define LOCALUSER_HASHSIZE	1024

// User_AltListItem *hashtable_localuser[LOCALUSER_HASHSIZE];
CREATE_HASHTABLE_NOTAIL(localuser, User_AltListItem, LOCALUSER_HASHSIZE)

// void hash_localuser_add(User_AltListItem *node);
static CREATE_HASH_ADD(localuser, User_AltListItem, user->nick)

// void hash_localuser_remove(User_AltListItem *node);
static CREATE_HASH_REMOVE_NOTAIL(localuser, User_AltListItem, user->nick)

// User_AltListItem *hash_localuser_find(const char *value);
CREATE_HASH_FIND(localuser, User_AltListItem, user->nick)



#ifdef USE_SERVICES

// online users by IP/HOST

#ifndef ENABLE_CAPAB_NICKIP /* no NICKIP support, use the standard hash function */

	// User_AltListItem *hashtable_onlinehost[ONLINEHOST_HASHSIZE];
	CREATE_HASHTABLE_NOTAIL(onlinehost, User_AltListItem, ONLINEHOST_HASHSIZE)

	// void hash_onlinehost_add(User_AltListItem *node);
	static CREATE_HASH_ADD(onlinehost, User_AltListItem, str_compare_nocase, user->nick)

	// void hash_onlinehost_remove(User_AltListItem *node);
	static CREATE_HASH_REMOVE_NOTAIL(onlinehost, User_AltListItem, user->nick)

	// User_AltListItem *hash_onlinehost_find(const char *value);
	//CREATE_HASH_FIND(onlinehost, User_AltListItem, const char *, str_compare_nocase, user->nick)


#else /* ENABLE_CAPAB_NICKIP */

	#undef  HASH_HASHFUNC
	#define HASH_HASHFUNC(key)	USER_ONLINEHOST_HASHFUNC(key)

	// User_AltListItem *hashtable_onlinehost[ONLINEHOST_HASHSIZE];
	CREATE_HASHTABLE_NOTAIL(onlinehost, User_AltListItem, ONLINEHOST_HASHSIZE)

	// void hash_onlinehost_add(User_AltListItem *node);
	static CREATE_HASH_ADD_SCALAR(onlinehost, User_AltListItem, user->ip)

	// void hash_onlinehost_remove(User_AltListItem *node);
	static CREATE_HASH_REMOVE_NOTAIL(onlinehost, User_AltListItem, user->ip)

	// User_AltListItem *hash_onlinehost_find(unsigned long int value);
	//CREATE_HASH_FIND_SCALAR(onlinehost, User_AltListItem, user->ip)

#endif /* ENABLE_CAPAB_NICKIP */

	
User_AltListItem	*list_onlineuser_ipv6 = NULL;

#define LIST_ADD_IPv6_USER(user) \
	if (FlagSet((user)->flags, USER_FLAG_HAS_IPV6)) { \
		\
		User_AltListItem	*item; \
		\
		item = mem_malloc(sizeof(User_AltListItem)); \
		item->user = (user); \
		LIST_INSERT_ORDERED((item), list_onlineuser_ipv6, str_compare_nocase, user->nick); \
	}

#define LIST_DEL_IPv6_USER(user) \
	if (FlagSet((user)->flags, USER_FLAG_HAS_IPV6)) { \
		\
		User_AltListItem	*item; \
		\
		LIST_SEARCH_ORDERED(list_onlineuser_ipv6, user->nick, user->nick, str_compare_nocase, item); \
		if (item) \
			LIST_REMOVE(item, list_onlineuser_ipv6); \
	}

#endif /* USE_SERVICES */


unsigned int		user_local_user_count = 0;
unsigned int		user_online_user_count = 0;
unsigned int		user_online_operator_count = 0;
unsigned int		user_online_user_max = 0;



#if defined (USE_SERVICES)
static void user_handle_newuserMODE(User *user, char *newmodes, const NickInfo *ni);
#elif defined (USE_STATS)
static void user_handle_newuserMODE(User *user, char *newmodes, SeenInfo *si);
#else
static void user_handle_newuserMODE(User *user, char *newmodes);
#endif


/*********************************************************
 * Helper                                                *
 *********************************************************/

BOOL user_init(void) {

	unsigned int idx;

	for (idx = 0; idx < ONLINEUSER_HASHSIZE; ++idx)
		hashtable_onlineuser[idx] = NULL;

	for (idx = 0; idx < LOCALUSER_HASHSIZE; ++idx)
		hashtable_localuser[idx] = NULL;

	#ifdef USE_SERVICES
	for (idx = 0; idx < ONLINEHOST_HASHSIZE; ++idx)
		hashtable_onlinehost[idx] = NULL;
	#endif

	#ifdef FIX_USE_MPOOL
	user_mempool = mempool_create(MEMPOOL_ID_USER, sizeof(User), MP_IPB_USERS, MB_IBC_USERS);
	#endif

	return TRUE;
}

void user_terminate(void) {

	#ifdef FIX_USE_MPOOL
	mempool_destroy(user_mempool);
	user_mempool = NULL;
	#endif
}


static BOOL user_localuser_add(User *user) {

	if (IS_NOT_NULL(user)) {

		User_AltListItem *item;

		item = mem_malloc(sizeof(User_AltListItem));
		item->user = user;
		hash_localuser_add(item);

		return TRUE;
	}

	return FALSE;
}

User *user_localuser_find(CSTR nick) {

	User_AltListItem *item = hash_localuser_find(nick);

	return IS_NOT_NULL(item) ? item->user : NULL;
}

static BOOL user_localuser_remove(const User *user) {

	if (IS_NOT_NULL(user)) {

		User_AltListItem *item;

		item = hash_localuser_find(user->nick);

		if (IS_NULL(item)) {

			log_error(FACILITY_USERS, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
				"user_localuser_remove(): couldn't find record for local user %s (%s@%s)", user->nick, user->username, user->host);

			return FALSE;
		}

		TRACE();
		hash_localuser_remove(item);

		TRACE();
		mem_free(item);

		return TRUE;
	}

	return FALSE;
}


#ifdef USE_SERVICES

static BOOL user_onlinehost_add(User *user) {

	if (IS_NOT_NULL(user)) {

		User_AltListItem	*item;

		item = mem_malloc(sizeof(User_AltListItem));
		item->user = user;
		hash_onlinehost_add(item);

		return TRUE;
	}

	return FALSE;
}

static BOOL user_onlinehost_remove(const User *user) {

	if (IS_NOT_NULL(user)) {

		User_AltListItem *item = NULL;

		HASH_FOREACH_BRANCH_ITEM(onlinehost, HASH_HASHFUNC(user->ip), item) {

			if (item->user->ip > user->ip) {

				item = NULL;
				break;
			}

			if (item->user == user)
				break;
		}

		if (IS_NOT_NULL(item)) {

			hash_onlinehost_remove(item);
			mem_free(item);
			return TRUE;
		}
		else
			LOG_DEBUG_SNOOP("user_onlinehost_remove() - !hash_onlinehost_find() user %s | item = 0x%0X | item->u = 0x%0X | user = 0x%0X", user->nick, item, item ? item->user : 0, user);
	}

	return FALSE;
}

#endif


static void user_change_nick(User *user, CSTR oldNick, CSTR newNick, BOOL equals) {

	#ifdef USE_STATS
	SeenInfo *si;
	#endif


	TRACE_FCLT(FACILITY_USERS_CHANGE_NICK);

	if (IS_NULL(user) || IS_NULL(newNick) || IS_EMPTY_STR(newNick)) {

		log_error(FACILITY_USERS_CHANGE_NICK, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_HALTED,
			"user_change_nick() called with invalid parameter(s) (%s, %s, %s)", IS_NULL(user) ? "NULL" : user->nick, oldNick, newNick);

		return;
	}

	hash_onlineuser_remove(user);
	str_copy_checked(newNick, user->nick, NICKMAX);
	hash_onlineuser_add(user);

	TRACE();

	#ifdef USE_STATS
	si = hash_seeninfo_find(newNick);

	if (equals) {

		if (IS_NOT_NULL(si)) {

			TRACE();
			mem_free(si->nick);
			si->nick = str_duplicate(newNick);
		}
		else {

			TRACE();
			LOG_DEBUG_SNOOP("[nickchange] Seen record for %s not found!", newNick);
		}

		return;
	}

	TRACE();
	if (IS_NOT_NULL(si)) {

		if (str_not_equals(newNick, si->nick)) {

			mem_free(si->nick);
			si->nick = str_duplicate(newNick);
		}

		if (IS_NOT_NULL(si->username)) {

			if (str_not_equals(si->username, user->username)) {

				TRACE();
				mem_free(si->username);
				si->username = str_duplicate(user->username);
			}
		}
		else
			LOG_DEBUG_SNOOP("si->username for user %s is null!", newNick);

		if (IS_NOT_NULL(si->host)) {

			if (str_not_equals(si->host, user->host)) {

				TRACE();
				mem_free(si->host);
				si->host = str_duplicate(user->host);
			}
		}
		else
			LOG_DEBUG_SNOOP("si->host for user %s is null!", newNick);

		if (IS_NOT_NULL(si->realname)) {

			if (str_not_equals(si->realname, user->realname)) {

				TRACE();
				mem_free(si->realname);
				si->realname = str_duplicate(user->realname);
			}
		}
		else
			LOG_DEBUG_SNOOP("si->realname for user %s is null!", newNick);

		si->type = SEEN_TYPE_NCFR;

		if (IS_NOT_NULL(si->tempnick))
			mem_free(si->tempnick);
		si->tempnick = str_duplicate(oldNick);

		if (IS_NOT_NULL(si->quitmsg)) {

			mem_free(si->quitmsg);
			si->quitmsg = NULL;
		}

		/* La user_reset_user() ha gia' eliminato +r e ID flags da user->mode e user->flags */

		TRACE();
		si->mode = user->mode;

		si->last_seen = NOW;
	}
	else {

		TRACE();
		if (IS_NULL(si = seenserv_create_record(user))) {

			TRACE();
			LOG_DEBUG_SNOOP("Error creating seen record for user %s!", newNick);
			return;
		}

		si->type = SEEN_TYPE_NCFR;
		si->tempnick = str_duplicate(oldNick);

		si->mode = user->mode;

		if (IS_NOT_NULL(si->quitmsg)) {

			mem_free(si->quitmsg);
			si->quitmsg = NULL;
		}
	}
	#endif	/* USE_STATS */
}


/*********************************************************
 * user_create_user()                                    *
 *                                                       *
 * Allocate a new User structure, fill in basic values,  *
 * link it to the overall list, and return it.           *
 * Always successful.                                    *
 *********************************************************/

static User *user_create_user(CSTR nick, BOOL myClient) {

	User *user;


	TRACE_FCLT(FACILITY_USERS_CREATE_USER);

	#ifdef	FIX_USE_MPOOL
	user = mempool_alloc(User*, user_mempool, TRUE);
	#else
	user = mem_calloc(1, sizeof(User));
	#endif

	if (IS_NULL(nick) || IS_EMPTY_STR(nick)) {

		log_error(FACILITY_USERS_CREATE_USER, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_RESUMED,
			s_LOG_ERR_PARAMETER, "user_create_user()", s_LOG_NULL, "nick");

		nick = s_NULL;
	}

	str_copy_checked(nick, user->nick, NICKMAX);

	TRACE();

	++user_online_user_count;

	#ifdef USE_STATS
	if (user_online_user_count > records.maxusers) {

		records.maxusers = user_online_user_count;
		records.maxusers_time = NOW;
	}

	if (user_online_user_count > stats_daily_maxusers)
		stats_daily_maxusers = user_online_user_count;
	#endif

	TRACE();

	#ifdef USE_SERVICES	
	if (!myClient) {

		if (IS_NOT_NULL(dynConf.welcomeNotice) && (synched == TRUE))
			send_notice_to_user(s_GlobalNoticer, user, dynConf.welcomeNotice);
	}

	user->current_lang = LANG_DEFAULT;
	#endif

	return user;
}


#ifdef USE_SERVICES

/*********************************************************
 * user_add_enforcer()                                   *
 *                                                       *
 * Add a local user entry for an enforcer                *
 *********************************************************/

User *user_add_enforcer(NickInfo *ni) {

	User	*user;


	TRACE_FCLT(FACILITY_USERS_ADD_SERVICES_CLIENT);

	user = user_create_user(ni->nick, TRUE);

	user->username = str_duplicate("enforcer");
	user->host = str_duplicate(CONF_SERVICES_HOST);
	user->maskedHost = str_duplicate(CONF_SERVICES_HOST);
	user->server = server_myself;
	user->realname = str_duplicate("Nick Protection Enforcement");

	user->signon = NOW;
	user->tsinfo = NOW;
	user->my_signon = NOW;
	user->ni = ni;
	user->mode = UMODE_i;
	user->flags = USER_FLAG_ENFORCER;

	#ifdef ENABLE_CAPAB_NICKIP
	user->ip = SERVICES_IP_NETWORK_ORDER;
	#endif

	if (!user_localuser_add(user))
		log_error(FACILITY_USERS_ADD_SERVICES_CLIENT, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
			"Failed to add localuser entry for user %s (%s@%s)", user->nick, user->username, user->host);

	++user_local_user_count;

	hash_onlineuser_add(user);

	if (!(user_onlinehost_add(user)))
		log_error(FACILITY_USERS_ADD_SERVICES_CLIENT, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
			"Failed to add onlinehost entry for user %s (%s@%s)", user->nick, user->username, user->host);

	return user;
}
#endif /* USE_SERVICES */


/*********************************************************
 * user_add_services_agent()                             *
 *                                                       *
 * Add a local services agent user                       *
 *********************************************************/

User *user_add_services_agent(CSTR nick, long int mode, CSTR realname) {

	User	*user;


	TRACE_FCLT(FACILITY_USERS_ADD_SERVICES_AGENT);

	user = user_create_user(nick, TRUE);

	user->username = str_duplicate(CONF_SERVICES_USERNAME);
	user->host = str_duplicate(CONF_SERVICES_HOST);
	user->maskedHost = str_duplicate(CONF_SERVICES_HOST);
	user->server = server_myself;
	user->realname = str_duplicate(realname);

	user->signon = NOW;
	user->tsinfo = NOW;
	user->my_signon = NOW;
	user->mode = mode;
	user->flags = USER_FLAG_AGENT;

	#ifdef ENABLE_CAPAB_NICKIP
	user->ip = SERVICES_IP_NETWORK_ORDER;
	#endif

	if (!user_localuser_add(user))
		log_error(FACILITY_USERS_ADD_SERVICES_AGENT, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
			"Failed to add localuser entry for user %s (%s@%s)", user->nick, user->username, user->host);

	++user_local_user_count;

	hash_onlineuser_add(user);

	#ifdef USE_SERVICES
	if (!(user_onlinehost_add(user)))
		log_error(FACILITY_USERS_ADD_SERVICES_AGENT, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
			"Failed to add onlinehost entry for user %s (%s@%s)", user->nick, user->username, user->host);
	#endif

	return user;
}


/*********************************************************
 * user_delete_user()                                    *
 *                                                       *
 * Remove and free a User structure.                     *
 *********************************************************/

void user_delete_user(User *user) {

	TRACE_FCLT(FACILITY_USERS_DELETE_USER);

	if (IS_NULL(user)) {

		log_error(FACILITY_USERS_DELETE_USER, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, s_LOG_ERR_PARAMETER, "user_delete_user()", s_LOG_NULL, "user");
		return;
	}

	--user_online_user_count;

	servers_user_remove(user);

	if (FlagSet(user->mode, UMODE_o))
		--user_online_operator_count;

	TRACE();

	#ifdef USE_SERVICES	
	memoserv_delete_flagged_memos(user->nick, TRUE);

	TRACE();

	if (!(user_onlinehost_remove(user)))
		log_error(FACILITY_USERS_DELETE_USER, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
			"user_delete_user(): Failed to remove onlinehost entry for user %s (%s@%s)", user->nick, user->username, user->host);

	LIST_DEL_IPv6_USER(user);
	#endif

	TRACE();

	hash_onlineuser_remove(user);

	TRACE();

	if (user_is_services_client(user)) {

		TRACE();

		if (!(user_localuser_remove(user)))
			log_error(FACILITY_USERS_DELETE_USER, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
				"user_delete_user(): Failed to remove localuser entry for user %s (%s@%s)", user->nick, user->username, user->host);

		--user_local_user_count;
	}

	TRACE();

	mem_free(user->username);
	mem_free(user->host);
	mem_free(user->maskedHost);
	mem_free(user->realname);

	TRACE();

	#if defined(USE_SERVICES) || defined(USE_STATS)
	if (IS_NOT_NULL(user->chans)) {

		ChanListItem *item, *next;


		item = user->chans;

		while (IS_NOT_NULL(item)) {

			next = item->next;
			chan_user_remove(user, item->chan);

			#ifdef	FIX_USE_MPOOL
			mempool_free(channels_chan_entry_mempool, item);
			#else
			mem_free(item);
			#endif

			item = next;
		}
	}
	#endif

	TRACE();

	#ifdef USE_SERVICES
	if (IS_NOT_NULL(user->founder_chans)) {

		ChanInfoListItem *item, *next;


		item = user->founder_chans;	

		while (IS_NOT_NULL(item)) {

			next = item->next;
			mem_free(item);
			item = next;
		}
	}

	if (user->idcount > 0) {

		char **idnicks;
		int idx;

		for (idnicks = user->id_nicks, idx = 0; idx < user->idcount; ++idnicks, ++idx)
			mem_free(*idnicks);

		mem_free(user->id_nicks);
	}
	#endif

	#ifdef	FIX_USE_MPOOL
	mempool_free(user_mempool, user);
	#else
	mem_free(user);
	#endif
}


/*********************************************************
 * user_delete_services_client()                         *
 *                                                       *
 * Remove a local services user (nick enforcers,         *
 * services agent, ...)                                  *
 *********************************************************/

void user_delete_services_client(CSTR nick) {

	User *user;


	TRACE_FCLT(FACILITY_USERS_DELETE_SERVICES_CLIENT);

	if (IS_NOT_NULL(user = hash_onlineuser_find(nick))) {

		if (user_is_services_client(user))
			user_delete_user(user);
		else
			log_error(FACILITY_USERS_DELETE_SERVICES_CLIENT, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
				"User %s (%s@%s) is not flagged as services client", user->nick, user->username, user->host);
	}
	else {

		log_error(FACILITY_USERS_DELETE_SERVICES_CLIENT, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
			"Failed to remove localuser entry for services client %s", nick);
	}
}


/*********************************************************
 * user_is_identified_to()                               *
 * Find if a user is identified to the given nick.       *
 *********************************************************/

#ifdef USE_SERVICES
BOOL user_is_identified_to(const User *user, CSTR nickname) {

	TRACE_FCLT(FACILITY_USERS_IS_IDENTIFIED_TO);

	if (IS_NULL(user) || IS_NULL(nickname) || IS_EMPTY_STR(nickname))
		log_error(FACILITY_USERS_IS_IDENTIFIED_TO, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_PROPAGATED,
			s_LOG_ERR_PARAMETER, "user_is_identified_to()", s_LOG_NULL, IS_NULL(user) ? "user" : "nickname");

	else if (user->idcount == 0)
		return FALSE;

	else {

		char **idnicks;
		int idx;

		for (idnicks = user->id_nicks, idx = 0; (idx < user->idcount); ++idnicks, ++idx) {

			TRACE();
			if (str_equals_nocase(*idnicks, nickname))
				return TRUE;
		}
	}

	return FALSE;
}

void user_remove_id(CSTR nickname, BOOL deleted) {

	User *user;
	int idx, nickIdx;
	char **idnicks;

	TRACE_FCLT(FACILITY_USERS_REMOVE_ID);

	HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM(onlineuser, idx, user) {

			for (idnicks = user->id_nicks, nickIdx = 0; (nickIdx < user->idcount); ++idnicks, ++nickIdx) {

				TRACE();
				if (str_equals_nocase(*idnicks, nickname)) {

					mem_free(*idnicks);
					--(user->idcount);

					if (nickIdx < user->idcount)	/* if it wasn't the last entry... */
						memmove(idnicks, (idnicks + 1), (user->idcount - nickIdx) * sizeof(char *));

					TRACE_MAIN();
					if (user->idcount)	/* if there are any entries left... */
						user->id_nicks = mem_realloc(user->id_nicks, user->idcount * sizeof(char *));

					else {

						mem_free(user->id_nicks);
						user->id_nicks = NULL;
					}

					break;
				}
			}

			if ((deleted == TRUE) && IS_NOT_NULL(user->ni) && str_equals_nocase(user->ni->nick, nickname))
				user->ni = NULL;
		}
	}
}

void user_remove_chanid(ChannelInfo *ci) {

	ChanInfoListItem *item;
	User *user;
	int	idx;


	TRACE_FCLT(FACILITY_USERS_REMOVE_CHANID);

	if (IS_NULL(ci))
		return;

	HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM(onlineuser, idx, user) {

			for (item = user->founder_chans; IS_NOT_NULL(item); item = item->next) {

				if (item->ci == ci) {

					TRACE();
					if (item->next)
						item->next->prev = item->prev;

					if (item->prev)
						item->prev->next = item->next;
					else
						user->founder_chans = item->next;

					TRACE();
					mem_free(item);
					break;
				}
			}
		}
	}
}


/*********************************************************
 * user_handle_services_kick()                           *
 * Handle a KICK command by ChanServ/OperServ.           *
 *********************************************************/

void user_handle_services_kick(CSTR chan, User *user) {

	ChanListItem *item;


	TRACE_MAIN_FCLT(FACILITY_USERS_HANDLE_SERVICES_KICK);

	if (IS_NULL(chan) || IS_EMPTY_STR(chan)) {

		log_error(FACILITY_USERS_HANDLE_SERVICES_KICK, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, s_LOG_ERR_PARAMETER, "user_handle_services_kick()", s_LOG_NULL, "chan");
		return;
	}

	if (IS_NULL(user)) {

		log_error(FACILITY_USERS_HANDLE_SERVICES_KICK, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"user_handle_services_kick: KICK by services for nonexistent user on %s", chan);

		return;
	}

	for (item = user->chans; IS_NOT_NULL(item) && (str_not_equals_nocase(chan, item->chan->name)); item = item->next)
		;

	TRACE_MAIN();
	if (IS_NOT_NULL(item)) {

		chan_user_remove(user, item->chan);

		if (IS_NOT_NULL(item->next))
			item->next->prev = item->prev;

		if (IS_NOT_NULL(item->prev))
			item->prev->next = item->next;
		else
			user->chans = item->next;

		TRACE_MAIN();
		#ifdef	FIX_USE_MPOOL
		mempool_free(channels_chan_entry_mempool, item);
		#else
		mem_free(item);
		#endif
	}
}

#endif


/*********************************************************
 * user_handle_NICK()                                    *
 *                                                       *
 * Handle a server NICK command.                         *
 *                                                       *
 * av[0] = nick                                          *
 *                                                       *
 * If a new user:                                        *
 *		av[1] = hop count                                *
 *		av[2] = signon time                              *
 *		av[3] = usermode                                 *
 *		av[4] = username                                 *
 *		av[5] = hostname                                 *
 *		av[6] = user's server                            *
 *		av[7] = services id (not used here)              *
 *      -- with NICKIP --                                *
 *		av[8] = user IP                                  *
 *		av[9] = user's real name                         *
 *      -- without NICKIP --                             *
 *		av[8] = user's real name                         *
 *                                                       *
 * Else:                                                 *
 *		av[1] = time of change                           *                                                                           *
 *********************************************************/

void user_handle_NICK(CSTR source, const int ac, char **av) {

	User		*user;
	Server		*server;
	time_t		signon;

	#if defined(USE_SERVICES) || defined(USE_SOCKSMONITOR)
	int			hasAccess = AC_RESULT_DENIED;
	BOOL		isExempt;
	#endif

	#ifdef USE_SERVICES
	NickTimeoutData		*ntd;
	#endif

	#ifdef USE_STATS
	SeenInfo	*si;
	#endif


	TRACE_MAIN_FCLT(FACILITY_USERS_HANDLE_NICK);

	if (IS_NULL(source) || IS_EMPTY_STR(source)) {

		/*********************************************************
		 * A new user                                            *
		 *********************************************************/

		HOST_TYPE			htype;
		short int			dotsCount;
		unsigned long int	ip = 0;


		TRACE_MAIN();

		/* This is a new user; create a User structure for it. */

		#ifdef USE_SERVICES
		/* Sanity check */
		if (IS_NOT_NULL(user = user_localuser_find(av[0]))) {

			if (IS_NOT_NULL(user->ni) && FlagSet(user->flags, USER_FLAG_ENFORCER)) {

				TRACE_MAIN();

				LOG_DEBUG_SNOOP("Warning: new nick %s already exists as services client (%s@%s)!", av[0], user->username, user->host);

				if (FlagSet(user->ni->flags, NI_TIMEOUT)) {

					if (!timeout_remove(toNickServ, TOTYPE_NICKSERV_COUNTDOWN, (unsigned long) user->ni))
						log_error(FACILITY_USERS_HANDLE_NICK, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING, 
							"user_handle_nick(): Timeout not found for %s (NickServ/Countdown) at connect", user->ni->nick);
				}

				if (FlagSet(user->ni->flags, NI_ENFORCED)) {

					if (!timeout_remove(toNickServ, TOTYPE_NICKSERV_RELEASE, (unsigned long) user->ni))
						log_error(FACILITY_USERS_HANDLE_NICK, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING, 
							"user_handle_nick(): Timeout not found for %s (NickServ/Release) at connect", user->ni->nick);
				}

				RemoveFlag(user->ni->flags, NI_TIMEOUT);
				RemoveFlag(user->ni->flags, NI_ENFORCED);
				RemoveFlag(user->ni->flags, NI_ENFORCE);

				TRACE_MAIN();
				user_delete_services_client(av[0]);
			}
			else
				LOG_DEBUG_SNOOP("Warning: new nick %s already exists! (%s@%s)", av[0], user->username, user->host);
		}
		#endif

		TRACE_MAIN();
		#ifdef USE_STATS
		++(total.connections);
		++(monthly.connections);
		++(weekly.connections);
		++(daily.connections);
		#endif		

		#ifdef ENABLE_CAPAB_NICKIP
		if (FlagSet(uplink_capab, CAPAB_NICKIP) && (ac == 10) && !index(av[8], ':')) {

			ip = strtoul(av[8], NULL, 10);
			ip = ntohl(ip);
		}
		#endif

		TRACE_MAIN();

		#if defined(USE_SERVICES) || defined(USE_SOCKSMONITOR)
		/* First check for AKILLs. */
		if (akill_match(av[0], av[4], av[5], ip) == TRUE)
			return;
		#endif

		TRACE_MAIN();

		if (IS_NULL(server = findserver(av[6]))) {

			LOG_DEBUG_SNOOP("Couldn't find server %s used by %s (%s@%s)!", av[6], av[0], av[4], av[5]);
			return;
		}

		signon = atol(av[2]);

		#if defined(USE_SERVICES) || defined(USE_SOCKSMONITOR)
		isExempt = (strchr(av[3], 'A') || strchr(av[3], 'a') || strchr(av[3], 'o') || strchr(av[3], 'z'));
		#endif

		#ifdef USE_SOCKSMONITOR
		switch ((hasAccess = check_access(APMList, av[0], av[4], av[5], av[6], signon))) {

			case AC_RESULT_NOTFOUND:
				break;

			case AC_RESULT_DENIED:
				if (isExempt) {

					send_globops(NULL, "\2WARNING\2: \2%s\2 (%s@%s) is overriding an APM entry!", av[0], av[4], av[5]);
					break;
				}

				send_KILL(s_SocksMonitor, av[0], "This nick is reserved for services and may not be used. Please change your nick and reconnect.", FALSE);
				return;

			case AC_RESULT_GRANTED:

				if (FlagSet(server->flags, SERVER_FLAG_HAVEAPM))
					LOG_DEBUG_SNOOP("An APM is already logged in for %s", server->name);

				else {

					AddFlag(server->flags, SERVER_FLAG_HAVEAPM);
					LOG_PROXY(s_SocksMonitor, "APM %s logged in. Proxy scan for server \2%s\2 halted.", av[0], server->name);
				}
				break;
		}
		#endif

		TRACE_MAIN();

		#ifdef USE_SERVICES
		/* Controllo server-bot */
		if ((hasAccess = check_access(serverBotList, av[0], av[4], av[5], av[6], signon)) == AC_RESULT_DENIED) {

			if (!isExempt) {

				send_KILL(NULL, av[0], lang_msg(GetCallerLang(), RESERVED_BOT_KILL_REASON), FALSE);
				return;
			}
			else
				send_globops(NULL, "\2WARNING\2: \2%s\2 (%s@%s) is overriding a Server Bot entry!", av[0], av[4], av[5]);
		}

		TRACE_MAIN();

		/* Controllo nomi riservati. */
		switch (reserved_match(av[0], RESERVED_NICK, 0, s_NickServ, av[0], av[4], av[5], ip, isExempt, LANG_DEFAULT)) {

			case reservedKill:
				send_KILL(s_NickServ, av[0], lang_msg(GetCallerLang(), RESERVED_NAME_KILL_REASON_USE), FALSE);
				/* Fall... */

			case reservedAutoKill:
				return;

			case reservedBlock:
				send_notice_lang_to_nick(s_NickServ, av[0], GetCallerLang(), ERROR_NICK_RESERVED, av[0]);
				break;

			case reservedValid:
				/* Don't do anything. */
				break;
		}
		#endif

		TRACE_MAIN();

		/* Allocate User structure. */
		user = user_create_user(av[0], FALSE);

		TRACE_MAIN();

		/* Fill it. */
		user->signon = user->tsinfo = signon;
		user->username = str_duplicate(av[4]);
		user->host = str_duplicate(av[5]);
		user->server = server;

		TRACE_MAIN();
		++(user->server->userCount);

		htype = host_type(user->host, &dotsCount);

		if (htype == htInvalid)
			log_error(FACILITY_USERS_HANDLE_NICK, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
				"user_handle_NICK(): Invalid host supplied by %s (%s@%s) [Dots: %d]", user->nick, user->username, user->host, dotsCount);

		TRACE_MAIN();

		#ifdef ENABLE_CAPAB_NICKIP
		if (FlagSet(uplink_capab, CAPAB_NICKIP)) {

			TRACE_MAIN();

			if (ac != 10) {

				LOG_DEBUG_SNOOP("user_handle_NICK() - Missing NICKIP parameter -> disabling NICKIP support %d!", ac);
				RemoveFlag(uplink_capab, CAPAB_NICKIP);
				user->realname = str_duplicate(av[8]);

				if (htype == htIPv6)
					user->current_lang = LANG_DEFAULT;

				else {

					user->current_lang = LangFromRegionID(region_match(0, user->host, REGIONTYPE_HOST));

					if (user->current_lang == LANG_INVALID)
						user->current_lang = LANG_DEFAULT;
				}
			}
			else {

				user->ip = ip;
				user->realname = str_duplicate(av[9]);

				TRACE_MAIN();

				if (htype == htIPv6)
					user->current_lang = LANG_DEFAULT;

				else {

					user->current_lang = LangFromRegionID(region_match(ip, user->host, REGIONTYPE_BOTH));

					if (user->current_lang == LANG_INVALID)
						user->current_lang = LANG_DEFAULT;
				}
			}
		}
		else
			user->realname = str_duplicate(av[8]);

		#else
		user->realname = str_duplicate(av[8]);

		if (htype == htIPv6)
			user->current_lang = LANG_DEFAULT;

		else {

			user->current_lang = LangFromRegionID(region_match(0, user->host, REGIONTYPE_HOST));

			if (user->current_lang == LANG_INVALID)
				user->current_lang = LANG_DEFAULT;
		}
		#endif

		TRACE_MAIN();

		#ifdef USE_SERVICES
		if (htype == htIPv6) {

			/* IPv6 host. */
			AddFlag(user->flags, USER_FLAG_HAS_IPV6);
			user->maskedHost = expand_ipv6(user->host);
		}
		else
			user->maskedHost = crypt_userhost(user->host, htype, dotsCount);

		#else
		user->maskedHost = ((htype == htIPv4) || (htype == htHostname)) ? crypt_userhost(user->host, htype, dotsCount) : str_duplicate(user->host);
		#endif

		TRACE_MAIN();

		hash_onlineuser_add(user);

		TRACE_MAIN();

		#ifdef USE_SERVICES
		if (!(user_onlinehost_add(user)))
			log_error(FACILITY_USERS_HANDLE_NICK, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
				"Failed to add onlinehost entry for user %s (%s@%s)", user->nick, user->username, user->host);

		LIST_ADD_IPv6_USER(user);

		TRACE_MAIN();

		user->ni = findnick(user->nick);
		#endif

		TRACE_MAIN();

		#ifdef USE_STATS
		if (!is_seen_exempt(user->nick, user->username, user->host, user->ip)) {

			if (IS_NULL(si = hash_seeninfo_find(av[0]))) {

				TRACE_MAIN();

				if (IS_NOT_NULL(si = seenserv_create_record(user))) {

					si->type = SEEN_TYPE_NICK;

					if (IS_NOT_NULL(si->quitmsg)) {

						mem_free(si->quitmsg);
						si->quitmsg = NULL;
					}

					if (IS_NOT_NULL(si->tempnick)) {

						mem_free(si->tempnick);
						si->tempnick = NULL;
					}

					TRACE_MAIN();
				}
				else
					LOG_DEBUG_SNOOP("Error creating seen record for user %s!", user->nick);
			}
			else {

				TRACE_MAIN();

				if (str_not_equals(av[0], si->nick)) {

					mem_free(si->nick);
					si->nick = str_duplicate(av[0]);
				}

				if (IS_NOT_NULL(si->username)) {

					mem_free(si->username);
					si->username = str_duplicate(user->username);
				}
				else
					LOG_DEBUG_SNOOP("si->username for user %s is null!", source);			

				TRACE_MAIN();

				if (IS_NOT_NULL(si->host)) {

					mem_free(si->host);
					si->host = str_duplicate(user->host);
				}
				else
					LOG_DEBUG_SNOOP("si->host for user %s is null!", source);			

				if (IS_NOT_NULL(si->realname)) {

					mem_free(si->realname);
					si->realname = str_duplicate(user->realname);
				}
				else
					LOG_DEBUG_SNOOP("si->realname for user %s is null!", source);			

				TRACE_MAIN();

				si->ip = user->ip;
				si->mode = 0;
				si->type = SEEN_TYPE_NICK;
				si->last_seen = NOW;

				TRACE_MAIN();

				if (IS_NOT_NULL(si->quitmsg)) {

					mem_free(si->quitmsg);
					si->quitmsg = NULL;
				}

				if (IS_NOT_NULL(si->tempnick)) {

					mem_free(si->tempnick);
					si->tempnick = NULL;
				}
			}

			user_handle_newuserMODE(user, av[3], si);
		}

		TRACE_MAIN();
		servers_user_add(user);
		#endif

		TRACE_MAIN();

		#ifdef USE_SERVICES
		user_handle_newuserMODE(user, av[3], user->ni);	/* Se passo il +r mi mette ID qui */
		#endif

		TRACE_MAIN();

		#ifdef USE_SOCKSMONITOR
		user_handle_newuserMODE(user, av[3]);
		#endif

		TRACE_MAIN();

		#ifdef USE_SERVICES		
		if (hasAccess == AC_RESULT_GRANTED) {

			AddFlag(user->flags, USER_FLAG_IS_SERVERBOT);

			/* This needs to be fixed for bot->modes_on/off to work. */
			AddFlag(user->mode, UMODE_z);
			RemoveFlag(user->mode, UMODE_x);
		}

		TRACE_MAIN();

		/* Check to see if it looks like clones. */
		if ((CONF_SET_CLONE == TRUE) && (synched == TRUE)) {

			if (FlagSet(user->flags, USER_FLAG_HAS_IPV6)) {

				if (CONF_CLONE_SCAN_V6 > 0)
					check_clones_v6(user);
			}
			else
				check_clones(user);
		}

		TRACE_MAIN();

		if (str_equals_partial(user->nick, "Guest", 5)) {

			long int guestNumber;
			char *err;

			guestNumber = strtol(user->nick + 5, &err, 10);

			if (*err == '\0')
				nickserv_guest_reserve(guestNumber);
		}

		TRACE_MAIN();

		if (user->ni) {

			if (FlagSet(user->ni->flags, NI_TIMEOUT)) {

				ntd = (NickTimeoutData*) timeout_get_data(toNickServ, TOTYPE_NICKSERV_COUNTDOWN, (unsigned long) user->ni);

				if (IS_NOT_NULL(ntd))
					ntd->user_online = TRUE;
			}

			TRACE_MAIN();
			validate_user(user);
		}
		#endif

		#ifdef USE_SOCKSMONITOR
		if (hasAccess == AC_RESULT_GRANTED)
			AddFlag(user->flags, USER_FLAG_IS_APM);

		else {

			if (synched) {

				if (FlagSet(uplink_capab, CAPAB_NICKIP)) {

					if (check_flooder(user->nick, user->username, user->host, user->ip, user->realname, user->current_lang))
						return;

					if (CONF_NGILAMER_DETECT)
						check_ngi_lamer(user->nick, user->username, user->host, user->realname, user->ip);
				}
				else {

					if (check_flooder(user->nick, user->username, user->host, 0, user->realname, user->current_lang))
						return;
				}
			}

			/* "!" means this is not an oper request via CHECK. */
			if (FlagUnset(server->flags, SERVER_FLAG_SCANEXEMPT) &&		/* Server is not exempt. */
				FlagUnset(server->flags, SERVER_FLAG_BURSTING) &&		/* Server is not bursting. */
				FlagUnset(server->flags, SERVER_FLAG_HAVEAPM))			/* Server doesn't have an APM. */
				proxy_check(av[0], av[5], ip, "!", user->current_lang);
		}
		#endif

		TRACE_MAIN();

		user->my_signon = time(NULL);
	}
	else {

		/*********************************************************
		 * An old user changing nicks                            *
		 *********************************************************/

		TRACE_MAIN();

		if (IS_NULL(user = hash_onlineuser_find(source))) {

			log_error(FACILITY_USERS_HANDLE_NICK, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
				"user_handle_NICK(): NICK from nonexistent nick %s: %s", source, merge_args(ac, av));

			return;
		}

		#ifdef USE_STATS
		++total.nicks;
		++monthly.nicks;
		++weekly.nicks;
		++daily.nicks;

		servers_increase_messages(user);
		#endif

		TRACE_MAIN();

		if (str_equals_nocase(source, av[0])) {

			TRACE_MAIN();

			user_change_nick(user, source, av[0], TRUE);

			TRACE_MAIN();

			/* Not sure if we have to update this. cfr. bahamut, m_nick.c */
			user->tsinfo = atol(av[1]);
			return;
		}
		else {

			TRACE_MAIN();

			#ifdef USE_SERVICES
			if (IS_NOT_NULL(user->ni)) {

				if (FlagUnset(user->ni->flags, NI_FORBIDDEN) &&
					(user_is_identified_to(user, source) || is_on_access(user, user->ni))) {

					TRACE_MAIN();

					user->ni->last_seen = NOW;
					if (user->ni->last_usermask)
						mem_free(user->ni->last_usermask);

					TRACE_MAIN();

					user->ni->last_usermask = mem_malloc(str_len(user->username) + str_len(user_public_host(user)) + 2);
					sprintf(user->ni->last_usermask, "%s@%s", user->username, user_public_host(user));

					TRACE_MAIN();
				}

				if (FlagSet(user->ni->flags, NI_TIMEOUT)) {

					ntd = (NickTimeoutData*) timeout_get_data(toNickServ, TOTYPE_NICKSERV_COUNTDOWN, (unsigned long) user->ni);

					if (IS_NOT_NULL(ntd))
						ntd->user_online = FALSE;
				}

				check_enforce(user->ni);
			}

			TRACE_MAIN();

			/* Il vecchio nick e' un GuestXXXXX ? */
			if (str_equals_partial(source, "Guest", 5)) {

				long int guestNumber;
				char *err;

				guestNumber = strtol(source + 5, &err, 10);

				if (*err == '\0')
					nickserv_guest_free(guestNumber);
			}

			TRACE_MAIN();

			/* Il nuovo nick e' un GuestXXXXX ? */
			if (str_equals_partial(av[0], "Guest", 5)) {

				long int guestNumber;
				char *err;

				guestNumber = strtol(av[0] + 5, &err, 10);

				if (*err == '\0')
					nickserv_guest_reserve(guestNumber);
			}
			#endif

			TRACE_MAIN();

			#ifdef USE_STATS
			if (IS_NOT_NULL(si = hash_seeninfo_find(source))) {

				if (str_not_equals(si->username, user->username))
					LOG_DEBUG_SNOOP("[nickchange] username mismatch (%s != %s) for nick %s", si->username, user->username, user->nick);

				if (str_not_equals(si->host, user->host))
					LOG_DEBUG_SNOOP("[nickchange] host mismatch (%s != %s) for nick %s", si->host, user->host, user->nick);

				if (str_not_equals(si->realname, user->realname))
					LOG_DEBUG_SNOOP("[nickchange] realname mismatch (%s != %s) for nick %s", si->realname, user->realname, user->nick);

				si->type = SEEN_TYPE_NCTO;

				if (IS_NOT_NULL(si->tempnick))
					mem_free(si->tempnick);
				si->tempnick = str_duplicate(av[0]);

				if (IS_NOT_NULL(si->quitmsg)) {

					mem_free(si->quitmsg);
					si->quitmsg = NULL;
				}

				/* -2 per far comparire prima il nuovo nick in un seen. */
				si->last_seen = NOW - 2;
			}
			else
				LOG_DEBUG_SNOOP("[nickchange] No seen record for %s", source);
			#endif

			RemoveFlag(user->mode, UMODE_r);

			TRACE_MAIN();

			user_change_nick(user, source, av[0], FALSE);

			TRACE_MAIN();

			user->tsinfo = atol(av[1]);

			#if defined(USE_SERVICES) || defined(USE_SOCKSMONITOR)
			isExempt = (IS_NOT_NULL(user->oper) || user_is_ircop(user) || user_is_admin(user) || user_is_services_agent(user));
			#endif

			#ifdef USE_SERVICES
			/* Controllo server-bot. */
			if ((hasAccess = check_access(serverBotList, av[0], user->username, user->host, user->server->name, user->tsinfo)) == AC_RESULT_DENIED) {

				if (!isExempt) {

					send_KILL(s_NickServ, av[0], lang_msg(GetCallerLang(), RESERVED_BOT_KILL_REASON), TRUE);
					return;
				}
				else
					send_globops(NULL, "\2WARNING\2: \2%s\2 (%s@%s) is overriding a Server Bot entry!", user->nick, user->username, user->host);
			}

			TRACE_MAIN();

			/* Controllo nomi riservati. */
			switch (reserved_match(av[0], RESERVED_NICK, 0, s_NickServ, source, user->username, user->host, user->ip, isExempt, user->current_lang)) {

				case reservedKill:
					send_KILL(s_NickServ, av[0], lang_msg(GetCallerLang(), RESERVED_NAME_KILL_REASON_USE), TRUE);
					/* Fall... */

				case reservedAutoKill:
					return;

				case reservedBlock:
					send_notice_lang_to_nick(s_NickServ, av[0], GetCallerLang(), ERROR_NICK_RESERVED, av[0]);
					break;

				case reservedValid:
					/* Don't do anything. */
					break;
			}

			TRACE_MAIN();

			if (hasAccess == AC_RESULT_GRANTED) {

				AddFlag(user->flags, USER_FLAG_IS_SERVERBOT);

				/* This needs to be fixed for bot->modes_on/off to work. */
				AddFlag(user->mode, UMODE_z);
				RemoveFlag(user->mode, UMODE_x);
			}

			TRACE_MAIN();

			if (IS_NOT_NULL(user->ni = findnick(av[0]))) {

				ntd = (NickTimeoutData*) timeout_get_data(toNickServ, TOTYPE_NICKSERV_COUNTDOWN, (unsigned long) user->ni);

				if (IS_NOT_NULL(ntd))
					ntd->user_online = TRUE;

				TRACE_MAIN();

				if (user_is_identified_to(user, user->ni->nick)) {

					TRACE_MAIN();

					if (FlagUnset(user->ni->flags, NI_AUTH)) {

						/* Only grant +r if the nick has been authorized. */
						send_user_SVSMODE(s_NickServ, user->ni->nick, "+r", user->tsinfo);
						AddFlag(user->mode, UMODE_r);
					}

					user->current_lang = GetNickLang(user->ni);

					if (IS_NOT_NULL(ntd)) {

						if (!timeout_remove(toNickServ, TOTYPE_NICKSERV_COUNTDOWN, (unsigned long)user->ni))
							log_error(FACILITY_USERS_HANDLE_NICK, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING, 
								"user_handle_nick(): Timeout not found for %s (NickServ/Countdown) at nickchange", user->ni->nick);
					}

					RemoveFlag(user->ni->flags, NI_TIMEOUT);
					RemoveFlag(user->ni->flags, NI_ENFORCED);
					RemoveFlag(user->ni->flags, NI_ENFORCE);
				}

				TRACE_MAIN();
				validate_user(user);
			}
			#endif
		}
	}
}

#if defined(USE_SERVICES) || defined(USE_STATS)

/*********************************************************
 * user_handle_JOIN()                                    *
 * Handle a server JOIN command.                         *
 *                                                       *
 * av[0] = channels to join                              *
 *********************************************************/

void user_handle_JOIN(CSTR source, const int ac, char **av) {

	User *user;
	char *channel, *ptr;


	TRACE_MAIN_FCLT(FACILITY_USERS_HANDLE_JOIN);

	if (IS_NULL(user = hash_onlineuser_find(source))) {

		log_error(FACILITY_USERS_HANDLE_JOIN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"user_handle_JOIN(): JOIN from nonexistent user %s: %s", source, merge_args(ac, av));

		return;
	}

	ptr = av[0];

	while (*(channel = ptr)) {

		TRACE_MAIN();
		ptr = channel + strcspn(channel, s_COMMA);

		if (*ptr)
			*ptr++ = 0;

		if (str_equals(channel, "0")) {

			char *ov[1];

			while (IS_NOT_NULL(user->chans)) {

				if (IS_NOT_NULL(user->chans->chan)) {

					ov[0] = user->chans->chan->name;
					user_handle_PART(source, 1, ov);
				}
			}
		}
		else {

			/* Shouldn't happen - bahamut should force a SJOIN itself,
			   but let's help if it doesn't. */

			Channel *chan;
			time_t	TimeStamp;
			char	channel_TS[12];


			LOG_DEBUG_SNOOP("%s forced a JOIN in %s", source, channel);

			if (IS_NOT_NULL(chan = hash_channel_find(channel)))
				TimeStamp = chan->creation_time;
			else
				TimeStamp = NOW;

			snprintf(channel_TS, sizeof(channel_TS), "%lu", TimeStamp);

			if (FlagSet(uplink_capab, CAPAB_SSJOIN)) {

				char *ov[2];

				ov[0] = channel_TS;
				ov[1] = channel;

				chan_handle_SJOIN(source, 2, ov);
			}
			else {

				char *ov[5];

				ov[0] = channel_TS;
				ov[1] = channel_TS;
				ov[2] = channel;
				ov[3] = "+";
				ov[4] = (char *)source;

				chan_handle_SJOIN(user->server->name, 5, ov);
			}
		}
	}
}


/*********************************************************
 * user_handle_PART()                                    *
 * Handle a server PART command.                         *
 *                                                       *
 * av[0] = channels to leave                             *
 * av[1] = reason (optional)                             *
 *********************************************************/

void user_handle_PART(CSTR source, const int ac, char **av) {

	User *user;
	char *channel, *ptr;
	ChanListItem *item;

	#ifdef USE_STATS
	ChannelStats *cs;
	#endif


	TRACE_MAIN_FCLT(FACILITY_USERS_HANDLE_PART);

	if (IS_NULL(user = hash_onlineuser_find(source))) {

		log_error(FACILITY_USERS_HANDLE_PART, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"user_handle_PART: PART from nonexistent user %s: %s", source, merge_args(ac, av));

		return;
	}

	ptr = av[0];

	while (*(channel = ptr)) {

		TRACE_MAIN();
		ptr = channel + strcspn(channel, s_COMMA);

		if (*ptr)
			*ptr++ = 0;

		LOG_DEBUG("channels: %s (%s@%s) leaves %s", source, user->username, user->host, channel);

		for (item = user->chans; IS_NOT_NULL(item) && (str_not_equals_nocase(channel, item->chan->name)); item = item->next)
			;

		TRACE_MAIN();
		if (IS_NOT_NULL(item)) {

			TRACE_MAIN();
			chan_user_remove(user, item->chan);

			if (IS_NOT_NULL(item->next))
				item->next->prev = item->prev;

			if (IS_NOT_NULL(item->prev))
				item->prev->next = item->next;
			else
				user->chans = item->next;

			#ifdef USE_STATS
			++total.parts;
			++monthly.parts;
			++weekly.parts;
			++daily.parts;

			if (IS_NOT_NULL(cs = hash_chanstats_find(channel))) {

				++(cs->totalparts);
				++(cs->monthlyparts);
				++(cs->weeklyparts);
				++(cs->dailyparts);
				cs->last_change = NOW;
			}
			else
				LOG_DEBUG_SNOOP("error: [part] No channel record for %s", channel);

			TRACE_MAIN();

			servers_increase_messages(user);
			#endif

			TRACE_MAIN();
			#ifdef	FIX_USE_MPOOL
			mempool_free(channels_chan_entry_mempool, item);
			#else
			mem_free(item);
			#endif
		}
	}
}


/*********************************************************
 * user_handle_KICK()                                    *
 * Handle a server KICK command.                         *
 *                                                       *
 * av[0] = channel                                       *
 * av[1] = nick(s) being kicked                          *
 * av[2] = reason                                        *
 *********************************************************/

void user_handle_KICK(CSTR source, const int ac, char **av) {

	User *user;
	char *nick, *ptr;
	ChanListItem *item;

	#ifdef USE_STATS
	ChannelStats *cs;
	User *kicker;
	#endif


	TRACE_MAIN_FCLT(FACILITY_USERS_HANDLE_KICK);

	ptr = av[1];

	while (*(nick = ptr)) {

		TRACE_MAIN();
		ptr = nick + strcspn(nick, s_COMMA);

		if (*ptr)
			*ptr++ = 0;

		if (IS_NULL(user = hash_onlineuser_find(nick))) {

			log_error(FACILITY_USERS_HANDLE_KICK, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
				"user_handle_KICK: KICK for nonexistent user %s on %s: %s", nick, av[0], merge_args(ac, av));

			continue;
		}

		LOG_DEBUG("channels: kicking %s (%s@%s) from %s", user->nick, user->username, user->host, av[0]);

		for (item = user->chans; IS_NOT_NULL(item) && (str_not_equals_nocase(av[0], item->chan->name)); item = item->next)
			;

		TRACE_MAIN();
		if (IS_NOT_NULL(item)) {

			chan_user_remove(user, item->chan);

			if (IS_NOT_NULL(item->next))
				item->next->prev = item->prev;

			if (IS_NOT_NULL(item->prev))
				item->prev->next = item->next;
			else
				user->chans = item->next;

			TRACE_MAIN();

			#ifdef USE_STATS
			++total.kicks;
			++monthly.kicks;
			++weekly.kicks;
			++daily.kicks;

			if (IS_NOT_NULL(cs = hash_chanstats_find(av[0]))) {

				++(cs->totalkicks);
				++(cs->monthlykicks);
				++(cs->weeklykicks);
				++(cs->dailykicks);
				cs->last_change = NOW;
			}
			else
				LOG_DEBUG_SNOOP("error: [kick] No channel stats for %s", av[0]);

			if (IS_NOT_NULL(kicker = hash_onlineuser_find(source)))
				servers_increase_messages(kicker);
			#endif

			TRACE_MAIN();
			#ifdef	FIX_USE_MPOOL
			mempool_free(channels_chan_entry_mempool, item);
			#else
			mem_free(item);
			#endif
		}
	}
}
#endif /* defined(USE_SERVICES) || defined(USE_STATS) */


/*********************************************************
 * user_handle_newuserMODE()                             *
 * Handle user modes for connecting users.               *
 *********************************************************/

#if defined (USE_SERVICES)
static void user_handle_newuserMODE(User *user, char *newmodes, const NickInfo *ni) {

	char *ptr = newmodes;

	TRACE_MAIN_FCLT(FACILITY_USERS_HANDLE_NEWUSERMODE);

	while (*ptr) {

		switch (*ptr++) {

			case 'a':	AddFlag(user->mode, UMODE_a);	break;
			case 'A':	AddFlag(user->mode, UMODE_A);	break;
			case 'h':	AddFlag(user->mode, UMODE_h);	break;
			case 'i':	AddFlag(user->mode, UMODE_i);	break;
			case 'I':	AddFlag(user->mode, UMODE_I);	break;

			case 'o':
				/* Global operator. */

				AddFlag(user->mode, UMODE_o);
				++user_online_operator_count;
				break;


			case 'r':

				if (IS_NOT_NULL(ni)) {

					AddFlag(user->mode, UMODE_r);
					TRACE_MAIN();

					if (!user_is_identified_to(user, user->nick)) {

						++(user->idcount);
						user->id_nicks = mem_realloc(user->id_nicks, sizeof(char *) * user->idcount);
						user->id_nicks[user->idcount - 1] = str_duplicate(user->nick);
						user->current_lang = EXTRACT_LANG_ID(ni->langID);
					}

					check_oper(user, user->nick, NULL);
				}
				break;

			case 'R':	AddFlag(user->mode, UMODE_R);	break;
			case 'S':	AddFlag(user->mode, UMODE_S);	break;
			case 'x':	AddFlag(user->mode, UMODE_x);	break;
			case 'y':	AddFlag(user->mode, UMODE_y);	break;
			case 'z':	AddFlag(user->mode, UMODE_z);	break;
		}
	}
}

#elif defined (USE_STATS)
static void user_handle_newuserMODE(User *user, char *newmodes, SeenInfo *si) {

	char *ptr = newmodes;

	TRACE_MAIN_FCLT(FACILITY_USERS_HANDLE_NEWUSERMODE);

	if (IS_NULL(si))
		LOG_DEBUG_SNOOP("error: [newmode] Seen record for user %s not found!", user->nick);

	while (*ptr) {

		switch (*ptr++) {

			case 'a':
				AddFlag(user->mode, UMODE_a);

				if (IS_NOT_NULL(si))
					AddFlag(si->mode, UMODE_a);

				break;


			case 'A':
				AddFlag(user->mode, UMODE_A);

				if (IS_NOT_NULL(si))
					AddFlag(si->mode, UMODE_A);

				break;


			case 'h':
				AddFlag(user->mode, UMODE_h);

				if (IS_NOT_NULL(si))
					AddFlag(si->mode, UMODE_h);

				break;


			case 'i':
				AddFlag(user->mode, UMODE_i);

				if (IS_NOT_NULL(si))
					AddFlag(si->mode, UMODE_i);

				break;


			case 'I':
				AddFlag(user->mode, UMODE_I);

				if (IS_NOT_NULL(si))
					AddFlag(si->mode, UMODE_I);

				break;


			case 'o':
				/* Global operator. */

				AddFlag(user->mode, UMODE_o);
				++user_online_operator_count;

				if (IS_NOT_NULL(si))
					AddFlag(si->mode, UMODE_o);

				servers_oper_add(user);

				if (user_online_operator_count > records.maxopers) {

					records.maxopers = user_online_operator_count;
					records.maxopers_time = NOW;
				}

				break;


			case 'r':
				AddFlag(user->mode, UMODE_r);

				if (IS_NOT_NULL(si))
					AddFlag(si->mode, UMODE_r);

				break;


			case 'R':
				AddFlag(user->mode, UMODE_R);

				if (IS_NOT_NULL(si))
					AddFlag(si->mode, UMODE_R);

				break;


			case 'S':
				AddFlag(user->mode, UMODE_S);

				if (IS_NOT_NULL(si))
					AddFlag(si->mode, UMODE_S);

				break;


			case 'x':
				AddFlag(user->mode, UMODE_x);

				if (IS_NOT_NULL(si))
					AddFlag(si->mode, UMODE_x);

				break;


			case 'y':
				AddFlag(user->mode, UMODE_y);

				if (IS_NOT_NULL(si))
					AddFlag(si->mode, UMODE_y);

				break;


			case 'z':
				AddFlag(user->mode, UMODE_z);

				if (IS_NOT_NULL(si))
					AddFlag(si->mode, UMODE_z);

				break;
		}
	}
}
#else
static void user_handle_newuserMODE(User *user, char *newmodes) {

	char *ptr = newmodes;

	TRACE_MAIN_FCLT(FACILITY_USERS_HANDLE_NEWUSERMODE);

	while (*ptr) {

		switch (*ptr++) {

			case 'a':	AddFlag(user->mode, UMODE_a);	break;
			case 'A':	AddFlag(user->mode, UMODE_A);	break;
			case 'h':	AddFlag(user->mode, UMODE_h);	break;
			case 'i':	AddFlag(user->mode, UMODE_i);	break;
			case 'I':	AddFlag(user->mode, UMODE_I);	break;

			case 'o':
				/* Global operator. */

				AddFlag(user->mode, UMODE_o);
				++user_online_operator_count;

				break;

			case 'r':	AddFlag(user->mode, UMODE_r);	break;
			case 'R':	AddFlag(user->mode, UMODE_R);	break;
			case 'S':	AddFlag(user->mode, UMODE_S);	break;
			case 'x':	AddFlag(user->mode, UMODE_x);	break;
			case 'y':	AddFlag(user->mode, UMODE_y);	break;
			case 'z':	AddFlag(user->mode, UMODE_z);	break;
		}
	}
}
#endif


/* Handy macro. */

#ifdef USE_STATS

#define MODE(flag) \
	if (IS_NOT_NULL(si)) \
		add ? AddFlag(si->mode, (flag)) : RemoveFlag(si->mode, (flag)); \
	++(total.umodes); \
	++(monthly.umodes); \
	++(weekly.umodes); \
	++(daily.umodes); \
	if (add) \
		AddFlag(user->mode, (flag)); \
	else \
		RemoveFlag(user->mode, (flag));

#else

#define MODE(flag) \
	if (add) \
		AddFlag(user->mode, (flag)); \
	else \
		RemoveFlag(user->mode, (flag));

#endif


/*********************************************************
 * user_handle_userMODE()                                *
 * Handle a server MODE command for a user.              *
 *                                                       *
 * av[0] = nick to change mode for                       *
 * av[1] = modes                                         *
 *********************************************************/

void user_handle_userMODE(CSTR source, const int ac, char **av) {

	User *user;
	char *ptr;
	BOOL add = TRUE;

	#ifdef USE_STATS
	SeenInfo *si;
	#endif


	TRACE_MAIN_FCLT(FACILITY_USERS_HANDLE_USERMODE);

	if (str_not_equals_nocase(source, av[0])) {

		log_error(FACILITY_USERS_HANDLE_USERMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"user_handle_userMODE: MODE %s %s from different nick %s!", av[0], av[1], source);

		return;
	}

	TRACE_MAIN();

	if (IS_NULL(user = hash_onlineuser_find(source))) {

		log_error(FACILITY_USERS_HANDLE_USERMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"user_handle_userMODE: MODE %s for nonexistent nick %s: %s", av[1], source, merge_args(ac, av));

		return;
	}

	LOG_DEBUG("users: Changing mode for %s (%s@%s) to %s", source, user->username, user->host, av[1]);

	#ifdef USE_STATS
	if (IS_NULL(si = hash_seeninfo_find(source)) && !is_seen_exempt(user->nick, user->username, user->host, user->ip))
		LOG_DEBUG_SNOOP("error: [mode] Seen record for user %s not found!", source);

	servers_increase_messages(user);
	#endif

	ptr = av[1];

	TRACE_MAIN();

	while (*ptr) {

		switch (*ptr++) {

			case '+':	add = TRUE;		break;
			case '-':	add = FALSE;	break;

			case 'a':
				MODE(UMODE_a)
				break;

			case 'A':
				MODE(UMODE_A)
				break;

			case 'h':
				MODE(UMODE_h)
				break;

			case 'i':
				MODE(UMODE_i)
				break;

			case 'I':
				MODE(UMODE_I)
				break;

			case 'o':
				/* Global operator. */

				if (add) {

					AddFlag(user->mode, UMODE_o);
					++user_online_operator_count;

					#ifdef USE_STATS
					if (IS_NOT_NULL(si))
						AddFlag(si->mode, UMODE_o);

					servers_oper_add(user);

					if (user_online_operator_count > records.maxopers) {

						records.maxopers = user_online_operator_count;
						records.maxopers_time = NOW;
					}
					#endif
				}
				else {

					RemoveFlag(user->mode, UMODE_o);
					--user_online_operator_count;

					#ifdef USE_STATS
					servers_oper_remove(user);

					if (IS_NOT_NULL(si))
						RemoveFlag(si->mode, UMODE_o);
					#endif
				}

				break;

			case 'r':
				#ifdef USE_SERVICES
				/* Services should never use this case anymore. */

				if (IS_NOT_NULL(user->ni)) {
				#endif

					if (add) {

						AddFlag(user->mode, UMODE_r);

						#ifdef USE_STATS
						if (IS_NOT_NULL(si))
							AddFlag(si->mode, UMODE_r);
						#endif

						#ifdef USE_SERVICES
						if (!user_is_identified_to(user, user->nick)) {

							++(user->idcount);

							user->id_nicks = mem_realloc(user->id_nicks, sizeof(char *) * user->idcount);
							user->id_nicks[user->idcount - 1] = str_duplicate(user->nick);

							user->current_lang = EXTRACT_LANG_ID(user->ni->langID);
						}
						#endif

					}
					else {

						RemoveFlag(user->mode, UMODE_r);

						#ifdef USE_STATS
						if (IS_NOT_NULL(si))
							RemoveFlag(si->mode, UMODE_r);
						#endif
					}

				#ifdef USE_SERVICES
				}
				#endif

				break;

			case 'R':
				MODE(UMODE_R)
				break;

			case 'S':
				MODE(UMODE_S)
				break;

			case 'x':
				MODE(UMODE_x)
				break;

			case 'y':
				MODE(UMODE_y)
				break;

			case 'z':
				MODE(UMODE_z)
				break;
		}
	}
}

#undef MODE


/*********************************************************
 * user_handle_QUIT()                                    *
 * Handle a server QUIT command.                         *
 *                                                       *
 * av[0] = reason                                        *
 *********************************************************/

void user_handle_QUIT(CSTR source, const int ac, char **av) {

	User		*user;

	#ifdef USE_STATS
	SeenInfo	*si;
	BOOL		isKill = FALSE;
	#endif


	TRACE_MAIN_FCLT(FACILITY_USERS_HANDLE_QUIT);

	if (IS_NULL(user = hash_onlineuser_find(source))) {

		if ((ac > 0) && str_not_equals_partial(av[0], "Autokilled:", 11))
			log_error(FACILITY_USERS_HANDLE_QUIT, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
				"user_handle_QUIT: QUIT for nonexistent nick %s: %s", source, merge_args(ac, av));

		return;
	}

	if (FlagSet(user->flags, USER_FLAG_AGENT)) {

		user_delete_user(user);
		introduce_services_agent(source);
		send_globops(NULL, "\2%s\2 revived after quit", source);
		return;
	}

	TRACE_MAIN();

	#ifdef USE_SERVICES
	if (IS_NOT_NULL(user->ni)) {

		if (FlagSet(user->flags, USER_FLAG_ENFORCER)) {

			if (!timeout_remove(toNickServ, TOTYPE_NICKSERV_RELEASE, (unsigned long)user->ni))
				log_error(FACILITY_USERS_HANDLE_QUIT, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING, 
					"user_handle_QUIT(): Timeout not found for %s (NickServ/Release)", user->ni->nick);

			RemoveFlag(user->ni->flags, NI_ENFORCED);
		}
		else if (FlagSet(user->ni->flags, NI_TIMEOUT)) {

			NickTimeoutData		*ntd;

			ntd = (NickTimeoutData*) timeout_get_data(toNickServ, TOTYPE_NICKSERV_COUNTDOWN, (unsigned long) user->ni);

			if (IS_NOT_NULL(ntd))
				ntd->user_online = FALSE;
		}
		else if (FlagUnset(user->ni->flags, NI_FORBIDDEN) &&
			(user_is_identified_to(user, user->ni->nick) || is_on_access(user, user->ni))) {

			user->ni->last_seen = NOW;

			if (IS_NOT_NULL(user->ni->last_usermask))
				mem_free(user->ni->last_usermask);
			user->ni->last_usermask = mem_malloc(str_len(user->username) + str_len(user_public_host(user)) + 2);
			sprintf(user->ni->last_usermask, "%s@%s", user->username, user_public_host(user));
		}
	}
	else if (str_equals_partial(source, "Guest", 5)) {

		long int guestNumber;
		char *err;

		/* Make sure only real Guests are removed. Use strtol() to ignore Guest343ABC and the like. */
		guestNumber = strtol(source + 5, &err, 10);

		/* nickserv_guest_free() will make sure the guest number is valid. Guest123 and the like will be ignored. */
		if (*err == '\0')
			nickserv_guest_free(guestNumber);
	}
	#endif

	TRACE_MAIN();

	#ifdef USE_STATS
	isKill = str_equals_partial(av[0], "Local kill by ", 14);

	if (isKill) {

		if (IS_NOT_NULL(user->server->stats))
			servers_update_killcount(user, user);
		else
			LOG_DEBUG_SNOOP("user_handle_quit(): Server %s used by %s is without stats", user->server->name, user->nick);
	}

	if (!is_seen_exempt(user->nick, user->username, user->host, user->ip)) {

		TRACE_MAIN();

		if (IS_NOT_NULL(si = hash_seeninfo_find(source))) {

			if (IS_NOT_NULL(si->tempnick)) {

				mem_free(si->tempnick);
				si->tempnick = NULL;
			}

			if (isKill) {

				char *string = &av[0][14];	/* Points to first char of the killer. */
				char *killer, *reason;

				++(total.kills);
				++(monthly.kills);
				++(weekly.kills);
				++(daily.kills);

				si->type = SEEN_TYPE_KILL;

				killer = strtok(string, s_SPACE);

				if (IS_NOT_NULL(si->tempnick))
					mem_free(si->tempnick);
				si->tempnick = str_duplicate(killer);

				/* Free it -- it will be filled below. */
				if (IS_NOT_NULL(si->quitmsg))
					mem_free(si->quitmsg);

				reason = strtok(NULL, s_NULL);

				if (IS_NOT_NULL(reason)) {

					/* Skip leading '('. */
					++reason;

					/* Skip trailing ')'. */
					reason[str_len(reason) - 1] = '\0';

					if (str_not_equals_nocase(killer, reason))
						si->quitmsg = str_duplicate(reason);
					else
						si->quitmsg = str_duplicate("Nessun motivo specificato.");
				}
				else
					si->quitmsg = str_duplicate("Nessun motivo specificato.");

				si->last_seen = NOW;
			}
			else {

				if (IS_NOT_NULL(si->quitmsg))
					mem_free(si->quitmsg);

				if (str_equals_partial(av[0], "Autokilled: ", 12)) {

					si->type = SEEN_TYPE_AKILL;
					si->quitmsg = str_duplicate(av[0] + 12);
				}
				else if (str_equals_partial(av[0], "K-Lined: ", 9)) {

					si->type = SEEN_TYPE_KLINE;
					si->quitmsg = str_duplicate(av[0] + 9);
				}
				else {

					si->type = SEEN_TYPE_QUIT;
					si->quitmsg = str_duplicate(av[0]);
				}

				++(total.quits);
				++(monthly.quits);
				++(weekly.quits);
				++(daily.quits);

				si->last_seen = NOW;

				if (IS_NOT_NULL(si->tempnick)) {

					mem_free(si->tempnick);
					si->tempnick = NULL;
				}
			}
		}
		else
			LOG_DEBUG_SNOOP("[quit] No seen record for user %s!", source);
	}

	servers_increase_messages(user);
	#endif

	#ifdef USE_SOCKSMONITOR
	remove_apm(user->nick, 'q');
	#endif

	TRACE_MAIN();
	user_delete_user(user);
	TRACE_MAIN();
}

#ifdef ENABLE_CAPAB_NOQUIT
int user_handle_server_SQUIT(const Server *server) {

	/* This server just split and we have to remove all its users. */

	User		*user, *next;
	int			idx, count = 0;

	#ifdef USE_STATS
	SeenInfo	*si;
	#endif


	TRACE_MAIN_FCLT(FACILITY_USERS_HANDLE_SERVER_SQUIT);

	HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM_SAFE(onlineuser, idx, user, next) {

			if (user->server != server)
				continue;

			++count;

			LOG_DEBUG("users: %s (%s@%s) splits", user->nick, user->username, user->host);

			if (FlagSet(user->flags, USER_FLAG_AGENT)) {

				/* WTF? */
				char *nick = str_duplicate(user->nick);

				user_delete_user(user);
				introduce_services_agent(nick);
				send_globops(NULL, "\2%s\2 revived after server split", nick);
				mem_free(nick);
				continue;
			}

			#ifdef USE_SERVICES
			TRACE_MAIN();

			if (IS_NOT_NULL(user->ni)) {

				if (FlagUnset(user->ni->flags, NI_FORBIDDEN) && FlagUnset(user->mode, UMODE_I) &&
					(user_is_identified_to(user, user->ni->nick) || is_on_access(user, user->ni))) {

					user->ni->last_seen = NOW;

					if (IS_NOT_NULL(user->ni->last_usermask))
						mem_free(user->ni->last_usermask);
					user->ni->last_usermask = mem_malloc(str_len(user->username) + str_len(user_public_host(user)) + 2);
					sprintf(user->ni->last_usermask, "%s@%s", user->username, user_public_host(user));
				}

				if (FlagSet(user->ni->flags, NI_TIMEOUT)) {

					NickTimeoutData *ntd;

					ntd = (NickTimeoutData*) timeout_get_data(toNickServ, TOTYPE_NICKSERV_COUNTDOWN, (unsigned long) user->ni);

					if (IS_NOT_NULL(ntd))
						ntd->user_online = FALSE;
				}
			}
			else if (str_equals_partial(user->nick, "Guest", 5)) {

				long int guestNumber;
				char *err;

				guestNumber = strtol(user->nick + 5, &err, 10);

				if (*err == '\0')
					nickserv_guest_free(guestNumber);
			}
			#endif

			#ifdef USE_STATS
			if (!is_seen_exempt(user->nick, user->username, user->host, user->ip)) {

				TRACE_MAIN();

				if (IS_NOT_NULL(si = hash_seeninfo_find(user->nick))) {

					if (IS_NOT_NULL(si->tempnick)) {

						mem_free(si->tempnick);
						si->tempnick = NULL;
					}

					if (IS_NOT_NULL(si->quitmsg)) {

						mem_free(si->quitmsg);
						si->quitmsg = NULL;
					}

					++(total.quits);
					++(monthly.quits);
					++(weekly.quits);
					++(daily.quits);

					si->type = SEEN_TYPE_SPLIT;
					si->last_seen = NOW;
				}
				else
					LOG_DEBUG_SNOOP("[quit] No seen record for user %s!", user->nick);
			}

			servers_increase_messages(user);
			#endif

			#ifdef USE_SOCKSMONITOR
			remove_apm(user->nick, 'q');
			#endif

			TRACE_MAIN();
			user_delete_user(user);
			TRACE_MAIN();
		}
	}

	return count;
}
#endif


/*********************************************************
 * user_handle_KILL()                                    *
 * Handle a server KILL command.                         *
 *                                                       *
 * av[0] = nick being killed                             *
 * av[1] = reason                                        *
 *********************************************************/

void user_handle_KILL(CSTR source, const int ac, char **av) {

	User *user, *killerUser;

	#ifdef USE_STATS
	SeenInfo	*si;
	#endif


	TRACE_MAIN_FCLT(FACILITY_USERS_HANDLE_KILL);

	if (IS_NULL(user = hash_onlineuser_find(av[0]))) {

		log_error(FACILITY_USERS_HANDLE_KILL, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"user_handle_KILL: KILL for nonexistent nick %s by %s: %s", av[0], source, merge_args(ac, av));

		return;
	}

	LOG_DEBUG("users: %s (%s@%s) was killed by %s", av[0], user->username, user->host, source);

	if (FlagSet(user->flags, USER_FLAG_AGENT)) {

		if (!strchr(source, '.')) {

			if (IS_NOT_NULL(killerUser = hash_onlineuser_find(source))) {

				send_notice_to_user(s_Snooper, killerUser, "Do \2*NOT*\2 kill services!");
				send_user_SVSMODE(s_Snooper, source, "-oaAz", 0);
			}

			send_globops(NULL, "\2%s\2 tried to kill a services client!", source);
		}
		else
			send_globops(NULL, "\2%s\2 revived after server kill", av[0]);

		user_delete_user(user);
		introduce_services_agent(av[0]);
		return;
	}

	#ifdef USE_SERVICES
	if (IS_NOT_NULL(user->ni)) {

		if (FlagSet(user->ni->flags, NI_ENFORCED)) {

			if (!timeout_remove(toNickServ, TOTYPE_NICKSERV_RELEASE, (unsigned long)user->ni))
				log_error(FACILITY_USERS_HANDLE_KILL, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING, 
					"user_handle_KILL(): Timeout not found for %s (NickServ/Release)", user->ni->nick);

			RemoveFlag(user->ni->flags, NI_ENFORCED);
		}
		else if (FlagSet(user->ni->flags, NI_TIMEOUT)) {

			NickTimeoutData *ntd;

			ntd = (NickTimeoutData*) timeout_get_data(toNickServ, TOTYPE_NICKSERV_COUNTDOWN, (unsigned long)user->ni);

			if (IS_NOT_NULL(ntd))
				ntd->user_online = FALSE;
		}
	}
	else if (str_equals_partial(av[0], "Guest", 5)) {

		long int guestNumber;
		char *err;

		guestNumber = strtol(av[0] + 5, &err, 10);

		if (*err == '\0')
			nickserv_guest_free(guestNumber);
	}
	#endif

	TRACE_MAIN();

	#ifdef USE_STATS
	if (!is_seen_exempt(user->nick, user->username, user->host, user->ip)) {

		if (IS_NOT_NULL(si = hash_seeninfo_find(av[0]))) {

			char *reason;


			si->type = SEEN_TYPE_KILL;

			TRACE_MAIN();
			if (IS_NOT_NULL(si->quitmsg))
				mem_free(si->quitmsg);

			reason = strchr(av[1], '(');

			if (IS_NULL(reason) || str_equals(reason, "())"))
				si->quitmsg = str_duplicate("Nessun motivo specificato.");

			else {

				/* Kill leading '(' and trailing ')' */
				++reason;
				reason[str_len(reason) - 1] = '\0';

				si->quitmsg = str_duplicate(reason);
			}

			if (IS_NOT_NULL(si->tempnick))
				mem_free(si->tempnick);
			si->tempnick = str_duplicate(source);

			si->last_seen = NOW;
		}
		else
			LOG_DEBUG_SNOOP("[kill] No seen record for user %s!", av[0]);
	}

	TRACE_MAIN();
	if (!strchr(source, '.')) {

		if (IS_NOT_NULL(killerUser = hash_onlineuser_find(source)))
			servers_increase_messages(killerUser);
	}
	else
		killerUser = NULL;

	servers_update_killcount(user, killerUser);

	++(total.kills);
	++(monthly.kills);
	++(weekly.kills);
	++(daily.kills);
	#endif

	#ifdef USE_SOCKSMONITOR
	remove_apm(user->nick, 'k');
	#endif

	TRACE_MAIN();
	user_delete_user(user);
	TRACE_MAIN();
}


/*********************************************************
 * introduce_services_agent()                            *
 *                                                       *
 * Send a NICK command for the given pseudo-client, or   *
 * for all of them if 'nick' is NULL.                    *
 *********************************************************/

void introduce_services_agent(CSTR nick) {

#define LTSIZE 3
	static int lasttimes[LTSIZE];

	if (lasttimes[0] >= time(NULL)-3)
		fatal_error(FACILITY_USERS, __LINE__, "introduce_user() loop detected");

	memmove(lasttimes, lasttimes+1, sizeof(lasttimes)-sizeof(int));
	lasttimes[LTSIZE-1] = time(NULL);
#undef LTSIZE

	TRACE_FCLT(FACILITY_USERS_INTRODUCE_USER);

	#ifdef USE_SERVICES	
	if (IS_NULL(nick) || IS_EMPTY_STR(nick) || str_equals_nocase(nick, s_NickServ)) {

		send_NICK(s_NickServ, "+", CONF_SERVICES_USERNAME, CONF_SERVICES_HOST, "Nickname Services");
		user_add_services_agent(s_NickServ, 0, "Nickname Services");
	}

	TRACE();
	if (IS_NULL(nick) || IS_EMPTY_STR(nick) || str_equals_nocase(nick, s_ChanServ)) {

		send_NICK(s_ChanServ, "+z", CONF_SERVICES_USERNAME, CONF_SERVICES_HOST, "Channel Services");
		user_add_services_agent(s_ChanServ, UMODE_z, "Channel Services");
	}

	TRACE();
	if (IS_NULL(nick) || IS_EMPTY_STR(nick) || str_equals_nocase(nick, s_HelpServ)) {

		send_NICK(s_HelpServ, "+", CONF_SERVICES_USERNAME, CONF_SERVICES_HOST, "Help Services");
		user_add_services_agent(s_HelpServ, 0, "Help Services");
	}

	TRACE();
	if (IS_NULL(nick) || IS_EMPTY_STR(nick) || str_equals_nocase(nick, s_MemoServ)) {

		send_NICK(s_MemoServ, "+", CONF_SERVICES_USERNAME, CONF_SERVICES_HOST, "Memo Services");
		user_add_services_agent(s_MemoServ, 0, "Memo Services");
	}

	TRACE();
	if (IS_NULL(nick) || IS_EMPTY_STR(nick) || str_equals_nocase(nick, s_OperServ)) {

		send_NICK(s_OperServ, "+i", CONF_SERVICES_USERNAME, CONF_SERVICES_HOST, "Operator Services");
		user_add_services_agent(s_OperServ, UMODE_i, "Operator Services");
	}

	TRACE();
	if (IS_NULL(nick) || IS_EMPTY_STR(nick) || str_equals_nocase(nick, s_RootServ)) {

		send_NICK(s_RootServ, "+i", CONF_SERVICES_USERNAME, CONF_SERVICES_HOST, "Services Root System");
		user_add_services_agent(s_RootServ, UMODE_i, "Services Root System");
	}

	TRACE();
	if (IS_NULL(nick) || IS_EMPTY_STR(nick) || str_equals_nocase(nick, s_GlobalNoticer)) {

		send_NICK(s_GlobalNoticer, "+iz", CONF_SERVICES_USERNAME, CONF_SERVICES_HOST, "Global Noticer");
		user_add_services_agent(s_GlobalNoticer, UMODE_i | UMODE_z, "Global Noticer");

		if (nick)
			send_SJOIN(s_GlobalNoticer, CONF_SNOOP_CHAN);
	}
	#endif

	TRACE();
	if (IS_NULL(nick) || IS_EMPTY_STR(nick) || str_equals_nocase(nick, s_DebugServ)) {

		send_NICK(s_DebugServ, "+iz", CONF_SERVICES_USERNAME, CONF_SERVICES_HOST, "Coders Aid Services");
		user_add_services_agent(s_DebugServ, UMODE_i | UMODE_z, "Coders Aid Services");

		if (nick)
			send_SJOIN(s_DebugServ, CONF_DEBUG_CHAN);
	}

	#ifdef USE_SOCKSMONITOR
	TRACE();
	if (IS_NULL(nick) || IS_EMPTY_STR(nick) || str_equals_nocase(nick, s_SocksMonitor)) {

		send_NICK(s_SocksMonitor, "+i", CONF_SERVICES_USERNAME, CONF_SERVICES_HOST, "Socks Monitor");
		user_add_services_agent(s_SocksMonitor, UMODE_i, "Socks Monitor");
	}
	#endif

	#ifdef USE_STATS
	TRACE();
	if (IS_NULL(nick) || IS_EMPTY_STR(nick) || str_equals_nocase(nick, s_StatServ)) {

		send_NICK(s_StatServ, "+i", CONF_SERVICES_USERNAME, CONF_SERVICES_HOST, "Statistical Services");
		user_add_services_agent(s_StatServ, 0, "Statistical Services");
	}

	TRACE();
	if (IS_NULL(nick) || IS_EMPTY_STR(nick) || str_equals_nocase(nick, s_SeenServ)) {

		send_NICK(s_SeenServ, "+", CONF_SERVICES_USERNAME, CONF_SERVICES_HOST, "Seen Services");
		user_add_services_agent(s_SeenServ, 0, "Seen Services");
	}
	#endif

	#ifdef USE_BOTSERV
	TRACE();
	if (IS_NULL(nick) || IS_EMPTY_STR(nick) || str_equals_nocase(nick, s_BotServ)) {

		send_NICK(s_BotServ, "+iz", CONF_SERVICES_USERNAME, CONF_SERVICES_HOST, "Bot Services");
		user_add_services_agent(s_BotServ, UMODE_i | UMODE_z, "Bot Services");
	}
	#endif
}


/*********************************************************
 * Utility                                               *
 *********************************************************/

BOOL user_is_ircop(const User *user) {

	if (IS_NULL(user)) {

		log_error(FACILITY_USERS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "user_is_ircop()", s_LOG_NULL, "user");

		return FALSE;
	}

	return FlagSet(user->mode, UMODE_o);
}


BOOL nick_is_ircop(CSTR nick) {

	if (IS_NULL(nick) || IS_EMPTY_STR(nick)) {

		log_error(FACILITY_USERS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "nick_is_ircop()", s_LOG_NULL, "nick");

		return FALSE;
	}
	else {

		User *user;

		if (IS_NULL(user = hash_onlineuser_find(nick)))
			return FALSE;

		return FlagSet(user->mode, UMODE_o);
	}
}


BOOL user_is_admin(const User *user) {

	if (IS_NULL(user)) {

		log_error(FACILITY_USERS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "user_is_admin()", s_LOG_NULL, "user");

		return FALSE;
	}

	return FlagSet(user->mode, UMODE_A);
}


BOOL nick_is_service(CSTR name) {

	if (
		#ifdef USE_SERVICES
		(str_equals_nocase(name, s_NickServ)) ||
		(str_equals_nocase(name, s_ChanServ)) ||
		(str_equals_nocase(name, s_OperServ)) ||
		(str_equals_nocase(name, s_MemoServ)) ||
		(str_equals_nocase(name, s_RootServ)) ||
		(str_equals_nocase(name, s_GlobalNoticer)) ||
		#endif
		#ifdef USE_STATS
		(str_equals_nocase(name, s_StatServ)) ||
		(str_equals_nocase(name, s_SeenServ)) ||
		#endif
		#ifdef USE_SOCKSMONITOR
		(str_equals_nocase(name, s_SocksMonitor)) ||
		#endif
		#ifdef USE_BOTSERV
		(str_equals_nocase(name, s_BotServ)) ||
		#endif
		(str_equals_nocase(name, s_DebugServ)))

		return TRUE;
	else
		return FALSE;
}


BOOL user_is_services_agent(const User *user) {

	if (IS_NULL(user)) {

		log_error(FACILITY_USERS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "user_is_services_agent()", s_LOG_NULL, "user");

		return FALSE;
	}

	return FlagSet(user->mode, UMODE_z);
}

BOOL nick_is_services_agent(CSTR nick) {

	if (IS_NULL(nick) || IS_EMPTY_STR(nick)) {

		log_error(FACILITY_USERS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "nick_is_services_agent()", s_LOG_NULL, "nick");

		return FALSE;
	}
	else {

		User *user;

		if (IS_NULL(user = hash_onlineuser_find(nick)))
			return FALSE;

		return FlagSet(user->mode, UMODE_z);
	}
}

BOOL user_is_services_client(const User *user) {

	if (IS_NULL(user))
		return FALSE;

	return (FlagSet(user->flags, USER_FLAG_ENFORCER) || FlagSet(user->flags, USER_FLAG_AGENT));
}

BOOL nick_is_services_client(CSTR nick) {

	if (IS_NULL(nick) || IS_EMPTY_STR(nick))
		return FALSE;

	else {

		User *user;

		if (IS_NULL(user = hash_onlineuser_find(nick)))
			return FALSE;

		return user_is_services_client(user);
	}
}


#if defined(USE_SERVICES) || defined(USE_STATS)

BOOL user_isin_chan(const User *user, CSTR chan) {

	ChanListItem *item;


	if (IS_NULL(user) || IS_NULL(chan)) {

		log_error(FACILITY_USERS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "user_isin_chan()", s_LOG_NULL, IS_NULL(user) ? "user" : "chan");

		return FALSE;
	}

	item = user->chans;

	while (IS_NOT_NULL(item)) {

		if (IS_NOT_NULL(item->chan) && str_equals_nocase(item->chan->name, chan))
			return TRUE;

		item = item->next;
	}

	return FALSE;
}


BOOL user_is_chanop(CSTR nick, CSTR channel, Channel *chan) {

	UserListItem *item;


	if (IS_NULL(nick)) {

		log_error(FACILITY_USERS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "user_is_chanop()", s_LOG_NULL, "nick");

		return FALSE;
	}

	if (IS_NULL(chan))
		chan = hash_channel_find(channel);

	if (IS_NOT_NULL(chan)) {

		for (item = chan->chanops; IS_NOT_NULL(item); item = item->next) {

			if (str_equals_nocase(item->user->nick, nick))
				return TRUE;
		}
	}

	return FALSE;
}

BOOL user_is_chanhalfop(CSTR nick, CSTR channel, Channel *chan) {

	UserListItem *item;


	if (IS_NULL(nick)) {

		log_error(FACILITY_USERS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "user_is_chanhalfop()", s_LOG_NULL, "nick");

		return FALSE;
	}

	if (IS_NULL(chan))
		chan = hash_channel_find(channel);

	if (IS_NOT_NULL(chan)) {

		for (item = chan->halfops; IS_NOT_NULL(item); item = item->next) {

			if (str_equals_nocase(item->user->nick, nick))
				return TRUE;
		}
	}

	return FALSE;
}

BOOL user_is_chanvoice(CSTR nick, CSTR channel, Channel *chan) {

	UserListItem *item;


	if (IS_NULL(nick)) {

		log_error(FACILITY_USERS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "user_is_chanvoice()", s_LOG_NULL, "nick");

		return FALSE;
	}

	if (IS_NULL(chan))
		chan = hash_channel_find(channel);

	if (IS_NOT_NULL(chan)) {

		for (item = chan->voices; IS_NOT_NULL(item); item = item->next) {

			if (str_equals_nocase(item->user->nick, nick))
				return TRUE;
		}
	}

	return FALSE;
}
#endif /* defined(USE_SERVICES) || defined(USE_STATS) */


/*********************************************************
 * user_usermask_match()                                 *
 *                                                       *
 * Does the user's usermask match the given mask         *
 * (either nick!user@host or just user@host) ?           *
 *********************************************************/

BOOL user_usermask_match(CSTR mask, const User *user, BOOL matchMaskedHost, BOOL matchCIDR) {

 	char nick[NICKSIZE], username[USERSIZE], host[HOSTSIZE], token[MASKSIZE];
	char *ptr;
	CIDR_IP cidr;


	TRACE_FCLT(FACILITY_USERS_USERMASK_MATCH);

	if (IS_NULL(mask) || IS_EMPTY_STR(mask) || IS_NULL(user)) {

		log_error(FACILITY_USERS_USERMASK_MATCH, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, s_LOG_ERR_PARAMETER, 
			"user_usermask_match()", s_LOG_NULL, IS_NULL(user) ? "user" : "mask");

		return FALSE;
	}

	memset(token, 0, sizeof(token));
	memset(nick, 0, sizeof(nick));
	memset(username, 0, sizeof(username));
	memset(host, 0, sizeof(host));

	/* Begin splitting the mask. */
	if (strchr(mask, c_EXCLAM)) {

		if ((ptr = str_tokenize(mask, token, sizeof(token), c_EXCLAM)))
			str_copy_checked(token, nick, NICKSIZE);

		if ((ptr = str_tokenize(ptr, token, sizeof(token), c_AT)))
			str_copy_checked(token, username, USERSIZE);
	}
	else {

		if ((ptr = str_tokenize(mask, token, sizeof(token), c_AT)))
			str_copy_checked(token, username, USERSIZE);
	}

	if ((ptr = str_tokenize(ptr, token, sizeof(token), c_NULL)))
		str_copy_checked(token, host, HOSTSIZE);

	/* Done splitting. Sanity checks: if any of these is empty, the mask was bogus. */
	if (IS_EMPTY_STR(username) || IS_EMPTY_STR(host))
		return FALSE;

	/* If we have a nick, make sure it matches ours. */
	if (IS_NOT_EMPTY_STR(nick) && !str_match_wild_nocase(nick, user->nick))
		return FALSE;

	/* The given username must match ours. */
	if (!str_match_wild_nocase(username, user->username))
		return FALSE;

	/* The given host must also match ours. */
	if (str_match_wild_nocase(host, user->host))
		return TRUE;

	/* If we chose to match the masked host as well, make sure it does match. */
	if (matchMaskedHost && str_match_wild_nocase(host, user->maskedHost))
		return TRUE;

	if (matchCIDR) {

		char *ip = get_ip(user->ip);

		if (str_match_wild_nocase(host, ip))
			return TRUE;

		if (cidr_ip_fill(host, &cidr, FALSE) != cidrSuccess)
			return FALSE;

		if (cidr_match(&cidr, user->ip))
			return TRUE;
	}

	return FALSE;
}


/*********************************************************
 * user_usermask_split()                                 *
 *                                                       *
 * Split a usermask up into its constitutent parts.      *
 * Returned strings are malloc()'d, and should be        *
 * free()'d when done with.                              *
 * Returns "*" for missing parts.                        *
 *********************************************************/

void user_usermask_split(CSTR mask, char **nick, char **user, char **host) {

	char *ptr, token[IRCBUFSIZE];
	char nickbuf[NICKSIZE], userbuf[USERSIZE], hostbuf[HOSTSIZE];


	TRACE_FCLT(FACILITY_USERS_USERMASK_SPLIT);

	if (IS_NULL(mask) || IS_EMPTY_STR(mask)) {

		log_error(FACILITY_USERS_USERMASK_SPLIT, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, s_LOG_ERR_PARAMETER, 
			"user_usermask_split()", s_LOG_NULL, "mask");

		return;
	}

	str_copy_checked(s_STAR, nickbuf, NICKSIZE);
	str_copy_checked(s_STAR, userbuf, USERSIZE);
	str_copy_checked(s_STAR, hostbuf, HOSTSIZE);

	if (strchr(mask, c_EXCLAM)) {

		if ((ptr = str_tokenize(mask, token, sizeof(token), c_EXCLAM)) && *token)
			str_copy_checked(token, nickbuf, 31 /* Change to NICKSIZE when NICKMAX = 30 */);

		if ((ptr = str_tokenize(ptr, token, sizeof(token), c_AT)) && *token)
			str_copy_checked(token, userbuf, USERSIZE);
	}
	else {

		if ((ptr = str_tokenize(mask, token, sizeof(token), c_AT)) && *token) {

			if (*ptr)
				str_copy_checked(token, userbuf, USERSIZE);
			else
				str_copy_checked(token, nickbuf, 31);
		}
	}

	if ((ptr = str_tokenize(ptr, token, sizeof(token), c_NULL)) && *token)
		str_copy_checked(token, hostbuf, HOSTSIZE);

	TRACE();
	*nick = str_duplicate(nickbuf);
	*user = str_duplicate(userbuf);
	*host = str_duplicate(hostbuf);
}


/*********************************************************
 * user_usermask_create()                                *
 *                                                       *
 * Given a user, return a mask that in the requested     *
 * format. Available formats are:                        *
 *                                                       *
 * 0: *!user@host.domain                                 *
 * 1: *!*user@host.domain                                *
 * 2: *!*@host.domain                                    *
 * 3: *!*user@*.domain                                   *
 * 4: *!*@*.domain                                       *
 * 5: nick!user@host.domain (default)                    *
 * 6: nick!*user@host.domain                             *
 * 7: nick!*@host.domain                                 *
 * 8: nick!*user@*.domain                                *
 * 9: nick!*@*.domain                                    *
 *                                                       *
 * Return value is allocated and must be freed when done.*
 *********************************************************/

char *user_usermask_create(const User *user, short type) {

	char *mask, *user_host;


	TRACE_FCLT(FACILITY_USERS_USERMASK_CREATE);

	if (IS_NULL(user)) {

		log_error(FACILITY_USERS_USERMASK_CREATE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "user_usermask_create()", s_LOG_NULL, "user");

		return NULL;
	}

	TRACE();
	user_host = user_public_host(user);

	switch (type) {

		case 0:
			/* *!user@host.domain */
			mask = mem_malloc(str_len(user->username) + str_len(user_host) + 4);
			sprintf(mask, "*!%s@%s", user->username, user_host);
			break;

		case 1: {
			/* *!*user@host.domain */

			size_t len = str_len(user->username);

			mask = mem_malloc(len + str_len(user_host) + ((len > 9) ? 4 : 5));
			sprintf(mask, "*!*%s@%s", (len > 9 || user->username[0] == '~') ? &user->username[1] : user->username, user_host);
			break;
		}

		case 2:
			/* *!*@host.domain */

			mask = mem_malloc(str_len(user_host) + 5);
			sprintf(mask, "*!*@%s", user_host);
			break;

		case 3: {
			/* *!*user@*.domain */

			size_t len = str_len(user->username);
			char *ptr;

			if (FlagSet(user->mode, UMODE_x)) {

				int A, B;
				char cloak[HOSTSIZE];

				if ((sscanf(user_host, "%d.%d.%s", &A, &B, cloak) == 3)
					&& str_equals_partial(cloak, CRYPT_NETNAME, CRYPT_NETNAME_LEN)) {

					mask = mem_malloc(len + ((A < 10) ? 1 : (A < 100) ? 2 : 3) + ((B < 10) ? 1 : (B < 100) ? 2 : 3) + ((len > 9) ? 7 : 8));
					sprintf(mask, "*!*%s@%d.%d.*", (len > 9 || user->username[0] == '~') ? &user->username[1] : user->username, A, B);
					break;
				}
			}
			else {

				int A, B, C, D;

				if (sscanf(user_host, "%d.%d.%d.%d", &A, &B, &C, &D) == 4) {

					mask = mem_malloc(len + ((A < 10) ? 1 : (A < 100) ? 2 : 3) + ((B < 10) ? 1 : (B < 100) ? 2 : 3) + ((C < 10) ? 1 : (C < 100) ? 2 : 3) + ((len > 9) ? 8 : 9));
					sprintf(mask, "*!*%s@%d.%d.%d.*", (len > 9 || user->username[0] == '~') ? &user->username[1] : user->username, A, B, C);
					break;
				}
			}

			if ((ptr = strchr(user_host, '.')) && strchr(ptr + 1, '.')) {

				mask = mem_malloc(len + str_len(ptr) + ((len > 9) ? 5 : 6));
				sprintf(mask, "*!*%s@*%s", (len > 9 || user->username[0] == '~') ? &user->username[1] : user->username, ptr);
			}
			else {

				mask = mem_malloc(len + str_len(user_host) + ((len > 9) ? 4 : 5));
				sprintf(mask, "*!*%s@%s", (len > 9 || user->username[0] == '~') ? &user->username[1] : user->username, user_host);
			}

			break;
		}

		case 4: {
			/* *!*@*.domain */

			char *ptr;

			if (FlagSet(user->mode, UMODE_x)) {

				int A, B;
				char cloak[HOSTSIZE];

				if ((sscanf(user_host, "%d.%d.%s", &A, &B, cloak) == 3)
					&& str_equals_partial(cloak, CRYPT_NETNAME, CRYPT_NETNAME_LEN)) {

					mask = mem_malloc(((A < 10) ? 1 : (A < 100) ? 2 : 3) + ((B < 10) ? 1 : (B < 100) ? 2 : 3) + 8);
					sprintf(mask, "*!*@%d.%d.*", A, B);
					break;
				}
			}
			else {

				int A, B, C, D;

				if (sscanf(user_host, "%d.%d.%d.%d", &A, &B, &C, &D) == 4) {

					mask = mem_malloc(((A < 10) ? 1 : (A < 100) ? 2 : 3) + ((B < 10) ? 1 : (B < 100) ? 2 : 3) + ((C < 10) ? 1 : (C < 100) ? 2 : 3) + 9);
					sprintf(mask, "*!*@%d.%d.%d.*", A, B, C);
					break;
				}
			}

			if ((ptr = strchr(user_host, '.')) && strchr(ptr + 1, '.')) {

				mask = mem_malloc(str_len(ptr) + 6);
				sprintf(mask, "*!*@*%s", ptr);
			}
			else {

				mask = mem_malloc(str_len(user_host) + 5);
				sprintf(mask, "*!*@%s", user_host);
			}

			break;
		}

		case 6: {
			/* nick!*user@host.domain */

			size_t len = str_len(user->username);

			mask = mem_malloc(str_len(user->nick) + len + str_len(user_host) + ((len > 9) ? 3 : 4));
			sprintf(mask, "%s!*%s@%s", user->nick, (len > 9 || user->username[0] == '~') ? &user->username[1] : user->username, user_host);
			break;
		}

		case 7:
			/* nick!*@host.domain */

			mask = mem_malloc(str_len(user->nick) + str_len(user_host) + 4);
			sprintf(mask, "%s!*@%s", user->nick, user_host);
			break;

		case 8: {
			/* nick!*user@*.domain */

			size_t len = str_len(user->username);
			char *ptr;

			if (FlagSet(user->mode, UMODE_x)) {
			
				int A, B;
				char cloak[HOSTSIZE];

				if ((sscanf(user_host, "%d.%d.%s", &A, &B, cloak) == 3)
					&& str_equals_partial(cloak, CRYPT_NETNAME, CRYPT_NETNAME_LEN)) {

					mask = mem_malloc(str_len(user->nick) + len + ((A < 10) ? 1 : (A < 100) ? 2 : 3) + ((B < 10) ? 1 : (B < 100) ? 2 : 3) + ((len > 9) ? 6 : 7));
					sprintf(mask, "%s!*%s@%d.%d.*", user->nick, (len > 9 || user->username[0] == '~') ? &user->username[1] : user->username, A, B);
					break;
				}
			}
			else {

				int A, B, C, D;

				if (sscanf(user_host, "%d.%d.%d.%d", &A, &B, &C, &D) == 4) {

					mask = mem_malloc(str_len(user->nick) + len + ((A < 10) ? 1 : (A < 100) ? 2 : 3) + ((B < 10) ? 1 : (B < 100) ? 2 : 3) + ((C < 10) ? 1 : (C < 100) ? 2 : 3) + ((len > 9) ? 7 : 8));
					sprintf(mask, "%s!*%s@%d.%d.%d.*", user->nick, (len > 9 || user->username[0] == '~') ? &user->username[1] : user->username, A, B, C);
					break;
				}
			}

			if ((ptr = strchr(user_host, '.')) && strchr(ptr + 1, '.')) {

				mask = mem_malloc(str_len(user->nick) + len + str_len(ptr) + ((len > 9) ? 4 : 5));
				sprintf(mask, "%s!*%s@*%s", user->nick, (len > 9 || user->username[0] == '~') ? &user->username[1] : user->username, ptr);
			}
			else {

				mask = mem_malloc(str_len(user->nick) + len + str_len(user_host) + ((len > 9) ? 3 : 4));
				sprintf(mask, "%s!*%s@%s", user->nick, (len > 9 || user->username[0] == '~') ? &user->username[1] : user->username, user_host);
			}

			break;
		}

		case 9: {
			/* nick!*@*.domain */

			char *ptr;

			if (FlagSet(user->mode, UMODE_x)) {

				int A, B;
				char cloak[HOSTSIZE];

				if ((sscanf(user_host, "%d.%d.%s", &A, &B, cloak) == 3)
					&& str_equals_partial(cloak, CRYPT_NETNAME, CRYPT_NETNAME_LEN)) {

					mask = mem_malloc(str_len(user->nick) + ((A < 10) ? 1 : (A < 100) ? 2 : 3) + ((B < 10) ? 1 : (B < 100) ? 2 : 3) + 7);
					sprintf(mask, "%s!*@%d.%d.*", user->nick, A, B);
					break;
				}
			}
			else {

				int A, B, C, D;

				if (sscanf(user_host, "%d.%d.%d.%d", &A, &B, &C, &D) == 4) {

					mask = mem_malloc(str_len(user->nick) + ((A < 10) ? 1 : (A < 100) ? 2 : 3) + ((B < 10) ? 1 : (B < 100) ? 2 : 3) + ((C < 10) ? 1 : (C < 100) ? 2 : 3) + 8);
					sprintf(mask, "%s!*@%d.%d.%d.*", user->nick, A, B, C);
					break;
				}
			}

			if ((ptr = strchr(user_host, '.')) && strchr(ptr + 1, '.')) {

				mask = mem_malloc(str_len(user->nick) + str_len(ptr) + 5);
				sprintf(mask, "%s!*@*%s", user->nick, ptr);
			}
			else {

				mask = mem_malloc(str_len(user->nick) + str_len(user_host) + 4);
				sprintf(mask, "%s!*@%s", user->nick, user_host);
			}

			break;
		}

		case 5:
		default:
			/* nick!user@host.domain */

			mask = mem_malloc(str_len(user->nick) + str_len(user->username) + str_len(user_host) + 3);
			sprintf(mask, "%s!%s@%s", user->nick, user->username, user_host);
			break;

	}

	TRACE();
	return mask;
}

/*********************************************************/

char *get_user_modes(long int modeOn, long int modeOff) {

	static char modebuf[35];	/* 2*16 modes, +, -, \0 */
	int modeIdx = 0;


	TRACE_FCLT(FACILITY_USERS_GET_USER_MODE);

	if (modeOn != 0) {

		modebuf[modeIdx++] = '+';

		if (FlagSet(modeOn, UMODE_a))
			modebuf[modeIdx++] = 'a';

		if (FlagSet(modeOn, UMODE_A))
			modebuf[modeIdx++] = 'A';

		if (FlagSet(modeOn, UMODE_h))
			modebuf[modeIdx++] = 'h';

		if (FlagSet(modeOn, UMODE_i))
			modebuf[modeIdx++] = 'i';

		if (FlagSet(modeOn, UMODE_I))
			modebuf[modeIdx++] = 'I';

		if (FlagSet(modeOn, UMODE_o))
			modebuf[modeIdx++] = 'o';

		if (FlagSet(modeOn, UMODE_r))
			modebuf[modeIdx++] = 'r';

		if (FlagSet(modeOn, UMODE_R))
			modebuf[modeIdx++] = 'R';

		if (FlagSet(modeOn, UMODE_S))
			modebuf[modeIdx++] = 'S';

		if (FlagSet(modeOn, UMODE_x))
			modebuf[modeIdx++] = 'x';

		if (FlagSet(modeOn, UMODE_y))
			modebuf[modeIdx++] = 'y';

		if (FlagSet(modeOn, UMODE_z))
			modebuf[modeIdx++] = 'z';

		if (modeIdx == 1)
			log_error(FACILITY_USERS_GET_USER_MODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING, 
				"get_user_mode(): Unknown positive mode value ignored (%ld)", modeOn);
	}

	if (modeOff != 0) {

		int startIdx;


		modebuf[modeIdx++] = '-';

		startIdx = modeIdx;

		if (FlagSet(modeOff, UMODE_a))
			modebuf[modeIdx++] = 'a';

		if (FlagSet(modeOff, UMODE_A))
			modebuf[modeIdx++] = 'A';

		if (FlagSet(modeOff, UMODE_h))
			modebuf[modeIdx++] = 'h';

		if (FlagSet(modeOff, UMODE_i))
			modebuf[modeIdx++] = 'i';

		if (FlagSet(modeOff, UMODE_I))
			modebuf[modeIdx++] = 'I';

		if (FlagSet(modeOff, UMODE_o))
			modebuf[modeIdx++] = 'o';

		if (FlagSet(modeOff, UMODE_r))
			modebuf[modeIdx++] = 'r';

		if (FlagSet(modeOff, UMODE_R))
			modebuf[modeIdx++] = 'R';

		if (FlagSet(modeOff, UMODE_S))
			modebuf[modeIdx++] = 'S';

		if (FlagSet(modeOff, UMODE_x))
			modebuf[modeIdx++] = 'x';

		if (FlagSet(modeOff, UMODE_y))
			modebuf[modeIdx++] = 'y';

		if (FlagSet(modeOff, UMODE_z))
			modebuf[modeIdx++] = 'z';

		if (modeIdx == startIdx)
			log_error(FACILITY_USERS_GET_USER_MODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING, 
				"get_user_mode(): Unknown negative mode value ignored (%ld)", modeOff);
	}

	if (modeIdx == 0)
		return "None";

	modebuf[modeIdx] = '\0';
	return modebuf;
}

/*********************************************************/

char *get_user_flags(long int flags) {

	static char buffer[IRCBUFSIZE];
	size_t		len = 0;


	APPEND_FLAG(flags, USER_FLAG_ENFORCER, "USER_FLAG_ENFORCER")
	APPEND_FLAG(flags, USER_FLAG_AGENT, "USER_FLAG_AGENT")
	APPEND_FLAG(flags, USER_FLAG_HAS_IPV6, "USER_FLAG_HAS_IPV6")
	APPEND_FLAG(flags, USER_FLAG_IS_APM, "USER_FLAG_IS_APM")
	APPEND_FLAG(flags, USER_FLAG_IS_SERVERBOT, "USER_FLAG_IS_SERVERBOT")
	APPEND_FLAG(flags, USER_FLAG_BOTTLER, "USER_FLAG_BOTTLER")
	APPEND_FLAG(flags, USER_FLAG_ISBOTTLER, "USER_FLAG_ISBOTTLER")
	APPEND_FLAG(flags, USER_FLAG_EMPTYFINGER, "USER_FLAG_EMPTYFINGER")
	APPEND_FLAG(flags, USER_FLAG_EMPTYUSERINFO, "USER_FLAG_EMPTYUSERINFO")

	if (len == 0)
		return "None";

	return buffer;
}


/*********************************************************
 * Handle the UINFO command.                             *
 *********************************************************/

void handle_uinfo(CSTR source, User *callerUser, ServiceCommandData *data) {

	const char	*nick;
	User		*user;


	TRACE_MAIN_FCLT(FACILITY_USERS_HANDLE_UINFO);

	if (IS_NULL(nick = strtok(NULL, " "))) {

		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2UINFO\2 nick");
		send_notice_to_user(data->agent->nick, callerUser, "Type \2/%s OHELP UINFO\2 for more information.", data->agent->shortNick);
	}
	else if (IS_NULL(user = hash_onlineuser_find(nick)))
		send_notice_to_user(data->agent->nick, callerUser, "\2%s\2 is not online.", nick);

	else {

		char buffer[IRCBUFSIZE];

		TRACE_MAIN();

		if (data->operMatch)
			LOG_SNOOP(data->agent->nick, "%s U %s -- by %s (%s@%s)", data->agent->shortNick, user->nick, callerUser->nick, callerUser->username, callerUser->host);
		else
			LOG_SNOOP(data->agent->nick, "%s U %s -- by %s (%s@%s) through %s", data->agent->shortNick, user->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName);

		TRACE_MAIN();

		send_notice_to_user(data->agent->nick, callerUser, "User Info for nick \2%s\2:", user->nick);

		send_notice_to_user(data->agent->nick, callerUser, "\2Online as\2: %s@%s [ %s ]", user->username, user->maskedHost, user->host);

		#ifdef ENABLE_CAPAB_NICKIP
		send_notice_to_user(data->agent->nick, callerUser, "\2IP\2: %lu [ %s ]", user->ip, get_ip(user->ip));
		#endif

		#if defined(USE_SERVICES) || defined(USE_STATS)
		if (IS_NOT_NULL(user->chans)) {

			ChanListItem *item;
			size_t len = 0;


			item = user->chans;

			while (IS_NOT_NULL(item)) {

				if (len > 0) {

					*(buffer + len++) = c_COMMA;
					*(buffer + len++) = c_SPACE;
				}

				len += str_copy_checked(item->chan->name, (buffer + len), (sizeof(buffer) - len));

				if (len > 400) {

					send_notice_to_user(data->agent->nick, callerUser, "\2Channels\2: %s", buffer);
					len = 0;
				}

				item = item->next;
			}

			if (len > 0)
				send_notice_to_user(data->agent->nick, callerUser, "\2Channels\2: %s", buffer);
		}
		#endif

		TRACE_MAIN();

		#ifdef USE_SERVICES
		if (user->idcount > 0) {

			char	**idnicks;
			int		nickIdx;
			size_t	len = 0;


			for (idnicks = user->id_nicks, nickIdx = 0; nickIdx < user->idcount; ++idnicks, ++nickIdx) {

				if (len > 0) {

					*(buffer + len++) = c_COMMA;
					*(buffer + len++) = c_SPACE;
				}

				len += str_copy_checked(*idnicks, (buffer + len), (sizeof(buffer) - len));

				if (len > 400) {

					send_notice_to_user(data->agent->nick, callerUser, "\2ID Nicks\2: %s", buffer);
					len = 0;
				}
			}

			if (len > 0)
				send_notice_to_user(data->agent->nick, callerUser, "\2ID Nicks\2: %s", buffer);
		}

		if (IS_NOT_NULL(user->founder_chans)) {

			ChanInfoListItem *item;
			size_t len = 0;


			item = user->founder_chans;

			while (IS_NOT_NULL(item)) {

				if (len > 0) {

					*(buffer + len++) = c_COMMA;
					*(buffer + len++) = c_SPACE;
				}

				len += str_copy_checked(item->ci->name, (buffer + len), (sizeof(buffer) - len));

				if (len > 400) {

					send_notice_to_user(data->agent->nick, callerUser, "\2ID Chans\2: %s", buffer);
					len = 0;
				}

				item = item->next;
			}

			if (len > 0)
				send_notice_to_user(data->agent->nick, callerUser, "\2ID Chans\2: %s", buffer);
		}

		if (user->lastmemosend)
			send_notice_to_user(data->agent->nick, callerUser, "\2Last Memo Send\2: %s ago", convert_time(buffer, sizeof(buffer), (NOW - user->lastmemosend), LANG_DEFAULT));

		if (user->lastnickreg)
			send_notice_to_user(data->agent->nick, callerUser, "\2Last nick reg:\2: %s ago", convert_time(buffer, sizeof(buffer), (NOW - user->lastnickreg), LANG_DEFAULT));

		if (user->lastchanreg)
			send_notice_to_user(data->agent->nick, callerUser, "\2Last chan reg:\2: %s ago", convert_time(buffer, sizeof(buffer), (NOW - user->lastchanreg), LANG_DEFAULT));

		if (IS_NOT_NULL(user->ni)) {

			LANG_ID langid = EXTRACT_LANG_ID(user->ni->langID);
			send_notice_to_user(data->agent->nick, callerUser, "\2NickInfo\2: %s [Lang: %s (%s)]", user->ni->nick, lang_get_name(langid, TRUE), lang_get_name(langid, FALSE));
		}
		else
			send_notice_to_user(data->agent->nick, callerUser, "\2NickInfo\2: None");
		#endif

		send_notice_to_user(data->agent->nick, callerUser, "\2User Modes\2: %s", get_user_modes(user->mode, 0));

		send_notice_to_user(data->agent->nick, callerUser, "\2User Flags\2: %s", get_user_flags(user->flags));

		send_notice_to_user(data->agent->nick, callerUser, "\2Language\2: %s (%s)", lang_get_name(user->current_lang, TRUE), lang_get_name(user->current_lang, FALSE));

		send_notice_to_user(data->agent->nick, callerUser, "\2Flood status\2: Level %d / Message count %d / Resets in %d seconds", user->flood_current_level, user->flood_msg_count, (user->flood_reset_time > NOW) ? (user->flood_reset_time - NOW) : 0);
		send_notice_to_user(data->agent->nick, callerUser, "\2Invalid password status\2: Level %d / Count %d / Resets in %d seconds", user->invalid_pw_current_level, user->invalid_pw_count, (user->invalid_pw_reset_time > NOW) ? (user->invalid_pw_reset_time - NOW) : 0);

		send_notice_to_user(data->agent->nick, callerUser, "\2Current Server\2: %s", user->server->name);

		send_notice_to_user(data->agent->nick, callerUser, "\2TS Info\2: %lu", user->tsinfo);
		send_notice_to_user(data->agent->nick, callerUser, "\2Online Time (Server pov)\2: %s", convert_time(buffer, sizeof(buffer), (NOW - user->signon), LANG_DEFAULT));
		send_notice_to_user(data->agent->nick, callerUser, "\2Online Time (Services pov)\2: %s", convert_time(buffer, sizeof(buffer), (NOW - user->my_signon), LANG_DEFAULT));

		send_notice_to_user(data->agent->nick, callerUser, "*** \2End of User Info\2 ***");
	}
}


/*********************************************************
 * Return statistics. Pointers are assumed to be valid.  *
 *********************************************************/

unsigned long user_mem_report(CSTR sourceNick, const User *callerUser) {

	User				*user;
	unsigned long		count = 0, mem = 0, mem_total;
	int					idx;

	#if defined(USE_SERVICES) || defined(USE_STATS)
	ChanListItem		*item;
	#endif

	#ifdef USE_SERVICES
	int nickIdx;
	ChanInfoListItem	*infoItem;
	char **idnicks;
	#endif


	TRACE_FCLT(FACILITY_USERS_MEM_REPORT);

	send_notice_to_user(sourceNick, callerUser, "\2USER\2:");

	/* Utenti online. */
	HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM(onlineuser, idx, user) {

			TRACE();
			++count;
			mem += sizeof(User) + sizeof(User_AltListItem);

			if (IS_NOT_NULL(user->username))
				mem += str_len(user->username) + 1;

			if (IS_NOT_NULL(user->host))
				mem += str_len(user->host) + 1;

			if (IS_NOT_NULL(user->maskedHost))
				mem += str_len(user->maskedHost) + 1;

			if (IS_NOT_NULL(user->realname))
				mem += str_len(user->realname) + 1;

			#if defined(USE_SERVICES) || defined(USE_STATS)
			for (item = user->chans; IS_NOT_NULL(item); item = item->next)
				mem += sizeof(ChanListItem);
			#endif

			#ifdef USE_SERVICES
			for (infoItem = user->founder_chans; IS_NOT_NULL(infoItem); infoItem = infoItem->next)
				mem += sizeof(ChanInfoListItem);

			for (idnicks = user->id_nicks, nickIdx = 0; nickIdx < user->idcount; ++idnicks, ++nickIdx)
				mem += str_len(*idnicks);
			#endif
		}
	}

	TRACE();
	mem_total = mem;

	send_notice_to_user(sourceNick, callerUser, "Online users: \2%d\2 [%d] -> \2%d\2 KB (\2%d\2 B)", count, user_online_user_count, mem / 1024, mem);

	return mem_total;
}

/*********************************************************/

static void user_ds_dump_display(CSTR sourceNick, const User *callerUser, const User *user) {

	#ifdef USE_SERVICES
	ChanInfoListItem	*infoItem;
	char 				**idnicks;
	#endif

	#if defined(USE_SERVICES) || defined(USE_STATS)
	ChanListItem		*item;
	int					idx;
	#endif


	if (IS_NULL(user)) {

		log_error(FACILITY_USERS_DUMP, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "user_ds_dump_display()", s_LOG_NULL, "user");

		return;
	}

	send_notice_to_user(sourceNick, callerUser, "DUMP: user \2%s\2", user->nick);
	send_notice_to_user(sourceNick, callerUser, "Address 0x%08X, size %d B",				(unsigned long)user, sizeof(User) + str_len(user->username) + str_len(user->host) + str_len(user->maskedHost) + str_len(user->realname) + 4);
	send_notice_to_user(sourceNick, callerUser, "Nick: %s",									user->nick);
	send_notice_to_user(sourceNick, callerUser, "Username: 0x%08X \2[\2%s\2]\2",			(unsigned long)user->username, str_get_valid_display_value(user->username));
	send_notice_to_user(sourceNick, callerUser, "Host: 0x%08X \2[\2%s\2]\2",				(unsigned long)user->host, str_get_valid_display_value(user->host));

	#ifdef ENABLE_CAPAB_NICKIP
	send_notice_to_user(sourceNick, callerUser, "IP from NICKIP: 0x%08X \2[\2%lu\2]\2",		user->ip, user->ip);
	#endif

	send_notice_to_user(sourceNick, callerUser, "Masked host: 0x%08X \2[\2%s\2]\2",			(unsigned long)user->maskedHost, str_get_valid_display_value(user->maskedHost));
	send_notice_to_user(sourceNick, callerUser, "Realname: 0x%08X \2[\2%s\2]\2",			(unsigned long)user->realname, str_get_valid_display_value(user->realname));
	send_notice_to_user(sourceNick, callerUser, "Server: 0x%08X \2[\2%s\2]\2",				(unsigned long)user->server, str_get_valid_display_value(user->server ? user->server->name : NULL));
	send_notice_to_user(sourceNick, callerUser, "Username: 0x%08X \2[\2%s\2]\2",			(unsigned long)user->username, str_get_valid_display_value(user->username));
	send_notice_to_user(sourceNick, callerUser, "TS Info: %lu",								user->tsinfo);
	send_notice_to_user(sourceNick, callerUser, "Signon (Server POV): %lu",					user->signon);
	send_notice_to_user(sourceNick, callerUser, "Signon (Services POV): %lu",				user->my_signon);
	send_notice_to_user(sourceNick, callerUser, "Modes: 0x%08X (%s)",						(unsigned long)user->mode, get_user_modes(user->mode, 0));
	send_notice_to_user(sourceNick, callerUser, "Flags: 0x%08X (%s)",						(unsigned long)user->flags, get_user_flags(user->flags));

	#ifdef USE_SERVICES
	send_notice_to_user(sourceNick, callerUser, "Invalid password status: Level / Count / Reset C-time: %d / %d / %d", user->invalid_pw_current_level, user->invalid_pw_count, user->invalid_pw_reset_time);
	send_notice_to_user(sourceNick, callerUser, "Last memo C-time: %d",						user->lastmemosend);
	send_notice_to_user(sourceNick, callerUser, "Last nick registration C-time: %d",		user->lastnickreg);
	send_notice_to_user(sourceNick, callerUser, "Flood status: Level / Message count / Reset C-time: %d / %d / %d", user->flood_current_level, user->flood_msg_count, user->flood_reset_time);

	send_notice_to_user(sourceNick, callerUser, "NickInfo record: 0x%08X \2[\2%s\2]\2",		(unsigned long)user->ni, user->ni ? str_get_valid_display_value(user->ni->nick) : "NULL");
	#endif

	send_notice_to_user(sourceNick, callerUser, "Next / previous record: 0x%08X / 0x%08X",	(unsigned long)user->next, (unsigned long)user->prev);

	#if defined(USE_SERVICES) || defined(USE_STATS)
	send_notice_to_user(sourceNick, callerUser, s_SPACE);
	send_notice_to_user(sourceNick, callerUser, "\2Channel list\2 (name | next / previous record):");

	for (item = user->chans, idx = 1; IS_NOT_NULL(item); ++idx, item = item->next)
		send_notice_to_user(sourceNick, callerUser, "%d) %s | 0x%08X / 0x%08X", idx, IS_NOT_NULL(item->chan) ? item->chan->name : "NULL pointer", item->next, item->prev);
	#endif

	#ifdef USE_SERVICES
	send_notice_to_user(sourceNick, callerUser, s_SPACE);
	send_notice_to_user(sourceNick, callerUser, "\2Identified-channel list\2 (name | next / previous record):");

	for (infoItem = user->founder_chans, idx = 1; IS_NOT_NULL(infoItem); ++idx, infoItem = infoItem->next)
		send_notice_to_user(sourceNick, callerUser, "%d) %s | 0x%08X / 0x%08X", idx, IS_NOT_NULL(infoItem->ci) ? infoItem->ci->name : "NULL pointer", infoItem->next, infoItem->prev);

	send_notice_to_user(sourceNick, callerUser, s_SPACE);
	send_notice_to_user(sourceNick, callerUser, "\2Identified-nick list\2:");

	for (idnicks = user->id_nicks, idx = 0; idx < user->idcount; ++idnicks, ++idx)
		send_notice_to_user(sourceNick, callerUser, "%d) %s", (idx + 1), str_get_valid_display_value(*idnicks));
	#endif

	LOG_DEBUG_SNOOP("Command: DUMP USER NICK %s -- by %s (%s@%s)", user->nick, callerUser->nick, callerUser->username, callerUser->host);
}


void user_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	STR		command;
	STR		value;
	BOOL	needSyntax = FALSE;
	User	*user;

	if (IS_NULL(command = strtok(request, s_SPACE)))
		needSyntax = TRUE;

	else if (str_equals_nocase(command, "NICK")) {

		if (IS_NOT_NULL(value = strtok(NULL, s_SPACE))) {

			if (IS_NULL(user = hash_onlineuser_find(value)))
				send_notice_to_user(sourceNick, callerUser, "DUMP: User \2%s\2 not found.", value);
			else
				user_ds_dump_display(sourceNick, callerUser, user);
		}
		else
			needSyntax = TRUE;
	}
	else if (str_equals_nocase(command, "PTR")) {

		if (IS_NOT_NULL(value = strtok(NULL, s_SPACE))) {

			unsigned long int address;
			unsigned int idx;
			char *err;


			address = strtoul(value, &err, 16);

			if ((address != 0) && (*err == '\0')) {

				HASH_FOREACH_BRANCH(idx, ONLINEUSER_HASHSIZE) {

					HASH_FOREACH_BRANCH_ITEM(onlineuser, idx, user) {

						if ((unsigned long)user == address) {

							user_ds_dump_display(sourceNick, callerUser, user);
							return;
						}
					}
				}

				send_notice_to_user(sourceNick, callerUser, "DUMP: User \2%s\2 not found.", value);
			}
			else
				send_notice_to_user(sourceNick, callerUser, "\2DUMP\2 - Invalid address.");
		}
		else
			needSyntax = TRUE;
	}

	#ifdef USE_SERVICES
	else if (str_equals_nocase(command, "HOST")) {

		if (IS_NOT_NULL(value = strtok(NULL, s_SPACE))) {

			if (str_equals_nocase(value, "LIST")) {

				User_AltListItem	*host_item;
				char				*s_item = strtok(NULL, s_SPACE);
				char				*err = NULL;
				long				idx;
				int					count = 0;


				if (s_item) {

					if (s_item[0] == '+') {

						++s_item;

						idx = strtol(s_item, &err, 10);

						if (*err != '\0' || idx < 0 || idx >= ONLINEHOST_HASHSIZE || errno == ERANGE)
							send_notice_to_user(sourceNick, callerUser, "\2DUMP\2 - Invalid index.");

						else {

							HASH_FOREACH_BRANCH_ITEM(onlinehost, idx, host_item) {

								user = host_item->user;
								send_notice_to_user(sourceNick, callerUser, "%d) %s", ++count, user ? user->nick : "NULL USER!");
							}
						}
					}
					else {

						unsigned long	nickip;

						nickip = strtoul(s_item, &err, 10); // get the NICKIP

						if (*err != '\0' || errno == ERANGE)
							send_notice_to_user(sourceNick, callerUser, "\2DUMP\2 - Invalid NICKIP.");

						else {

							idx = HASH_HASHFUNC(nickip);

							HASH_FOREACH_BRANCH_ITEM(onlinehost, idx, host_item) {

								user = host_item->user;
								send_notice_to_user(sourceNick, callerUser, "%d) %s", ++count, user ? user->nick : "NULL USER!");
							}
						}
					}
				}
				else if (str_equals_nocase(value, "HEADS")) {

					HASH_FOREACH_BRANCH(idx, ONLINEHOST_HASHSIZE) {

						host_item = hashtable_onlinehost[idx];
						send_notice_to_user(sourceNick, callerUser, "%d) 0x%X", idx ,host_item);
					}
				}
			}
		}
		else
			needSyntax = TRUE;
	}
	#endif

	#ifdef FIX_USE_MPOOL
	else if (str_equals_nocase(command, "POOLSTAT")) {

		MemoryPoolStats pstats;

		mempool_stats(user_mempool, &pstats);
		send_notice_to_user(sourceNick, callerUser, "DUMP: Users memory pool - Address 0x%08X, ID: %d",	(unsigned long)user_mempool, pstats.id);
		send_notice_to_user(sourceNick, callerUser, "Memory allocated / free: %d B / %d B",				pstats.memory_allocated, pstats.memory_free);
		send_notice_to_user(sourceNick, callerUser, "Items allocated / free: %d / %d",					pstats.items_allocated, pstats.items_free);
		send_notice_to_user(sourceNick, callerUser, "Items per block / block count: %d / %d",			pstats.items_per_block, pstats.block_count);
		//send_notice_to_user(sourceNick, callerUser, "Avarage use: %.2f%%",								pstats.block_avg_usage);
	}
	#endif

	else
		needSyntax = TRUE;

	if (needSyntax) {

		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 USER NICK nickname");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 USER PTR user-record-address");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 USER HOST [HEADS | LIST char]");
		#ifdef FIX_USE_MPOOL
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 USER POOLSTAT");
		#endif
	}
}
