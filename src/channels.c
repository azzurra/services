/*
*
* Azzurra IRC Services
*
* channels.c - Gestione canali
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
#include "../inc/misc.h"
#include "../inc/servers.h"
#include "../inc/main.h"
#include "../inc/conf.h"
#include "../inc/channels.h"
#include "../inc/timeout.h"

#ifdef USE_STATS
#include "../inc/statserv.h"
#endif


#if defined(USE_SERVICES) || defined(USE_STATS)


/*********************************************************
 * Prototipi                                             *
 *********************************************************/

static void chan_sjoin_add_user(User *user, Channel *chan);

#ifdef USE_SERVICES
static void chan_sjoin_ops_check(Channel *chan, User **checklist, int count);

/* From chanserv.c, because extern.h doesn't like Timeout */
extern __inline__ void timeout_leave(Timeout *to);
extern __inline__ void timeout_unban(Timeout *to);
#endif


/*********************************************************
 * Variabili globali                                     *
 *********************************************************/

unsigned int stats_open_channels_count = 0;

unsigned int known_cmodes_count;

ChannelMode known_cmodes[] = {

	{ CMODE_c,	'c' },
	{ CMODE_C,	'C' },
	{ CMODE_d,	'd' },
	{ CMODE_i,	'i' },
	{ CMODE_j,	'j' },
	{ CMODE_k,	'k' },
	{ CMODE_l,	'l' },
	{ CMODE_m,	'm' },
	{ CMODE_M,	'M' },
	{ CMODE_n,	'n' },
	{ CMODE_O,	'O' },
	{ CMODE_p,	'p' },
	{ CMODE_r,	'r' },
	{ CMODE_R,	'R' },
	{ CMODE_s,	's' },
	{ CMODE_S,	'S' },
	{ CMODE_t,	't' },
	{ CMODE_u,	'u' },
	{ CMODE_U,	'U' }
};


/*********************************************************
 * Variabili locali                                      *
 *********************************************************/

#ifdef	FIX_USE_MPOOL
MemoryPool	*channels_mempool;
MemoryPool	*channels_chan_entry_mempool;
MemoryPool	*channels_user_entry_mempool;
#endif

#define HASH_DATA_MODIFIER			static
#define HASH_FUNCTIONS_MODIFIER		
#undef  LIST_USE_MY_HASH

#include "../inc/list.h"

#define CHANNEL_HASHSIZE	1024

// Channel *hashtable_channel[CHANNEL_HASHSIZE];
CREATE_HASHTABLE_NOTAIL(channel, Channel, CHANNEL_HASHSIZE)

// void hash_channel_add(Channel *node);
static CREATE_HASH_ADD(channel, Channel, name)

// void hash_channel_remove(Channel *node);
static CREATE_HASH_REMOVE_NOTAIL(channel, Channel, name)

// Channel *hash_channel_find(const char *value);
CREATE_HASH_FIND(channel, Channel, name)


/*********************************************************
 * Init/clean up                                         *
 *********************************************************/

__inline__ void chan_init() {

	unsigned int idx;

	for (idx = 0; idx < CHANNEL_HASHSIZE; ++idx)
		hashtable_channel[idx] = NULL;

	known_cmodes_count = (sizeof(known_cmodes) / sizeof(ChannelMode));

	#ifdef FIX_USE_MPOOL
	channels_mempool = mempool_create(MEMPOOL_ID_CHANS, sizeof(Channel), MP_IPB_CHANS, MB_IBC_CHANS);
	channels_chan_entry_mempool = mempool_create(MEMPOOL_ID_CHANS_CHAN_ENTRY, sizeof(ChanListItem), MP_IPB_CHANS_CHAN_ENTRY, MB_IBC_CHANS_CHAN_ENTRY);
	channels_user_entry_mempool = mempool_create(MEMPOOL_ID_CHANS_USER_ENTRY, sizeof(UserListItem), MP_IPB_CHANS_USER_ENTRY, MB_IBC_CHANS_USER_ENTRY);
	#endif
}

__inline__ void chan_terminate() {

	#ifdef FIX_USE_MPOOL
	mempool_destroy(channels_mempool);
	mempool_destroy(channels_chan_entry_mempool);
	mempool_destroy(channels_user_entry_mempool);

	channels_mempool = channels_chan_entry_mempool = channels_user_entry_mempool = NULL;
	#endif
}


/*********************************************************
 * Bahamut (TS3) SJOIN procedure                         *
 *********************************************************/

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * chan_handle_SJOIN()                                                                       *
 *                                                                                           *
 * Senza SSJOIN:                                                                             *
 * :nomeserver.azzurra.org SJOIN 998558815 998558815 #shaka +tnr  :@Shaka marco              *
 *                                                                                           *
 * av[0] = time stamp 1                                                                      *
 * av[1] = time stamp 2 (ignorata)                                                           *
 * av[2] = #chan                                                                             *
 * av[3] = chan mode (or 0 if there's more than one SJOIN for this channel during sync)      *
 * av[4] = nick(s) (@|+|@+nick) (if -lk) / +l parameter (if +l) / +k parameter (if -l+k)     *
 * av[5] = nick(s) (@|+|@+nick) (if +l-k or -l+k) / +k parameter (if +lk)                    *
 * av[6] = nick(s) (@|+|@+nick) (if +lk)                                                     *
 *                                                                                           *
 * Con SSJOIN:                                                                               *
 *                                                                                           *
 *   Durante il sync o con canale vuoto:                                                     *
 *   :kodocha.azzurra.org SJOIN 1041739068 #bugs +nrt :@Wolf7                                *
 *                                                                                           *
 *   av[0] = time stamp                                                                      *
 *   av[1] = #chan                                                                           *
 *   av[2] = chan mode (or 0 if there's more than one SJOIN for this channel during sync)    *
 *   av[3] = nick(s) (@|+|@+nick) (if -lk) / +l parameter (if +l) / +k parameter (if -l+k)   *
 *   av[4] = nick(s) (@|+|@+nick) (if +l-k or -l+k) / +k parameter (if +lk)                  *
 *   av[5] = nick(s) (@|+|@+nick) (if +lk)                                                   *
 *                                                                                           *
 *   A sync avvenuto, con canale gia' esistente:                                             *
 *   :Wolf7 SJOIN 1041617403 #bugs                                                           *
 *                                                                                           *
 *   av[0] = time stamp                                                                      *
 *   av[1] = #chan                                                                           *
 *                                                                                           *
 *   *   *   *   *   *   *   *   *   *   *   *   *   *   *   *   *   *   *   *   *   *   *   *
 *                                                                                           *
 * Possono esserci piu' SJOIN per lo stesso canale (se non ne basta uno per tutti gli users).*
 * Solo il primo contiene info nel campo mode, gli altri hanno 0.                            *
 * Se il chan ha operatori, il primo nick del primo SJOIN per quel chan e' un operatore.     *
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

void chan_handle_SJOIN(CSTR source, const int ac, char **av) {

	Channel		*chan;
	User		*user;
	int			param = 0;
	const char	*chan_name;


	#ifdef ENABLE_CAPAB_SSJOIN
	TRACE_MAIN_FCLT(FACILITY_CHANNELS_HANDLE_SJOIN);

	if (FlagSet(uplink_capab, CAPAB_SSJOIN)) {

		if (!strchr(source, '.')) {

			#ifdef USE_SERVICES
			User *checklist[1];
			#endif

			/* This is a single client joining a (hopefully) existent channel. */

			user = hash_onlineuser_find(source);

			if (IS_NULL(user)) {

				log_error(FACILITY_CHANNELS_HANDLE_SJOIN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
					"handle_SJOIN(): SJOIN for %s from nonexistent user %s", av[1], source);

				return;
			}

			chan_name = av[1];

			chan = hash_channel_find(chan_name);

			if (IS_NULL(chan)) {

				/* This shouldn't happen, but let's not desync ourselves because of it. */

				TRACE_MAIN();

				LOG_DEBUG("channels: Creating new channel %s via SJOIN [Forced]", chan_name);

				#ifdef	FIX_USE_MPOOL
				chan = mempool_alloc(Channel*, channels_mempool, TRUE);
				#else
				chan = mem_calloc(1, sizeof(Channel));
				#endif

				str_copy_checked(chan_name, chan->name, sizeof(chan->name));

				hash_channel_add(chan);

				TRACE_MAIN();

				++stats_open_channels_count;

				#ifdef USE_SERVICES
				chan->ci = cs_findchan(chan_name);
				#endif

				#ifdef USE_STATS
				if (!hash_chanstats_find(chan_name))
					add_channel_stats(chan_name);

				if (stats_open_channels_count > records.maxchannels) {

					records.maxchannels = stats_open_channels_count;
					records.maxchannels_time = NOW;
				}

				if (stats_open_channels_count > stats_daily_maxchans)
					stats_daily_maxchans = stats_open_channels_count;
				#endif
			}

			/* Most likely it'll be the same, but might be different, so just update it. */
			chan->creation_time = (time_t) atol(av[0]);

			#ifdef USE_SERVICES
			SetCallerLang(user->current_lang);

			if (chanserv_check_user_join(user, chan) == TRUE) {
			#endif

				TRACE_MAIN();
				chan_sjoin_add_user(user, chan);	/* aggiunta dell'utente alla lista degli utenti del canale */

			#ifdef USE_SERVICES
			}
			else
				return;
			#endif

			TRACE_MAIN();

			#ifdef USE_SERVICES
			checklist[0] = user;

			if (IS_NOT_NULL(chan->ci)) {

				if (synched == TRUE)
					check_welcome(user, chan->ci);

				chan_sjoin_ops_check(chan, checklist, 1);
				check_modelock(chan, NULL);
			}
			#endif

			return;
		}
		else {

			/* This is a SJOIN during sync. */
			param = 1;
		}
	}
	#endif /* ENABLE_CAPAB_SSJOIN */

	/* Old-style SJOIN handling begins here. */
	{
		int		bogus = 0, smembers = 0;
		BOOL	newChannel = FALSE, isOp, isHalfOp, isVoice;
		char	*nick, *nick_token_ptr, nick_token[NICKSIZE + 3]; /* "%@+" */
		time_t	timestamp;

		#ifdef USE_SERVICES
		/* Note: maximum users in a SJOIN is well below 160. We know because bahamut cuts the SJOIN
		   after (buf + str_len(nicks) + 80 > 512) where buf is (SSJOIN enabled):
		   :server_name SJOIN TS #channel modes :
		   Minimum length for this is ":a SJOIN 0 # + :" = 16, which leaves the
		   most chars for nicks: 512 - 80 - 16 = 416. Now, assuming all nicks have the shortest
		   possible length and none is @+/@/+, we have 60 single-char nicks at most, which account
		   for 120 chars including spaces, leaving 296 for two-chars nicks, which take up three
		   chars each, including the space. That makes 60 + 296/3 = 158 nicks max.
		   As for deop, it's at least one more char per nick (@), which means 180 chars for
		   single-char nicks, leaving 416 - 180 = 236 for two-chars nicks which take up 4 spaces.
		   Max nicks is 60 + 236/4 = 119. -- Gastaman */

		User	*checklist[160], *deoplist[120];
		int		check = 0, deop = 0, failed = 0;
		BOOL	resetTS = FALSE;
		#endif


		#ifdef USE_SERVICES
		memset(checklist, 0, sizeof(checklist));
		memset(deoplist, 0, sizeof(deoplist));
		#endif

		/* Variable initializations, sanity checks. */
		chan_name = av[2 - param];

		nick_token_ptr = av[ac - 1];

		if (IS_NULL(nick_token_ptr) || IS_EMPTY_STR(nick_token_ptr)) {

			/* Nobody joined? wtf? */

			log_error(FACILITY_CHANNELS_HANDLE_SJOIN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
				"handle_SJOIN(): Empty SJOIN received for %s (%s)", chan_name, merge_args(ac, av));

			return;
		}

		timestamp = (time_t) atol(av[0]);

		TRACE_MAIN();

		chan = hash_channel_find(chan_name);

		TRACE_MAIN();

		if (IS_NULL(chan)) {

			TRACE_MAIN();

			LOG_DEBUG("channels: Creating new channel %s via SJOIN", chan_name);

			#ifdef	FIX_USE_MPOOL
			chan = mempool_alloc(Channel*, channels_mempool, TRUE);
			#else
			chan = mem_calloc(1, sizeof(Channel));
			#endif

			str_copy_checked(chan_name, chan->name, sizeof(chan->name));

			hash_channel_add(chan);

			TRACE_MAIN();

			chan->creation_time = timestamp;

			++stats_open_channels_count;

			#ifdef USE_SERVICES
			chan->ci = cs_findchan(chan_name);
			#endif

			#ifdef USE_STATS
			if (!hash_chanstats_find(chan_name))
				add_channel_stats(chan_name);

			if (stats_open_channels_count > records.maxchannels) {

				records.maxchannels = stats_open_channels_count;
				records.maxchannels_time = NOW;
			}

			if (stats_open_channels_count > stats_daily_maxchans)
				stats_daily_maxchans = stats_open_channels_count;
			#endif

			newChannel = TRUE;
		}
		else if (timestamp < chan->creation_time) {

			/* We received a SJOIN with a lower TS. Reset all channel modes (including ops
			and voices) before processing the SJOIN. */

			UserListItem *item, *next;


			LOG_DEBUG("Received SJOIN for %s at %ld (-%ds) by %s, resetting channel.", chan_name, timestamp, (chan->creation_time - timestamp), nick_token_ptr);

			/* Reset channel modes. */
			chan->mode = 0;

			/* Clear operators list. */
			for (item = chan->chanops; IS_NOT_NULL(item); item = next) {

				next = item->next;

				#ifdef FIX_USE_MPOOL
				mempool_free(channels_user_entry_mempool, item);
				#else
				mem_free(item);
				#endif
			}

			chan->chanops = NULL;
			
			/* Clear halfops list. */
			for (item = chan->halfops; IS_NOT_NULL(item); item = next) {

				next = item->next;

				#ifdef FIX_USE_MPOOL
				mempool_free(channels_user_entry_mempool, item);
				#else
				mem_free(item);
				#endif
			}

			chan->halfops = NULL;

			/* Clear voices list. */
			for (item = chan->voices; IS_NOT_NULL(item); item = next) {

				next = item->next;

				#ifdef FIX_USE_MPOOL
				mempool_free(channels_user_entry_mempool, item);
				#else
				mem_free(item);
				#endif
			}

			chan->voices = NULL;

			/* Clear bans. */
			chan_clear_bans(chan);

			/* Reset the channel TS. */
			chan->creation_time = timestamp;

			#ifdef USE_SERVICES
			resetTS = TRUE;
			#endif
		}

		TRACE_MAIN();

		/* Controllare i modes ? */
		if (av[3 - param][1]) {

			char *ptr = av[3 - param];

			TRACE_MAIN();
			while (*ptr) {

				switch (*ptr++) {

				case 'c':
					AddFlag(chan->mode, CMODE_c);
					break;

				case 'C':
					AddFlag(chan->mode, CMODE_C);
					break;

				case 'd':
					AddFlag(chan->mode, CMODE_d);
					break;

				case 'i':
					AddFlag(chan->mode, CMODE_i);
					break;

				case 'j':
					AddFlag(chan->mode, CMODE_j);
					break;

				case 'k':

					TRACE_MAIN();
					if (chan->key) {

						mem_free(chan->key);
						chan->key = NULL;
					}

					TRACE_MAIN();
					AddFlag(chan->mode, CMODE_k);

					TRACE_MAIN();
					if (FlagSet(chan->mode, CMODE_l))
						/* il chan e' +l -> prima del parametro del +k c'è quello del +l -> saltarlo */
						chan->key = str_duplicate(av[5 - param]);
					else
						chan->key = str_duplicate(av[4 - param]);

					TRACE_MAIN();
					break;

				case 'l':
					AddFlag(chan->mode, CMODE_l);

					TRACE_MAIN();
					if (FlagSet(chan->mode, CMODE_k))
						/* il chan e' +k -> prima del parametro del +l c'è quello del +k -> saltarlo */
						chan->limit = atoi(av[5 - param]);
					else
						chan->limit = atoi(av[4 - param]);

					TRACE_MAIN();
					break;

				case 'm':
					AddFlag(chan->mode, CMODE_m);
					break;

				case 'M':
					AddFlag(chan->mode, CMODE_M);
					break;

				case 'n':
					AddFlag(chan->mode, CMODE_n);
					break;

				case 'O':
					AddFlag(chan->mode, CMODE_O);
					break;

				case 'p':
					AddFlag(chan->mode, CMODE_p);
					break;

				case 'r':
					AddFlag(chan->mode, CMODE_r);
					break;

				case 'R':
					AddFlag(chan->mode, CMODE_R);
					break;

				case 's':
					AddFlag(chan->mode, CMODE_s);
					break;

				case 'S':
					AddFlag(chan->mode, CMODE_S);
					break;

				case 't':
					AddFlag(chan->mode, CMODE_t);
					break;

				case 'u':
					AddFlag(chan->mode, CMODE_u);
					break;
				
				case 'U':
					AddFlag(chan->mode, CMODE_U);
					break;
				}
			}
		}

		TRACE_MAIN();

		memset(nick_token, 0, sizeof(nick_token));
		nick_token_ptr = str_tokenize(nick_token_ptr, nick_token, sizeof(nick_token), c_SPACE);

		/* In case of lag, or akills processed before the sjoin synch, we gotta
		search for bogus users... if all of the users are bogus (like 20 clones)
		then we must delete the channel as well */

		TRACE_MAIN();

		while (IS_NOT_NULL(nick_token_ptr)) {

			++smembers;

			nick = nick_token;

			TRACE_MAIN();
			
			isOp = FALSE;
			isHalfOp = FALSE;
			isVoice = FALSE;
			
			for(;;) {
				if (*nick == c_AT)
					isOp = TRUE;
				else if (*nick == '%')
					isHalfOp = TRUE;
				else if (*nick == c_PLUS)
					isVoice = TRUE;
				else
					break;
				nick++;
			}
			
			if (IS_NULL(user = hash_onlineuser_find(nick))) {

				++bogus;
				nick_token_ptr = str_tokenize(nick_token_ptr, nick_token, sizeof(nick_token), c_SPACE);
				continue;
			}
			
			TRACE_MAIN();

			#ifdef USE_SERVICES
			SetCallerLang(user->current_lang);

			if (chanserv_check_user_join(user, chan) == TRUE) {
			#endif
			
				chan_sjoin_add_user(user, chan);
				TRACE_MAIN();
				
				if (isVoice)
					chan_add_voice(chan, user);
				TRACE_MAIN();
				if (isHalfOp)
					chan_add_halfop(chan, user);
				TRACE_MAIN();
	
				if (isOp) {
					#ifdef USE_SERVICES
					if (check_valid_op(user, chan->ci, 1)) {
					#endif
		
						TRACE_MAIN();
		
						chan_add_op(chan, user);
	
				#ifdef USE_SERVICES
						if (IS_NOT_NULL(chan->ci))
							chan->ci->last_used = NOW;
					}
					else {
	
						TRACE_MAIN();
	
						deoplist[deop++] = user;
	
						if (synched == TRUE)
							send_notice_lang_to_user(s_ChanServ, user, FindNickLang(user->nick, user), JOIN_CHAN_IS_REGISTERED, chan->name);
	
						TRACE_MAIN();
					}
				#endif
				}
				#ifdef USE_SERVICES
			}
			else {

				++failed;
				nick_token_ptr = str_tokenize(nick_token_ptr, nick_token, sizeof(nick_token), c_SPACE);
				continue;
			}
			#endif

			TRACE_MAIN();
			#ifdef USE_SERVICES
			checklist[check++] = user;

			if (IS_NOT_NULL(chan->ci) && (synched == TRUE))
				check_welcome(user, chan->ci);
			#endif

			nick_token_ptr = str_tokenize(nick_token_ptr, nick_token, sizeof(nick_token), c_SPACE);
		} /* while */

		TRACE_MAIN();

		if ((bogus == smembers) && (newChannel == TRUE)) {

			TRACE_MAIN();

			hash_channel_remove(chan);

			TRACE_MAIN();

			#ifdef FIX_USE_MPOOL
			mempool_free(channels_mempool, chan);
			#else
			mem_free(chan);
			#endif

			return;
		}

		#ifdef USE_SERVICES
		if (IS_NOT_NULL(deoplist[0])) {

			int		idx, modeIdx = 0;
			char	deopnicks[IRCBUFSIZE], modes[SERVER_MAX_MODES + 1];
			size_t	deopLen = 0;


			memset(modes, 0, sizeof(modes));

			for (idx = 0; idx < deop; ++idx) {

				user = deoplist[idx];

				if (IS_NULL(user))
					continue;

				if (deopLen > 0)
					*(deopnicks + deopLen++) = c_SPACE;

				deopLen += str_copy_checked(user->nick, (deopnicks + deopLen), (sizeof(deopnicks) - deopLen));

				modes[modeIdx++] = 'o';

				/* We don't have to check for the command length; we won't be sending more than
				   SERVER_MAX_MODES (11) modes in a single line anyway, and that makes 11 * 30 (nicks)
				   + 4 (MODE) + 30 (channel) + 13 (modes) + (12 + 4) (spaces) = 393 chars at most,
				   which is well below the 512 chars per line limit. -- Gastaman */

				if (modeIdx == SERVER_MAX_MODES) {

					modes[modeIdx] = '\0';
					send_cmd(":%s MODE %s -%s %s", s_ChanServ, chan_name, modes, deopnicks);
					deopLen = 0;
					memset(modes, 0, SERVER_MAX_MODES + 1);
					modeIdx = 0;
				}
			}

			modes[modeIdx] = '\0';

			if (deopLen > 0)
				send_cmd(":%s MODE %s -%s %s", s_ChanServ, chan_name, modes, deopnicks);
		}

		/* Skip if no valid users joined the channel. */
		if (IS_NOT_NULL(chan->ci) && (resetTS || (smembers > failed + bogus))) {

			if (IS_NOT_NULL(checklist[0]))
				chan_sjoin_ops_check(chan, checklist, check);

			check_modelock(chan, NULL);

			/* Restore the topic if it's a new channel, or if it has been reset, or if someone has just been
			   kicked by services (AutoKick, Restrict, etc) and ChanServ is alone in the channel. */
			if (synched && (newChannel || resetTS || (FlagSet(chan->mode, CMODE_CS) && (chan->userCount == 1))))
				restore_topic(chan);
		}
		#endif
	}
}


/*********************************************************
 * chan_handle_internal_SJOIN()                          *
 *                                                       *
 * Handle an internal channel MODE, either by a server   *
 * or by CS/OS if we're using services. DO NOT call this *
 * for modes by normal clients. "item" is either the     *
 * banmask (mode +b) or the channel key (+k).            *
 *********************************************************/

void chan_handle_internal_SJOIN(const char *nick, const char *chan_name) {

	Channel		*chan;

	#ifdef USE_STATS
	ChannelStats *cs;
	#endif

	BOOL	newchan = FALSE;
	User	*user;

	TRACE_MAIN_FCLT(FACILITY_CHANNELS_HANDLE_INTERNAL_SJOIN);

	if (IS_NULL(chan_name) || IS_EMPTY_STR(chan_name)) {

		log_error(FACILITY_CHANNELS_HANDLE_INTERNAL_SJOIN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "chan_handle_SJOIN()", s_LOG_NULL, "chan_name");

		return;
	}

	/* Did the server or client spawn the sjoin? */

	TRACE_MAIN();

	chan = hash_channel_find(chan_name);

	TRACE_MAIN();

	if (IS_NULL(chan)) {

		TRACE_MAIN();

		LOG_DEBUG("channels: Creating new channel %s via internal SJOIN", chan_name);

		#ifdef	FIX_USE_MPOOL
		chan = mempool_alloc(Channel*, channels_mempool, TRUE);
		#else
		chan = mem_calloc(1, sizeof(Channel));
		#endif

		str_copy_checked(chan_name, chan->name, sizeof(chan->name));

		hash_channel_add(chan);

		TRACE_MAIN();

		chan->creation_time = time(NULL);

		++stats_open_channels_count;

		#ifdef USE_SERVICES
		chan->ci = cs_findchan(chan_name);
		#endif

		#ifdef USE_STATS
		cs = hash_chanstats_find(chan_name);

		if (!cs)
			add_channel_stats(chan_name);

		if (stats_open_channels_count > records.maxchannels) {
			
			records.maxchannels = stats_open_channels_count;
			records.maxchannels_time = NOW;
		}

		if (stats_open_channels_count > stats_daily_maxchans)
			stats_daily_maxchans = stats_open_channels_count;
		#endif

		newchan = TRUE;
	}

	TRACE_MAIN();

	if (IS_NULL(user = user_localuser_find(nick))) {

		log_error(FACILITY_CHANNELS_HANDLE_INTERNAL_SJOIN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "chan_handle_internal_SJOIN()", s_LOG_NULL, "user");

		return;
	}

	#ifdef ENABLE_CAPAB_SSJOIN
	if (FlagSet(uplink_capab, CAPAB_SSJOIN)) {

		if (newchan)
			send_cmd("SJOIN %ld %s +int :%s", chan->creation_time, chan_name, nick);
		else
			send_cmd(":%s SJOIN %ld %s", nick, chan->creation_time, chan_name);
	}
	else
	#endif
		send_cmd("SJOIN %ld %ld %s %s :%s", chan->creation_time, chan->creation_time, chan_name, (newchan ? "+int" : "0"), nick);

	chan_sjoin_add_user(user, chan);	/* aggiunta dell'utente alla lista degli utenti del canale */

	TRACE_MAIN();

	#ifdef USE_SERVICES
	if (IS_NOT_NULL(chan) && IS_NOT_NULL(chan->ci) && newchan) {

		check_modelock(chan, NULL);

		if (synched == TRUE)
			restore_topic(chan);
	}
	#endif
}


/*********************************************************
 * chan_sjoin_add_user()                                 *
 *                                                       *
 * Inserisce l'utente indicato nelle liste utenti del    *
 * canale e il canale nella lista dei canali dell'user.  *
 *********************************************************/

static void chan_sjoin_add_user(User *user, Channel *chan) {

	UserListItem	*userItem;
	ChanListItem	*chanItem;

	#ifdef USE_STATS
	ChannelStats *cs;
	#endif


	TRACE_FCLT(FACILITY_CHANNELS_SJOIN_ADD_USER);

	if (IS_NULL(chan) || IS_NULL(user)) {

		log_error(FACILITY_CHANNELS_SJOIN_ADD_USER, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "chan_sjoin_add_user()", s_LOG_NULL, IS_NULL(chan) ? "chan" : "user");

		return;
	}

	LOG_DEBUG("channels: %s (%s@%s) joins %s", user->nick, user->username, user->host, chan->name);

	TRACE();

	/* Inserimento dell'utente nella lista degli utenti del canale. */

	#ifdef	FIX_USE_MPOOL
	userItem = mempool_alloc(UserListItem *, channels_user_entry_mempool, FALSE);
	#else
	userItem = mem_malloc(sizeof(UserListItem));
	#endif

	userItem->next = chan->users;
	userItem->prev = NULL;

	if (IS_NOT_NULL(chan->users))
		chan->users->prev = userItem;

	TRACE();
	chan->users = userItem;
	userItem->user = user;

	++(chan->userCount);

	#ifdef USE_STATS
	cs = hash_chanstats_find(chan->name);

	if (IS_NOT_NULL(cs)) {

		TRACE();
		cs->last_change = NOW;

		if (chan->userCount > cs->dailypeak)
			cs->dailypeak = chan->userCount;

		if (cs->dailypeak > cs->weeklypeak)
			cs->weeklypeak = cs->dailypeak;

		if (cs->weeklypeak > cs->monthlypeak)
			cs->monthlypeak = cs->weeklypeak;

		if (cs->monthlypeak > cs->totalpeak)
			cs->totalpeak = cs->monthlypeak;
	}
	else
		LOG_DEBUG_SNOOP("No channel stats record for channel %s", chan->name);

	if (synched) {

		++total.joins;
		++monthly.joins;
		++weekly.joins;
		++daily.joins;

		if (IS_NOT_NULL(cs)) {

			++cs->dailyjoins;
			++cs->weeklyjoins;
			++cs->monthlyjoins;
			++cs->totaljoins;
		}
	}

	servers_increase_messages(user);
	#endif

	/* Inserimento del canale nella lista dei canali dell'utente. */

	TRACE();
	
	#ifdef	FIX_USE_MPOOL
	chanItem = mempool_alloc(ChanListItem *, channels_chan_entry_mempool, FALSE);
	#else
	chanItem = mem_malloc(sizeof(ChanListItem));
	#endif

	chanItem->next = user->chans;
	chanItem->prev = NULL;
	
	if (IS_NOT_NULL(user->chans))
		user->chans->prev = chanItem;

	TRACE();
	user->chans = chanItem;
	chanItem->chan = chan;
}


/*********************************************************
 * chan_sjoin_ops_check()                                *
 *                                                       *
 * Controlla il livello di accesso degli utenti          *
 * specificati (checklist) al canale.                    *
 * Inserisce op e voice nelle liste opportune.           *
 *********************************************************/

#ifdef USE_SERVICES

static void chan_sjoin_ops_check(Channel *chan, User **checklist, int count) {

	UserListItem	*item;
	User			*user, *oplist[160], *halfoplist[160], *voicelist[160];
	int				idx, accessLevel, toop = 0, tohalfop = 0, tovoice = 0;
	ChannelInfo		*ci;


	TRACE_FCLT(FACILITY_CHANNELS_SJOIN_OPS_CHECK);

	if (IS_NULL(chan) || IS_NULL(checklist) || IS_NULL((ci = chan->ci))) {

		log_error(FACILITY_CHANNELS_SJOIN_OPS_CHECK, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"chan_sjoin_ops_check() called with invalid parameter(s) (%s [%s], %s, %d)", chan ? chan->name : NULL, (chan && chan->ci) ? chan->ci->name : NULL, checklist ? "checklist" : NULL, count);

		return;
	}

	memset(oplist, 0, sizeof(oplist));
	memset(halfoplist, 0, sizeof(halfoplist));
	memset(voicelist, 0, sizeof(voicelist));

	TRACE();
	for (idx = 0; idx < count; ++idx) {

		user = checklist[idx];

		if (IS_NULL(user))
			continue;

		accessLevel = get_access(user, ci, NULL, NULL, NULL);

		TRACE();
		if (((accessLevel == CS_ACCESS_VOP) && FlagUnset(ci->flags, CI_AUTOHALFOP) && FlagUnset(ci->flags, CI_AUTOOP)) ||
			((accessLevel < CS_ACCESS_HOP) && FlagSet(ci->flags, CI_AUTOVOICE))) {

			if (!user_is_chanvoice(user->nick, chan->name, chan) && check_should_voice(user, ci)) {

				TRACE();
				#ifdef	FIX_USE_MPOOL
				item = mempool_alloc(UserListItem *, channels_user_entry_mempool, FALSE);
				#else
				item = mem_malloc(sizeof(UserListItem));
				#endif

				item->next = chan->voices;
				item->prev = NULL;

				if (IS_NOT_NULL(chan->voices))
					chan->voices->prev = item;

				chan->voices = item;
				item->user = user;

				voicelist[tovoice++] = user;
			}
		}
		else if (((accessLevel == CS_ACCESS_HOP) && FlagUnset(ci->flags, CI_AUTOOP)) ||
			((accessLevel < CS_ACCESS_AOP) && FlagSet(ci->flags, CI_AUTOHALFOP))) {

			if (!user_is_chanhalfop(user->nick, chan->name, chan) && check_should_halfop(user, ci)) {

				TRACE();
				#ifdef	FIX_USE_MPOOL
				item = mempool_alloc(UserListItem *, channels_user_entry_mempool, FALSE);
				#else
				item = mem_malloc(sizeof(UserListItem));
				#endif

				item->next = chan->halfops;
				item->prev = NULL;

				if (IS_NOT_NULL(chan->halfops))
					chan->halfops->prev = item;

				chan->halfops = item;
				item->user = user;

				halfoplist[tohalfop++] = user;
			}
		}
		else if ((accessLevel > CS_ACCESS_HOP) || FlagSet(ci->flags, CI_AUTOOP)) {

			if (!user_is_chanop(user->nick, chan->name, chan) && check_should_op(user, ci)) {

				TRACE();
				/* L'utente e' stato oppato -> aggiungerlo all'elenco degli operatori. */

				#ifdef	FIX_USE_MPOOL
				item = mempool_alloc(UserListItem *, channels_user_entry_mempool, FALSE);
				#else
				item = mem_malloc(sizeof(UserListItem));
				#endif

				item->next = chan->chanops;
				item->prev = NULL;

				if (IS_NOT_NULL(chan->chanops))
					chan->chanops->prev = item;

				chan->chanops = item;
				item->user = user;

				oplist[toop++] = user;
			}
		}
	}

	if (IS_NOT_NULL(oplist[0]) || IS_NOT_NULL(halfoplist[0]) || IS_NOT_NULL(voicelist[0])) {

		int 	paramCount = 0;
		char 	nicks[IRCBUFSIZE], modes[SERVER_MAX_MODES + 1];
		char 	*ptr;
		size_t	len = 0;


		if (IS_NOT_NULL(oplist[0])) {

			for (idx = 0; idx < toop; ++idx) {

				user = oplist[idx];

				if (IS_NULL(user))
					continue;

				if (len > 0)
					nicks[len++] = c_SPACE;

				ptr = user->nick;

				while (*ptr)
					nicks[len++] = *ptr++;

				modes[paramCount++] = 'o';

				if (paramCount == SERVER_MAX_MODES) {

					modes[paramCount] = '\0';
					nicks[len] = '\0';
					send_cmd(":%s MODE %s +%s %s", s_ChanServ, chan->name, modes, nicks);
					paramCount = 0;
					len = 0;
				}
			}
		}
		
		if (IS_NOT_NULL(halfoplist[0])) {

			for (idx = 0; idx < tohalfop; ++idx) {

				user = halfoplist[idx];

				if (IS_NULL(user))
					continue;

				if (len > 0)
					nicks[len++] = c_SPACE;

				ptr = user->nick;

				while (*ptr)
					nicks[len++] = *ptr++;

				modes[paramCount++] = 'h';

				if (paramCount == SERVER_MAX_MODES) {

					modes[paramCount] = '\0';
					nicks[len] = '\0';
					send_cmd(":%s MODE %s +%s %s", s_ChanServ, chan->name, modes, nicks);
					paramCount = 0;
					len = 0;
				}
			}
		}

		if (IS_NOT_NULL(voicelist[0])) {

			for (idx = 0; idx < tovoice; ++idx) {

				user = voicelist[idx];

				if (IS_NULL(user))
					continue;

				if (len > 0)
					nicks[len++] = c_SPACE;

				ptr = user->nick;

				while (*ptr)
					nicks[len++] = *ptr++;

				modes[paramCount++] = 'v';

				if (paramCount == SERVER_MAX_MODES) {

					modes[paramCount] = '\0';
					nicks[len] = '\0';
					send_cmd(":%s MODE %s +%s %s", s_ChanServ, chan->name, modes, nicks);
					len = 0;
					paramCount = 0;
				}
			}
		}

		if (paramCount > 0) {

			modes[paramCount] = '\0';
			nicks[len] = '\0';
			send_cmd(":%s MODE %s +%s %s", s_ChanServ, chan->name, modes, nicks);
		}
	}
}

#endif

/*********************************************************
 * Utilities                                             *
 *********************************************************/

/*********************************************************
 * chan_user_remove()                                    *
 *                                                       *
 * Remove a user from a channel, deleting the channel as *
 * necessary.                                            *
 *********************************************************/

void chan_user_remove(const User *user, Channel *chan) {

	UserListItem *item;


	TRACE_FCLT(FACILITY_CHANNELS_USER_REMOVE);

	if (IS_NULL(user) || IS_NULL(chan)) {

		log_error(FACILITY_CHANNELS_USER_REMOVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "chan_user_remove()", s_LOG_NULL, IS_NULL(user) ? "user" : "chan");

		return;
	}

	if (IS_NULL(chan->users)) {

		log_error(FACILITY_CHANNELS_USER_REMOVE, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_HALTED,
			"chan_user_remove([%s], [%s]) : chan->users is NULL. Nothing to do.", user->nick, chan->name);

		return;
	}

	#ifdef USE_SERVICES
	if (str_equals_nocase(user->nick, s_ChanServ))
		RemoveFlag(chan->mode, CMODE_CS);
	#endif

	/* Eliminazione dalla lista generica degli utenti del canale. */

	TRACE();
	for (item = chan->users; IS_NOT_NULL(item) && (item->user != user); item = item->next)
		;

	if (IS_NULL(item))
		return;

	if (IS_NOT_NULL(item->next))
		item->next->prev = item->prev;

	if (IS_NOT_NULL(item->prev))
		item->prev->next = item->next;
	else
		chan->users = item->next;

	TRACE();

	#ifdef	FIX_USE_MPOOL
	mempool_free(channels_user_entry_mempool, item);
	#else
	mem_free(item);
	#endif

	--(chan->userCount);

	/* Eliminazione dalla lista chan-ops. */
	
	for (item = chan->chanops; IS_NOT_NULL(item) && (item->user != user); item = item->next)
		;

	if (IS_NOT_NULL(item)) {

		TRACE();
		if (IS_NOT_NULL(item->next))
			item->next->prev = item->prev;

		if (IS_NOT_NULL(item->prev))
			item->prev->next = item->next;
		else
			chan->chanops = item->next;

		TRACE();

		#ifdef	FIX_USE_MPOOL
		mempool_free(channels_user_entry_mempool, item);
		#else
		mem_free(item);
		#endif
	}

	TRACE();

	/* Eliminazione dalla lista chan-halfops. */
	for (item = chan->halfops; IS_NOT_NULL(item) && (item->user != user); item = item->next)
		;

	if (IS_NOT_NULL(item)) {

		TRACE();
		if (IS_NOT_NULL(item->next))
			item->next->prev = item->prev;

		if (IS_NOT_NULL(item->prev))
			item->prev->next = item->next;
		else
			chan->halfops = item->next;

		TRACE();

		#ifdef	FIX_USE_MPOOL
		mempool_free(channels_user_entry_mempool, item);
		#else
		mem_free(item);
		#endif
	}

	TRACE();
	
	/* Eliminazione dalla lista chan-voices. */
	for (item = chan->voices; IS_NOT_NULL(item) && (item->user != user); item = item->next)
		;

	if (IS_NOT_NULL(item)) {

		TRACE();
		if (IS_NOT_NULL(item->next))
			item->next->prev = item->prev;

		if (IS_NOT_NULL(item->prev))
			item->prev->next = item->next;
		else
			chan->voices = item->next;

		TRACE();

		#ifdef	FIX_USE_MPOOL
		mempool_free(channels_user_entry_mempool, item);
		#else
		mem_free(item);
		#endif
	}

	TRACE();

	/* Se il canale e' rimasto vuoto, cancellarlo. */
	if (IS_NULL(chan->users)) {

		--stats_open_channels_count;

		LOG_DEBUG("channels: Deleting channel %s", chan->name);

		if (IS_NOT_NULL(chan->topic))
			mem_free(chan->topic);

		if (IS_NOT_NULL(chan->key))
			mem_free(chan->key);

		if (chan->bancount > 0) {

			int banIdx;

			for (banIdx = 0; banIdx < chan->bancount; ++banIdx)
				mem_free(chan->bans[banIdx]);
		}

		if (chan->bansize)
			mem_free(chan->bans);

		TRACE();
		if (IS_NOT_NULL(chan->chanops) || IS_NOT_NULL(chan->halfops) || IS_NOT_NULL(chan->voices)) {

			log_error(FACILITY_CHANNELS_USER_REMOVE, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_WARNING, 
				"channels: Memory leak freeing %s:%s%s%s not NULL!",
				chan->name,
				chan->chanops ? " chan->chanops" : "",
				chan->halfops ? " chan->halfops" : "",
				chan->voices ? " chan->voices" : "");
		}

		hash_channel_remove(chan);

		TRACE();

		#ifdef FIX_USE_MPOOL
		mempool_free(channels_mempool, chan);
		#else
		mem_free(chan);
		#endif
	}
}


/*********************************************************
 * chan_handle_chanMODE()                                *
 *                                                       *
 * Handle a channel MODE command.                        *
 *********************************************************/

#ifdef USE_SERVICES
/* An inline function we'll need later. */
static __inline__ BOOL grant_protection(Channel *chan, const User *callerUser, const User *targetUser) {

	int accessLevel, targetLevel;


	if (IS_NULL(chan) || IS_NULL(chan->ci) || FlagUnset(chan->ci->flags, CI_PROTECTED))
		return FALSE;

	/* If the user is deopping himself, no protection is given. */
	if (callerUser == targetUser)
		return FALSE;

	accessLevel = get_access(callerUser, chan->ci, NULL, NULL, NULL);
	targetLevel = get_access(targetUser, chan->ci, NULL, NULL, NULL);

	if ((targetLevel >= accessLevel) && (targetLevel > CS_ACCESS_HOP) && user_is_chanop(targetUser->nick, chan->name, chan))
		return TRUE;

	return FALSE;
}


/* Another inline function we'll need later. */
static __inline__ BOOL enforce_opguard(Channel *chan, const User *callerUser, const User *targetUser) {

	/* Make sure the channel is registered. */
	if (IS_NULL(chan) || IS_NULL(chan->ci))
		return FALSE;

	/* If the user opped himself, it's via /samode. Let it through. */
	if (callerUser == targetUser)
		return FALSE;

	/* Enforce OpGuard if the user doesn't have enough access to the channel. */
	if (!check_valid_op(targetUser, chan->ci, FALSE))
		return TRUE;

	/* ...or if who gave the ops is not an op and didn't use /samode and isn't a services agent (race condition on join). */
	if (FlagUnset(callerUser->mode, UMODE_a) && FlagUnset(callerUser->mode, UMODE_z)
	&& !user_is_chanop(callerUser->nick, chan->name, chan))
		return TRUE;

	return FALSE;
}

#endif /* USE_SERVICES */

/* Handy macro. */
#ifdef USE_STATS
#define MODE(flag) \
	if (add) { \
		AddFlag(chan->mode, (flag)); \
		++addmodes; \
	} else { \
		RemoveFlag(chan->mode, (flag)); \
		++delmodes; \
	}
#else
#define MODE(flag) \
	if (add) \
		AddFlag(chan->mode, (flag)); \
	else \
		RemoveFlag(chan->mode, (flag)); \
	 \
	checkModelock = TRUE;
#endif


void chan_handle_chanMODE(const char *source, const int ac, char **av) {

	Channel				*chan;
	User				*callerUser = NULL, *targetUser;
	char				*modes, *nick, *chan_name;
	BOOL				add = TRUE;
	int					argc;

	#ifdef USE_SERVICES
	int					idx, deopIdx = 0, reopIdx = 0, deopCount = 0, reopCount = 0;
	static User			*toDeop[16], *toReop[16];
	BOOL				checkModelock = FALSE;
	#endif

	#ifdef USE_STATS
	ChannelStats		*cs;
	int					addmodes = 0, delmodes = 0;
	#endif

	TRACE_MAIN_FCLT(FACILITY_CHANNELS_HANDLE_CHANMODE);

	if (IS_NULL(source) || IS_EMPTY_STR(source) || ac < 2 || IS_NULL(av[0]) ||
		IS_EMPTY_STR(av[0]) || IS_NULL(av[1]) || IS_EMPTY_STR(av[1])) {

		log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"chan_handle_chanMODE() called with invalid parameter(s) (%s, %d, %s, %s)", source, ac, av[0], av[1]);

		return;
	}

	TRACE_MAIN();

	chan_name = av[0];

	chan = hash_channel_find(chan_name);

	TRACE_MAIN();

	if (IS_NULL(chan)) {

		log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"MODE %s for nonexistent channel %s: %s", av[1], chan_name, merge_args(ac, av));

		return;
	}

	if (!strchr(source, '.') && IS_NULL(callerUser = hash_onlineuser_find(source))) {

		log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"MODE %s %s from nonexistent user %s", chan_name, av[1], source);

		return;
	}

	#ifdef USE_STATS
	cs = hash_chanstats_find(chan_name);

	if (IS_NULL(cs))
		log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
			"MODE %s %s: no channel stats found", chan_name, av[1]);

	if (callerUser)
		servers_increase_messages(callerUser);
	#endif

	#ifdef USE_SERVICES
	/* Initialize the static User arrays. */
	for (idx = 0; idx < 16; ++idx) {

		toDeop[idx] = NULL;
		toReop[idx] = NULL;
	}
	#endif

	modes = av[1];

	argc = ac - 2;
	av += 2;

	TRACE_MAIN();

	while (*modes) {

		switch (*modes++) {

			case '+':
				add = TRUE;
				break;

			case '-':
				add = FALSE;
				break;

			case 'b':
				if (--argc < 0) {

					log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
						"MODE %s %s: missing parameter for %cb", chan_name, av[1], add ? '+' : '-');

					break;
				}

				if (add) {

					chan_add_ban(chan, *av);

					#ifdef USE_STATS
					++total.bans;
					++monthly.bans;
					++weekly.bans;
					++daily.bans;

					if (cs) {

						++cs->totalbans;
						++cs->monthlybans;	
						++cs->weeklybans;
						++cs->dailybans;
						cs->last_change = NOW;
					}
					#endif
				}
				else
					chan_remove_ban(chan, *av);

				++av;
				break;

			case 'c':
				MODE(CMODE_c);
				break;

			case 'C':
				MODE(CMODE_C);
				break;

			case 'd':
				MODE(CMODE_d);
				break;
				
			case 'h':

				if (--argc < 0) {

					log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
						"MODE %s %s by %s: missing parameter for %ch", chan_name, av[1], source, add ? '+' : '-');

					break;
				}

				nick = *av++;

				if (IS_NULL(targetUser = hash_onlineuser_find(nick))) {

					log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
						"MODE %ch for nonexistent user %s on %s by %s", add ? '+' : '-', nick, chan_name, source);

					break;
				}

				/* Make sure the user is in the channel, in case an akicked user gets halfopped. */
				if (!user_isin_chan(targetUser, chan_name)) {

					log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
						"MODE %ch from %s: user %s is not on %s", add ? '+' : '-', source, nick, chan_name);

					break;
				}

				if (add) {

					chan_add_halfop(chan, targetUser);

					#ifdef USE_STATS
					++total.halfoppings;
					++monthly.halfoppings;
					++weekly.halfoppings;
					++daily.halfoppings;

					if (cs) {

						++cs->totalhalfoppings;
						++cs->monthlyhalfoppings;
						++cs->weeklyhalfoppings;
						++cs->dailyhalfoppings;
						cs->last_change = NOW;
					}
					#endif
				}
				else {

					chan_remove_halfop(chan, targetUser);

					#ifdef USE_STATS
					++total.dehalfoppings;
					++monthly.dehalfoppings;
					++weekly.dehalfoppings;
					++daily.dehalfoppings;

					if (cs) {

						++cs->totaldehalfoppings;
						++cs->monthlydehalfoppings;
						++cs->weeklydehalfoppings;
						++cs->dailydehalfoppings;
						cs->last_change = NOW;
					}
					#endif
				}

				break;
				
			case 'i':
				MODE(CMODE_i);
				break;

			case 'j':
				MODE(CMODE_j);
				break;

			case 'k': {

				char *key;

				if (--argc < 0) {

					log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
						"MODE %s %s: missing parameter for %ck", chan_name, av[1], add ? '+' : '-');

					break;
				}

				if (add) {

					if (IS_NOT_NULL(chan->key)) {

						mem_free(chan->key);
						chan->key = NULL;
					}

					key = *av++;

					if (IS_NOT_NULL(key)) {

						chan->key = str_duplicate(key);
						AddFlag(chan->mode, CMODE_k);
					}

					#ifdef USE_STATS
					++addmodes;
					#endif
				}
				else {

					if (IS_NOT_NULL(chan->key)) {

						mem_free(chan->key);
						chan->key = NULL;
					}

					/* Skip the key, if a -k arrives, we know the key is the same. */
					++av;

					RemoveFlag(chan->mode, CMODE_k);

					#ifdef USE_STATS
					++delmodes;
					#endif
				}

				#ifdef USE_SERVICES
				checkModelock = TRUE;
				#endif

				break;
			}

			case 'l':

				if (add) {

					char *limit;

					if (--argc < 0) {

						log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
							"MODE %s %s: missing parameter for +l", chan_name, av[1]);

						break;
					}

					limit = *av++;

					if (IS_NOT_NULL(limit)) {

						chan->limit = atoi(limit);
						AddFlag(chan->mode, CMODE_l);
					}

					#ifdef USE_STATS
					++addmodes;
					#endif
				}
				else {

					RemoveFlag(chan->mode, CMODE_l);
					chan->limit = 0;

					#ifdef USE_STATS
					++delmodes;
					#endif
				}

				#ifdef USE_SERVICES
				checkModelock = TRUE;
				#endif

				break;

			case 'm':
				MODE(CMODE_m);
				break;

			case 'M':
				MODE(CMODE_M);
				break;

			case 'n':
				MODE(CMODE_n);
				break;

			case 'o':

				#ifdef USE_SERVICES
				if (IS_NULL(callerUser)) {

					log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
						"MODE %co for channel %s from nonexistent user %s", add ? '+' : '-', chan_name, source);

					break;
				}
				#endif

				if (--argc < 0) {

					log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
						"MODE %s %s by %s: missing parameter for %co", chan_name, av[1], source, add ? '+' : '-');

					break;
				}

				nick = *av++;

				if (IS_NULL(targetUser = hash_onlineuser_find(nick))) {

					log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
						"MODE %co for nonexistent user %s on %s by %s", add ? '+' : '-', nick, chan_name, source);

					break;
				}

				/* Make sure the user is in the channel, in case an akicked user gets opped. */
				if (!user_isin_chan(targetUser, chan_name)) {

					log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
						"MODE %co from %s: user %s is not on %s", add ? '+' : '-', source, nick, chan_name);

					break;
				}

				if (add) {

					#ifdef USE_SERVICES
					if (enforce_opguard(chan, callerUser, targetUser)) {

						toDeop[deopIdx++] = targetUser;
						++deopCount;
					}
					else {

						BOOL wasOpped = FALSE;

						/* Remove the user from the list of users to be opped, if it was in.
						   We don't want to end up sending a +o for an op. Case of "-o+o nick nick" */
						for (idx = 0; idx < reopIdx; ++idx) {

							if (toReop[idx] == targetUser) {

								toReop[idx] = NULL;
								--reopCount;
								wasOpped = TRUE;
								break;
							}
						}

						if (wasOpped == FALSE)
					#endif
							chan_add_op(chan, targetUser);

					#ifdef USE_SERVICES
					}
					#endif

					#ifdef USE_STATS
					++total.oppings;
					++monthly.oppings;
					++weekly.oppings;
					++daily.oppings;

					if (cs) {

						++cs->totaloppings;
						++cs->monthlyoppings;
						++cs->weeklyoppings;
						++cs->dailyoppings;
						cs->last_change = NOW;
					}
					#endif
				}
				else {

					#ifdef USE_SERVICES
					/* Check if we need to reop this user due to ChanServ's Protected option. */
					if (grant_protection(chan, callerUser, targetUser)) {

						toReop[reopIdx++] = targetUser;
						++reopCount;
					}
					else {

						BOOL wasDeopped = FALSE;

						/* Remove the user from the list of users to be deopped, if it was in.
						   We don't want to end up sending a -o for a non-op. Case of "+o-o nick nick" */
						for (idx = 0; idx < deopIdx; ++idx) {

							if (toDeop[idx] == targetUser) {

								toDeop[idx] = NULL;
								--deopCount;
								wasDeopped = TRUE;
								break;
							}
						}

						if (wasDeopped == FALSE)
					#endif
							chan_remove_op(chan, targetUser);

					#ifdef USE_SERVICES
					}
					#endif

					#ifdef USE_STATS
					++total.deoppings;
					++monthly.deoppings;
					++weekly.deoppings;
					++daily.deoppings;

					if (cs) {

						++cs->totaldeoppings;
						++cs->monthlydeoppings;
						++cs->weeklydeoppings;
						++cs->dailydeoppings;
						cs->last_change = NOW;
					}
					#endif
				}
				break;

			case 'O':
				MODE(CMODE_O);
				break;

			case 'p':
				MODE(CMODE_p);
				break;

			case 'r':
				MODE(CMODE_r);
				break;

			case 'R':
				MODE(CMODE_R);
				break;

			case 's':
				MODE(CMODE_s);
				break;

			case 'S':
				MODE(CMODE_S);
				break;

			case 't':
				MODE(CMODE_t);
				break;

			case 'u':
				MODE(CMODE_u);
				break;

			case 'U':
				MODE(CMODE_U);
				break;
			
			case 'v':

				if (--argc < 0) {

					log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
						"MODE %s %s by %s: missing parameter for %cv", chan_name, av[1], source, add ? '+' : '-');

					break;
				}

				nick = *av++;

				if (IS_NULL(targetUser = hash_onlineuser_find(nick))) {

					log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
						"MODE %cv for nonexistent user %s on %s by %s", add ? '+' : '-', nick, chan_name, source);

					break;
				}

				/* Make sure the user is in the channel, in case an akicked user gets voiced. */
				if (!user_isin_chan(targetUser, chan_name)) {

					log_error(FACILITY_CHANNELS_HANDLE_CHANMODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_SKIPPED, 
						"MODE %cv from %s: user %s is not on %s", add ? '+' : '-', source, nick, chan_name);

					break;
				}

				if (add) {

					chan_add_voice(chan, targetUser);

					#ifdef USE_STATS
					++total.voicings;
					++monthly.voicings;
					++weekly.voicings;
					++daily.voicings;

					if (cs) {

						++cs->totalvoicings;
						++cs->monthlyvoicings;
						++cs->weeklyvoicings;
						++cs->dailyvoicings;
						cs->last_change = NOW;
					}
					#endif
				}
				else {

					chan_remove_voice(chan, targetUser);

					#ifdef USE_STATS
					++total.devoicings;
					++monthly.devoicings;
					++weekly.devoicings;
					++daily.devoicings;

					if (cs) {

						++cs->totaldevoicings;
						++cs->monthlydevoicings;
						++cs->weeklydevoicings;
						++cs->dailydevoicings;
						cs->last_change = NOW;
					}
					#endif
				}

				break;
		}
	}

	#ifdef USE_STATS
	if (addmodes > 0) {

		total.addcmodes += addmodes;
		monthly.addcmodes += addmodes;
		weekly.addcmodes += addmodes;
		daily.addcmodes += addmodes;

		TRACE_MAIN();

		if (cs) {

			cs->totaladdcmodes += addmodes;
			cs->monthlyaddcmodes += addmodes;
			cs->weeklyaddcmodes += addmodes;
			cs->dailyaddcmodes += addmodes;
			cs->last_change = NOW;
		}
	}

	if (delmodes > 0) {

		total.delcmodes += delmodes;
		monthly.delcmodes += delmodes;
		weekly.delcmodes += delmodes;
		daily.delcmodes += delmodes;

		TRACE_MAIN();

		if (cs) {

			cs->totaldelcmodes += delmodes;
			cs->monthlydelcmodes += delmodes;
			cs->weeklydelcmodes += delmodes;
			cs->dailydelcmodes += delmodes;
			cs->last_change = NOW;
		}
	}
	#endif

	TRACE_MAIN();

	#ifdef USE_SERVICES
	if ((deopCount > 0) || (reopCount > 0)) {

		int paramCount = 0;
		char nicks[IRCBUFSIZE], chanmodes[SERVER_MAX_MODES + 3];
		char *ptr;
		size_t len = 0;

		if (deopCount > 0) {

			for (idx = 0; idx < deopIdx; ++idx) {

				if (IS_NULL(targetUser = toDeop[idx]))
					continue;

				if (len > 0)
					nicks[len++] = c_SPACE;

				ptr = targetUser->nick;

				while (*ptr)
					nicks[len++] = *ptr++;

				if (paramCount == 0)
					chanmodes[paramCount++] = '-';

				chanmodes[paramCount++] = 'o';

				if (paramCount > SERVER_MAX_MODES) {

					chanmodes[paramCount] = '\0';
					nicks[len] = '\0';
					send_cmd(":%s MODE %s %s %s", s_ChanServ, chan_name, chanmodes, nicks);
					paramCount = 0;
					len = 0;
				}
			}
		}

		if (reopCount > 0) {

			chanmodes[paramCount++] = '+';

			for (idx = 0; idx < reopIdx; ++idx) {

				if (IS_NULL(targetUser = toReop[idx]))
					continue;

				if (len > 0)
					nicks[len++] = c_SPACE;

				ptr = targetUser->nick;

				while (*ptr)
					nicks[len++] = *ptr++;

				if (paramCount == 0)
					chanmodes[paramCount++] = '+';

				chanmodes[paramCount++] = 'o';

				if (paramCount > SERVER_MAX_MODES) {

					chanmodes[paramCount] = '\0';
					nicks[len] = '\0';
					send_cmd(":%s MODE %s %s %s", s_ChanServ, chan_name, chanmodes, nicks);
					paramCount = 0;
					len = 0;
				}
			}
		}

		if (paramCount > 0) {

			chanmodes[paramCount] = '\0';
			nicks[len] = '\0';
			send_cmd(":%s MODE %s %s %s", s_ChanServ, chan_name, chanmodes, nicks);
		}
	}

	/* Check modes against ChanServ mode lock */
	if (IS_NOT_NULL(chan->ci) && (checkModelock == TRUE))
		check_modelock(chan, callerUser);
	#endif
}


BOOL chan_add_op(Channel *chan, User *user) {

	UserListItem *item;


	TRACE_MAIN_FCLT(FACILITY_CHANNELS_ADD_OP);

	if (IS_NULL(chan) || IS_NULL(user)) {

		log_error(FACILITY_CHANNELS_ADD_OP, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"chan_add_op() called with invalid parameter(s) (%s, %s)", chan ? chan->name : NULL, user ? user->nick : NULL);

		return FALSE;
	}

	for (item = chan->chanops; IS_NOT_NULL(item) && (item->user != user); item = item->next)
		;

	if (IS_NOT_NULL(item)) {

//		log_error(FACILITY_CHANNELS_ADD_OP, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
//			"MODE %s +o for channel operator %s", chan->name, user->nick);

		return FALSE;
	}

	LOG_DEBUG("channels: Setting +o on %s for %s", chan->name, user->nick);

	#ifdef	FIX_USE_MPOOL
	item = mempool_alloc(UserListItem *, channels_user_entry_mempool, FALSE);
	#else
	item = mem_malloc(sizeof(UserListItem));
	#endif

	item->next = chan->chanops;
	item->prev = NULL;

	if (IS_NOT_NULL(chan->chanops))
		chan->chanops->prev = item;

	chan->chanops = item;
	item->user = user;

	return TRUE;
}

BOOL chan_remove_op(Channel *chan, const User *user) {

	UserListItem *item;


	TRACE_MAIN_FCLT(FACILITY_CHANNELS_REMOVE_OP);

	if (IS_NULL(chan) || IS_NULL(user)) {

		log_error(FACILITY_CHANNELS_REMOVE_OP, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"chan_remove_op() called with invalid parameter(s) (%s, %s)", chan ? chan->name : NULL, user ? user->nick : NULL);

		return FALSE;
	}

	for (item = chan->chanops; IS_NOT_NULL(item) && (item->user != user); item = item->next)
		;

	if (IS_NULL(item)) {

//		log_error(FACILITY_CHANNELS_REMOVE_OP, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
//			"MODE %s -o for channel non-op %s", chan->name, user->nick);

		return FALSE;
	}

	if (IS_NOT_NULL(item->next))
		item->next->prev = item->prev;

	if (IS_NOT_NULL(item->prev))
		item->prev->next = item->next;
	else
		chan->chanops = item->next;

	#ifdef FIX_USE_MPOOL
	mempool_free(channels_user_entry_mempool, item);
	#else
	mem_free(item);
	#endif

	return TRUE;
}


BOOL chan_add_halfop(Channel *chan, User *user) {

	UserListItem *item;


	TRACE_MAIN_FCLT(FACILITY_CHANNELS_ADD_HALFOP);

	if (IS_NULL(chan) || IS_NULL(user)) {

		log_error(FACILITY_CHANNELS_ADD_HALFOP, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"chan_add_halfop() called with invalid parameter(s) (%s, %s)", chan ? chan->name : NULL, user ? user->nick : NULL);

		return FALSE;
	}

	for (item = chan->halfops; IS_NOT_NULL(item) && (item->user != user); item = item->next)
		;

	if (IS_NOT_NULL(item)) {

//		log_error(FACILITY_CHANNELS_ADD_HALFOP, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
//			"MODE %s +h for channel halfop %s", chan->name, user->nick);

		return FALSE;
	}

	LOG_DEBUG("channels: Setting +h on %s for %s", chan->name, user->nick);

	#ifdef	FIX_USE_MPOOL
	item = mempool_alloc(UserListItem *, channels_user_entry_mempool, FALSE);
	#else
	item = mem_malloc(sizeof(UserListItem));
	#endif

	item->next = chan->halfops;
	item->prev = NULL;

	if (IS_NOT_NULL(chan->halfops))
		chan->halfops->prev = item;

	chan->halfops = item;
	item->user = user;

	return TRUE;
}


BOOL chan_remove_halfop(Channel *chan, const User *user) {

	UserListItem *item;


	TRACE_MAIN_FCLT(FACILITY_CHANNELS_REMOVE_HALFOP);

	if (IS_NULL(chan) || IS_NULL(user)) {

		log_error(FACILITY_CHANNELS_REMOVE_HALFOP, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"chan_remove_halfop() called with invalid parameter(s) (%s, %s)", chan ? chan->name : NULL, user ? user->nick : NULL);

		return FALSE;
	}

	for (item = chan->halfops; IS_NOT_NULL(item) && (item->user != user); item = item->next)
		;

	if (IS_NULL(item)) {

//		log_error(FACILITY_CHANNELS_REMOVE_HALFOP, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
//			"MODE %s -h for channel user %s", chan->name, user->nick);

		return FALSE;
	}

	if (IS_NOT_NULL(item->next))
		item->next->prev = item->prev;

	if (IS_NOT_NULL(item->prev))
		item->prev->next = item->next;
	else
		chan->halfops = item->next;

	#ifdef	FIX_USE_MPOOL
	mempool_free(channels_user_entry_mempool, item);
	#else
	mem_free(item);
	#endif

	return TRUE;
}


BOOL chan_add_voice(Channel *chan, User *user) {

	UserListItem *item;


	TRACE_MAIN_FCLT(FACILITY_CHANNELS_ADD_VOICE);

	if (IS_NULL(chan) || IS_NULL(user)) {

		log_error(FACILITY_CHANNELS_ADD_VOICE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"chan_add_voice() called with invalid parameter(s) (%s, %s)", chan ? chan->name : NULL, user ? user->nick : NULL);

		return FALSE;
	}

	for (item = chan->voices; IS_NOT_NULL(item) && (item->user != user); item = item->next)
		;

	if (IS_NOT_NULL(item)) {

//		log_error(FACILITY_CHANNELS_ADD_VOICE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
//			"MODE %s +v for channel voice %s", chan->name, user->nick);

		return FALSE;
	}

	LOG_DEBUG("channels: Setting +v on %s for %s", chan->name, user->nick);

	#ifdef	FIX_USE_MPOOL
	item = mempool_alloc(UserListItem *, channels_user_entry_mempool, FALSE);
	#else
	item = mem_malloc(sizeof(UserListItem));
	#endif

	item->next = chan->voices;
	item->prev = NULL;

	if (IS_NOT_NULL(chan->voices))
		chan->voices->prev = item;

	chan->voices = item;
	item->user = user;

	return TRUE;
}


BOOL chan_remove_voice(Channel *chan, const User *user) {

	UserListItem *item;


	TRACE_MAIN_FCLT(FACILITY_CHANNELS_REMOVE_VOICE);

	if (IS_NULL(chan) || IS_NULL(user)) {

		log_error(FACILITY_CHANNELS_REMOVE_VOICE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"chan_remove_voice() called with invalid parameter(s) (%s, %s)", chan ? chan->name : NULL, user ? user->nick : NULL);

		return FALSE;
	}

	for (item = chan->voices; IS_NOT_NULL(item) && (item->user != user); item = item->next)
		;

	if (IS_NULL(item)) {

//		log_error(FACILITY_CHANNELS_REMOVE_VOICE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
//			"MODE %s -v for channel user %s", chan->name, user->nick);

		return FALSE;
	}

	if (IS_NOT_NULL(item->next))
		item->next->prev = item->prev;

	if (IS_NOT_NULL(item->prev))
		item->prev->next = item->next;
	else
		chan->voices = item->next;

	#ifdef	FIX_USE_MPOOL
	mempool_free(channels_user_entry_mempool, item);
	#else
	mem_free(item);
	#endif

	return TRUE;
}

int chan_has_ban(Channel *chan, CSTR banmask, char *buffer) {

	char	**aBan;
	int		banIdx = 0;


	TRACE_MAIN_FCLT(FACILITY_CHANNELS_HAS_BAN);

	if (IS_NULL(chan) || IS_NULL(banmask) || IS_EMPTY_STR(banmask)) {

		log_error(FACILITY_CHANNELS_HAS_BAN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"chan_has_ban() called with invalid parameter(s) (%s, %s)", chan ? chan->name : NULL, banmask);

		return 0;
	}

	aBan = chan->bans;

	while (banIdx < chan->bancount) {

		if (str_match_wild_nocase(*aBan, banmask)) {

			if (IS_NOT_NULL(buffer))
				str_copy_checked(*aBan, buffer, MASKSIZE);

			if (str_equals_nocase(*aBan, banmask))
				return 2;

			return 1;
		}

		++banIdx;
		++aBan;
	}

	return 0;
}


BOOL chan_add_ban(Channel *chan, const char *mask) {

	TRACE_MAIN_FCLT(FACILITY_CHANNELS_ADD_BAN);

	if (IS_NULL(chan) || IS_NULL(mask) || IS_EMPTY_STR(mask)) {

		log_error(FACILITY_CHANNELS_ADD_BAN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"chan_add_ban() called with invalid parameter(s) (%s, %s)", chan ? chan->name : NULL, mask);

		return FALSE;
	}

	/* If this channel reached the ban limit don't add it, the ircd would block it anyway. */
	if (chan->bancount >= IRCD_MAX_BANS)
		return FALSE;

	/* Reallocate the array if necessary. */
	if (chan->bancount >= chan->bansize) {

		chan->bansize += 8;
		chan->bans = mem_realloc(chan->bans, sizeof(char *) * chan->bansize);
	}

	/* Add the new ban. */
	chan->bans[chan->bancount++] = str_duplicate(mask);

	return TRUE;
}

BOOL chan_remove_ban(Channel *chan, CSTR banmask) {

	char	**aBan;
	int		banIdx = 0;


	TRACE_MAIN_FCLT(FACILITY_CHANNELS_REMOVE_BAN);

	if (IS_NULL(chan) || IS_NULL(banmask) || IS_EMPTY_STR(banmask)) {

		log_error(FACILITY_CHANNELS_REMOVE_BAN, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"chan_remove_ban() called with invalid parameter(s) (%s, %s)", chan ? chan->name : NULL, banmask);

		return FALSE;
	}

	aBan = chan->bans;

	while ((banIdx < chan->bancount) && str_not_equals_nocase(*aBan, banmask)) {

		++banIdx;
		++aBan;
	}

	if (banIdx < chan->bancount) {

		--(chan->bancount);

		/* Free this entry. */
		mem_free(*aBan);

		/* Was it the only one? */
		if (chan->bancount == 0) {

			mem_free(chan->bans);
			chan->bans = NULL;
			chan->bansize = 0;
		}
		else if (banIdx < chan->bancount)	/* Was it in the middle of the list? */
			memmove(aBan, (aBan + 1), sizeof(char *) * (chan->bancount - banIdx));

		return TRUE;
	}

	return FALSE;
}


/*********************************************************
 * chan_clear_bans()                                     *
 *                                                       *
 * Removes all channel bans from memory.                 *
 *********************************************************/

void chan_clear_bans(Channel *chan) {

	int banIdx;


	TRACE_MAIN_FCLT(FACILITY_CHANNELS_CLEAR_BANS);

	if (IS_NULL(chan)) {

		log_error(FACILITY_CHANNELS_CLEAR_BANS, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, s_LOG_ERR_PARAMETER, "chan_clear_bans()", s_LOG_NULL, "chan");
		return;
	}

	for (banIdx = 0; banIdx < chan->bancount; ++banIdx)
		mem_free(chan->bans[banIdx]);

	if (chan->bansize)
		mem_free(chan->bans);

	chan->bans = NULL;
	chan->bancount = 0;
	chan->bansize = 0;
}


/*********************************************************
 * chan_handle_TOPIC()                                   *
 *                                                       *
 * Handle a TOPIC command.                               *
 *********************************************************/

void chan_handle_TOPIC(const char *source, const int ac, char **av) {

	Channel *chan;

	#ifdef USE_STATS
	ChannelStats *cs;
	#endif


	TRACE_MAIN_FCLT(FACILITY_CHANNELS_HANDLE_TOPIC);

	chan = hash_channel_find(av[0]);

	if (IS_NULL(chan)) {

		log_error(FACILITY_CHANNELS_HANDLE_TOPIC, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"TOPIC for nonexistent channel %s: %s", av[0], merge_args(ac, av));
		return;
	}

	if (IS_NULL(strchr(source, c_DOT))) {

		User *user;

		if (IS_NULL(user = hash_onlineuser_find(source))) {

			log_error(FACILITY_CHANNELS_HANDLE_TOPIC, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
				"TOPIC for channel %s from nonexistent user %s", av[0], source);
			return;
		}

		#ifdef USE_STATS
		servers_increase_messages(user);
		#endif

		#ifdef USE_SERVICES
		if (check_topiclock(user, chan))
			return;

		if (FlagSet(chan->mode, CMODE_t) && !user_is_chanop(source, av[0], chan) && !user_is_chanhalfop(source, av[0], chan)) {

			restore_topic(chan);
			return;
		}
		#endif
	}

	#ifdef USE_SERVICES
	else {

		/* This is a server topic. We are going to treat server topics just like normal topics
		   during normal operation for now. */

		if (synched == TRUE) {

			ChannelInfo *ci = chan->ci;

			if (IS_NOT_NULL(ci) && FlagSet(ci->flags, CI_TOPICLOCK)) {
					
				/* This is a server topic and channel has topiclock on, block this TOPIC
				   and replace it with ours (code taken from check_topiclock()) */

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
				return;
			}
		}
	}
	#endif

	TRACE_MAIN();
	str_copy_checked(av[1], chan->topic_setter, sizeof(chan->topic_setter));

	chan->topic_time = atol(av[2]);

	if (chan->topic) {

		mem_free(chan->topic);
		chan->topic = NULL;
	}

	TRACE_MAIN();
	if ((ac > 3) && *av[3])
		chan->topic = str_duplicate(av[3]);

	#ifdef USE_STATS
	++total.topics;
	++monthly.topics;
	++weekly.topics;
	++daily.topics;
	
	cs = hash_chanstats_find(av[0]);

	if (cs) {

		TRACE_MAIN();
		++cs->totaltopics;
		++cs->monthlytopics;
		++cs->weeklytopics;
		++cs->dailytopics;
		cs->last_change = NOW;
	}
	else
		LOG_DEBUG("[topic] No channel stats record for channel %s", av[0]);
	#endif

	TRACE_MAIN();

	#ifdef USE_SERVICES
	/* If we aren't synched this is a server topic, we save it in the channel struct but wait
	   for synch_topics() to record it if it is the case. */

	if ((synched == TRUE) && IS_NOT_NULL(chan->ci))
		record_topic(chan);
	#endif
}

/*********************************************************/

#ifdef USE_SERVICES

/* Restore the topic in a channel when it's created, if we should. */
void synch_topics() {

	Channel *chan;
	ChannelInfo *ci;
	int idx;


	HASH_FOREACH_BRANCH(idx, CHANNEL_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM(channel, idx, chan) {

			if (IS_NULL(chan->topic))
				continue;

			if (IS_NOT_NULL(ci = chan->ci)) {

				if (FlagUnset(ci->flags, CI_KEEPTOPIC) || IS_NULL(ci->last_topic) || str_equals(ci->last_topic, chan->topic)) {

					record_topic(chan);
					continue;
				}

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
		}
	}
}
#endif

/*********************************************************/

#ifdef USE_STATS
void handle_list(const char *source, User *callerUser, ServiceCommandData *data) {

	Channel *chan;
	int add = -1, idx, userCount = 0, opCount = 0, halfopCount = 0, voiceCount = 0, wantLimit = 0, matchModes = 0;
	long int matchLimit = 0;
	char g;
	char *token, *what;
	char *matchName = NULL, *matchTopic = NULL, *matchTopicSetter = NULL, *matchKey = NULL;
	BOOL wantUsers = FALSE, wantOps = FALSE, wantHalfops = FALSE, wantVoices = FALSE, wantCreationTime = FALSE, wantTopicTime = FALSE;
	BOOL wantModes = FALSE;
	time_t creationTime = 0, topicTime = 0;


	if (IS_NULL(what = strtok(NULL, " ")) || ((what[0] != '+') && (what[0] != '-'))) {

		send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
		return;
	}

	while (*what) {

		switch (g = *what++) {

			case '+':
				add = 1;
				break;

			case '-':
				add = 0;
				break;

			case 'c': {

				char *err;
				time_t ts;

				if (!(token = strtok(NULL, " ")) || ((ts = strtol(token, &err, 10)) <= 0) || *err != 0) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				creationTime = ts;
				wantCreationTime = add;
				break;
			}

			case 'h': {

				char *err;

				/* Users count */
				if (IS_NULL(token = strtok(NULL, " ")) || ((halfopCount = strtol(token, &err, 10)) <= 0) || *err != 0) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				wantHalfops = add;
				break;
			}

			case 'k':

				/* Key */
				if (IS_NULL(token = strtok(NULL, " "))) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				matchKey = str_duplicate(token);
				break;


			case 'l': {

				char *err;

				if (!(token = strtok(NULL, " ")) || ((matchLimit = strtol(token, &err, 10)) <= 0) || *err != 0) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				wantLimit = add;
				break;
			}


			case 'm':

				/* Channel Modes */
				if (IS_NULL(token = strtok(NULL, " "))) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				while (*token) {

					switch (*token++) {

						case 'c': AddFlag(matchModes, CMODE_c); break;
						case 'C': AddFlag(matchModes, CMODE_C); break;
						case 'd': AddFlag(matchModes, CMODE_d); break;
						case 'i': AddFlag(matchModes, CMODE_i); break;
						case 'j': AddFlag(matchModes, CMODE_j); break;
						case 'k': AddFlag(matchModes, CMODE_k); break;
						case 'l': AddFlag(matchModes, CMODE_l); break;
						case 'm': AddFlag(matchModes, CMODE_m); break;
						case 'M': AddFlag(matchModes, CMODE_M); break;
						case 'n': AddFlag(matchModes, CMODE_n); break;
						case 'O': AddFlag(matchModes, CMODE_O); break;
						case 'p': AddFlag(matchModes, CMODE_p); break;
						case 'r': AddFlag(matchModes, CMODE_r); break;
						case 'R': AddFlag(matchModes, CMODE_R); break;
						case 's': AddFlag(matchModes, CMODE_s); break;
						case 'S': AddFlag(matchModes, CMODE_S); break;
						case 't': AddFlag(matchModes, CMODE_t); break;
						case 'u': AddFlag(matchModes, CMODE_u); break;
						case 'U': AddFlag(matchModes, CMODE_U); break;
					}
				}

				if (matchModes == 0) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				wantModes = add;
				break;


			case 'n':

				/* Channel name */
				if (IS_NULL(token = strtok(NULL, " "))) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				matchName = str_duplicate(token);
				break;


			case 'o': {

				char *err;

				/* Users count */
				if (IS_NULL(token = strtok(NULL, " ")) || ((opCount = strtol(token, &err, 10)) <= 0) || *err != 0) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				wantOps = add;
				break;
			}


			case 's':

				/* Topic setter */
				if (IS_NULL(token = strtok(NULL, " "))) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				matchTopicSetter = str_duplicate(token);
				break;


			case 't':

				/* Topic */
				if (IS_NULL(token = strtok(NULL, " "))) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				matchTopic = str_duplicate(token);
				break;


			case 'T': {

				char *err;
				time_t ts;

				/* Topic time */
				if (!(token = strtok(NULL, " ")) || ((ts = strtol(token, &err, 10)) <= 0) || *err != 0) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				topicTime = ts;
				wantTopicTime = add;
				break;
			}


			case 'u': {

				char *err;

				/* Users count */
				if (IS_NULL(token = strtok(NULL, " ")) || ((userCount = strtol(token, &err, 10)) <= 0) || *err != 0) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				wantUsers = add;
				break;
			}


			case 'v': {

				char *err;

				/* Users count */
				if (IS_NULL(token = strtok(NULL, " ")) || ((voiceCount = strtol(token, &err, 10)) <= 0) || *err != 0) {

					send_notice_to_user(s_StatServ, callerUser, "Syntax Error.");
					goto done;
				}

				wantVoices = add;
				break;
			}
			
		}
	}

	send_cmd("321 %s Channel :Users Name", source);

	HASH_FOREACH_BRANCH(idx, CHANNEL_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM(channel, idx, chan) {

			if (IS_NOT_NULL(matchName) && !str_match_wild_nocase(matchName, chan->name))
				continue;

			if (IS_NOT_NULL(matchKey) && (IS_NULL(chan->key) || !str_match_wild_nocase(matchKey, chan->key)))
				continue;

			if (IS_NOT_NULL(matchTopic) && (IS_NULL(chan->topic) || !str_match_wild_nocase(matchTopic, chan->topic)))
				continue;

			if (IS_NOT_NULL(matchTopicSetter) && (IS_EMPTY_STR(chan->topic_setter) ||
				!str_match_wild_nocase(matchTopicSetter, chan->topic_setter)))
				continue;

			if ((matchLimit > 0) && ((chan->limit <= 0) || (wantLimit ? (chan->limit < matchLimit) : (chan->limit > matchLimit))))
				continue;

			if ((topicTime > 0) && ((chan->topic_time <= 0) ||
				(wantTopicTime ? (NOW - chan->topic_time < topicTime) : (NOW - chan->topic_time > topicTime))))
				continue;

			if ((creationTime > 0) && ((chan->creation_time <= 0) ||
				(wantCreationTime ? (NOW - chan->creation_time < creationTime) : (NOW - chan->creation_time < creationTime))))
				continue;

			if (opCount > 0) {

				int ops = 0;
				UserListItem *item;


				for (item = chan->chanops; IS_NOT_NULL(item); item = item->next)
					++ops;

				if (wantOps ? (ops <= opCount) : (ops >= opCount))
					continue;
			}
			
			if (halfopCount > 0) {

				int halfops = 0;
				UserListItem *item;


				for (item = chan->halfops; IS_NOT_NULL(item); item = item->next)
					++halfops;

				if (wantHalfops ? (halfops <= halfopCount) : (halfops >= halfopCount))
					continue;
			}
			
			if (voiceCount > 0) {

				int voices = 0;
				UserListItem *item;


				for (item = chan->voices; IS_NOT_NULL(item); item = item->next)
					++voices;

				if (wantVoices ? (voices <= voiceCount) : (voices >= voiceCount))
					continue;
			}


			if (matchModes != 0) {

				if ((wantModes && !((chan->mode & matchModes) == matchModes)) ||
					(!wantModes && ((chan->mode & matchModes) == matchModes)))
					continue;
			}

			if ((userCount > 0) && (wantUsers ? (chan->userCount <= userCount) : (chan->userCount >= userCount)))
				continue;

			if (chan->mode != 0)
				send_cmd("322 %s %s %u :[%s] %s", source, chan->name, chan->userCount, get_channel_mode(chan->mode, 0), chan->topic ? chan->topic : "");
			else
				send_cmd("322 %s %s %u :%s", source, chan->name, chan->userCount, chan->topic ? chan->topic : "");
		}
	}

	send_cmd("323 %s :End of /LIST", source);

done:

	if (matchTopic)
		mem_free(matchTopic);

	if (matchTopicSetter)
		mem_free(matchTopicSetter);

	if (matchKey)
		mem_free(matchKey);

	if (matchName)
		mem_free(matchName);
}
#endif

/*********************************************************/

char *get_channel_mode(const long int modeOn, const long int modeOff) {

	static char modebuf[67];	/* 2*32 modes, +, -, \0 */
	int modeIdx = 0;


	TRACE_MAIN_FCLT(FACILITY_CHANNELS_GET_CHANNEL_MODE);

	if (modeOn != 0) {

		modebuf[modeIdx++] = '+';

		if (FlagSet(modeOn, CMODE_c))
			modebuf[modeIdx++] = 'c';

		if (FlagSet(modeOn, CMODE_C))
			modebuf[modeIdx++] = 'C';

		if (FlagSet(modeOn, CMODE_d))
			modebuf[modeIdx++] = 'd';

		if (FlagSet(modeOn, CMODE_i))
			modebuf[modeIdx++] = 'i';

		if (FlagSet(modeOn, CMODE_j))
			modebuf[modeIdx++] = 'j';

		if (FlagSet(modeOn, CMODE_k))
			modebuf[modeIdx++] = 'k';

		if (FlagSet(modeOn, CMODE_l))
			modebuf[modeIdx++] = 'l';

		if (FlagSet(modeOn, CMODE_m))
			modebuf[modeIdx++] = 'm';

		if (FlagSet(modeOn, CMODE_M))
			modebuf[modeIdx++] = 'M';

		if (FlagSet(modeOn, CMODE_n))
			modebuf[modeIdx++] = 'n';

		if (FlagSet(modeOn, CMODE_O))
			modebuf[modeIdx++] = 'O';

		if (FlagSet(modeOn, CMODE_p))
			modebuf[modeIdx++] = 'p';

		if (FlagSet(modeOn, CMODE_r))
			modebuf[modeIdx++] = 'r';

		if (FlagSet(modeOn, CMODE_R))
			modebuf[modeIdx++] = 'R';

		if (FlagSet(modeOn, CMODE_s))
			modebuf[modeIdx++] = 's';

		if (FlagSet(modeOn, CMODE_S))
			modebuf[modeIdx++] = 'S';

		if (FlagSet(modeOn, CMODE_t))
			modebuf[modeIdx++] = 't';

		if (FlagSet(modeOn, CMODE_u))
			modebuf[modeIdx++] = 'u';
		
		if (FlagSet(modeOn, CMODE_U))
			modebuf[modeIdx++] = 'U';

		if (modeIdx == 1)
			log_error(FACILITY_CHANNELS_GET_CHANNEL_MODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING,
				"get_channel_mode(): Unknown positive mode value ignored (%ld)", modeOn);
	}

	if (modeOff != 0) {

		int startIdx;


		modebuf[modeIdx++] = '-';

		startIdx = modeIdx;

		if (FlagSet(modeOff, CMODE_c))
			modebuf[modeIdx++] = 'c';

		if (FlagSet(modeOff, CMODE_C))
			modebuf[modeIdx++] = 'C';

		if (FlagSet(modeOff, CMODE_d))
			modebuf[modeIdx++] = 'd';

		if (FlagSet(modeOff, CMODE_i))
			modebuf[modeIdx++] = 'i';

		if (FlagSet(modeOff, CMODE_j))
			modebuf[modeIdx++] = 'j';

		if (FlagSet(modeOff, CMODE_k))
			modebuf[modeIdx++] = 'k';

		if (FlagSet(modeOff, CMODE_l))
			modebuf[modeIdx++] = 'l';

		if (FlagSet(modeOff, CMODE_m))
			modebuf[modeIdx++] = 'm';

		if (FlagSet(modeOff, CMODE_M))
			modebuf[modeIdx++] = 'M';

		if (FlagSet(modeOff, CMODE_n))
			modebuf[modeIdx++] = 'n';

		if (FlagSet(modeOff, CMODE_O))
			modebuf[modeIdx++] = 'O';

		if (FlagSet(modeOff, CMODE_p))
			modebuf[modeIdx++] = 'p';

		if (FlagSet(modeOff, CMODE_r))
			modebuf[modeIdx++] = 'r';

		if (FlagSet(modeOff, CMODE_R))
			modebuf[modeIdx++] = 'R';

		if (FlagSet(modeOff, CMODE_s))
			modebuf[modeIdx++] = 's';

		if (FlagSet(modeOff, CMODE_S))
			modebuf[modeIdx++] = 'S';

		if (FlagSet(modeOff, CMODE_t))
			modebuf[modeIdx++] = 't';

		if (FlagSet(modeOff, CMODE_u))
			modebuf[modeIdx++] = 'u';

		if (FlagSet(modeOff, CMODE_U))
			modebuf[modeIdx++] = 'U';
		
		if (modeIdx == startIdx)
			log_error(FACILITY_CHANNELS_GET_CHANNEL_MODE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_WARNING,
				"get_channel_mode(): Unknown negative mode value ignored (%ld)", modeOff);
	}

	if (modeIdx == 0)
		return "None";

	modebuf[modeIdx] = '\0';
	return modebuf;
}

/*********************************************************/
#ifdef USE_SERVICES
void handle_masscmds(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *chan_name;
	Channel *chan;
	ChannelInfo *ci;
	int accessLevel, accessMatch;
	char accessName[NICKSIZE];
	BOOL isChanServ = (data->agent->agentID == AGENTID_CHANSERV);


	TRACE_MAIN_FCLT(FACILITY_CHANNELS_HANDLE_MASSCMDS);

	if (IS_NULL(chan_name = strtok(NULL, " "))) {

		switch (data->commandName[3]) {

			case 'C':	/* MKICK */
				send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_MKICK_SYNTAX_ERROR);
				break;

			default:
				send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_CLEAR_SYNTAX_ERROR, data->commandName);
				break;
		}

		return;
	}

	if (chan_name[0] != '#') {

		send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, chan_name, chan_name);
		return;
	}

	if (IS_NULL(chan = hash_channel_find(chan_name))) {

		send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_CHAN_DOES_NOT_EXIST, chan_name);
		return;
	}

	ci = chan->ci;

	if (isChanServ) {

		if (IS_NULL(ci)) {

			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, chan_name);
			return;
		}

		accessLevel = get_access(callerUser, ci, accessName, &accessMatch, NULL);

		if (accessLevel < CS_ACCESS_SOP) {

			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
			return;
		}
		else if (FlagSet(ci->flags, CI_FROZEN)) {

			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_ERROR_CHAN_FROZEN, ci->name);
			return;
		}
		else if (FlagSet(ci->flags, CI_CLOSED)) {

			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_ERROR_CHAN_CLOSED, ci->name);
			return;
		}
		else if (FlagSet(ci->flags, CI_SUSPENDED)) {

			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_ERROR_CHAN_SUSPENDED, ci->name);
			return;
		}
		else if (FlagSet(ci->flags, CI_NOENTRY)) {

			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_ERROR_NOENTRY_ON, ci->name);
			return;
		}
	}

	switch (data->commandName[3]) {

	case 'B': {		/* MUNBAN */

		char		nickbuf[IRCBUFSIZE], modebuf[SERVER_MAX_MODES + 2];
		char		*nickptr = nickbuf, *modeptr = modebuf;
		const char	*banptr;
		size_t		len = 0;
		int			banIdx, bancount = 0;

		if (chan->bancount == 0) {

			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_BANLIST_EMPTY, chan->name);
			return;
		}

		memset(nickbuf, 0, sizeof(nickbuf));

		TRACE_MAIN();

		for (banIdx = 0; banIdx < chan->bancount; ++banIdx) {

			TRACE_MAIN();
			if (IS_NOT_EMPTY_STR(nickbuf))
				*nickptr++ = c_SPACE;
			else
				*modeptr++ = '-';

			banptr = chan->bans[banIdx];

			while (*banptr != '\0') {

				*nickptr++ = *banptr++;
				++len;
			}

			*modeptr++ = 'b';

			++bancount;

			/* 512 - 4 (MODE) - 30 (chan) - 13 ((SERVER_MAX_MODES - 1) + "-")
				- 4 (spaces + \0) - 105 (max length of 1 ban) = 355 */

			if ((bancount >= SERVER_MAX_MODES) || (len > 350)) {

				*nickptr = '\0';
				*modeptr = '\0';

				send_cmd(":%s MODE %s %s %s", s_ChanServ, chan_name, modebuf, nickbuf);

				bancount = len = 0;

				memset(nickbuf, 0, sizeof(nickbuf));

				nickptr = nickbuf;
				modeptr = modebuf;
			}
		}

		if (IS_NOT_EMPTY_STR(nickbuf)) {

			*nickptr = '\0';
			*modeptr = '\0';

			send_cmd(":%s MODE %s %s %s", s_ChanServ, chan_name, modebuf, nickbuf);
		}

		chan_clear_bans(chan);

		send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_UNBAN_ALL_BANS_LIFTED, chan_name);

		if (isChanServ) {

			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_CLEAR)) {

				if (accessMatch)
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_CLEAR_BANS), data->agent->nick, chan_name, callerUser->nick);
				else
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_CLEAR_BANS_THROUGH), data->agent->nick, chan_name, callerUser->nick, accessName);
			}

			if (accessMatch) {

				LOG_SNOOP(s_OperServ, "CS C %s -- by %s (%s@%s) [Bans]", ci->name, source, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "C %s -- by %s (%s@%s) [Bans]", ci->name, source, callerUser->username, callerUser->host);
			}
			else {

				LOG_SNOOP(s_OperServ, "CS C %s -- by %s (%s@%s) through %s [Bans]", ci->name, source, callerUser->username, callerUser->host, accessName);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "C %s -- by %s (%s@%s) through %s [Bans]", ci->name, source, callerUser->username, callerUser->host, accessName);
			}
		}
		else {

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 cleared all bans on \2%s\2", source, chan_name);

				LOG_SNOOP(s_OperServ, "OS C %s -- by %s (%s@%s) [Bans]", chan_name, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "C %s -- by %s (%s@%s) [Bans]", chan_name, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) cleared all bans on \2%s\2", source, data->operName, chan_name);

				LOG_SNOOP(s_OperServ, "OS C %s -- by %s (%s@%s) through %s [Bans]", chan_name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "C %s -- by %s (%s@%s) through %s [Bans]", chan_name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}
		}

		break;
	}


	case 'E': {		/* RESETMODES */

		char modebuf[48];	/* To be on the safe side. */
		unsigned int idx, modeIdx = 1;
		BOOL removeKey = FALSE;

		TRACE_MAIN();

		modebuf[0] = '-';

		for (idx = 0; idx < known_cmodes_count; ++idx) {

			if (FlagSet(chan->mode, known_cmodes[idx].mode) && (isChanServ ? FlagUnset(ci->mlock_on, known_cmodes[idx].mode) : TRUE)) {

				if (known_cmodes[idx].letter == 'r')
					continue;

				else if (known_cmodes[idx].letter == 'k') {

					if (chan->key && (isChanServ ? (!ci->mlock_key || str_not_equals(chan->key, ci->mlock_key)) : TRUE))
						removeKey = TRUE;
					else
						continue;
				}

				RemoveFlag(chan->mode, known_cmodes[idx].mode);
				modebuf[modeIdx++] = known_cmodes[idx].letter;
			}
		}

		/* Remove the modes, if any. */
		if (modeIdx > 1) {

			modebuf[modeIdx] = '\0';

			send_chan_MODE(s_ChanServ, chan_name, modebuf, 0, (removeKey ? chan->key : NULL));

			if (removeKey) {

				mem_free(chan->key);
				chan->key = NULL;
			}

			/* Did we remove the limit? */
			if (FlagUnset(chan->mode, CMODE_l))
				chan->limit = 0;
		}

		TRACE_MAIN();
		send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_CLEAR_MODES_CLEARED, chan_name);

		if (isChanServ) {

			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_CLEAR)) {

				if (accessMatch)
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_MODES_CLEARED), s_ChanServ, chan_name, callerUser->nick);
				else
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_MODES_CLEARED_THROUGH), s_ChanServ, chan_name, callerUser->nick, accessName);
			}

			if (accessMatch) {

				LOG_SNOOP(s_OperServ, "CS C %s -- by %s (%s@%s) [Modes]", ci->name, source, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "C %s -- by %s (%s@%s) [Modes]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				LOG_SNOOP(s_OperServ, "CS C %s -- by %s (%s@%s) through %s [Modes]", ci->name, source, callerUser->username, callerUser->host, accessName);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "C %s -- by %s (%s@%s) through %s [Modes]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName);
			}

			check_modelock(chan, NULL);
		}
		else {

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 cleared all modes on \2%s\2", source, chan->name);

				LOG_SNOOP(s_OperServ, "OS C %s -- by %s (%s@%s) [Modes]", chan->name, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_OPERSERV, "C %s -- by %s (%s@%s) [Modes]", chan->name, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) cleared all modes on \2%s\2", source, data->operName, chan->name);

				LOG_SNOOP(s_OperServ, "OS C %s -- by %s (%s@%s) through %s [Modes]", chan->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
				log_services(LOG_SERVICES_OPERSERV, "C %s -- by %s (%s@%s) through %s [Modes]", chan->name, callerUser->nick, callerUser->username, callerUser->host, data->operName);
			}
		}

		break;
	}

	case 'O':		/* MDEOP */
	case 'H':		/* MDEHALFOP */
	case 'V': {		/* MDEVOICE */

		char			nickbuf[IRCBUFSIZE], modebuf[SERVER_MAX_MODES + 2];
		char			*nickptr = nickbuf, *modeptr = modebuf;
		const char		*userptr;
		UserListItem	*item, *next_item;
		int				count = 0;
		BOOL			isDeop = (data->commandName[3] == 'O');
		BOOL			isDehalfop = (data->commandName[3] == 'H');
		BOOL			isDevoice = (data->commandName[3] == 'V');

		TRACE_MAIN();

		memset(nickbuf, 0, sizeof(nickbuf));

		if (isChanServ) {

			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_CLEAR)) {

				if (accessMatch) {
					if (isDevoice)
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_MASS_DEVOICE), s_ChanServ, chan_name, callerUser->nick);
					if (isDehalfop) 
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_MASS_DEHALFOP), s_ChanServ, chan_name, callerUser->nick);
					if (isDeop)
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_MASS_DEOP), s_ChanServ, chan_name, callerUser->nick);
				}
				else {
					if (isDevoice)
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_MASS_DEVOICE_THROUGH), s_ChanServ, chan_name, callerUser->nick, accessName);
					if (isDehalfop) 
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_MASS_DEHALFOP_THROUGH), s_ChanServ, chan_name, callerUser->nick, accessName);
					if (isDeop)
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_MASS_DEOP_THROUGH), s_ChanServ, chan_name, callerUser->nick, accessName);
				}
			}

			if (accessMatch) {

				LOG_SNOOP(s_OperServ, "CS C %s -- by %s (%s@%s) [%s]", ci->name, source, callerUser->username, callerUser->host, isDeop ? "Ops" : (isDehalfop ? "HalfOps" : "Voices"));
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "C %s -- by %s (%s@%s) [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, isDeop ? "Ops" : (isDehalfop ? "HalfOps" : "Voices"));
			}
			else {

				LOG_SNOOP(s_OperServ, "CS C %s -- by %s (%s@%s) through %s [%s]", ci->name, source, callerUser->username, callerUser->host, accessName, isDeop ? "Ops" : (isDehalfop ? "HalfOps" : "Voices"));
				log_services(LOG_SERVICES_CHANSERV_ACCESS, "C %s -- by %s (%s@%s) through %s [%s]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName, isDeop ? "Ops" : (isDehalfop ? "HalfOps" : "Voices"));
			}
		}

		item = (isDeop) ? chan->chanops : ((isDehalfop) ? chan->halfops : chan->voices);

		for (; item; item = next_item) {

			TRACE_MAIN();
			next_item = item->next;

			TRACE_MAIN();
			if (str_not_equals_nocase(item->user->nick, source)) {

				TRACE_MAIN();
				if (IS_NOT_EMPTY_STR(nickbuf))
					*nickptr++ = c_SPACE;
				else
					*modeptr++ = '-';

				userptr = item->user->nick;

				while (*userptr != '\0')
					*nickptr++ = *userptr++;

				++count;

				if (isDeop) {

					*modeptr++ = 'o';
					chan_remove_op(chan, item->user);
				}
				else if (isDehalfop) {

					*modeptr++ = 'h';
					chan_remove_halfop(chan, item->user);
				}
				else {

					*modeptr++ = 'v';
					chan_remove_voice(chan, item->user);
				}

				if (count >= SERVER_MAX_MODES) {

					*nickptr = '\0';
					*modeptr = '\0';

					send_cmd(":%s MODE %s %s %s", data->agent->nick, chan_name, modebuf, nickbuf);

					/* Re-initialize variables. */
					count  = 0;
					memset(nickbuf, 0, sizeof(nickbuf));
					nickptr = nickbuf;
					modeptr = modebuf;
				}
			}
		}

		if (IS_NOT_EMPTY_STR(nickbuf)) {

			*nickptr = '\0';
			*modeptr = '\0';

			send_cmd(":%s MODE %s %s %s", data->agent->nick, chan_name, modebuf, nickbuf);
		}

		if (isDevoice)
			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_CLEAR_VOICES_COMPLETE, chan->name);
		if (isDehalfop)
			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_CLEAR_HALFOPS_COMPLETE, chan->name);
		if (isDeop)
			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_CLEAR_OPS_COMPLETE, chan->name);

		if (data->agent->agentID == AGENTID_OPERSERV) {

			if (data->operMatch) {

				send_globops(s_OperServ, "\2%s\2 cleared all %s [\2%d\2] on \2%s\2.", source, isDeop ? "Ops" : "Voices", count, chan_name);

				LOG_SNOOP(s_OperServ, "OS C %s -- by %s (%s@%s) [%s (%d)]", chan_name, callerUser->nick, callerUser->username, callerUser->host, isDeop ? "Ops" : "Voices", count);
				log_services(LOG_SERVICES_OPERSERV, "C %s -- by %s (%s@%s) [%s (%d)]", chan_name, callerUser->nick, callerUser->username, callerUser->host, isDeop ? "Ops" : (isDehalfop ? "HalfOps" : "Voices"), count);
			}
			else {

				send_globops(s_OperServ, "\2%s\2 (through \2%s\2) cleared all %s [\2%d\2] on \2%s\2.", source, data->operName, isDeop ? "Ops" : (isDehalfop ? "HalfOps" : "Voices"), count, chan_name);

				LOG_SNOOP(s_OperServ, "OS C %s -- by %s (%s@%s) through %s [%s (%d)]", chan_name, callerUser->nick, callerUser->username, callerUser->host, data->operName, isDeop ? "Ops" : (isDehalfop ? "HalfOps" : "Voices"), count);
				log_services(LOG_SERVICES_OPERSERV, "C %s -- by %s (%s@%s) through %s [%s (%d)]", chan_name, callerUser->nick, callerUser->username, callerUser->host, data->operName, isDeop ? "Ops" : (isDehalfop ? "HalfOps" : "Voices"), count);
			}
		}

		break;
	}


	case 'C': {		/* MKICK */

		const char *reason;

		if (isChanServ && FlagSet(ci->flags, CI_NOMKICK)) {

			send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_CLEAR_ERROR_NOMKICK_ON, chan_name);

			if (CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_CLEAR)) {

				if (accessMatch)
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_MASS_KICK_FAILED), s_ChanServ, chan_name, callerUser->nick);
				else
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_MASS_KICK_FAILED_THROUGH), s_ChanServ, chan_name, callerUser->nick, accessName);
			}

			if (accessMatch) {

				LOG_SNOOP(s_OperServ, "CS *C %s -- by %s (%s@%s) [Users]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "*C %s -- by %s (%s@%s) [Users]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
			}
			else {

				LOG_SNOOP(s_OperServ, "CS *C %s -- by %s (%s@%s) through %s [Users]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName);
				log_services(LOG_SERVICES_CHANSERV_GENERAL, "*C %s -- by %s (%s@%s) through %s [Users]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName);
			}

			return;
		}

		if ((ci && FlagSet(ci->flags, CI_NOENTRY)) || (!ci && FlagSet(chan->mode, CMODE_CS))) {

			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_CLEAR_USERS_ERROR_WAIT, CONF_CHANNEL_INHABIT, chan->name);
			return;
		}

		reason = strtok(NULL, "");

		if (reason && (str_len(reason) > 200))
			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_ERROR_REASON_MAX_LENGTH, 200);

		else {

			UserListItem	*item, *next_item;
			char			kick_msg[IRCBUFSIZE];
			int				count = 0, skipped = 0;

			TRACE_MAIN();

			if (IS_NOT_NULL(ci) && CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_CLEAR)) {

				if (accessMatch)
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_MASS_KICK), s_ChanServ, chan_name, callerUser->nick);
				else
					send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_MASS_KICK_THROUGH), s_ChanServ, chan_name, callerUser->nick, accessName);
			}

			TRACE_MAIN();
			if (FlagUnset(chan->mode, CMODE_CS)) {

				send_SJOIN(s_ChanServ, chan_name);
				AddFlag(chan->mode, CMODE_CS);
			}

			send_cmd(":%s MODE %s +b *!*@* %lu", s_ChanServ, chan_name, NOW);

			for (item = chan->users; item; item = next_item) {

				next_item = item->next;

				if (user_is_services_agent(item->user) || is_services_admin(item->user)) {

					++skipped;
					continue;
				}

				++count;

				if (!isChanServ || accessMatch) {

					if (reason)
						snprintf(kick_msg, sizeof(kick_msg), lang_msg(item->user->current_lang, CS_CLEAR_USERS_KICK_REASON), isChanServ ? source : s_GlobalNoticer, reason);
					else
						snprintf(kick_msg, sizeof(kick_msg), lang_msg(item->user->current_lang, CS_CLEAR_USERS_KICK_NOREASON), isChanServ ? source : s_GlobalNoticer);
				}
				else {

					if (reason)
						snprintf(kick_msg, sizeof(kick_msg), lang_msg(item->user->current_lang, CS_CLEAR_USERS_KICK_REASON_THROUGH), source, accessName, reason);
					else
						snprintf(kick_msg, sizeof(kick_msg), lang_msg(item->user->current_lang, CS_CLEAR_USERS_KICK_NOREASON_THROUGH), source, accessName);
				}

				send_cmd(":%s KICK %s %s :%s", s_ChanServ, chan_name, item->user->nick, kick_msg);
				user_handle_services_kick(chan_name, item->user);
			}

			--skipped; /* Let's not count ChanServ as skipped. */

			TRACE_MAIN();

			if (IS_NULL(ci) || FlagUnset(ci->flags, CI_TIMEOUT)) {

				ChannelTimeoutData	*data1, *data2;

				TRACE();
				data1 = mem_malloc(sizeof(ChannelTimeoutData));
				data2 = mem_malloc(sizeof(ChannelTimeoutData));

				if (IS_NOT_NULL(ci)) {

					data1->type = data2->type = CTOD_CHAN_RECORD;
					data1->info.record = data2->info.record = ci;
					AddFlag(ci->flags, CI_NOENTRY);
					AddFlag(ci->flags, CI_TIMEOUT);
				}
				else {

					data1->type = data2->type = CTOD_CHAN_NAME;
					data1->info.name = str_duplicate(chan_name);
					data2->info.name = str_duplicate(chan_name);
				}

				timeout_add(toChanServ, TOTYPE_CHANSERV_UNBAN, ci ? (unsigned long)ci : (unsigned long)data1->info.name, CONF_CHANNEL_INHABIT, FALSE, timeout_unban, (void *)data1);
				timeout_add(toChanServ, TOTYPE_CHANSERV_LEAVE, ci ? (unsigned long)ci : (unsigned long)data2->info.name, CONF_CHANNEL_INHABIT + 1, FALSE, timeout_leave, (void *)data2);
			}

			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_CLEAR_USERS_COMPLETE, chan->name);

			if (isChanServ) {

				if (accessMatch) {

					LOG_SNOOP(s_OperServ, "CS C %s -- by %s (%s@%s) [Users]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
					log_services(LOG_SERVICES_CHANSERV_GENERAL, "C %s -- by %s (%s@%s) [Users]", ci->name, callerUser->nick, callerUser->username, callerUser->host);
				}
				else {

					LOG_SNOOP(s_OperServ, "CS C %s -- by %s (%s@%s) through %s [Users]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName);
					log_services(LOG_SERVICES_CHANSERV_GENERAL, "C %s -- by %s (%s@%s) through %s [Users]", ci->name, callerUser->nick, callerUser->username, callerUser->host, accessName);
				}
			}
			else {

				if (data->operMatch) {

					if (skipped > 0)
						send_globops(s_OperServ, "\2%s\2 kicked all users (%d [Skipped: %d]) on \2%s\2 [Reason: %s]", source, count, skipped, chan_name, reason ? reason : "None");
					else
						send_globops(s_OperServ, "\2%s\2 kicked all users (%d) on \2%s\2 [Reason: %s]", source, count, chan_name, reason ? reason : "None");

					LOG_SNOOP(s_OperServ, "OS C %s -- by %s (%s@%s) [Users (%d [%d]) - Reason: %s]", chan_name, callerUser->nick, callerUser->username, callerUser->host, count, skipped, reason ? reason : "None");
					log_services(LOG_SERVICES_OPERSERV, "C %s -- by %s (%s@%s) [Users (%d [%d]) - Reason: %s]", chan_name, callerUser->nick, callerUser->username, callerUser->host, count, skipped, reason ? reason : "None");
				}
				else {

					if (skipped > 0)
						send_globops(s_OperServ, "\2%s\2 (through \2%s\2) kicked all users (%d [Skipped: %d]) on \2%s\2 [Reason: %s]", source, data->operName, count, skipped, chan_name, reason ? reason : "None");
					else
						send_globops(s_OperServ, "\2%s\2 (through \2%s\2) kicked all users (%d) on \2%s\2 [Reason: %s]", source, data->operName, count, chan_name, reason ? reason : "None");

					LOG_SNOOP(s_OperServ, "OS C %s -- by %s (%s@%s) through %s [Users (%d [%d]) - Reason: %s]", chan_name, callerUser->nick, callerUser->username, callerUser->host, data->operName, count, skipped, reason ? reason : "None");
					log_services(LOG_SERVICES_OPERSERV, "C %s -- by %s (%s@%s) through %s [Users (%d [%d]) - Reason: %s]", chan_name, callerUser->nick, callerUser->username, callerUser->host, data->operName, count, skipped, reason ? reason : "None");
				}
			}
		}

		break;
	}
	}
}

/*********************************************************/

#define APPEND_CHAR(buffer, c) \
	if (!strchr((buffer), (c))) { \
		char *p = (buffer); \
		while (*p != '\0') \
			++p; \
		*p = (c); \
		*(p + 1) = '\0'; \
	}

#define CHANMODE(flag, letter) \
	if (add) { \
		if (isChanServ && (accessLevel < CS_ACCESS_COFOUNDER) && FlagSet(ci->mlock_off, (flag))) { \
			APPEND_CHAR(lockedModes, (letter)) \
			break; \
		} \
		if (FlagSet(addmode, (flag))) \
			break; \
		RemoveFlag(delmode, (flag)); \
		if (FlagSet(chan->mode, (flag))) \
			break; \
		AddFlag(addmode, (flag)); \
		++mode_count; \
	} \
	else { \
		if (isChanServ && (accessLevel < CS_ACCESS_COFOUNDER) && FlagSet(ci->mlock_on, (flag))) { \
			APPEND_CHAR(lockedModes, (letter)) \
			break; \
		} \
		if (FlagSet(delmode, (flag))) \
			break; \
		RemoveFlag(addmode, (flag)); \
		if (FlagUnset(chan->mode, (flag))) \
			break; \
		AddFlag(delmode, (flag)); \
		++mode_count; \
	}

#define USERMODE(flag) \
	if (add) { \
		if (FlagSet(addmode, (flag))) \
			break; \
		RemoveFlag(delmode, (flag)); \
		if (FlagSet(user->mode, (flag))) \
			break; \
		AddFlag(addmode, (flag)); \
	} \
	else { \
		if (FlagSet(delmode, (flag))) \
			break; \
		RemoveFlag(addmode, (flag)); \
		if (FlagUnset(user->mode, (flag))) \
			break; \
		AddFlag(delmode, (flag)); \
	}

#define ADD_USERMODE(flag, letter) \
	if (FlagSet(addmode, (flag))) { \
		modebuf[modeIdx++] = (letter); \
		AddFlag(user->mode, (flag)); \
	}

#define DEL_USERMODE(flag, letter) \
	if (FlagSet(delmode, (flag))) { \
		modebuf[modeIdx++] = (letter); \
		RemoveFlag(user->mode, (flag)); \
	}

void handle_mode(CSTR source, User *callerUser, ServiceCommandData *data) {

	char *target, *modes;


	TRACE_MAIN_FCLT(FACILITY_CHANNELS_HANDLE_MODE);

	if (IS_NULL(target = strtok(NULL, " ")) || IS_NULL(modes = strtok(NULL, " ")) || ((modes[0] != '+') && (modes[0] != '-'))) {

		switch (data->agent->agentID) {

			case AGENTID_CHANSERV:
				send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_MODE_SYNTAX_ERROR);
				break;

			case AGENTID_ROOTSERV:
				send_notice_to_user(s_RootServ, callerUser, "Syntax: MODE nick <+|->modes");
				break;

			default:
				send_notice_to_user(data->agent->nick, callerUser, "Syntax: MODE <nick|channel> <+|->modes");
				break;
		}

		send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), GET_MORE_INFO_ON_COMMAND, data->agent->shortNick, "MODE");
	}
	else if (target[0] == '#') {

		Channel *chan;
		ChannelInfo *ci;
		BOOL isChanServ = (data->agent->agentID == AGENTID_CHANSERV);

		if (IS_NULL(chan = hash_channel_find(target)))
			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_CHAN_DOES_NOT_EXIST, target);

		else if (IS_NULL(ci = chan->ci) && isChanServ)
			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), ERROR_CHAN_NOT_REG, target);

		else if (isChanServ && FlagSet(ci->flags, CI_FORBIDDEN))
			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_ERROR_CHAN_FORBIDDEN, ci->name);

		else if (isChanServ && FlagSet(ci->flags, CI_FROZEN))
			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_ERROR_CHAN_FROZEN, ci->name);

		else if (isChanServ && FlagSet(ci->flags, CI_CLOSED))
			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_ERROR_CHAN_CLOSED, ci->name);

		else if (isChanServ && FlagSet(ci->flags, CI_SUSPENDED))
			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_ERROR_CHAN_SUSPENDED, ci->name);

		else if (isChanServ && FlagSet(ci->flags, CI_NOENTRY))
			send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_ERROR_NOENTRY_ON, ci->name);

		else {

			int accessLevel = CS_ACCESS_NONE, accessMatch, mode_count = 1, modeIdx = 0;
			char *token, *key = NULL;
			char accessName[NICKSIZE], modebuf[48], unknownModes[256], invalidModes[256], lockedModes[256];
			char c;
			BOOL add = TRUE, addKey = FALSE, removeKey = FALSE, silent = FALSE;
			BOOL send_v = FALSE, send_h = FALSE, send_o = FALSE, send_b = FALSE, send_b2 = FALSE, send_O = FALSE;
			BOOL send_l = FALSE, send_l2 = FALSE, send_k = FALSE, send_k2 = FALSE, send_k3 = FALSE;
			long limit = 0, addmode = 0, delmode = 0;
			unsigned int idx;

			if (isChanServ) {

				accessLevel = get_access(callerUser, ci, accessName, &accessMatch, NULL);

				if (accessLevel < CS_ACCESS_SOP) {

					send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), ERROR_ACCESS_DENIED);
					return;
				}
			}

			memset(unknownModes, 0, sizeof(unknownModes));
			memset(invalidModes, 0, sizeof(invalidModes));
			memset(lockedModes, 0, sizeof(lockedModes));

			while (*modes) {

				if (isChanServ ? (mode_count > USER_MAX_MODES) : (mode_count > SERVER_MAX_MODES))
					break;

				switch (c = *modes++) {

					case '+':
						add = TRUE;
						break;

					case '-':
						add = FALSE;
						break;

					case 'b': {

						char buf[MASKSIZE];
						char *nick, *user, *host;

						if (isChanServ) {

							APPEND_CHAR(invalidModes, 'b')
							break;
						}

						silent = TRUE;

						if (IS_NULL(token = strtok(NULL, " "))) {

							if (send_b == FALSE) {

								send_notice_to_user(s_OperServ, callerUser, "Parameter required for chanmode %cb.", add ? '+' : '-');
								send_b = TRUE;
							}
							break;
						}

						if (str_len(token) > MASKMAX) {

							if (send_b2 == FALSE) {

								send_notice_to_user(s_OperServ, callerUser, "Bans may not exceed %d characters in length.", MASKMAX);
								send_b2 = TRUE;
							}

							break;
						}

						user_usermask_split(token, &nick, &user, &host);

						if (str_len(user) > USERMAX) {

							user[USERMAX - 1] = c_STAR;
							user[USERMAX] = '\0';
						}

						if (!validate_nick(nick, TRUE) || !validate_username(user, TRUE) ||
							!validate_host(host, TRUE, FALSE, FALSE)) {

							send_notice_to_user(s_OperServ, callerUser, "Invalid mask.");

							mem_free(nick);
							mem_free(user);
							mem_free(host);
							return;
						}

						token = mem_malloc(str_len(nick) + str_len(user) + str_len(host) + 3);
						sprintf((char *) token, "%s!%s@%s", nick, user, host);
						mem_free(nick);
						mem_free(user);
						mem_free(host);

						str_compact(token);

						if (add) {

							int result;

							if (chan->bancount >= IRCD_MAX_BANS) {

								send_notice_to_user(s_OperServ, callerUser, "Banlist for \2%s\2 is full.", chan->name);
								break;
							}

							result = chan_has_ban(chan, token, buf);

							if (result > 0) {

								if (result == 1)
									send_notice_to_user(s_OperServ, callerUser, "\2%s\2 channel ban on \2%s\2 is already covered by: \2%s\2", chan->name, token, buf);
								else
									send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is already banned on \2%s\2.", token, chan->name);

								mem_free(token);
								break;
							}

							chan_add_ban(chan, token);
							send_cmd(":%s MODE %s +b %s %lu", s_OperServ, chan->name, token, NOW);

							send_notice_to_user(s_OperServ, callerUser, "Channel ban on \2%s\2 added on \2%s\2.", token, chan->name);
						}
						else {

							if (!chan_remove_ban(chan, token)) {

								send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is not banned on \2%s\2.", token, chan->name);

								mem_free(token);
								break;
							}

							send_cmd(":%s MODE %s -b %s", s_OperServ, chan->name, token);
							send_notice_to_user(s_OperServ, callerUser, "Channel ban on \2%s\2 removed from \2%s\2.", token, chan->name);
						}

						++mode_count;
						mem_free(token);
						break;
					}

					case 'c':
						CHANMODE(CMODE_c, 'c')
						break;

					case 'C':
						CHANMODE(CMODE_C, 'C')
						break;

					case 'd':
						CHANMODE(CMODE_d, 'd')
						break;

					case 'h': {

						User *user;

						if (isChanServ) {

							APPEND_CHAR(invalidModes, 'h')
							break;
						}

						silent = TRUE;

						if (IS_NULL(token = strtok(NULL, " "))) {

							if (send_h == FALSE) {

								send_notice_to_user(s_OperServ, callerUser, "Parameter required for chanmode %ch.", add ? '+' : '-');
								send_h = TRUE;
							}

							break;
						}

						if (IS_NULL(user = hash_onlineuser_find(token))) {

							send_notice_to_user(s_OperServ, callerUser, "User %s is offline.", token);
							break;
						}

						if (!user_isin_chan(user, chan->name)) {

							send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is not in \2%s\2.", user->nick, chan->name);
							break;
						}

						if (add) {

							if (user_is_chanhalfop(token, chan->name, chan)) {

								send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is already halfopped on \2%s\2.", user->nick, chan->name);
								break;
							}

							chan_add_halfop(chan, user);
							send_cmd(":%s MODE %s +h %s", s_OperServ, chan->name, user->nick);
						}
						else {

							if (!user_is_chanhalfop(token, chan->name, chan)) {

								send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is not halfopped on \2%s\2.", user->nick, chan->name);
								break;
							}

							chan_remove_halfop(chan, user);
							send_cmd(":%s MODE %s -h %s", s_OperServ, chan->name, user->nick);
						}

						++mode_count;
						break;
					}

					case 'i':
						CHANMODE(CMODE_i, 'i')
						break;

					case 'j':
						CHANMODE(CMODE_j, 'j')
						break;

					case 'k':
						if (IS_NULL(token = strtok(NULL, " "))) {

							if (send_k == FALSE) {

								send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_MISSING_PARAM, 'k');
								send_k = TRUE;
								silent = TRUE;
							}
							break;
						}

						if (add) {

							if (isChanServ && (accessLevel < CS_ACCESS_COFOUNDER) &&
								(FlagSet(ci->mlock_on, CMODE_k) || FlagSet(ci->mlock_off, CMODE_k))) {

								APPEND_CHAR(lockedModes, 'k')
								break;
							}

							if (FlagSet(addmode, CMODE_k))
								break;

							if (strchr(token, '*') || strchr(token, ',')) {

								if (send_k2 == FALSE) {

									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_KEY_HAS_STAR);
									send_k2 = TRUE;
									silent = TRUE;
								}
								break;
							}

							while (*token == ':')
								++token;

							if (*token == '\0') {

								if (send_k3 == FALSE) {

									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_INVALID_KEY);
									send_k3 = TRUE;
									silent = TRUE;
								}

								break;
							}

							if (str_len(token) > KEYMAX)
								token[KEYMAX] = '\0';

							if (FlagSet(delmode, CMODE_k))
								RemoveFlag(delmode, CMODE_k);

							if (key) {

								mem_free(key);
								key = NULL;
							}

							if (FlagSet(chan->mode, CMODE_k) && str_equals(chan->key, token))
								break;

							key = str_duplicate(token);
							AddFlag(addmode, CMODE_k);
						}
						else {

							if (isChanServ && (accessLevel < CS_ACCESS_COFOUNDER) && FlagSet(ci->mlock_on, CMODE_k)) {

								APPEND_CHAR(lockedModes, 'k')
								break;
							}

							if (FlagSet(delmode, CMODE_k))
								break;

							if (key) {

								mem_free(key);
								key = NULL;
								RemoveFlag(addmode, CMODE_k);
								--mode_count;
							}

							if (FlagUnset(chan->mode, CMODE_k))
								break;

							AddFlag(delmode, CMODE_k);
						}

						++mode_count;
						break;

					case 'l':
						if (add) {

							char		*err;


							/* If there is no param, ignore it and error out. */
							if (IS_NULL(token = strtok(NULL, " "))) {

								if (send_l == FALSE) {

									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_MISSING_PARAM, 'l');
									send_l = TRUE;
									silent = TRUE;
								}
								break;
							}

							/* If it's locked ignore it. It can't be removed, and it can't be added if it's different. */
							if (isChanServ && (accessLevel < CS_ACCESS_COFOUNDER) &&
								(FlagSet(ci->mlock_on, CMODE_l) || FlagSet(ci->mlock_off, CMODE_l))) {

								APPEND_CHAR(lockedModes, 'l')
								break;
							}

							/* If it's already being added, ignore it. */
							if (FlagSet(addmode, CMODE_l))
								break;

							/* If we previously chose to remove it, scratch that. */
							if (FlagSet(delmode, CMODE_l)) {

								RemoveFlag(delmode, CMODE_l);
								--mode_count;
							}

							limit = strtol(token, &err, 10);

							/* If the given limit is not valid, ignore it. */
							if ((limit <= 0) || (*err != '\0')) {

								if (send_l2 == FALSE) {

									send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_ERROR_NEGATIVE_LIMIT);
									send_l2 = TRUE;
									silent = TRUE;
								}

								limit = 0;
								break;
							}

							/* If the channel is already +l and the limit is the same, ignore it. */
							if (FlagSet(chan->mode, CMODE_l) && (limit == chan->limit)) {

								limit = 0;
								break;
							}

							AddFlag(addmode, CMODE_l);
						}
						else {

							/* If it's locked, ignore it. */
							if (isChanServ && (accessLevel < CS_ACCESS_COFOUNDER) && FlagSet(ci->mlock_on, CMODE_l)) {

								APPEND_CHAR(lockedModes, 'l')
								break;
							}

							/* If we're already removing, ignore it. */
							if (FlagSet(delmode, CMODE_l))
								break;

							/* If we previously asked to add it, cancel the previous attempt. */
							if (FlagSet(addmode, CMODE_l)) {

								RemoveFlag(addmode, CMODE_l);
								limit = 0;
								--mode_count;
							}

							/* If the channel isn't +l, ignore it. */
							if (FlagUnset(chan->mode, CMODE_l))
								break;

							AddFlag(delmode, CMODE_l);
						}

						++mode_count;
						break;

					case 'm':
						CHANMODE(CMODE_m, 'm')
						break;

					case 'M':
						CHANMODE(CMODE_M, 'M')
						break;

					case 'n':
						CHANMODE(CMODE_n, 'n')
						break;

					case 'o': {

						User *user;

						if (isChanServ) {

							APPEND_CHAR(invalidModes, 'o')
							break;
						}

						silent = TRUE;

						if (IS_NULL(token = strtok(NULL, " "))) {

							if (send_o == FALSE) {

								send_notice_to_user(s_OperServ, callerUser, "Parameter required for chanmode %co.", add ? '+' : '-');
								send_o = TRUE;
								silent = TRUE;
							}

							break;
						}

						if (IS_NULL(user = hash_onlineuser_find(token))) {

							send_notice_to_user(s_OperServ, callerUser, "User %s is offline.", token);
							break;
						}

						if (!user_isin_chan(user, chan->name)) {

							send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is not in \2%s\2.", user->nick, chan->name);
							break;
						}

						if (add) {

							if (user_is_chanop(token, chan->name, chan)) {

								send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is already an op on \2%s\2.", user->nick, chan->name);
								break;
							}

							chan_add_op(chan, user);
							send_cmd(":%s MODE %s +o %s", s_OperServ, chan->name, user->nick);
						}
						else {

							if (!user_is_chanop(token, chan->name, chan)) {

								send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is not opped on \2%s\2.", user->nick, chan->name);
								break;
							}

							chan_remove_op(chan, user);
							send_cmd(":%s MODE %s -o %s", s_OperServ, chan->name, user->nick);
						}

						++mode_count;
						break;
					}

					case 'O':
						if (isChanServ && !user_is_ircop(callerUser)) {

							if (send_O == FALSE) {

								send_notice_lang_to_user(s_ChanServ, callerUser, GetCallerLang(), CS_MODE_ERROR_IRCOP_ONLY_MODE, c);
								send_O = TRUE;
								silent = TRUE;
							}

							break;
						}

						CHANMODE(CMODE_O, 'O')
						break;

					case 'p':
						CHANMODE(CMODE_p, 'p')
						break;

					case 'r':
						APPEND_CHAR(invalidModes, 'r')
						break;

					case 'R':
						CHANMODE(CMODE_R, 'R')
						break;

					case 's':
						CHANMODE(CMODE_s, 's')
						break;

					case 'S':
						CHANMODE(CMODE_S, 'S')
						break;

					case 't':
						CHANMODE(CMODE_t, 't')
						break;

					case 'u':
						CHANMODE(CMODE_u, 'u')
						break;
					
					case 'U':
						CHANMODE(CMODE_U, 'U');
						break;

					case 'v': {

						User *user;

						if (isChanServ) {

							APPEND_CHAR(invalidModes, 'v')
							break;
						}

						silent = TRUE;

						if (IS_NULL(token = strtok(NULL, " "))) {

							if (send_v == FALSE) {

								send_notice_to_user(s_OperServ, callerUser, "Parameter required for chanmode %cv.", add ? '+' : '-');
								send_v = TRUE;
							}

							break;
						}

						if (IS_NULL(user = hash_onlineuser_find(token))) {

							send_notice_to_user(s_OperServ, callerUser, "User %s is offline.", token);
							break;
						}

						if (!user_isin_chan(user, chan->name)) {

							send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is not in \2%s\2.", user->nick, chan->name);
							break;
						}

						if (add) {

							if (user_is_chanvoice(token, chan->name, chan)) {

								send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is already voiced on \2%s\2.", user->nick, chan->name);
								break;
							}

							chan_add_voice(chan, user);
							send_cmd(":%s MODE %s +v %s", s_OperServ, chan->name, user->nick);
						}
						else {

							if (!user_is_chanvoice(token, chan->name, chan)) {

								send_notice_to_user(s_OperServ, callerUser, "\2%s\2 is not voiced on \2%s\2.", user->nick, chan->name);
								break;
							}

							chan_remove_voice(chan, user);
							send_cmd(":%s MODE %s -v %s", s_OperServ, chan->name, user->nick);
						}

						++mode_count;
						break;
					}

					default:
						APPEND_CHAR(unknownModes, c)
						break;
				}
			}

			TRACE_MAIN();

			if (delmode) {

				modebuf[modeIdx++] = '-';

				for (idx = 0; idx < known_cmodes_count; ++idx) {

					if (FlagSet(delmode, known_cmodes[idx].mode)) {

						if (known_cmodes[idx].letter == 'k')
							removeKey = TRUE;

						RemoveFlag(chan->mode, known_cmodes[idx].mode);
						modebuf[modeIdx++] = known_cmodes[idx].letter;
					}
				}

				if (modebuf[modeIdx - 1] == '-')
					modeIdx = 0;
			}

			if (addmode) {

				modebuf[modeIdx++] = '+';

				for (idx = 0; idx < known_cmodes_count; ++idx) {

					if (FlagSet(addmode, known_cmodes[idx].mode)) {

						if (known_cmodes[idx].letter == 'k') {

							if (chan->key)
								mem_free(chan->key);
							chan->key = str_duplicate(key);
							mem_free(key);
							addKey = TRUE;
						}
						else if (known_cmodes[idx].letter == 'l')
							chan->limit = limit;

						AddFlag(chan->mode, known_cmodes[idx].mode);
						modebuf[modeIdx++] = known_cmodes[idx].letter;
					}
				}

				if (modebuf[modeIdx - 1] == '+')
					--modeIdx;
			}

			TRACE_MAIN();
			if (*invalidModes)
				send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_MODE_ERROR_INVALID_MODES, invalidModes);

			if (*unknownModes)
				send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_MODE_ERROR_UNKNOWN_MODES, unknownModes);

			if (*lockedModes)
				send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_MODE_ERROR_LOCKED_MODES, lockedModes);

			if (modeIdx > 0) {

				modebuf[modeIdx] = '\0';

				send_chan_MODE(data->agent->nick, target, modebuf, limit, ((addKey || removeKey) ? chan->key : NULL));

				if (removeKey) {

					mem_free(chan->key);
					chan->key = NULL;
				}

				/* Did we remove the limit? */
				if (FlagUnset(chan->mode, CMODE_l))
					chan->limit = 0;

				if (isChanServ && CSMatchVerbose(ci->settings, CI_NOTICE_VERBOSE_CLEAR)) {

					if (accessMatch)
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_MODE), s_ChanServ, target, callerUser->nick);
					else
						send_cmd(lang_msg(EXTRACT_LANG_ID(ci->langID), CS_VERBOSE_OPNOTICE_MODE_THROUGH), s_ChanServ, target, callerUser->nick, accessName);
				}

				if (isChanServ ? accessMatch : data->operMatch) {

					if (!isChanServ)
						send_globops(data->agent->nick, "\2%s\2 changed mode for channel \2%s\2 to: \2%s\2", source, target, modebuf);

					LOG_SNOOP(s_OperServ, "%s M %s -- by %s (%s@%s) [%s]", data->agent->shortNick, target, callerUser->nick, callerUser->username, callerUser->host, modebuf);
					log_services(data->agent->logID, "M %s -- by %s (%s@%s) [%s]", target, callerUser->nick, callerUser->username, callerUser->host, modebuf);
				}
				else {

					if (!isChanServ)
						send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) changed mode for channel \2%s\2 to: \2%s\2", source, isChanServ ? accessName : data->operName, target, modebuf);

					LOG_SNOOP(s_OperServ, "%s M %s -- by %s (%s@%s) through %s [%s]", data->agent->shortNick, target, callerUser->nick, callerUser->username, callerUser->host, isChanServ ? accessName : data->operName, modebuf);
					log_services(data->agent->logID, "M %s -- by %s (%s@%s) through %s [%s]", target, callerUser->nick, callerUser->username, callerUser->host, isChanServ ? accessName : data->operName, modebuf);
				}

				send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_MODE_COMPLETE, target, modebuf);
			}
			else if (!silent)
				send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_MODE_ERROR_NOTHING_TO_DO);
		}
	}
	else {

		User *user;
		BOOL isRootServ = FALSE;

		switch (data->agent->agentID) {

			case AGENTID_ROOTSERV:
				isRootServ = TRUE;
				break;

			case AGENTID_OPERSERV:
				break;

			default:
				send_notice_lang_to_user(data->agent->nick, callerUser, GetCallerLang(), CS_ERROR_INVALID_CHAN_NAME, target, target);
				return;
		}

		if (IS_NULL(user = hash_onlineuser_find(target)))
			send_notice_lang_to_user(s_OperServ, callerUser, GetCallerLang(), OPER_ERROR_NICK_OFFLINE, target);

		else if (user_is_services_client(user))
			send_notice_to_user(s_OperServ, callerUser, "Permission denied.");

		else {

			char modebuf[32], invalid[256], unknown[256], local_add[16], local_del[16];
			int modeIdx = 0;
			long addmode = 0, delmode = 0;
			char c;
			BOOL add = FALSE;

			memset(unknown, 0, sizeof(unknown));
			memset(invalid, 0, sizeof(invalid));
			memset(local_add, 0, sizeof(local_add));
			memset(local_del, 0, sizeof(local_del));

			while (*modes) {

				switch (c = *modes++) {

					case '+':
						add = 1;
						break;

					case '-':
						add = 0;
						break;

					case 'a':
						if (!isRootServ) {

							APPEND_CHAR(invalid, c)
							break;
						}

						USERMODE(UMODE_a)
						break;

					case 'A':
						if (!isRootServ) {

							APPEND_CHAR(invalid, c)
							break;
						}

						USERMODE(UMODE_A)
						break;

					case 'h':
						if (!isRootServ) {

							APPEND_CHAR(invalid, c)
							break;
						}

						USERMODE(UMODE_h)
						break;

					case 'i':
						USERMODE(UMODE_i)
						break;

					case 'I':
						USERMODE(UMODE_I)
						break;

					case 'o':
						if (!isRootServ) {

							APPEND_CHAR(invalid, c)
							break;
						}

						USERMODE(UMODE_o)
						break;

					case 'r':
						if (!isRootServ) {

							APPEND_CHAR(invalid, c)
							break;
						}

						USERMODE(UMODE_r)
						break;

					case 'R':
						USERMODE(UMODE_R)
						break;

					case 'S':
						USERMODE(UMODE_S)
						break;

					case 'x':
						USERMODE(UMODE_x)
						break;

					case 'y':
						USERMODE(UMODE_y)
						break;

					case 'z':
						if (!isRootServ) {

							APPEND_CHAR(invalid, c)
							break;
						}

						USERMODE(UMODE_z)
						break;


					case 'O':
						if (!isRootServ) {

							APPEND_CHAR(invalid, c)
							break;
						}

						/* Fall... */

					case 'b':
					case 'c':
					case 'd':
					case 'e':
					case 'f':
					case 'F':
					case 'g':
					case 'k':
					case 'm':
					case 'n':
					case 's':
					case 'w':
						if (add) {

							/* Append this mode to the local modes to be added. */
							APPEND_CHAR(local_add, c)
						}
						else {

							/* Append this mode to the local modes to be removed. */
							APPEND_CHAR(local_del, c)
						}

						break;

					default:
						APPEND_CHAR(unknown, c)
						break;
				}
			}

			TRACE_MAIN();

			if (addmode || *local_add) {

				modebuf[modeIdx++] = '+';

				ADD_USERMODE(UMODE_i, 'i')
				ADD_USERMODE(UMODE_I, 'I')
				ADD_USERMODE(UMODE_R, 'R')
				ADD_USERMODE(UMODE_S, 'S')
				ADD_USERMODE(UMODE_x, 'x')
				ADD_USERMODE(UMODE_y, 'y')

				if (isRootServ) {

					ADD_USERMODE(UMODE_a, 'a')
					ADD_USERMODE(UMODE_A, 'A')
					ADD_USERMODE(UMODE_h, 'h')
					ADD_USERMODE(UMODE_o, 'o')
					ADD_USERMODE(UMODE_r, 'r')
					ADD_USERMODE(UMODE_z, 'z')
				}

				if (*local_add) {

					int idx;

					for (idx = 0; ; ++idx) {

						if (local_add[idx] != '\0')
							modebuf[modeIdx++] = local_add[idx];
						else
							break;
					}
				}
			}

			TRACE();
			if (delmode || *local_del) {

				modebuf[modeIdx++] = '-';

				DEL_USERMODE(UMODE_i, 'i')
				DEL_USERMODE(UMODE_I, 'I')
				DEL_USERMODE(UMODE_R, 'R')
				DEL_USERMODE(UMODE_S, 'S')
				DEL_USERMODE(UMODE_x, 'x')
				DEL_USERMODE(UMODE_y, 'y')

				if (isRootServ) {

					DEL_USERMODE(UMODE_a, 'a')
					DEL_USERMODE(UMODE_A, 'A')
					DEL_USERMODE(UMODE_h, 'h')
					DEL_USERMODE(UMODE_o, 'o')
					DEL_USERMODE(UMODE_r, 'r')
					DEL_USERMODE(UMODE_z, 'z')
				}

				if (*local_del) {

					int idx;

					for (idx = 0; ; ++idx) {

						if (local_del[idx] != '\0')
							modebuf[modeIdx++] = local_del[idx];
						else
							break;
					}
				}
			}

			TRACE_MAIN();
			if (*invalid)
				send_notice_to_user(s_OperServ, callerUser, "The following modes are invalid and were ignored: \2%s\2", invalid);

			if (*unknown)
				send_notice_to_user(s_OperServ, callerUser, "The following modes are unknown and were ignored: \2%s\2", unknown);

			if (modeIdx > 0) {

				modebuf[modeIdx] = '\0';

				if (data->operMatch) {

					send_globops(data->agent->nick, "\2%s\2 changed mode for user \2%s\2 to: \2%s\2", source, user->nick, modebuf);

					LOG_SNOOP(s_OperServ, "%s M %s -- by %s (%s@%s) [%s]", data->agent->shortNick, user->nick, callerUser->nick, callerUser->username, callerUser->host, modebuf);
					log_services(data->agent->logID, "M %s -- by %s (%s@%s) [%s]", data->agent->shortNick, user->nick, callerUser->nick, callerUser->username, callerUser->host, modebuf);
				}
				else {

					send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) changed mode for user \2%s\2 to: \2%s\2", source, data->operName, user->nick, modebuf);

					LOG_SNOOP(s_OperServ, "%s M %s -- by %s (%s@%s) through %s [%s]", data->agent->shortNick, user->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, modebuf);
					log_services(data->agent->logID, "M %s -- by %s (%s@%s) through %s [%s]", user->nick, callerUser->nick, callerUser->username, callerUser->host, data->operName, modebuf);
				}

				send_user_SVSMODE(data->agent->nick, user->nick, modebuf, user->tsinfo);

				send_notice_to_user(s_OperServ, callerUser, "Mode for \2%s\2 changed to: \2%s\2", user->nick, modebuf);
			}
			else
				send_notice_to_user(s_OperServ, callerUser, "All requested modes are already set.");
		}
	}
}

#undef APPEND_CHAR
#undef CHANMODE
#undef USERMODE
#undef ADD_USERMODE
#undef DEL_USERMODE

#endif /* USE_SERVICES */

/*********************************************************
 * chan_ds_dump()                                        *
 *                                                       *
 * DebugServ DUMP support.                               *
 *********************************************************/

static void chan_ds_dump_display(CSTR sourceNick, const User *callerUser, const Channel *chan, CSTR what) {

	if (IS_NULL(chan)) {

		log_error(FACILITY_CHANNELS_DUMP, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "user_ds_dump_display()", s_LOG_NULL, "chan");

		return;
	}

	if (IS_NULL(what) || IS_EMPTY_STR(what)) {

		UserListItem	*item;
		int 			voices = 0, halfops = 0, ops = 0, users = 0;

		for (item = chan->users; IS_NOT_NULL(item); item = item->next)
			++users;

		for (item = chan->voices; IS_NOT_NULL(item); item = item->next)
			++voices;
			
		for (item = chan->halfops; IS_NOT_NULL(item); item = item->next)
			++halfops;

		for (item = chan->chanops; IS_NOT_NULL(item); item = item->next)
			++ops;

		send_notice_to_user(sourceNick, callerUser, "DUMP: channel \2%s\2", chan->name);
		send_notice_to_user(sourceNick, callerUser, "Address 0x%08X, size %d B",				(unsigned long)chan, sizeof(chan));
		send_notice_to_user(sourceNick, callerUser, "Name: %s",									chan->name);
		send_notice_to_user(sourceNick, callerUser, "Creation C-time: %d",						chan->creation_time);
		send_notice_to_user(sourceNick, callerUser, "Last topic: 0x%08X \2[\2%s\2]\2",			(unsigned long)chan->topic, str_get_valid_display_value(chan->topic));
		send_notice_to_user(sourceNick, callerUser, "Last topic setter: %s",					chan->topic_setter);
		send_notice_to_user(sourceNick, callerUser, "Last topic C-time: %d",					chan->topic_time);

		send_notice_to_user(sourceNick, callerUser, "Mode: %d (%s)",							chan->mode, get_channel_mode(chan->mode, 0));
		send_notice_to_user(sourceNick, callerUser, "Mode +l/+k values: %d / 0x%08X \2[\2%s\2]\2",	chan->limit, (unsigned long)chan->key, str_get_valid_display_value(chan->key));

		send_notice_to_user(sourceNick, callerUser, "Bans count / list size / list head: %d / %d / 0x%08X",			chan->bancount, chan->bansize, (unsigned long)chan->bans);
		send_notice_to_user(sourceNick, callerUser, "Users [%d/%d] / ops [%d] / halfops [%d] / voices [%d]",	chan->userCount, users, ops, halfops, voices);
		send_notice_to_user(sourceNick, callerUser, "List heads: 0x%08X / 0x%08X / 0x%08X / 0x%08X",		(unsigned long)chan->users, (unsigned long)chan->chanops, (unsigned long)chan->halfops, (unsigned long)chan->voices);

		#ifdef USE_SERVICES
		send_notice_to_user(sourceNick, callerUser, "ChanInfo record: 0x%08X \2[\2%s\2]\2",		(unsigned long)chan->ci, chan->ci ? str_get_valid_display_value(chan->ci->name) : "NULL");
		#endif

		send_notice_to_user(sourceNick, callerUser, "Next / previous record: 0x%08X / 0x%08X",	(unsigned long)chan->next, (unsigned long)chan->prev);
	}
	else if (str_equals_nocase(what, "USER") || str_equals_nocase(what, "OP") || str_equals_nocase(what, "HALFOP")|| str_equals_nocase(what, "VOICE")) {

		UserListItem	*item;
		STR				name;
		int				userIdx;


		switch (str_char_toupper(what[0])) {

			default:
			case 'U':
				item = chan->users;
				name = "USER";
				break;

			case 'O':
				item = chan->chanops;
				name = "OP";
				break;

			case 'H':
				item = chan->halfops;
				name = "HALFOP";
				break;

			case 'V':
				item = chan->voices;
				name = "VOICE";
				break;
		}

		send_notice_to_user(sourceNick, callerUser, "DUMP: channel \2%s\2 %s list", chan->name, name);

		for (userIdx = 1; IS_NOT_NULL(item); item = item->next, ++userIdx)
			send_notice_to_user(sourceNick, callerUser, "%d) %s", userIdx, IS_NOT_NULL(item->user) ? str_get_valid_display_value(item->user->nick) : "NULL User pointer");
		
		send_notice_to_user(sourceNick, callerUser, "DUMP: %d items diplayed", userIdx);
	}
	else if (str_equals_nocase(what, "BAN")) {

		int banIdx;


		send_notice_to_user(sourceNick, callerUser, "DUMP: channel \2%s\2 BAN list", chan->name);

		for (banIdx = 0; banIdx < chan->bancount; ++banIdx)
			send_notice_to_user(sourceNick, callerUser, "%d) %s", (banIdx + 1), str_get_valid_display_value(chan->bans[banIdx]));

		send_notice_to_user(sourceNick, callerUser, "DUMP: %d items diplayed", banIdx);
	}
	else
		send_notice_to_user(sourceNick, callerUser, "\2DUMP\2 - Invalid type.");

	if (IS_NULL(what) || IS_EMPTY_STR(what))
		LOG_DEBUG_SNOOP("Command: DUMP CHANNELS NAME %s -- by %s (%s@%s)", chan->name, callerUser->nick, callerUser->username, callerUser->host);
	else
		LOG_DEBUG_SNOOP("Command: DUMP CHANNELS NAME %s -- by %s (%s@%s) [%s]", chan->name, callerUser->nick, callerUser->username, callerUser->host, what);
}

void chan_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	STR		cmd = strtok(request, s_SPACE);
	STR		value = strtok(NULL, s_SPACE);
	STR		what = strtok(NULL, s_SPACE);
	BOOL	needSyntax = FALSE;
	Channel	*chan;


	if (IS_NOT_NULL(cmd)) {

		if (str_equals_nocase(cmd, "HELP")) {

			/* HELP ! */

		}
		else if (str_equals_nocase(cmd, "NAME")) {

			if (IS_NULL(value))
				needSyntax = TRUE;

			else {

				if (IS_NULL(chan = hash_channel_find(value)))
					send_notice_to_user(sourceNick, callerUser, "DUMP: Channel \2%s\2 not found.", value);
				else
					chan_ds_dump_display(sourceNick, callerUser, chan, what);
			}
		}
		else if (str_equals_nocase(cmd, "PTR")) {

			unsigned long	address;


			address = strtoul(value, NULL, 16);

			if (address != 0) {

				int idx;

				HASH_FOREACH_BRANCH(idx, CHANNEL_HASHSIZE) {

					HASH_FOREACH_BRANCH_ITEM(channel, idx, chan) {

						if ((unsigned long)chan == address) {

							chan_ds_dump_display(sourceNick, callerUser, chan, what);
							break;
						}
					}
				}

				if (IS_NULL(chan))
					send_notice_to_user(sourceNick, callerUser, "DUMP: Channel \2%s\2 not found.", value);
			}
			else
				send_notice_to_user(sourceNick, callerUser, "\2DUMP\2 - Invalid address.");

		#ifdef FIX_USE_MPOOL
		} else if (str_equals_nocase(cmd, "POOL")) {

		} else if (str_equals_nocase(cmd, "POOLSTAT")) {

			MemoryPoolStats pstats;

			mempool_stats(channels_mempool, &pstats);
			send_notice_to_user(sourceNick, callerUser, "DUMP: Channels memory pool - Address 0x%08X, ID: %d",	(unsigned long)channels_mempool, pstats.id);
			send_notice_to_user(sourceNick, callerUser, "Memory allocated / free: %d B / %d B",				pstats.memory_allocated, pstats.memory_free);
			send_notice_to_user(sourceNick, callerUser, "Items allocated / free: %d / %d",					pstats.items_allocated, pstats.items_free);
			send_notice_to_user(sourceNick, callerUser, "Items per block / block count: %d / %d",			pstats.items_per_block, pstats.block_count);
			//send_notice_to_user(sourceNick, callerUser, "Avarage use: %.2f%%",								pstats.block_avg_usage);

		#endif
		}
		else
			needSyntax = TRUE;
	}
	else
		needSyntax = TRUE;

	if (needSyntax) {

		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 CHAN NAME channame [USER|OP|HALFOP|VOICE|BAN]");
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 CHAN PTR address [USER|OP|HALFOP|VOICE|BAN]");
		#ifdef FIX_USE_MPOOL
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 CHAN POOLSTAT");
		#endif
	}
}


/*********************************************************
 * chan_mem_report()                                     *
 *                                                       *
 * Return statistics on memory usage.                    *
 * Pointers are assumed to be valid.                     *
 *********************************************************/

unsigned long chan_mem_report(CSTR sourceNick, const User *callerUser) {

	Channel			*chan;
	unsigned long	count = 0, mem = 0;
	UserListItem	*item;
	int				idx, banIdx;


	TRACE_FCLT(FACILITY_CHANNELS_MEM_REPORT);

	send_notice_to_user(sourceNick, callerUser, "\2CHANNEL\2:");

	/* channels */
	HASH_FOREACH_BRANCH(idx, CHANNEL_HASHSIZE) {

		HASH_FOREACH_BRANCH_ITEM(channel, idx, chan) {

			TRACE();
			++count;
			mem += sizeof(*chan);
			
			if (IS_NOT_NULL(chan->topic))
				mem += str_len(chan->topic) + 1;

			if (IS_NOT_NULL(chan->key))
				mem += str_len(chan->key) + 1;

			mem += sizeof(char *) * chan->bansize;

			for (banIdx = 0; banIdx < chan->bancount; ++banIdx) {
				
				if (IS_NOT_NULL(chan->bans[banIdx]))
					mem += str_len(chan->bans[banIdx]) + 1;
			}

			TRACE();
			for (item = chan->users; IS_NOT_NULL(item); item = item->next)
				mem += sizeof(*item);

			for (item = chan->chanops; IS_NOT_NULL(item); item = item->next)
				mem += sizeof(*item);
				
			for (item = chan->halfops; IS_NOT_NULL(item); item = item->next)
				mem += sizeof(*item);

			for (item = chan->voices; IS_NOT_NULL(item); item = item->next)
				mem += sizeof(*item);
		}
	}

	TRACE();
	send_notice_to_user(sourceNick, callerUser, "Open channels: \2%d\2 [%d] -> \2%d\2 KB (\2%d\2 B)", count, stats_open_channels_count, mem / 1024, mem);

	return mem;
}

#endif /* defined(USE_SERVICES) || defined(USE_STATS) */
