/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* timeout.c - time-delayed actions handling routines
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/timeout.h"
#include "../inc/logging.h"
#include "../inc/memory.h"
#include "../inc/send.h"
#include "../inc/conf.h"
#include "../inc/main.h"

#ifdef USE_STATS
#include "../inc/statserv.h"
#include "../inc/seenserv.h"
#endif


/*********************************************************
 * Timeouts                                              *
 *********************************************************/

#ifdef USE_SERVICES

static Timeout *timeout_list_head = NULL;
static Timeout *timeout_list_tail = NULL;
unsigned long	timeout_count = 0;


BOOL timeout_add(TimeoutType type, int user_type, unsigned long hash, int interval, BOOL repeat, TIMEOUT_HANDLER handler, void *data) {

	TRACE_FCLT(FACILITY_TIMEOUT_ADD_TIMEOUT);

	if (IS_NOT_NULL(handler) && (type != toInvalid) && (interval > 0)) {

		Timeout	*to;

		to = mem_calloc(1, sizeof(Timeout));

		to->hash = hash;
		to->type = type;
		to->user_type = user_type;

		time(&to->ts_creation);
		to->ts_expire = to->ts_creation + interval;

		#ifndef NEW_SOCK
		to->ts_expire += CONF_TIMEOUT_STARTUP_DELTA;
		#endif

		to->interval = interval;
		to->repeat = repeat;

		to->handler = handler;
		to->data = data;

		// inserimento in coda

		if (IS_NOT_NULL(timeout_list_tail)) {

			to->prev = timeout_list_tail;
			//to->next = NULL; // azzerato da mem_calloc()
			timeout_list_tail->next = to;
			timeout_list_tail = to;

		} else {

			// la lista e' vuota

			//to->prev = NULL; // azzerato da mem_calloc()
			//to->next = NULL; // azzerato da mem_calloc()
			timeout_list_head = timeout_list_tail = to;
		}

		++timeout_count;

		return TRUE;

	} else {

		log_error(FACILITY_TIMEOUT_ADD_TIMEOUT, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"timeout_add(%d, %d, %d, %d, %d, %08X, %08X) - Invalid parameters!", type, user_type, hash, interval, repeat, handler, data);
		
		return FALSE;
	}
}

/*********************************************************/

static void timeout_delete_item(Timeout *to) {

	if (IS_NOT_NULL(to)) {

		// eliminare dati aggiuntivi...
		switch (to->type) {

			#ifdef USE_SERVICES

			case toNickServ:
				nickserv_dispose_timeout_data(to->data);
				break;

			case toChanServ:
				chanserv_dispose_timeout_data(to->data);
				break;

			#endif


			default:
				// nulla da fare ...
				break;
		}

		// togliere il timeout dalla lista...
		if (IS_NOT_NULL(to->prev))
			to->prev->next = to->next;
		else
			// siamo alla testa della lista
			timeout_list_head = to->next;

		if (IS_NOT_NULL(to->next))
			to->next->prev = to->prev;
		else
			// siamo alla coda della lista
			timeout_list_tail = to->prev;

		// eliminare il timeout...
		mem_free(to);
		--timeout_count;
	}
}

/*********************************************************/

static Timeout *timeout_find(TimeoutType type, int user_type, unsigned long hash) {

	Timeout	*to = timeout_list_head;

	// ricerca del timeout

	while (IS_NOT_NULL(to)) {

		if ((to->hash == hash) && (to->type == type) && (to->user_type == user_type))
			return to;

		to = to->next;
	}

	return NULL;
}

/*********************************************************/

BOOL timeout_remove(TimeoutType type, int user_type, unsigned long hash) {

	TRACE_FCLT(FACILITY_TIMEOUT_DEL_TIMEOUT);

	if (type != toInvalid) {

		if (user_type == TOTYPE_ANYSUBTYPE) {

			Timeout	*to = timeout_list_head, *next;

			while (IS_NOT_NULL(to)) {

				if ((to->type == type) && (to->hash == hash)) {

					next = to->next;
					timeout_delete_item(to);
					to = next;
				}
				else
					to = to->next;
			}
		}
		else {

			Timeout		*to;

			// ricerca del timeout da cancellare

			to = timeout_find(type, user_type, hash);

			if (IS_NOT_NULL(to))
				timeout_delete_item(to);

			else
				return FALSE;
		}
	}
	else
		log_error(FACILITY_TIMEOUT_DEL_TIMEOUT, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, 
			"timeout_remove(%d, %d, %d) - Invalid parameters!", type, user_type, hash);

	return TRUE;
}

/*********************************************************/

void *timeout_get_data(TimeoutType type, int user_type, unsigned long hash) {

	Timeout		*to;

	to = timeout_find(type, user_type, hash);

	return IS_NOT_NULL(to) ? to->data : NULL;
}

/*********************************************************/

void timeout_check(const time_t now) {

	Timeout	*to = timeout_list_head;

	TRACE_FCLT(FACILITY_TIMEOUT_CHECK_TIMEOUTS);

	while (to) {

		if (now > to->ts_expire) {
			
			// timeout scaduto ...

			TRACE();
			to->handler(to);

			TRACE();
			if (to->repeat) {

				to->ts_expire += to->interval;
				to = to->next;
			}
			else {

				Timeout	*next = to->next;

				// eliminare questo timeout
				timeout_delete_item(to);

				to = next; // prossimo timeout da controllare
			}
		}
		else
			to = to->next; // prossimo timeout da controllare
	}
}

#endif /* USE_SERVICES */

/*********************************************************
 * Time-related check                                    *
 *********************************************************/

/*********************************************************
 * Global Variables                                      *
 *********************************************************/

time_t				time_next_midnight;
int					time_today_day, time_today_month, time_today_year, time_today_wday;


/*********************************************************
 * Local Variables                                       *
 *********************************************************/

#if defined(USE_SERVICES) || defined(USE_STATS)
/* How many daily database expirations did we go through? */
static unsigned long daily_dbcnt = 1;
#endif

void time_init() {

	struct tm	*ltm;
	time_t		now;

	now = time(NULL);
	ltm = localtime(&now);

	NOW = now;

	if (IS_NOT_NULL(ltm)) {

		time_next_midnight = now + (ONE_DAY - (ltm->tm_sec + (ltm->tm_min * ONE_MINUTE) + (ltm->tm_hour * ONE_HOUR)));

		time_today_day   = ltm->tm_mday;
		time_today_month = ltm->tm_mon + 1;
		time_today_year  = ltm->tm_year + 1900;
		time_today_wday  = ltm->tm_wday;
	}
	else {
		
		log_error(FACILITY_TIMEOUT_TIME_INIT, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_RESUMED, "time_init() - localtime() failed!");
		
		time_next_midnight = now + ONE_DAY;
		time_today_day = time_today_month = time_today_year = 0;
	}
}

/*********************************************************/

void time_check(const time_t now) {

	if (now >= time_next_midnight) {

		struct tm	*ltm = localtime(&now);
		int			new_day, new_month, new_year, new_wday;

		if (IS_NOT_NULL(ltm)) {

			new_day   = ltm->tm_mday;
			new_month = ltm->tm_mon + 1;
			new_year  = ltm->tm_year + 1900;
			new_wday  = ltm->tm_wday;
		}
		else {

			log_error(FACILITY_TIMEOUT_TIME_CHECK, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED, "time_check() - localtime() failed. Timed-checks skipped!");
			new_day   = time_today_day;
			new_month = time_today_month;
			new_year  = time_today_year;
			new_wday  = time_today_wday;
		}

		// midnight checks

		#if defined(USE_SERVICES) || defined(USE_STATS)
		send_globops(NULL, "Running Daily Database Expire %d", daily_dbcnt);
		#ifdef USE_SERVICES
		nickserv_daily_expire();
		chanserv_daily_expire();
		#endif
		#ifdef USE_STATS
		statserv_daily_expire();
		#endif
		++daily_dbcnt;
		#endif

		// week checks
		if ((new_wday != time_today_wday) && (new_wday == 1 /* domenica */)) {

			// la settimana e' cambiata
			time_today_wday = new_wday;
			#ifdef USE_STATS
			statserv_weekly_expire();
			seenserv_weekly_expire();
			#endif
		}

		// month checks
		if (new_month != time_today_month) {
			
			// il mese e' cambiato
			time_today_month = new_month;
			#ifdef USE_STATS
			statserv_monthly_expire();
			#endif
		}

		// year checks
		if (new_year != time_today_year) {
			
			// l'anno e' cambiato
			time_today_year = new_year;

			// ...
			LOG_DEBUG_SNOOP("year checks");
		}

		/* This creates new log files as well as update time_next_midnight. */
		log_rotate(FALSE);
	}
}


/*********************************************************
 * DebugServ DUMP support                                *
 *********************************************************/

#if defined(USE_SERVICES) || defined(USE_STATS)
void timeout_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	STR		cmd = strtok(request, s_SPACE);
	BOOL	needSyntax = FALSE;

	if (IS_NOT_NULL(cmd)) {

		if (str_equals_nocase(cmd, "HELP")) {

			// HELP !

		#ifdef USE_SERVICES
		} else if (str_equals_nocase(cmd, "LIST")) {

			Timeout	*to = timeout_list_head;
			int count = 0;

			while (IS_NOT_NULL(to)) {

				count++;

				switch (to->type) {

					case toNickServ: {

						NickTimeoutData *ntd = to->data ? (NickTimeoutData *)to->data : NULL;

						if (ntd) {

							NickInfo *ni = ntd->ni;

							send_notice_to_user(sourceNick, callerUser, "%d) \2%s\2 [Hash: %ld], Type: NickServ [%s], Created: %d seconds ago", count, ni ? ni->nick : "NULL", to->hash, to->user_type == TOTYPE_NICKSERV_COUNTDOWN ? "Countdown" : to->user_type == TOTYPE_NICKSERV_RELEASE ? "Release" : "Unknown", NOW - to->ts_creation);
							send_notice_to_user(sourceNick, callerUser, "Duration: %ds, Repeat: %s, Step: %d, User Online: %s", to->interval, to->repeat ? "Yes" : "No", ntd->step, ntd->user_online ? "Yes" : "No");
						}
						else {

							send_notice_to_user(sourceNick, callerUser, "%d) NULL [Hash: %ld], Type: NickServ [%s], Created: %d seconds ago", count, to->hash, to->user_type == TOTYPE_NICKSERV_COUNTDOWN ? "Countdown" : to->user_type == TOTYPE_NICKSERV_RELEASE ? "Release" : "Unknown", NOW - to->ts_creation);
							send_notice_to_user(sourceNick, callerUser, "Duration: %ds, Repeat: %s, Step: Unknown, User Online: Unknown [Note: to->data is NULL]", to->interval, to->repeat ? "Yes" : "No");
						}
						break;
					}

					case toChanServ: {

						ChannelTimeoutData *ctd = to->data ? (ChannelTimeoutData *)to->data : NULL;

						if (ctd) {

							switch (ctd->type) {

								case CTOD_CHAN_RECORD: {

									ChannelInfo *ci = ctd->info.record;

									send_notice_to_user(sourceNick, callerUser, "%d) \2%s\2 [Hash: %ld], Type: ChanServ [%s], Created: %d seconds ago", count, ci ? ci->name : "NULL", to->hash, to->user_type == TOTYPE_CHANSERV_UNBAN ? "Unban" : to->user_type == TOTYPE_CHANSERV_LEAVE ? "Leave" : "Unknown", NOW - to->ts_creation);
									send_notice_to_user(sourceNick, callerUser, "Duration: %ds, Repeat: %s", to->interval, to->repeat ? "Yes" : "No");
									break;
								}
								case CTOD_CHAN_NAME:

									send_notice_to_user(sourceNick, callerUser, "%d) \2%s\2 [Hash: %ld], Type: ChanServ [%s], Created: %d seconds ago", count, ctd->info.name ? ctd->info.name : "NULL", to->hash, to->user_type == TOTYPE_CHANSERV_UNBAN ? "Unban" : to->user_type == TOTYPE_CHANSERV_LEAVE ? "Leave" : "Unknown", NOW - to->ts_creation);
									send_notice_to_user(sourceNick, callerUser, "Duration: %ds, Repeat: %s", to->interval, to->repeat ? "Yes" : "No");
									break;

								default:
									send_notice_to_user(sourceNick, callerUser, "%d) \2Unknown\2 [Hash: %ld], Type: ChanServ [%s], Created: %d seconds ago", count, to->hash, to->user_type == TOTYPE_CHANSERV_UNBAN ? "Unban" : to->user_type == TOTYPE_CHANSERV_LEAVE ? "Leave" : "Unknown", NOW - to->ts_creation);
									send_notice_to_user(sourceNick, callerUser, "Duration: %ds, Repeat: %s", to->interval, to->repeat ? "Yes" : "No");
									break;
							}
						}
						else {

							send_notice_to_user(sourceNick, callerUser, "%d) NULL [Hash: %ld], Type: ChanServ [%s], Created: %d seconds ago", count, to->hash, to->user_type == TOTYPE_CHANSERV_UNBAN ? "Unban" : to->user_type == TOTYPE_CHANSERV_LEAVE ? "Leave" : "Unknown", NOW - to->ts_creation);
							send_notice_to_user(sourceNick, callerUser, "Duration: %ds, Repeat: %s [Note: to->data is NULL]", to->interval, to->repeat ? "Yes" : "No");
						}
						break;
					}
					default:
						send_notice_to_user(sourceNick, callerUser, "%d) NULL [Hash: %ld], Type: Unknown, Created: %d seconds ago", count, to->hash, NOW - to->ts_creation);
						send_notice_to_user(sourceNick, callerUser, "Duration: %ds, Repeat: %s", to->interval, to->repeat ? "Yes" : "No");
						break;
				}

				to = to->next;
			}

			LOG_DEBUG_SNOOP("Command: DUMP TIMEOUT LIST -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);
		#endif
		} else if (str_equals_nocase(cmd, "TIME")) {

			char	timebuf[64];
			struct tm tm;

			tm = *localtime(&time_next_midnight);
			strftime(timebuf, sizeof(timebuf), "%m %d %Y - %H:%M:%S (%Z)", &tm);
			timebuf[sizeof(timebuf)-1] = '\0';

			send_notice_to_user(sourceNick, callerUser, "Today values: day: \2%d\2, month: \2%d\2, year: \2%d\2, week day: \2%d\2", time_today_day, time_today_month, time_today_year, time_today_wday);
			send_notice_to_user(sourceNick, callerUser, "Next midnight TS: \2%d\2 -> \2%s\2", time_next_midnight, timebuf);

			LOG_DEBUG_SNOOP("Command: DUMP TIMEOUT TIME -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);

		} else
			needSyntax = TRUE;

	} else
		needSyntax = TRUE;

	if (needSyntax) {

		#ifdef USE_SERVICES
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 TIMEOUT <LIST|TIME>");
		#else
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 TIMEOUT TIME");
		#endif
	}
}

#endif
