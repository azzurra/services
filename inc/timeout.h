/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* timeout.h - Time-delayed actions handling routines include
* 
*/


#ifndef TIMEOUT_H
#define TIMEOUT_H

/*********************************************************
 * Headers                                               *
 *********************************************************/

#include <time.h>


/*********************************************************
 * Data types                                            *
 *********************************************************/

#ifdef USE_SERVICES
typedef struct _timeout	Timeout;

typedef enum _timeoutType { toInvalid, toNickServ, toChanServ } TimeoutType;

typedef void (*TIMEOUT_HANDLER)(Timeout*);

struct _timeout {

	unsigned long	hash;
	TimeoutType		type;
	int				user_type;

	time_t			ts_creation;
	time_t			ts_expire;
	int				interval;
	BOOL			repeat;

	TIMEOUT_HANDLER	handler;
	void			*data;

	Timeout			*next, *prev;
};
#endif


/*********************************************************
 * Constants                                             *
 *********************************************************/

#ifdef USE_SERVICES
#define	TO_HASH_NOHASH		0

// TO user types:

#define TOTYPE_NOSUBTYPE					0
#define TOTYPE_ANYSUBTYPE					TOTYPE_NOSUBTYPE

// NickServ
#define TOTYPE_NICKSERV_RELEASE				1	/* Release a collided nick */
#define TOTYPE_NICKSERV_COUNTDOWN			2	/* Kill countdown */
// ChanServ
#define TOTYPE_CHANSERV_UNBAN				3
#define TOTYPE_CHANSERV_LEAVE				4
#endif

/*********************************************************
 * Global variables                                      *
 *********************************************************/

#ifdef USE_SERVICES
extern unsigned long timeout_count;
#endif

extern time_t	time_next_midnight;
extern int		time_today_day, time_today_month, time_today_year, time_today_wday;


/*********************************************************
 * Public code                                           *
 *********************************************************/

#ifdef USE_SERVICES
extern BOOL timeout_add(TimeoutType type, int user_type, unsigned long int hash, int interval, BOOL repeat, TIMEOUT_HANDLER handler, void *data);
extern BOOL timeout_remove(TimeoutType type, int user_type, unsigned long int hash);
extern void *timeout_get_data(TimeoutType type, int user_type, unsigned long int hash);
extern void timeout_check(const time_t now);

extern void timeout_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
#endif

extern void time_init();
extern void time_check(const time_t now);


#endif	/* TIMEOUT_H */
