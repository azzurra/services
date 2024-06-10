/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* statserv.h - StatServ service
* 
*/


#ifndef SRV_STATSERV_H
#define SRV_STATSERV_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "memory.h"


/*********************************************************
 * Version stuff                                         *
 *********************************************************/

#define	STATSERV_DB_CURRENT_VERSION		7
#define STATSERV_DB_SUPPORTED_VERSION	"7 10"


/*********************************************************
 * Data types                                            *
 *********************************************************/

// channels statistics

typedef struct _ChannelStats_V10	ChannelStats_V10;
struct _ChannelStats_V10 {

	ChannelStats_V10	*next, *prev;

	#ifdef FIX_USE_MPOOL
	MEMORYBLOCK_ID		mblock_id;
	#endif

	char				*name;
	time_t				time_added;
	time_t				last_change;	/* when the last stat changed */

	unsigned long int	totaljoins, totalparts, totalkicks, totalbans, totaloppings, totaldeoppings, totalhalfoppings, totaldehalfoppings, totalvoicings, totaldevoicings, totaltopics, totaldelcmodes, totaladdcmodes;
	unsigned int		totalpeak, monthlypeak, weeklypeak, dailypeak;
	unsigned int		monthlyjoins, weeklyjoins, dailyjoins;
	unsigned int		monthlyparts, weeklyparts, dailyparts;
	unsigned int		monthlykicks, weeklykicks, dailykicks;
	unsigned int		monthlybans, weeklybans, dailybans;
	unsigned int		monthlyoppings, weeklyoppings, dailyoppings;
	unsigned int		monthlydeoppings, weeklydeoppings, dailydeoppings;
	unsigned int		monthlyhalfoppings, weeklyhalfoppings, dailyhalfoppings;
	unsigned int		monthlydehalfoppings, weeklydehalfoppings, dailydehalfoppings;
	unsigned int		monthlyvoicings, weeklyvoicings, dailyvoicings;
	unsigned int		monthlydevoicings, weeklydevoicings, dailydevoicings;
	unsigned int		monthlytopics, weeklytopics, dailytopics;
	unsigned int		monthlydelcmodes, weeklydelcmodes, dailydelcmodes;
	unsigned int		monthlyaddcmodes, weeklyaddcmodes, dailyaddcmodes;
};

// Current struct version
typedef ChannelStats_V10	ChannelStats;



// servers statistics

typedef struct _ServerStats_V10		ServerStats_V10;
struct _ServerStats_V10 {

	ServerStats_V10		*next, *prev;

	char				*name;
	time_t				time_added;

	unsigned short int	clients;
	unsigned short int	maxclients;
	time_t				maxclients_time;

	unsigned char		opers;
	unsigned char		maxopers;
	time_t				maxopers_time;

	unsigned short int	operkills;
	unsigned short int	servkills;

	time_t				connect;
	time_t				squit;

	unsigned long int	hits;
	unsigned long int	msgs;

	float				users_average;
	float				opers_average;

	unsigned char		dailysplits;
	unsigned char		weeklysplits;
	unsigned char		monthlysplits;
	unsigned short int	totalsplits;

	short_flags_t		flags;
};

// Current struct version
typedef ServerStats_V10		ServerStats;



// current records
typedef struct _RecordStats_V10 {

	time_t			started;

	unsigned short int	maxusers;
	time_t				maxusers_time;
	
	unsigned short int	maxchannels;
	time_t				maxchannels_time;

	unsigned char		maxopers;
	time_t				maxopers_time;
	
	unsigned char		maxservers;
	time_t				maxservers_time;
	
	unsigned long int	maxconn;
	time_t				maxconn_time;

} RecordStats_V10;

// Current structs version
typedef RecordStats_V10		RecordStats;


// Global stats
typedef struct _GlobalStats_V10 {

	time_t				last_update;
	
	unsigned long int	nicks;
	unsigned long int	kills;
	unsigned long int	skills;
	unsigned long int	joins;
	unsigned long int	parts;
	unsigned long int	quits;
	unsigned long int	kicks;
	unsigned long int	bans;
	unsigned long int	addcmodes;
	unsigned long int	delcmodes;
	unsigned long int	umodes;
	unsigned long int	connections;
	unsigned long int	oppings;
	unsigned long int	deoppings;
	unsigned long int	halfoppings;
	unsigned long int	dehalfoppings;
	unsigned long int	voicings;
	unsigned long int	devoicings;
	unsigned long int	topics;

} GlobalStats_V10;

// Current structs version
typedef GlobalStats_V10		GlobalStats;


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define STATS_SERVER_HIDDEN		0x0001
#define STATS_SERVER_ONLINE		0x0002


#define UPDATE_AVG      20
#define HOUR_CHECK      60*60



/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern RecordStats	records;
extern GlobalStats	total;
extern GlobalStats	monthly;
extern GlobalStats	weekly;
extern GlobalStats	daily;

extern unsigned int stats_daily_maxusers;
extern unsigned int stats_daily_maxchans;


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void statserv_init();
extern void statserv_terminate(void);

// Handlers
extern void statserv(CSTR source, User *callerUser, char *buf);

// Database stuff
extern BOOL statserv_chanstats_db_load(void);
extern BOOL statserv_chanstats_db_save(void);
extern BOOL statserv_servstats_db_load(void);
extern BOOL statserv_servstats_db_save(void);
extern void expire_stats();
extern void statserv_daily_expire();
extern void statserv_weekly_expire();
extern void statserv_monthly_expire();

extern ChannelStats *hash_chanstats_find(CSTR value);

extern void add_channel_stats(CSTR channel);
extern ServerStats *findserverstats(CSTR server);
extern ServerStats *make_server_stats(CSTR server);

extern void update_server_averages();
extern void update_averages();
extern void update_hour();

extern void statserv_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long statserv_mem_report(CSTR sourceNick, const User *callerUser);


#endif /* SRV_STATSERV_H */
