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

	uint64_t	totaljoins, totalparts, totalkicks, totalbans, totaloppings, totaldeoppings, totalhalfoppings,
				totaldehalfoppings, totalvoicings, totaldevoicings, totaltopics, totaldelcmodes, totaladdcmodes;
	uint64_t	totalpeak, monthlypeak, weeklypeak, dailypeak;
	uint64_t	monthlyjoins, weeklyjoins, dailyjoins;
	uint64_t	monthlyparts, weeklyparts, dailyparts;
	uint64_t	monthlykicks, weeklykicks, dailykicks;
	uint64_t	monthlybans, weeklybans, dailybans;
	uint64_t	monthlyoppings, weeklyoppings, dailyoppings;
	uint64_t	monthlydeoppings, weeklydeoppings, dailydeoppings;
	uint64_t	monthlyhalfoppings, weeklyhalfoppings, dailyhalfoppings;
	uint64_t	monthlydehalfoppings, weeklydehalfoppings, dailydehalfoppings;
	uint64_t	monthlyvoicings, weeklyvoicings, dailyvoicings;
	uint64_t	monthlydevoicings, weeklydevoicings, dailydevoicings;
	uint64_t	monthlytopics, weeklytopics, dailytopics;
	uint64_t	monthlydelcmodes, weeklydelcmodes, dailydelcmodes;
	uint64_t	monthlyaddcmodes, weeklyaddcmodes, dailyaddcmodes;
};

// Current struct version
typedef ChannelStats_V10	ChannelStats;

#ifdef OS_64BIT
#pragma pack(push, 4) // just tell the compiler we want a 4byte alignment to be sure
typedef struct _ChannelStats_V10_32	ChannelStats_V10_32;
struct _ChannelStats_V10_32 {

	int32_t	next, prev;

#ifdef FIX_USE_MPOOL
	int32_t		mblock_id;
#endif

	int32_t		name;
	int32_t		time_added;
	int32_t		last_change;	/* when the last stat changed */

	uint32_t	totaljoins, totalparts, totalkicks, totalbans, totaloppings, totaldeoppings, totalhalfoppings, totaldehalfoppings, totalvoicings, totaldevoicings, totaltopics, totaldelcmodes, totaladdcmodes;
	uint32_t	totalpeak, monthlypeak, weeklypeak, dailypeak;
	uint32_t	monthlyjoins, weeklyjoins, dailyjoins;
	uint32_t	monthlyparts, weeklyparts, dailyparts;
	uint32_t	monthlykicks, weeklykicks, dailykicks;
	uint32_t	monthlybans, weeklybans, dailybans;
	uint32_t	monthlyoppings, weeklyoppings, dailyoppings;
	uint32_t	monthlydeoppings, weeklydeoppings, dailydeoppings;
	uint32_t	monthlyhalfoppings, weeklyhalfoppings, dailyhalfoppings;
	uint32_t	monthlydehalfoppings, weeklydehalfoppings, dailydehalfoppings;
	uint32_t	monthlyvoicings, weeklyvoicings, dailyvoicings;
	uint32_t	monthlydevoicings, weeklydevoicings, dailydevoicings;
	uint32_t	monthlytopics, weeklytopics, dailytopics;
	uint32_t	monthlydelcmodes, weeklydelcmodes, dailydelcmodes;
	uint32_t	monthlyaddcmodes, weeklyaddcmodes, dailyaddcmodes;
};
#pragma pack(pop)
// Current struct version
typedef ChannelStats_V10_32	ChannelStats32;
#endif


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

#ifdef OS_64BIT

typedef struct _ServerStats_V10_32		ServerStats_V10_32;
struct _ServerStats_V10_32 {

	int32_t				next, prev;

	int32_t				name;
	int32_t				time_added;

	int16_t				clients;
	int16_t				maxclients;
	int32_t				maxclients_time;

	int8_t				opers;
	int8_t				maxopers;
	int32_t				maxopers_time;

	int16_t				operkills;
	int16_t				servkills;

	int32_t				connect;
	int32_t				squit;

	int32_t				hits;
	int32_t				msgs;

	float				users_average;
	float				opers_average;

	int8_t				dailysplits;
	int8_t				weeklysplits;
	int8_t				monthlysplits;
	int16_t	totalsplits;

	short_flags_t		flags;
};

// Current struct version
typedef ServerStats_V10_32		ServerStats32;
#endif



// current records
#ifdef OS_64BIT
/*We are not saving any memory using short or char followed by time_t that is 64bit today, just go with uint64_t*/
typedef struct _RecordStats_V10 {

	time_t				started;

	uint64_t			maxusers;
	time_t				maxusers_time;

	uint64_t			maxchannels;
	time_t				maxchannels_time;

	uint64_t			maxopers;
	time_t				maxopers_time;
	
	uint64_t			maxservers;
	time_t				maxservers_time;
	
	uint64_t			maxconn;
	time_t				maxconn_time;

} RecordStats_V10;
#else
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
#endif

// Current structs version
typedef RecordStats_V10		RecordStats;

#ifdef OS_64BIT
/*Fuck who ever wrote this...this is a fucking padding nightmare!
 Like the 25% of the space is wasted in padding. --Sonic
 */
#pragma pack(push, 4)
typedef struct _RecordStats_V10_32 {

	uint32_t			started;

	uint16_t			maxusers;
	uint32_t			maxusers_time;

	uint16_t			maxchannels;
	uint32_t			maxchannels_time;
	uint8_t 			maxopers;
	uint32_t			maxopers_time;

	uint8_t				maxservers;
	uint32_t			maxservers_time;

	uint32_t			maxconn;
	uint32_t			maxconn_time;

} RecordStats_V10_32;
#pragma pack(pop)
// Current structs version
typedef RecordStats_V10_32		RecordStats32;
#endif


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

#ifdef OS_64BIT
typedef struct _GlobalStats_V10_32 {

	int32_t				last_update;

	uint32_t	nicks;
	uint32_t	kills;
	uint32_t	skills;
	uint32_t	joins;
	uint32_t	parts;
	uint32_t	quits;
	uint32_t	kicks;
	uint32_t	bans;
	uint32_t	addcmodes;
	uint32_t	delcmodes;
	uint32_t	umodes;
	uint32_t	connections;
	uint32_t	oppings;
	uint32_t	deoppings;
	uint32_t	halfoppings;
	uint32_t	dehalfoppings;
	uint32_t	voicings;
	uint32_t	devoicings;
	uint32_t	topics;

} GlobalStats_V10_32;
typedef GlobalStats_V10_32		GlobalStats32;
#endif

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
