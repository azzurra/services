/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* channels.h - Channel data
* 
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
*
*/


#ifndef SRV_CHANNELS_H
#define SRV_CHANNELS_H

#if defined(USE_SERVICES) || defined(USE_STATS)


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "strings.h"
#include "users.h"
#include "chanserv.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct chan_userlist_item UserListItem;
struct chan_userlist_item {

	UserListItem *next, *prev;
	User *user;
};

// a channel
struct _Channel {
	
	Channel			*next, *prev;
	char			name[CHANMAX];
	time_t			creation_time;			/* when channel was created */

	char			*topic;
	char			topic_setter[NICKMAX];	/* who set the topic */
	time_t			topic_time;				/* when topic was set */

	long int		mode;					/* CMODE_* */
	long int		limit;					/* 0 if none */
	char			*key;					/* NULL if none */

	unsigned char	bancount;				/* MAX_BANS = 100 */
	unsigned char	bansize;
	char			**bans;

	UserListItem	*users;
	UserListItem	*chanops;
	UserListItem	*halfops;
	UserListItem	*voices;

	unsigned short	userCount;

	#ifdef USE_SERVICES
	ChannelInfo		*ci;
	#endif
};


typedef struct _ChannelMode ChannelMode;
struct _ChannelMode {

	int mode;
	char letter;
};


/*********************************************************
 * Constants                                             *
 *********************************************************/

// Channel.mode
#define CMODE_i		0x00000001
#define CMODE_m		0x00000002
#define CMODE_n		0x00000004
#define CMODE_p		0x00000008
#define CMODE_s		0x00000010
#define CMODE_t		0x00000020
#define CMODE_k		0x00000040
#define CMODE_l		0x00000080
#define CMODE_r		0x00000100
#define CMODE_C		0x00000200
#define CMODE_R		0x00000400
#define CMODE_c		0x00000800
#define CMODE_O		0x00001000
#define CMODE_U		0x00002000
#define CMODE_M		0x00004000
#define CMODE_u		0x00008000

#define CMODE_CS	0x80000000


/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern ChannelMode known_cmodes[];
extern unsigned int known_cmodes_count;


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void	chan_init();
extern void	chan_terminate();

// Handlers
extern void	chan_handle_SJOIN(CSTR source, const int ac, char **av);
extern void chan_handle_internal_SJOIN(CSTR nick, CSTR chan_name);
extern void	chan_handle_chanMODE(CSTR source, const int ac, char **av);
extern void	chan_handle_TOPIC(CSTR source, const int ac, char **av);

extern Channel *hash_channel_find(CSTR value);
extern void	chan_user_remove(const User *user, Channel *c);

extern BOOL chan_add_op(Channel *chan, User *user);
extern BOOL chan_remove_op(Channel *chan, const User *user);
extern BOOL chan_add_halfop(Channel *chan, User *user);
extern BOOL chan_remove_halfop(Channel *chan, const User *user);
extern BOOL chan_add_voice(Channel *chan, User *user);
extern BOOL chan_remove_voice(Channel *chan, const User *user);

extern void chan_clear_bans(Channel *chan);
extern int chan_has_ban(Channel *chan, CSTR ban, char *buffer);
extern BOOL chan_add_ban(Channel *chan, CSTR ban);
extern BOOL chan_remove_ban(Channel *chan, CSTR ban);


#ifdef USE_SERVICES
extern void synch_topics();
extern void handle_masscmds(CSTR source, User *callerUser, ServiceCommandData *data);
extern void handle_mode(CSTR source, User *callerUser, ServiceCommandData *data);
#endif

#ifdef USE_STATS
extern void handle_list(CSTR source, User *callerUser, ServiceCommandData *data);
#endif

extern char *get_channel_mode(const long int modeOn, const long int modeOff);
extern unsigned int stats_open_channels_count;

extern void chan_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int chan_mem_report(CSTR sourceNick, const User *callerUser);

#endif /* defined(USE_SERVICES) || defined(USE_STATS) */

#endif /* SRV_CHANNELS_H */
