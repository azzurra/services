/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* users.h - User record
* 
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
*
*/


#ifndef SRV_USERS_H
#define SRV_USERS_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "strings.h"
#include "cidr.h"
#include "lang.h"
#include "oper.h"
#include "channels.h"
#include "chanserv.h"
#include "nickserv.h"
#include "servers.h"
#include <arpa/inet.h>

/*********************************************************
 * Data types                                            *
 *********************************************************/

#if defined(USE_SERVICES) || defined(USE_STATS)
typedef struct user_chanlist_item ChanListItem;
struct user_chanlist_item {

	ChanListItem	*next, *prev;
	Channel			*chan;
};
#endif

#ifdef USE_SERVICES
typedef struct user_chaninfolist_item ChanInfoListItem;
struct user_chaninfolist_item {

	ChanInfoListItem	*next, *prev;
	ChannelInfo			*ci;
};
#endif

// an user
struct _User {

	User					*next, *prev;
	char					nick[NICKMAX];
	char					*username;
	char					*host;			/* user's hostname */
	char					*maskedHost;	/* umode +x host */
	char					*realname;
	Server					*server;	/* Pointer to the server struct the user is on. */

	#ifdef ENABLE_CAPAB_NICKIP
	unsigned long int			ip;
	unsigned char				ipv6[sizeof(struct in6_addr)];
	#endif

	time_t					tsinfo;			/* User's tsinfo, used for SVSMODE etc. */
	time_t					signon;			/* User's signon time. */
	time_t					my_signon;		/* when did _we_ see the user? */
	long int				mode;			/* UMODE_* */
	long int				flags;			/* U_* */

	#if defined(USE_SERVICES) || defined(USE_STATS)
	ChanListItem			*chans;			/* Channels user has joined. */
	#endif

	#ifdef USE_SERVICES
	ChanInfoListItem		*founder_chans;		/* Channels user has identified for. */

	short int				idcount;
	char					**id_nicks;
	time_t					lastmemosend;			/* last time MS SEND command used */
	time_t					lastnickreg;			/* last time NS REGISTER cmd used */
	time_t					lastchanreg;

	NickInfo				*ni;
	#endif /* USE_SERVICES */

	// Flood control
	time_t					flood_reset_time;
	unsigned char			flood_msg_count;
	unsigned char			flood_current_level;

	// Invalid password control
	time_t					invalid_pw_reset_time;
	unsigned char			invalid_pw_count;
	unsigned char			invalid_pw_current_level;

	LANG_ID					current_lang;
	Oper					*oper;
};


typedef struct _user_alt_list_item	User_AltListItem;
struct _user_alt_list_item {

	User				*user;
	User_AltListItem	*next, *prev;
};


/*********************************************************
 * Constants                                             *
 *********************************************************/

// User.mode
#define UMODE_a 0x0001
#define UMODE_A 0x0002
#define UMODE_h 0x0004
#define UMODE_i 0x0008
#define UMODE_I 0x0010
#define UMODE_o 0x0020
#define UMODE_r 0x0040
#define UMODE_R 0x0080
#define UMODE_S 0x0100
#define UMODE_x 0x0200
#define UMODE_y 0x0400
#define UMODE_z 0x0800

// User.flags
#define USER_FLAG_ENFORCER		0x00000001
#define USER_FLAG_AGENT			0x00000002
#define USER_FLAG_HAS_IPV6		0x00000004
#define USER_FLAG_IS_APM		0x00000008
#define USER_FLAG_IS_SERVERBOT		0x00000010
#define USER_FLAG_BOTTLER		0x00000020		/* User has been scanned for Bottler. */
#define USER_FLAG_ISBOTTLER		0x00000040		/* User is a Bottler and will be autokilled. */
#define USER_FLAG_EMPTYFINGER		0x00000080
#define USER_FLAG_EMPTYUSERINFO		0x00000100
#define USER_FLAG_FLOODER		0x00000200
#define USER_FLAG_PASSHACK		0x00000400
#define USER_FLAG_6TO4			0x00000800
#define USER_FLAG_TEREDO		0x00001000

// Users lists index validation
#define FIRST_VALID_NICK_CHAR	65
#define LAST_VALID_NICK_CHAR	125

#define FIRST_VALID_HOST_CHAR	48
#define LAST_VALID_HOST_CHAR	122

#define FIRST_ONLINE_USER_IDX	0
#define LAST_ONLINE_USER_IDX	60

#define FIRST_ONLINE_HOST_IDX	0
#define LAST_ONLINE_HOST_IDX	74


/*********************************************************
 * Global variables                                      *
 *********************************************************/

// Users lists
#define ONLINEUSER_HASHSIZE					1024

#ifndef ENABLE_CAPAB_NICKIP
	#define ONLINEHOST_HASHSIZE				1024
#else
	#define ONLINEHOST_HASHSIZE				256
	#define USER_ONLINEHOST_HASHFUNC(key)	((key) % ONLINEHOST_HASHSIZE)
#endif

extern User 				*hashtable_onlineuser[];
extern User_AltListItem 	*hashtable_onlinehost[];
extern User_AltListItem		*list_onlineuser_ipv6;

// Users stats
extern unsigned int user_online_user_count;
extern unsigned int user_online_operator_count;
extern unsigned int user_online_user_max;


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern BOOL user_init(void);
extern void user_terminate(void);
extern void register_agents(void);
extern User *hash_onlineuser_find(CSTR nick);
extern User *user_localuser_find(CSTR nick);
extern User *user_add_services_client(CSTR nick, CSTR mode, CSTR username, CSTR realname, int serviceAgent);
extern User *user_add_services_agent(CSTR nick, long int mode, CSTR realname);
extern void user_delete_services_client(CSTR nick);

#ifdef USE_SERVICES
extern User *user_add_enforcer(NickInfo *ni);
#endif

#define IS_INVALID_NICK_CHAR(c)	( ((c) < FIRST_VALID_NICK_CHAR) || ((c) > LAST_VALID_NICK_CHAR) )
#define IS_INVALID_HOST_CHAR(c)	( ((c) < FIRST_VALID_HOST_CHAR) || ((c) > LAST_VALID_HOST_CHAR) )


#define user_public_host(user)	((user)->mode & UMODE_x ? (user)->maskedHost : (user)->host )

// Handlers
extern void	user_handle_NICK(CSTR source, const int ac, char **av);
extern void	user_handle_JOIN(CSTR source, const int ac, char **av);
extern void	user_handle_PART(CSTR source, const int ac, char **av);
extern void	user_handle_KICK(CSTR source, const int ac, char **av);
extern void	user_handle_userMODE(CSTR source, const int ac, char **av);
extern void	user_handle_QUIT(CSTR source, const int ac, char **av);
extern void	user_handle_KILL(CSTR source, const int ac, char **av);

#ifdef ENABLE_CAPAB_NOQUIT
extern int user_handle_server_SQUIT(const Server *server);
#endif

#ifdef USE_SERVICES
extern void user_handle_services_kick(CSTR chan, User *user);
#endif

extern BOOL	user_is_identified_to(const User *callerUser, CSTR nickname);

#ifdef USE_SERVICES
extern void user_remove_id(CSTR nickname, BOOL deleted);
extern void user_remove_chanid(ChannelInfo *ci);
#endif

extern BOOL user_is_ircop(const User *user);
extern BOOL nick_is_ircop(CSTR nick);
extern BOOL user_is_admin(const User *user);
extern BOOL user_is_services_agent(const User *user);
extern BOOL nick_is_services_agent(CSTR nick);
extern BOOL user_is_services_client(const User *user);
extern BOOL nick_is_services_client(CSTR nick);
extern BOOL nick_is_service(CSTR name);

extern void introduce_services_agent(CSTR nick);

#if defined(USE_SERVICES) || defined(USE_STATS)
extern BOOL user_isin_chan(const User *user, CSTR chan);
extern BOOL	user_is_chanop(CSTR nick, CSTR chan, Channel *c);
extern BOOL	user_is_chanhalfop(CSTR nick, CSTR chan, Channel *c);
extern BOOL	user_is_chanvoice(CSTR nick, CSTR chan, Channel *c);
#endif

extern BOOL	user_usermask_match(CSTR mask, const User *user, BOOL matchMaskedHost, BOOL matchCIDR);
extern void	user_usermask_split(CSTR mask, char **nick, char **user, char **host);
extern char *user_usermask_create(const User *user, short int type);
extern char *get_user_modes(long int modeOn, long int modeOff);
extern char *get_user_flags(long int flags);

extern void handle_uinfo(CSTR source, User *callerUser, ServiceCommandData *data);

extern void user_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int user_mem_report(CSTR sourceNick, const User *callerUser);

#endif /* SRV_USERS_H */
