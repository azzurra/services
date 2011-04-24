/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* servers.h - Servers handling
*
*/


#ifndef SRV_SERVERS_H
#define SRV_SERVERS_H


/*********************************************************
 * Data types                                            *
 *********************************************************/

// a server
typedef struct _Server Server;
struct _Server {

	Server				*prev, *next;

	char				*name;		/* Server name. */
	char				*desc;		/* Server description. */

	Server				*uplink;	/* Link to our uplink's server structure. */

	unsigned char		hops;
	short_flags_t		flags;		/* SERVER_FLAG_* */

	unsigned short int	userCount;
	time_t				connected;	/* When the server linked. */
};


/*********************************************************
 * Constants                                             *
 *********************************************************/

// Server.flags
#define SERVER_FLAG_LINKED		0x0001		/* Is server online? */
#define SERVER_FLAG_SCANEXEMPT	0x0002		/* 1: Server is exempt from scan */
#define SERVER_FLAG_BURSTING	0x0004		/* Server is bursting (clients must not be scanned) */
#define SERVER_FLAG_UPLINK		0x0008		/* 1 if this is our uplink */
#define SERVER_FLAG_HAVEAPM		0x0010		/* Is there an APM taking care of the clients' proxies? */
#define SERVER_FLAG_HUB			0x0020		/* This server is a hub. */
#define SERVER_FLAG_MYSELF		0x0040		/* This server is us. */

// Server CAPAB
#define CAPAB_UNKNOWN			0x00000000
#define CAPAB_TS3				0x00000001	/* Dummy. */
#define CAPAB_NOQUIT			0x00000002	/* Don't send QUITs on server splits, just one SQUIT. */
#define CAPAB_SSJOIN			0x00000004	/* Use shorter and more intelligent SJOINs. */
#define CAPAB_BURST				0x00000008	/* Notify us when we're synched. */
#define CAPAB_UNCONNECT			0x00000010	/* Allow us to SQUIT servers below us. */
#define CAPAB_ZIP				0x00000020	/* Compress data during burst. */
#define CAPAB_NICKIP			0x00000040	/* Send IP in host format in the NICK line. */
#define CAPAB_TSMODE			0x00000080	/* Send TS along with any channel MODE. */
#define CAPAB_DKEY				0x00000100	/* Crypt data between our hub and us. */



/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern Server	*server_myself;



/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void servers_init(void);

extern Server *findserver(CSTR name);

extern void server_handle_SERVER(CSTR source, const int ac, char **av);
extern void server_handle_SQUIT(CSTR source, const int ac, char **av);
extern void server_create_entry(CSTR servername, CSTR desc, int flags);
extern void send_servers_list(CSTR source, const User *callerUser);
extern void handle_noop(CSTR source, User *callerUser, ServiceCommandData *data);

extern unsigned long server_mem_report(CSTR sourceNick, const User *callerUser);
extern void server_ds_dump(CSTR sourceNick, const User *callerUser, STR request);

extern void synch_servers(void);
extern void burst_servers(Server *hub);

extern void servers_user_add(User *user);
extern void servers_user_remove(User *user);

#endif /* SRV_SERVERS_H */
