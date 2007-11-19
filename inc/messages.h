/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* messages.h - Messages handling
* 
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
*
*/


#ifndef SRV_MESSAGES_H
#define SRV_MESSAGES_H


/*********************************************************
 * Data types                                            *
 *********************************************************/

/* Server messages handler */
typedef void (*SERVICE_MESSAGE_HANDLER)(const char *, const int , char **);
typedef struct {
    const char					*name;
	unsigned long int			usage_count;
    SERVICE_MESSAGE_HANDLER		func;

} Message;


/* Agent information to be passed to the main handler function */
typedef struct _Agent {

	CSTR	nick;
	CSTR	shortNick;
	int		agentID;
	int		logID;

} Agent;


/* Command Data holder */
typedef struct _ServiceCommandData {

	char		*commandName;

	int			userLevel;
	BOOL		operMatch;
	char		*operName;

	const Agent	*agent;

} ServiceCommandData;


/* Agents messages handler */
typedef void (*SERVICE_COMMAND_HANDLER)(const char *, User *, ServiceCommandData *);
typedef struct _ServiceCommand {

	char						*command;
	int							access_level;
	unsigned long				usage_count;
	SERVICE_COMMAND_HANDLER		handler;

} ServiceCommand;


/*********************************************************
 * Constants                                             *
 *********************************************************/

/* Flood levels: */

/* - Start here */
#define	FLOOD_LEVEL_0	0
/* - Grace Level */
#define	FLOOD_LEVEL_1	1
/* - Warns user, globops network */
#define	FLOOD_LEVEL_2	2
/* - Warns user, globops network again with "SEVERELY" message */
#define	FLOOD_LEVEL_3	3
/* - User is killed */
#define	FLOOD_LEVEL_4	4



/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern Message messages[];

/* my uplink CAPAB */
extern unsigned int		uplink_capab;

#ifdef USE_STATS
extern int nservers;
#endif


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern Message *find_message(CSTR name);


#endif /* SRV_MESSAGES_H */
