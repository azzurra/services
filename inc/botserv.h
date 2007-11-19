/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* botserv.h - BotServ service
* 
*/


#ifndef SRV_BOTSERV_H
#define SRV_BOTSERV_H

/*********************************************************
 * Headers                                               *
 *********************************************************/


/*********************************************************
 * Version stuff                                         *
 *********************************************************/

#define	BOTSERV_DB_CURRENT_VERSION		7
#define BOTSERV_DB_SUPPORTED_VERSION	"7"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _BotChannel_V10		BotChannel_V10;
struct _BotChannel_V10 {

	BotChannel_V10		*next, *prev;

	char				*name;

	CreationInfo		info;

	flags_t				flags;

	/* Caps */
	unsigned char		capspercent;

	/* Flood */
	unsigned char		floodLines;
	unsigned char		floodTime;
};

// Current structs version
typedef	BotChannel_V7	BotChannel;



/*********************************************************
 * Constants                                             *
 *********************************************************/


/*********************************************************
 * Global variables                                      *
 *********************************************************/


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void chanserv_init(void);
extern void chanserv_terminate(void);

#endif /* SRV_BOTSERV_H */
