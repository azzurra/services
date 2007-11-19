/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* tagline.h - Taglines
* 
*/


#ifndef SRV_TAGLINE_H
#define SRV_TAGLINE_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/strings.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _tagline_V10		Tagline_V10;
struct _tagline_V10 {

	Tagline_V10	*prev, *next;

	char		*text;
	Creator		creator;
};

// Current struct version
typedef	Tagline_V10		Tagline;


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define	TAGLINE_DB_CURRENT_VERSION		10
#define TAGLINE_DB_SUPPORTED_VERSION	"10"


/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern int TaglineCount;


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern BOOL tagline_db_load(void);
extern BOOL tagline_db_save(void);
extern void handle_tagline(CSTR source, User *callerUser, ServiceCommandData *data);
extern void tagline_show(const time_t now);
extern void tagline_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int tagline_mem_report(CSTR sourceNick, const User *callerUser);


#endif /* SRV_TAGLINE_H */
