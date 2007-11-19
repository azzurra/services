/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* jupe.h - Jupes
* 
*/


#ifndef SRV_JUPE_H
#define SRV_JUPE_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/strings.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _jupe_V10		Jupe_V10;
struct _jupe_V10 {

	Jupe_V10		*prev, *next;

	char			*name;

	CreationInfo	info;
};

// Current struct version
typedef	Jupe_V10		Jupe;


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void handle_jupe(CSTR source, User *callerUser, ServiceCommandData *data);
extern BOOL jupe_match(CSTR server, const User *callerUser, const BOOL sendSquit);
extern void jupe_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int jupe_mem_report(CSTR sourceNick, const User *callerUser);


#endif /* SRV_JUPE_H */
