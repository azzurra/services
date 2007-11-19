/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* sxline.h - Services G:/Q:/Z:Lines
* 
*/


#ifndef SRV_SXLINE_H
#define SRV_SXLINE_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/strings.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _SXLine_V10 SXLine_V10;
struct _SXLine_V10 {

	SXLine_V10 		*prev, *next;

	char			*name;		/* Realname if it's a G:Line, nick/channel if it's a Q:Line. */

	CreationInfo	info;

	time_t			lastUsed;
};

// Current struct version
typedef	SXLine_V10	SXLine;


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define	SXLINE_DB_CURRENT_VERSION		10
#define SXLINE_DB_SUPPORTED_VERSION		"10"

#define SXLINE_TYPE_GLINE	1
#define SXLINE_TYPE_QLINE	2


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern BOOL sxline_db_load(const int type);
extern BOOL sxline_db_save(const int type);
extern void sxline_burst_send(void);
extern int sxline_get_count(const int type);
extern void handle_sxline(CSTR source, User *callerUser, ServiceCommandData *data);
extern void sxline_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int sxline_mem_report(CSTR sourceNick, const User *callerUser);

#endif /* SRV_SXLINE_H */
