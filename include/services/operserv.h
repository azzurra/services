/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* operserv.h - OperServ service
* 
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
*
*/


#ifndef SRV_OPERSERV_H
#define SRV_OPERSERV_H

/*********************************************************
 * Public code                                           *
 *********************************************************/

// Handlers
extern void operserv(const char *source, User *callerUser, char *buf);

// Initializer
extern void operserv_init(void);

// Clones stuff
extern void check_clones(const User *user);
extern void check_clones_v6(const User *user);

// Debug stuff
extern void operserv_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long operserv_mem_report(CSTR sourceNick, const User *callerUser);

#endif /* SRV_OPERSERV_H */
