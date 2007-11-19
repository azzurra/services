/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* debugserv.h - DebugServ service
* 
*/


#ifndef SRV_DEBUGSERV_H
#define SRV_DEBUGSERV_H


/*********************************************************
 * Public code                                           *
 *********************************************************/

// Handlers
extern void debugserv(const char *source, User *callerUser, char *buf);
extern void debugserv_init(void);


#endif /* SRV_DEBUGSERV_H */
