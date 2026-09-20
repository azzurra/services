/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* helpserv.h - HelpServ service
* 
*/


#ifndef SRV_HELPSERV_H
#define SRV_HELPSERV_H

/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void handle_help(CSTR source, User *callerUser, ServiceCommandData *data);

extern void helpserv_init(void);
extern void helpserv(CSTR source, User *callerUser, char *buf);

#endif /* SRV_HELPSERV_H */
