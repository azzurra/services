/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* spam.h
* 
*/

#ifndef SRV_SPAM_H
#define SRV_SPAM_H

/*********************************************************
 * Version stuff                                         *
 *********************************************************/

#define	SPAM_DB_CURRENT_VERSION		10
#define SPAM_DB_SUPPORTED_VERSION	"10"


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void spam_init(void);
extern void spam_terminate(void);

extern BOOL spam_db_load(void);
extern BOOL spam_db_save(void);
extern void spam_burst_send(void);

extern void handle_spam(CSTR source, User *callerUser, ServiceCommandData *data);

#endif /* SRV_SPAM_H */
