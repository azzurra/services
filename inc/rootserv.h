/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* rootserv.h - RootServ service
* 
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
*
*/


#ifndef SRV_ROOTSERV_H
#define SRV_ROOTSERV_H

#include "../inc/access.h"

/*********************************************************
 * Version stuff                                         *
 *********************************************************/

#define	DYNCONF_DB_CURRENT_VERSION		10
#define DYNCONF_DB_SUPPORTED_VERSION	"10"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _dynConfig dynConfig;

struct _dynConfig {
   
   // limiti nelle registrazioni di nick e chan
   unsigned long    ns_regLimit;
   unsigned long    cs_regLimit;

   // notice on-connect
   char             *welcomeNotice;
};


/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern Access		*serverBotList;
extern dynConfig	dynConf;


/*********************************************************
 * Public code                                           *
 *********************************************************/

// Handlers
extern void rootserv(CSTR source, User *callerUser, char *buf);

// Initialization/termination
extern void rootserv_init(void);
extern void rootserv_terminate(void);

// Database stuff
extern void rootserv_db_load(void);
extern void rootserv_db_save(void);

// DebugServ dump support
extern void rootserv_ds_dump(CSTR sourceNick, const User *callerUser, STR request);

// DebugServ mem support
extern unsigned long int rootserv_mem_report(CSTR sourceNick, const User *callerUser);

#endif /* SRV_ROOTSERV_H */
