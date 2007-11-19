/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* lang_msg.h - Indice messaggi 
*
*/


#ifndef SRV_LANG_MSG_MAIN_H
#define SRV_LANG_MSG_MAIN_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "common.h"

#if defined USE_SERVICES
	#include "lang_msg_svc.h"
#elif defined USE_STATS
	#include "lang_msg_sts.h"
#elif defined USE_SOCKSMONITOR
	#include "lang_msg_cyb.h"
#endif


#endif /* SRV_LANG_MSG_MAIN_H */
