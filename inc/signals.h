/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* signals.h - signal handling
* 
*/


#ifndef SRV_SIGNALS_H
#define SRV_SIGNALS_H


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define	SIG_OUT_OF_MEMORY	SIGUSR1
#define	SIG_REHASH			SIGUSR2


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void signals_init(void);


#endif /* SRV_SIGNALS_H */
