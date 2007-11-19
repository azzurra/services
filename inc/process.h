/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* process.h - Messages processing
* 
*/


#ifndef SRV_PROCESS_H
#define SRV_PROCESS_H


/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern int		dispatched;
extern int		to_dispatched;

extern BOOL		debug_inject;
extern STR		debug_monitor_inputbuffer_filter;

unsigned long int total_recvM;


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void process_parse(void);
extern void process_debug_inject(CSTR buffer);
extern void process_check_debug_inject();

extern void process_init(void);
extern void process_terminate(void);


#endif /* SRV_PROCESS_H */
