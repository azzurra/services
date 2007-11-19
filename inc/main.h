/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* main.h - Startup module
* 
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
*
*/


#ifndef SRV_MAIN_H
#define SRV_MAIN_H


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef	enum _force_quit_values {dont_quit = 0, force_quit, quit_and_restart }	force_quit_values;


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define MISC_BUFFER_SIZE    512


/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern BOOL					global_running;
extern BOOL					global_force_save;
extern int					global_force_backup_count;
extern force_quit_values	global_force_quit;
extern int					quitting;

extern char					serv_input_buffer[BUFSIZE];
extern char					misc_buffer[MISC_BUFFER_SIZE];

extern BOOL					synched;
extern time_t				start_time;
extern time_t				NOW;

extern char					CAPAB[IRCBUFSIZE];


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void services_cleanup();
extern void database_expire(const time_t now);
extern void database_store();

extern void handle_quit(CSTR source, User *callerUser, ServiceCommandData *data);
extern void handle_restart(CSTR source, User *callerUser, ServiceCommandData *data);
extern void handle_shutdown(CSTR source, User *callerUser, ServiceCommandData *data);
extern void handle_update(CSTR source, User *callerUser, ServiceCommandData *data);
extern void handle_uptime(CSTR source, User *callerUser, ServiceCommandData *data);

#endif /* SRV_MAIN_H */
