/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* tagline.h - Taglines
* 
*/


#ifndef SRV_TAGLINE_H
#define SRV_TAGLINE_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include <services/strings.h>

/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _tagline {
    char *text;
    Creator	creator;

    mowgli_node_t node;
} Tagline;

/*********************************************************
 * Global variables                                      *
 *********************************************************/

 extern int TaglineCount;

/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void tagline_init(void);
extern void tagline_terminate(void);

extern void handle_tagline(const char * ource, User *callerUser, ServiceCommandData *data);
extern void tagline_show(const time_t now);
extern void tagline_ds_dump(const char *sourceNick, const User *callerUser, STR request);
extern unsigned long int tagline_mem_report(const char *sourceNick, const User *callerUser);

#endif /* SRV_TAGLINE_H */
