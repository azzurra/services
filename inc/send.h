/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* send.h - Routines for sending stuff to the network
* 
*/


#ifndef SRV_SEND_H
#define SRV_SEND_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "lang.h"


/*********************************************************
 * Global variables                                      *
 *********************************************************/

unsigned long int total_sendM;


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void send_cmd(CSTR fmt, ...);

extern void send_globops(CSTR source, CSTR fmt, ...);
extern void send_chatops(CSTR source, CSTR fmt, ...);
extern void send_SPAMOPS(CSTR source, CSTR fmt, ...);
extern void send_PRIVMSG(CSTR source, CSTR dest, CSTR fmt, ...);
extern void send_NICK(CSTR nickname, CSTR umode, CSTR username, CSTR hostname, CSTR realname);
extern void send_KILL(CSTR source, CSTR who, CSTR reason, BOOL killUser);
extern void send_AKILL(CSTR username, CSTR host, CSTR who, CSTR reason, const unsigned long int id, CSTR type);
extern void send_RAKILL(CSTR username, CSTR host);
extern void send_SVSKILL(CSTR who, CSTR reason);
extern void send_chan_MODE(CSTR agentNick, CSTR channel, CSTR modes, const unsigned long int limit, CSTR key);
extern void send_user_SVSMODE(CSTR source, CSTR target, CSTR modes, time_t ts);
extern void send_SJOIN(CSTR nickname, CSTR channel);
extern void send_PART(CSTR nickname, CSTR channel);
extern void send_QUIT(CSTR nickname, CSTR reason);
extern void send_SVSNOOP(CSTR server, char action);
extern void send_SVSNICK(CSTR nick, CSTR newnick);
extern void send_SHUN(CSTR source, CSTR target, CSTR reason);

#ifdef USE_SOCKSMONITOR
extern void send_CTCP(CSTR target, CSTR type);
#endif

extern void send_notice_to_nick(CSTR source, CSTR dest, CSTR fmt, ...);
extern void send_notice_to_user(CSTR source, const User *dest, CSTR fmt, ...);

extern void send_notice_lang_to_nick(CSTR source, CSTR dest, const LANG_ID lang_id, const LANG_MSG_ID msg_id, ...);
extern void send_notice_lang_to_user(CSTR source, const User *dest, const LANG_ID lang_id, const LANG_MSG_ID msg_id, ...);


#endif /* SRV_SEND_H */
