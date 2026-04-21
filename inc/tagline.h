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

#include "../inc/strings.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _tagline_V10		Tagline_V10;
struct _tagline_V10 {

	Tagline_V10	*prev, *next;

	char		*text;
	Creator		creator;
};

// Current struct version
typedef	Tagline_V10		Tagline;

#ifdef OS_64BIT
typedef struct _tagline_V10_32		Tagline_V10_32;
struct _tagline_V10_32 {

    int32_t	    prev, next;

    int32_t		text;
    Creator32	creator;
};

// Current struct version
typedef	Tagline_V10_32		Tagline32;
#endif


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define	TAGLINE_DB_CURRENT_VERSION		10
#define TAGLINE_DB_SUPPORTED_VERSION	"10"

/*
 * TAGLINE_MAX_LEN -- hard cap on tagline text length, in bytes.
 *
 * This is not an arbitrary knob. Taglines are broadcast through
 * send_globops() (see tagline_show() and handle_tagline() in tagline.c),
 * which ultimately produces an IRC server message of the form:
 *
 *     :<server> NOTICE $* :<OperServ> (through <oper>) added the
 *     following tagline: <text>\r\n
 *
 * The IRC protocol caps a single line at 512 bytes including the trailing
 * CR-LF (RFC 1459 section 2.3.1). The fixed overhead above -- server
 * prefix, command, target, boilerplate and the optional "(through <oper>)"
 * variant emitted when an operator acts via a service -- eats roughly
 * 100-110 bytes in realistic cases. 400 leaves comfortable headroom for
 * multibyte glyphs and long operator/server names without bumping into the
 * 512-byte ceiling.
 *
 * Before raising this value, re-derive the worst-case envelope against
 * every send_globops() call site that embeds a tagline: blind increases
 * cause silent truncation at the uplink (bahamut) with no feedback to the
 * originating operator.
 */
#define TAGLINE_MAX_LEN				400


/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern int TaglineCount;


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern BOOL tagline_db_load(void);
extern BOOL tagline_db_save(void);
extern void handle_tagline(CSTR source, User *callerUser, ServiceCommandData *data);
extern void tagline_show(const time_t now);
extern void tagline_ds_dump(CSTR sourceNick, const User *callerUser, STR request);
extern unsigned long int tagline_mem_report(CSTR sourceNick, const User *callerUser);


#endif /* SRV_TAGLINE_H */
