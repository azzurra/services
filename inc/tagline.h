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
 * This is not an arbitrary knob. The tightest constraint is not storage
 * or the inbound PRIVMSG the operator sends to OperServ (servers use a
 * nick-only prefix when propagating client traffic, per RFC 1459 s.2.3
 * and bahamut convention, which leaves ample room). It is the *outbound*
 * broadcast produced by send_globops() in handle_tagline() and
 * tagline_show(), which bahamut turns into a NOTICE to every +g operator
 * (see src/send.c:send_globops in bahamut):
 *
 *     :<server> NOTICE <destnick> :*** Global -- \2<caller>\2
 *     (through \2<oper>\2) added the following tagline: <text>\r\n
 *
 * The IRC protocol caps a single line at 512 bytes including the
 * trailing CR-LF (RFC 1459 s.2.3.1). Worst-case byte budget:
 *
 *     `:<server>` (HOSTMAX=63) + ` NOTICE ` (8) + `<destnick>`
 *     (NICKMAX=32) + ` :*** Global -- ` (16) + bold markers + `<caller>`
 *     (NICKMAX=32) + ` (through ` (10) + bold markers + `<oper>`
 *     (NICKMAX=32) + `) added the following tagline: ` (31) + <text>
 *     + `\r\n` (2) ~= 230 + text
 *
 * So the theoretical worst case caps text at ~280, though realistic
 * Azzurra params (server name ~21, operator nicks ~8-12) leave comfortable
 * headroom. 350 keeps us well clear of truncation across both realistic
 * and near-worst-case combinations without pushing the limit.
 *
 * Before raising this value, re-derive both envelopes (services-side
 * send_globops() and bahamut's send_globops() NOTICE wrapper) against
 * every call site that embeds a tagline. Blind increases cause silent
 * truncation at the receiving server with no feedback to the originating
 * operator -- the stored tagline is fine, but the GLOBOPS confirmation
 * message seen by +g opers gets its tail cut.
 */
#define TAGLINE_MAX_LEN				350


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
