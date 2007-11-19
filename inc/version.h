/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* version.h - version info include
* 
*/

#ifndef SRV_VERSION_H
#define SRV_VERSION_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "branch.h"


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define	VERS_IRCD		"BH14x"

// flags

#define	VERS_BF_LANG		"L"

#ifdef FIX_USE_MPOOL
#define	VERS_BF_POOL		"P"
#else
#define	VERS_BF_POOL		""
#endif


#ifdef ENABLE_DEBUG_COMMANDS
#define VERS_BF_DEBUG		"D"
#else
#define VERS_BF_DEBUG		""
#endif

#ifdef ENABLE_TRACE
#define VERS_BF_TRACE		"T"
#else
#define VERS_BF_TRACE		""
#endif

// capabs

#ifdef ENABLE_CAPAB_TS3
#define VERS_CP_TS3			"T"
#else
#define VERS_CP_TS3			""
#endif

#ifdef ENABLE_CAPAB_NOQUIT
#define VERS_CP_NOQUIT		"Q"
#else
#define VERS_CP_NOQUIT		""
#endif

#ifdef ENABLE_CAPAB_SSJOIN
#define VERS_CP_SSJOIN		"S"
#else
#define VERS_CP_SSJOIN		""
#endif

#ifdef ENABLE_CAPAB_BURST
#define VERS_CP_BURST		"B"
#else
#define VERS_CP_BURST		""
#endif

#ifdef ENABLE_CAPAB_UNCONNECT
#define VERS_CP_UNCONNECT	"U"
#else
#define VERS_CP_UNCONNECT	""
#endif

#ifdef ENABLE_CAPAB_ZIP
#define VERS_CP_ZIP			"Z"
#else
#define VERS_CP_ZIP			""
#endif

#ifdef ENABLE_CAPAB_NICKIP
#define VERS_CP_NICKIP		"N"
#else
#define VERS_CP_NICKIP		""
#endif

#ifdef ENABLE_CAPAB_TSMODE
#define VERS_CP_TSMODE		"M"
#else
#define VERS_CP_TSMODE		""
#endif

#ifdef ENABLE_CAPAB_DKEY
#define VERS_CP_DKEY		"D"
#else
#define VERS_CP_DKEY		""
#endif


#if defined(USE_SOCKSMONITOR)

// Cybcop build

#define VERS_BUILDNAME	"Security Services"
#define	VERS_MAJOR		"2"
#define VERS_MINOR		"4"
#define VERS_REVISION	"2"
#define VERS_CODENAME	"Kekkai"


#elif defined(USE_STATS)

// Stats build

#define VERS_BUILDNAME	"Statistical Services"
#define	VERS_MAJOR		"1"
#define VERS_MINOR		"8"
#define VERS_REVISION	"0"
#define VERS_CODENAME	"Murasaki"

#else

// Main services build

#define VERS_BUILDNAME	"Core Services"
#define	VERS_MAJOR	"2"
#define VERS_MINOR	"2"
#define VERS_REVISION	"2"
#define VERS_CODENAME	"Zero"

#endif

extern STDSTR	s_vers_name;
extern STDSTR	s_vers_build_name;
extern STDSTR	s_vers_version;
extern STDSTR	s_vers_buildtime;
extern STDSTR	s_vers_codedby;


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern void handle_version(CSTR source, User *callerUser, ServiceCommandData *data);

#endif /* SRV_VERSION_H */
