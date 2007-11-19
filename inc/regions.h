/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* regions.h
* 
*/

#ifndef SRV_REGIONS_H
#define SRV_REGIONS_H

/*********************************************************
 * Version stuff                                         *
 *********************************************************/

#define	REGIONS_DB_CURRENT_VERSION		10
#define REGIONS_DB_SUPPORTED_VERSION	"7 10"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef unsigned int	REGION_ID;
typedef unsigned int	REGION_TYPE;


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define	REGION_IT		(REGION_ID) 0
#define REGION_US		(REGION_ID) 1
#define REGION_FR		(REGION_ID) 2
#define REGION_DE		(REGION_ID) 3
#define REGION_ES		(REGION_ID) 4
#define REGION_JP		(REGION_ID) 5

#define REGION_INVALID	(REGION_ID) (-1)

#define REGION_FIRST	REGION_IT
#define REGION_LAST		REGION_JP
#define REGION_COUNT	6


#define REGIONTYPE_IP		(REGION_TYPE) 0x00000001
#define REGIONTYPE_HOST		(REGION_TYPE) 0x00000002
// only for region_match()
#define REGIONTYPE_BOTH		REGIONTYPE_IP | REGIONTYPE_HOST



/*********************************************************
 * Public code                                           *
 *********************************************************/

extern BOOL region_init(void);
extern void region_terminate(void);

#define	RegionFromLangID(lang_id)		( (REGION_ID)(lang_id) )

extern REGION_ID region_match(unsigned long int ip, CSTR host, REGION_TYPE behavior);

extern BOOL regions_db_load(void);
extern BOOL regions_db_save(void);

extern void handle_regions(CSTR source, User *callerUser, ServiceCommandData *data);

#endif /* SRV_REGIONS_H */
