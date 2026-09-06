/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* lang.h - Supporto multi-lingua
*
*/

#ifndef DBCONV_LANG_H
#define DBCONV_LANG_H


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef unsigned int        LANG_VERSION;
typedef unsigned int        LANG_ID;
typedef LANG_ID             LANG_MSG_ID;
typedef char *              LANG_MSG;
typedef unsigned short int  LANG_MSG_SIZE;
typedef LANG_MSG *          LANG_TABLE;

typedef uint8_t NICK_LANG_ID;


/*********************************************************
 * Constants                                             *
 *********************************************************/


#define LANG_VERS_A1    (LANG_VERSION) 1


/* ID lingue */

#define LANG_IT     (LANG_ID) 0
#define LANG_US     (LANG_ID) 1
#define LANG_ES     (LANG_ID) 2
#define LANG_FR     (LANG_ID) 3
#define LANG_DE     (LANG_ID) 4
#define LANG_JP     (LANG_ID) 5

#define LANG_INVALID    (LANG_ID) (-1)

#define LANG_FIRST  LANG_IT
#define LANG_LAST   LANG_JP
#define LANG_COUNT  6

#define LANG_DEFAULT    LANG_US

#endif /* DBCONV_LANG_H */
