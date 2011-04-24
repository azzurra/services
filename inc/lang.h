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

#ifndef SRV_LANG_H
#define SRV_LANG_H


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef unsigned int		LANG_VERSION;
typedef unsigned int		LANG_ID;
typedef LANG_ID				LANG_MSG_ID;
typedef STR					LANG_MSG;
typedef unsigned short int	LANG_MSG_SIZE;
typedef LANG_MSG *			LANG_TABLE;


typedef unsigned char	NICK_LANG_ID;


typedef struct lang_item {

	unsigned int		flags;
	time_t				time_loaded;
	time_t				time_created;
	STR					lang_name_loc; /* nome della lingua */
	STR					lang_name_eng; /* nome della lingua in inglese */
	char				lang_short_name[3]; /* sigla della lingua (eg: IT, US, FR) */
	unsigned long int	memory_size;	
	LANG_TABLE			msgs;
	char				news_path[30];
	size_t				news_size;

} LANG_ITEM;

/* LANG_ITEM.flags */

/* Lingua non utilizzata */
#define LIF_UNUSED			0x0000

/* Caricare all'avvio */
#define LIF_LOAD_START		0x0001
/* Caricare alla prima richiesta */
#define LIF_LOAD_DEFERRED	0x0002

/* Non scaricare dalla memoria */
#define LIF_HOLD			0x0010
/* Scaricare dalla memoria se non utilizzata per un certo periodo */
#define LIF_UNLOAD			0x0020

/* Lingua caricata */
#define LIF_LOADED			0x1000
/* Lingua non disponibile al momento, usare la lingua di default */
#define LIF_OFFLINE			0x2000


#define LIF_STANDARD		LIF_LOAD_START | LIF_HOLD
#define LIF_SAVEMEM			LIF_LOAD_DEFERRED | LIF_UNLOAD
#define LIF_DONTLOAD		LIF_UNUSED | LIF_OFFLINE


typedef struct lang_file_header {

	LANG_VERSION		version;
	LANG_ID				lang_id;
	time_t				created;
	unsigned int		standard_flags;
	unsigned int		message_count;
	char				lang_short_name[3];
	LANG_MSG_SIZE		name_loc_size;
	LANG_MSG_SIZE		name_eng_size;
	unsigned long int	signature;

} LANG_FILE_HEADER;

typedef struct lang_file_msg_header {

	LANG_MSG_ID		id;
	LANG_MSG_SIZE	size;

} LANG_FILE_MSG_HEADER;


#ifdef MAKE_LANG_COMPILER
typedef struct _user	User;
#endif


/*********************************************************
 * Constants                                             *
 *********************************************************/


#define	LANG_VERS_A1	(LANG_VERSION) 1


/* ID lingue */

#define	LANG_IT		(LANG_ID) 0
#define LANG_US		(LANG_ID) 1
#define LANG_ES		(LANG_ID) 2
#define LANG_FR		(LANG_ID) 3
#define LANG_DE		(LANG_ID) 4
#define LANG_JP		(LANG_ID) 5

#define LANG_INVALID	(LANG_ID) (-1)

#define LANG_FIRST	LANG_IT
#define LANG_LAST	LANG_JP
#define LANG_COUNT	6

#define LANG_DEFAULT	LANG_US


/* ID messaggi */

#ifndef MAKE_LANG_COMPILER
#include "lang_msg.h"
#endif


#define TABLE_UNLOAD_TIME	10000 /* BHO */


/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern LANG_ID			current_caller_lang;




/*********************************************************
 * Global code                                           *
 *********************************************************/

extern BOOL					lang_load_conf(void);
extern void					lang_start(void);
extern void					lang_unload_all(void);
extern BOOL					lang_reload(LANG_ID lang_id);
extern const LANG_MSG		lang_msg(LANG_ID lang_id, LANG_MSG_ID msg_id);
extern void					lang_check_unload(void);
extern BOOL					lang_check_data_files(void);

extern LANG_ID				lang_lookup_langid(CSTR lang_short_name);
BOOL						lang_is_active_language(LANG_ID lang_id);
#define						lang_is_valid_language(lang_id)	(BOOL)(((lang_id) >= LANG_FIRST) && ((lang_id) <= LANG_LAST))


extern unsigned int			lang_get_flags(LANG_ID lang_id);
extern void					lang_set_flags(LANG_ID lang_id, int add, unsigned int flags);
extern CSTR					lang_get_name(LANG_ID lang_id, int locale);
extern CSTR					lang_get_shortname(LANG_ID lang_id);
extern CSTR					lang_get_name_traslated(LANG_ID user_lang_id, LANG_ID language_lang_id);

extern int					lang_format_time(STR buffer, size_t bufferSize, LANG_ID lang_id, LANG_MSG_ID format_id, const struct tm *tm);
extern int					lang_format_localtime(STR buffer, size_t bufferSize, LANG_ID lang_id, LANG_MSG_ID format_id, time_t c_time);
extern void					handle_lang(CSTR source, User *callerUser, ServiceCommandData *data);
extern void					lang_send_list(CSTR source, const User *dest);

extern unsigned long int	lang_mem_report(CSTR sourceNick, const User *callerUser);


#define			EXTRACT_LANG_ID(nick_lid)	( (LANG_ID) (nick_lid) )
#define			COMPACT_LANG_ID(lid)		( (NICK_LANG_ID) (lid & 0xFF) )


/* recupera il LANG_ID utilizzato dal nick indicato */
#define			GetNickLang(nick)		(nick ? EXTRACT_LANG_ID(nick->langID) : LANG_DEFAULT)

/*  recupera il LANG_ID utilizzato dall'eventuale nick registrato avente il nome indicato (o LANG_DEFAULT) */
extern LANG_ID	FindNickLang(CSTR nickname, const User *user);

#define			FindCallerLang_ByNick(nick)				(current_caller_lang = (nick ? EXTRACT_LANG_ID(nick->langID) : LANG_DEFAULT))
#define			FindCallerLang_ByName(nickname, user)	(current_caller_lang = FindNickLang((nickname), (user)) )

extern void		rehash_news(void);
extern BOOL		lang_get_news(const LANG_ID lang_id);
extern BOOL		lang_send_news(const User *callerUser);

/* Ricerca del LANG_ID utilizzato dal chiamente. Usare GetCallerLang() per utilizzarlo. */
#define			GetCallerLang()						(current_caller_lang)

/* Imposta il linguaggio corrente a quello usato dall'user chiamante. */
#define			SetCallerLang(lang_id)				(current_caller_lang = (lang_id))

#define			LangFromRegionID(region_id)		( (LANG_ID)(region_id) )

#endif /* SRV_LANG_H */
