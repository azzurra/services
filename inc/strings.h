/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* version.h - common text strings include
* 
*/


#ifndef SRV_STRINGS_H
#define SRV_STRINGS_H


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef		char			CHAR;
typedef		const char		CCHAR;

typedef		char *			STR;
typedef		const char *	CSTR;

typedef		CCHAR			STDCHR;
typedef		CSTR			STDSTR;

typedef		int				STDVAL;


typedef struct _Creator {

	STR			name;
	time_t		time;

} Creator;


typedef struct _CreationInfo {

	Creator		creator;
	STR			reason;

} CreationInfo;


typedef struct	_SettingsInfo	SettingsInfo;
struct _SettingsInfo {

	SettingsInfo		*next;

	CreationInfo		creation;
	unsigned long int	type;
};


/*********************************************************
 * Global variables                                      *
 *********************************************************/

/* Caratteri generici */
extern STDCHR	c_NULL;
extern STDCHR	c_SPACE;
extern STDCHR	c_DOT;
extern STDCHR	c_COMMA;
extern STDCHR	c_COLON;
extern STDCHR	c_QUESTION;
extern STDCHR	c_EXCLAM;
extern STDCHR	c_STAR;
extern STDCHR	c_SHARP;
extern STDCHR	c_AMP;
extern STDCHR	c_AT;
extern STDCHR	c_PLUS;
extern STDCHR	c_MINUS;
extern STDCHR	c_BOLD;
extern STDCHR	c_CR;
extern STDCHR	c_LF;
extern STDCHR	c_EQUAL;
extern STDCHR	c_SLASH;

/* Stringhe generiche */
extern STDSTR	s_NULL;
extern STDSTR	s_SPACE;
extern STDSTR	s_DOT;
extern STDSTR	s_COMMA;
extern STDSTR	s_COLON;
extern STDSTR	s_QUESTION;
extern STDSTR	s_EXCLAM;
extern STDSTR	s_STAR;
extern STDSTR	s_SHARP;
extern STDSTR	s_AMP;
extern STDSTR	s_AT;
extern STDSTR	s_PLUS;
extern STDSTR	s_MINUS;
extern STDSTR	s_EQUAL;
extern STDSTR	s_SLASH;
extern STDSTR	s_BOLD;
extern STDSTR	s_CR;
extern STDSTR	s_LF;

extern STDSTR	s_YES;
extern STDSTR	s_NO;
extern STDSTR	s_ON;
extern STDSTR	s_OFF;
extern STDSTR	s_ENABLE;
extern STDSTR	s_DISABLE;
extern STDSTR	s_ENABLED;
extern STDSTR	s_DISABLED;

extern STDSTR	s_TODAY;

extern STDSTR	s_OPENMODE_READONLY;
extern STDSTR	s_OPENMODE_WRITEONLY;
extern STDSTR	s_OPENMODE_APPEND;


/* Oper levels names */
extern STDSTR	s_OPER_MASTER;
extern STDSTR	s_OPER_CODER;
extern STDSTR	s_OPER_SRA;
extern STDSTR	s_OPER_SA;
extern STDSTR	s_OPER_SOP;
extern STDSTR	s_OPER_HOP_OPER;
extern STDSTR	s_OPER_HOP;
extern STDSTR	s_OPER_OPER;

extern STDSTR	s_OPER_CMD_LEVEL_MASTER;
extern STDSTR	s_OPER_CMD_LEVEL_CODER;
extern STDSTR	s_OPER_CMD_LEVEL_SRA;
extern STDSTR	s_OPER_CMD_LEVEL_SA;
extern STDSTR	s_OPER_CMD_LEVEL_SOP;
extern STDSTR	s_OPER_CMD_LEVEL_HOP;
extern STDSTR	s_OPER_CMD_LEVEL_IRCOP;


/* Logging */
extern STDSTR	s_LOG_NULL;
extern STDSTR	s_LOG_INVALID;
extern STDSTR	s_LOG_EMPTY;

extern STDSTR	s_LOG_ERR_PARAMETER;


/* Errori */
extern STDSTR	s_ERR_OUT_OF_MEMORY;


/* Utility */
#define	STDVAL_UNK			(STDVAL) 0
#define	STDVAL_YES			(STDVAL) 1
#define	STDVAL_NO 			(STDVAL) 2
#define	STDVAL_ON 			(STDVAL) 3
#define	STDVAL_OFF			(STDVAL) 4
#define	STDVAL_ENABLE		(STDVAL) 5
#define	STDVAL_DISABLE		(STDVAL) 6
#define	STDVAL_ENABLED		STDVAL_ENABLE
#define	STDVAL_DISABLED		STDVAL_DISABLE
#define	STDVAL_BLOCK		(STDVAL) 7
#define	STDVAL_DONTBLOCK	(STDVAL) 8


/* str_char_tolower() / str_char_toupper() support */
extern const unsigned char _tolower_table[];
extern const unsigned char _toupper_table[];


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern STDVAL	str_parse_standard_value(CSTR value);

extern __inline__ CSTR str_get_valid_display_value(CSTR string);

extern STR str_replace(STR string, size_t size, CSTR find, CSTR replace);
/* extern STR str_tokenize(CSTR string, STR token, size_t token_len, CSTR delimiters); */
extern STR str_tokenize(CSTR string, STR token, size_t token_len, char delimiter);
extern STR str_compact(STR string);


/* RTL srings functions */

#define str_char_tolower(ch)	((unsigned int)_tolower_table[(const unsigned int)(const unsigned char)(ch)])
#define str_char_toupper(ch)	((unsigned int)_toupper_table[(const unsigned int)(const unsigned char)(ch)])

extern STR str_toupper(STR string);
extern STR str_tolower(STR string);

extern size_t str_len(CSTR string);
extern size_t str_count(CSTR string, int c);
extern BOOL str_spn(CSTR string, CSTR charset);

/*	Copia al massimo 'bufferSize' - 1 caratteri dalla stringa 'source' in 'buffer' 
	inserendo sempre il null-terminator come ultimo carattere. */
extern size_t str_copy_checked(CSTR source, STR buffer, size_t bufferSize);

/*  Aggiunge al massimo 'bufferFreeSpace' - 1 caratteri della stringa 'append' a 'buffer'
	inserendo sempre il null-terminator come ultimo carattere. 
	
	Restituisce il numero di caratteri aggiunti. Utilizzarlo per decrementare 'bufferFreeSpace'. 
	0 indica che non c'e' piu' spazio disponibile in 'buffer'. */
extern size_t str_append_checked(CSTR append, STR buffer, size_t bufferFreeSpace);

extern STR str_duplicate(CSTR string);

extern int str_compare(CSTR string1, CSTR string2);
extern int str_compare_nocase(CSTR string1, CSTR string2);
extern int str_compare_partial(CSTR string1, CSTR string2, size_t len);

#define	str_equals(string1, string2)					(str_compare((string1), (string2)) == 0)
#define	str_equals_nocase(string1, string2)				(str_compare_nocase((string1), (string2)) == 0)
#define	str_equals_partial(string1, string2, len)		(str_compare_partial((string1), (string2), (len)) == 0)
#define	str_not_equals(string1, string2)				(str_compare((string1), (string2)) != 0)
#define	str_not_equals_nocase(string1, string2)			(str_compare_nocase((string1), (string2)) != 0)
#define	str_not_equals_partial(string1, string2, len)	(str_compare_partial((string1), (string2), (len)) != 0)


/* String matching functions */
extern __inline__ BOOL str_match_wild(CSTR pattern, CSTR string);
extern __inline__ BOOL str_match_wild_nocase(CSTR pattern, CSTR string);
extern __inline__ BOOL str_match_everything(CSTR string);

/* "Creator" support
   Riempie i campi della struttura passata:
	name : se NULL il campo relativo non viene modificato altrimenti viene impostato al valore indicato (via str_duplicate())
	time : se 0 il campo relativo viene impostato all'ora corrente altrimenti a quanto indicato
*/
extern void str_creator_init(Creator *creator);
extern BOOL str_creator_set(Creator *creator, CSTR name, time_t time_set);
extern __inline__ void str_creator_free(Creator *creator);

extern void str_creationinfo_init(CreationInfo *info);
extern BOOL str_creationinfo_set(CreationInfo *info, CSTR creator, CSTR reason, time_t time_set);
extern __inline__ void str_creationinfo_free(CreationInfo *info);

extern BOOL str_settingsinfo_add(SettingsInfo **infoList, unsigned long int type, CSTR creator, CSTR reason);
extern BOOL str_settingsinfo_remove(SettingsInfo **infoList, unsigned long int type);

#endif /* SRV_STRINGS_H */
