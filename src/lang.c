/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* lang.c - Supporto multi-lingua
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/logging.h"
#include "../inc/memory.h"
#include "../inc/send.h"
#include "../inc/conf.h"
#include "../inc/lang.h"
#include "../inc/main.h"


/********************************************************
* Global variables                                      *
*********************************************************/

// linguaggio utilizzato dall'utente corrente
LANG_ID		current_caller_lang;

#ifndef LANG_FILE_SIGNATURE
#define LANG_FILE_SIGNATURE	0x123456
#endif


/********************************************************
* Local variables                                       *
*********************************************************/

#if defined USE_SERVICES
	#define CLNG_FILE_FORMAT	"lang/svc%d.clng"
#elif defined USE_STATS
	#define CLNG_FILE_FORMAT	"lang/sts%d.clng"
#elif defined USE_SOCKSMONITOR
	#define CLNG_FILE_FORMAT	"lang/cyb%d.clng"
#endif


// Tabella lingue

static LANG_ITEM lang_tables[LANG_COUNT] = {
	
	/* LANG_IT */ { LIF_UNUSED, 0, 0, NULL, NULL, "IT", 0, NULL, "", 0 },
	/* LANG_US */ { LIF_UNUSED, 0, 0, NULL, NULL, "US", 0, NULL, "", 0 },
	/* LANG_ES */ { LIF_UNUSED, 0, 0, NULL, NULL, "ES", 0, NULL, "", 0 },
	/* LANG_FR */ { LIF_UNUSED, 0, 0, NULL, NULL, "FR", 0, NULL, "", 0 },
	/* LANG_DE */ { LIF_UNUSED, 0, 0, NULL, NULL, "DE", 0, NULL, "", 0 },
	/* LANG_JP */ { LIF_UNUSED, 0, 0, NULL, NULL, "JP", 0, NULL, "", 0 }
};

static CSTR	lang_names[LANG_COUNT][LANG_COUNT] = {
	
	{
	/* LANG_IT */
		/*  IT */ "Italiano",
		/*  US */ "Inglese",
		/*  ES */ "Spagnolo",
		/*  FR */ "Francese",
		/*  DE */ "Tedesco",
		/*  JP */ "Giapponese"
	},

	{
	/* LANG_US */ 
		/*  IT */ "Italian",
		/*  US */ "English",
		/*  ES */ "Spanish",
		/*  FR */ "French",
		/*  DE */ "Deutsch",
		/*  JP */ "Japanese"
	},

	{
	/* LANG_ES */
		/*  IT */ "Italiano",
		/*  US */ "Inglés",
		/*  ES */ "Español",
		/*  FR */ "Francés",
		/*  DE */ "Alemán",
		/*  JP */ "Japonés"
	},

	{
	/* LANG_FR */ 
		/*  IT */ "Italien",
		/*  US */ "Anglais",
		/*  ES */ "Espagnol",
		/*  FR */ "Francais",
		/*  DE */ "Allemand",
		/*  JP */ "Japonais"
	},

	{
	/* LANG_DE */ 
		/*  IT */ "Italienisch",
		/*  US */ "Englisch",
		/*  ES */ "Spanisch",
		/*  FR */ "Franzosisch",
		/*  DE */ "Deutsch",
		/*  JP */ "Japanisch"
	},

	{
	/* LANG_JP */ /* FIX */
		/*  IT */ "Italiano",
		/*  US */ "Inglese",
		/*  ES */ "Spagnolo",
		/*  FR */ "Francese",
		/*  DE */ "Tedesco",
		/*  JP */ "Giapponese"
	}
};


static char		lang_not_loaded[]		= "Message table not loaded";
static char		lang_load_error[]		= "Unable to load message table";
static char		lang_not_valid[]		= "Not a valid language";
static char		lang_not_valid_short[]	= "??";
static char		lang_msg_not_valid[]	= "Not a valid message";


static unsigned int			lang_loaded_count;
static unsigned long int	lang_memory_commit;


static int					lang_load(LANG_ID lang_id);
static void					lang_unload(LANG_ID lang_id);
static LANG_ITEM 			*lang_get_table(LANG_ID lang_id);


#define	LANG_CONF_FILE	"../lang.conf"


/*********************************************************
 * Private code                                          *
 *********************************************************/

static LANG_ITEM *lang_get_table(LANG_ID lang_id) {
	
	TRACE_FCLT(FACILITY_LANG_GET_TABLE);
	
	if (lang_is_valid_language(lang_id))
		return &lang_tables[lang_id];
	else 
		return NULL;
}


BOOL conf_get_valid_line(FILE *file, STR buffer, size_t bufferSize, int *lineNum) {

	TRACE_FCLT(FACILITY_LANG_CONF_GET_VALID_LINE);

	if (IS_NOT_NULL(file) && IS_NOT_NULL(buffer)) {

		STR		ptr;
		char	first;

		TRACE();

		do {

			if (IS_NULL(fgets(buffer, bufferSize, file)))
				return FALSE;

			if (IS_NOT_NULL(lineNum))
				*lineNum = *lineNum + 1;

			TRACE();
			first = buffer[0];

		} while ((first == c_SHARP) || (first == c_LF) || (first == c_CR));

		TRACE();
		// eliminazione del \n finale
		ptr = buffer + str_len(buffer) - 1;

		if ((*ptr == c_LF) || (*ptr == c_CR))
			*ptr = c_NULL;

		return TRUE;
	}
	else {

		log_error(FACILITY_CONF, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_PROPAGATED,
			 s_LOG_ERR_PARAMETER, "conf_get_valid_line()", s_LOG_NULL, IS_NULL(file) ? "file" : "buffer");

		return FALSE;
	}
}


BOOL lang_load_conf(void) {

	FILE	*conf;

	/*
	# Formato:
	# ADDLANG SIGLA START|DEFERRED HOLD|UNLOAD
	*/

	TRACE_FCLT(FACILITY_LANG_LOAD_CONF);

	conf = fopen(LANG_CONF_FILE, s_OPENMODE_READONLY);

	if (IS_NOT_NULL(conf)) {

		char			buffer[64];
		STR				param[4];
		int				i, lineNum;
		BOOL			errors;

		LANG_ITEM		*table;
		LANG_ID			lang_id;
		unsigned int	flags;


		TRACE();
		for (lang_id = LANG_FIRST; lang_id <= LANG_LAST; lang_id++)
			lang_tables[lang_id].flags = LIF_UNUSED;

		lineNum = 0;
		errors = FALSE;

		while (feof(conf) == 0) {

			if (conf_get_valid_line(conf, buffer, sizeof(buffer), &lineNum)) {

				TRACE();

				// divisione della linea letta

				i = 0;
				param[i] = strtok(buffer, " \n\r\t");

				while ((i < 3) && IS_NOT_NULL(param[i])) {

					++i;
					param[i] = strtok(NULL, " \n\r\t");
				}

				++i;

				if (i != 4) {

					log_error(FACILITY_LANG_LOAD_CONF, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_HALTED,
						"LANG: lang_load_conf(): \2Syntax error\2 on line %d : only %d parameter present", lineNum, i);

					errors = TRUE;
					break;
				}

				TRACE();
				// param 1: e' "ADDLANG" ?

				if (str_not_equals_nocase(param[0], "ADDLANG")) {

					log_error(FACILITY_LANG_LOAD_CONF, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_HALTED,
						"LANG: lang_load_conf(): \2Invalid syntax\2 on line %d : ADDLANG non present", lineNum);

					errors = TRUE;
					break;
				}
				
				TRACE();
				// param 2: sigla corretta ?
				
				lang_id = lang_lookup_langid(param[1]);
				
				if (lang_id == LANG_INVALID) {

					log_error(FACILITY_LANG_LOAD_CONF, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_HALTED,
						"LANG: lang_load_conf(): \2Invalid language\2 on line %d : \2%s\2", lineNum, param[1]);

					errors = TRUE;
					break;
				}

				TRACE();
				// param 3: metodo di caricamento

				flags = 0;

				if (str_equals_nocase(param[2], "START"))
					AddFlag(flags, LIF_LOAD_START);

				else if (str_equals_nocase(param[2], "DEFERRED"))
					AddFlag(flags, LIF_LOAD_DEFERRED);

				else {

					log_error(FACILITY_LANG_LOAD_CONF, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_HALTED,
						"LANG: lang_load_conf(): \2Invalid load-type flag\2 on line %d : \2%s\2", lineNum, param[2]);

					errors = TRUE;
					break;
				}

				TRACE();
				// param 4: metodo di scaricamento

				if (str_equals_nocase(param[3], "HOLD"))
					AddFlag(flags, LIF_HOLD);

				else if (str_equals_nocase(param[3], "UNLOAD"))
					AddFlag(flags, LIF_UNLOAD);

				else {

					log_error(FACILITY_LANG_LOAD_CONF, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_HALTED,
						"LANG: lang_load_conf(): \2Invalid unload-type flag\2 on line %d : \2-%s-\2", lineNum, param[3]);

					errors = TRUE;
					break;
				}

				TRACE();
				// parametri ok, aggiornare la tabella corrispondente

				table = lang_get_table(lang_id);
				table->flags = flags;
			}
			else
				break;
		} // while

		fclose(conf);

		return (errors == FALSE);

	} else {

		log_error(FACILITY_LANG, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_PROPAGATED,
			"lang_load_conf() - unable to open configuration file (%s)", LANG_CONF_FILE);

		return FALSE;
	}
}


BOOL lang_check_data_file(LANG_ID lang_id) {

	char				filename[24];
	LANG_FILE_HEADER	header;
	FILE				*f;


	header.signature = 0;

	// siamo gia' in ./data/
	snprintf(filename, sizeof(filename), CLNG_FILE_FORMAT, lang_id);
	f = fopen(filename, s_OPENMODE_READONLY);

	if (IS_NOT_NULL(f)) {

		if (fread(&header, sizeof(header), 1, f) != 1)
			header.signature = 0;

		fclose(f);
	}

	return (header.signature == LANG_FILE_SIGNATURE);
}


static BOOL lang_load(LANG_ID lang_id) {

	LANG_ITEM 	*table;
	int			errors = 0;


	TRACE_FCLT(FACILITY_LANG_LOAD);

	TRACE();
	table = lang_get_table(lang_id);

	if (IS_NULL(table))
		return FALSE;

	table->memory_size = 0;

	table->msgs = mem_calloc(LANG_MSG_COUNT, sizeof(LANG_MSG));

	if (IS_NOT_NULL(table->msgs)) {

		// tabella allocata, caricare i messaggi

		char				filename[24];
		LANG_FILE_HEADER	header;
		FILE				*f;

		TRACE();
		table->memory_size += LANG_MSG_COUNT * sizeof(LANG_MSG);

		// siamo gia' in ./data/
		snprintf(filename, sizeof(filename), CLNG_FILE_FORMAT, lang_id);
		f = fopen(filename, s_OPENMODE_READONLY);

		if (IS_NOT_NULL(f)) {

			unsigned int	idx;

			TRACE();
			// lettura header

			if (fread(&header, sizeof(header), 1, f) == 1) {

				TRACE();
				// header caricato
				/*
				if (header.signature != LANG_FILE_SIGNATURE) {

					send_globops(NULL, "\2ERROR\2: invalid signature found loading language %s", table->lang_short_name);
					log_error(FACILITY_LANG, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_WARNING,
						"invalid signature found loading language %s", table->lang_short_name);

					mem_free(table->msgs);
					table->msgs = NULL;
					table->memory_size -= LANG_MSG_COUNT * sizeof(LANG_MSG);

					return FALSE; // error
				}
				*/
				// file ok ...

				AddFlag(table->flags, header.standard_flags);

				table->time_loaded = time(NULL);
				table->time_created = header.created;
				table->lang_name_loc = mem_calloc(header.name_loc_size + 1, sizeof(char));
				table->lang_name_eng = mem_calloc(header.name_eng_size + 1, sizeof(char));
				str_copy_checked(header.lang_short_name, table->lang_short_name, sizeof(table->lang_short_name));

				if (IS_NULL(table->lang_name_loc) || IS_NULL(table->lang_name_eng)) {

					mem_free(table->lang_name_loc);
					mem_free(table->lang_name_eng);
				}
				else {

					table->memory_size += sizeof(char) * (header.name_loc_size + header.name_eng_size + 2);

					if (fread(table->lang_name_loc, header.name_loc_size, 1, f) &&
						fread(table->lang_name_eng, header.name_eng_size, 1, f)) {

						LANG_FILE_MSG_HEADER	msgheader;
						LANG_MSG			msg;
						unsigned int		len;

						TRACE();
						// caricamento messaggi
						for (idx = 0; idx < header.message_count; idx++) {
							// lettura header messaggio
							if (fread(&msgheader, sizeof(msgheader), 1, f)) {

								if ((msgheader.id >= LANG_MSG_FIRST) &&
									(msgheader.id <= LANG_MSG_LAST)) {

									// lettura messaggio
									len = sizeof(char) * (msgheader.size + 1);
									msg = mem_calloc(1, len);

									if (IS_NOT_NULL(msg)) {

										if (fread(msg, len - 1, 1, f)) {

											table->msgs[msgheader.id] = msg;
											table->memory_size += len;
										}
										else {

											LOG_DEBUG_SNOOP("lang_load() not fread!");

											mem_free(msg);
											errors++;
											break;
										}
									}
									else {

										LOG_DEBUG_SNOOP("lang_load() msg is null!");

										errors++;
										break;
									}
								}
								else {

									LOG_DEBUG_SNOOP("lang_load() invalid id! %d", msgheader.id);
									continue; // il messaggio non e' previsto, saltarlo
								}
							}
							else {

								LOG_DEBUG_SNOOP("lang_load() not fread msgheader!");

								++errors;
								break; // errore
							}
						}
					}
				}			
			}

			TRACE();
			fclose(f);

			lang_loaded_count++;
			lang_memory_commit += table->memory_size;			
			AddFlag(table->flags, LIF_LOADED);

			if (errors) {

				send_globops(NULL, "\2WARNING\2: errors found loading language %s", table->lang_short_name);
				log_error(FACILITY_LANG, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_WARNING,
					"errors found loading language %s", table->lang_short_name);
			}

			return TRUE; // messaggi caricati
		}

		// fall in error ..
		//send_globops(NULL, "Errori nel caricamento della lingua %d !", lang_id);

		TRACE();
		mem_free(table->msgs);
		table->msgs = NULL;
		table->memory_size -= LANG_MSG_COUNT * sizeof(LANG_MSG);
	}

	TRACE();
	return FALSE; // error
}


static void lang_unload(LANG_ID lang_id) {

	LANG_ITEM	*table;
	int			idx;


	TRACE_FCLT(FACILITY_LANG_UNLOAD);

	table = lang_get_table(lang_id);
	if (IS_NULL(table) || IS_NULL(table->msgs))
		return;

	TRACE();
	for (idx = 0; idx < LANG_MSG_COUNT; ++idx)
		mem_free(table->msgs[idx]);

	lang_memory_commit -= table->memory_size;

	mem_free(table->msgs);
	mem_free(table->lang_name_loc);
	mem_free(table->lang_name_eng);	

	TRACE();

	table->msgs = NULL;
	table->lang_name_loc = NULL;
	table->lang_name_eng = NULL;
	table->time_loaded = 0;	
	RemoveFlag(table->flags, LIF_LOADED);
}


/********************************************************
* Public code                                           *
*********************************************************/

unsigned long lang_mem_report(CSTR sourceNick, const User *callerUser) {

	int		i;

	TRACE_FCLT(FACILITY_LANG_GET_STATS);

	send_notice_to_user(sourceNick, callerUser, "\2Multi-language support\2:");
	send_notice_to_user(sourceNick, callerUser, "Language loaded: \2%d\2 -> \2%d\2 KB (\2%d\2 B)", lang_loaded_count, lang_memory_commit / 1024, lang_memory_commit);

	for (i = 0; i < LANG_COUNT; i++) {

		if (FlagSet(lang_tables[i].flags, LIF_LOADED))
			send_notice_to_user(sourceNick, callerUser, "%d) %s : \2%d\2 KB (\2%d\2 B)", i + 1, lang_tables[i].lang_name_loc, lang_tables[i].memory_size / 1024, lang_tables[i].memory_size);
	}

	return lang_memory_commit;
}

LANG_ID lang_lookup_langid(CSTR lang_short_name) {

	TRACE_FCLT(FACILITY_LANG_LOOKUP_LANGID);

	if (IS_NULL(lang_short_name) || IS_EMPTY_STR(lang_short_name))
		log_error(FACILITY_LANG, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_PROPAGATED,
			s_LOG_ERR_PARAMETER, "lang_lookup_langid()", s_LOG_NULL, "lang_short_name");

	else {

		LANG_ID lang_id;

		for (lang_id = LANG_FIRST; lang_id <= LANG_LAST; lang_id++) {

			if (str_equals_nocase(lang_short_name, lang_tables[lang_id].lang_short_name))
				return lang_id;				
		}
	}

	return LANG_INVALID;
}

BOOL lang_is_active_language(LANG_ID lang_id) {

	LANG_ITEM 	*table;

	table = lang_get_table(lang_id);
	return IS_NOT_NULL(table) ? (table->flags != LIF_UNUSED) && (FlagUnset(table->flags, LIF_OFFLINE)) : FALSE;
}

CSTR lang_get_name(LANG_ID lang_id, int locale) {

	LANG_ITEM 	*table;

	table = lang_get_table(lang_id);
	return (CSTR) (IS_NOT_NULL(table) ? (locale ? table->lang_name_loc : table->lang_name_eng) : lang_not_valid);
}


CSTR lang_get_shortname(LANG_ID lang_id) {

	LANG_ITEM 	*table;

	table = lang_get_table(lang_id);
	return (CSTR) (IS_NOT_NULL(table) ? table->lang_short_name : lang_not_valid_short);
}

CSTR lang_get_name_traslated(LANG_ID user_lang_id, LANG_ID language_lang_id) {

	if (lang_is_valid_language(user_lang_id) && lang_is_valid_language(language_lang_id))
		return lang_names[user_lang_id][language_lang_id];
	else
		return lang_not_valid;
}


const LANG_MSG lang_msg(LANG_ID lang_id, LANG_MSG_ID msg_id) {

	LANG_ITEM 	*table;
	LANG_MSG	msg = NULL;


	TRACE_FCLT(FACILITY_LANG_MSG);

	if ((msg_id < LANG_MSG_FIRST) || (msg_id > LANG_MSG_LAST)) {

		log_error(FACILITY_LANG_MSG, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_PROPAGATED,
			"lang_msg(): message ID %d for language %d (%s) is out of bounds", msg_id, lang_id, lang_get_name(lang_id, FALSE));

		return lang_msg_not_valid;
	}

	table = lang_get_table(lang_id);

	if (IS_NULL(table)) {

		log_error(FACILITY_LANG_MSG, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_PROPAGATED,
			"lang_msg(): requested table for message ID %d in language %d (%s) is empty", msg_id, lang_id, lang_get_name(lang_id, FALSE));

		if (lang_id != LANG_DEFAULT)
			return lang_msg(LANG_DEFAULT, msg_id);

		return lang_not_loaded;
	}

	TRACE();

	if (table->flags != LIF_UNUSED) {

		// lingua non è disattiva o non utilizzata

		// lingua offline ?
		if (FlagSet(table->flags, LIF_OFFLINE)) {

			log_error(FACILITY_LANG_MSG, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_PROPAGATED,
				"lang_msg(): requested table for message ID %d in language %d (%s) is offline", msg_id, lang_id, lang_get_name(lang_id, FALSE));

			if (lang_id != LANG_DEFAULT)
				return lang_msg(LANG_DEFAULT, msg_id);

			return lang_not_loaded;
		}

		// lingua non caricata ?
		if (FlagUnset(table->flags, LIF_LOADED)) {

			// lingua a caricamento posticipato
			if (FlagSet(table->flags, LIF_LOAD_DEFERRED)) {

				if (!lang_load(lang_id))
					return lang_load_error;
				else
					return lang_not_loaded;
			}
		}

		// sanity check
		if (FlagUnset(table->flags, LIF_LOADED)) {

			log_error(FACILITY_LANG_MSG, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_PROPAGATED,
				"lang_msg(): requested table for message ID %d in language %d (%s) is not loaded", msg_id, lang_id, lang_get_name(lang_id, FALSE));

			return lang_not_loaded;
		}

		TRACE();

		// tabella valida ...

		msg = table->msgs[msg_id];

		if (IS_NOT_NULL(msg))
			// messaggio valido
			return msg;

		else {

			log_error(FACILITY_LANG_MSG, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_PROPAGATED,
				"lang_msg(): requested entry with message ID %d in language %d (%s) is empty", msg_id, lang_id, lang_get_name(lang_id, FALSE));

			if (lang_id != LANG_DEFAULT)
				return lang_msg(LANG_DEFAULT, msg_id);

			return lang_msg_not_valid;
		}
	}
	else {

		log_error(FACILITY_LANG_MSG, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_PROPAGATED,
			"lang_msg(): requested language %d (%s) was not loaded (message ID: %d)", lang_id, lang_get_name(lang_id, FALSE), msg_id);

		if (lang_id != LANG_DEFAULT)
			return lang_msg(LANG_DEFAULT, msg_id);

		return lang_not_valid;
	}
}


/*********************************************************
 * Time formats                                          *
 *********************************************************/

static STR*	datetime_strings[LANG_COUNT];

#define DATETIME_STRING_SLOT	36

#define DATETIME_TYPE_MONTH_SHORT	0x01
#define DATETIME_TYPE_MONTH_LONG	0x02
#define DATETIME_TYPE_DAY_SHORT		0x03
#define DATETIME_TYPE_DAY_LONG		0x04


static CSTR lang_get_time_string(LANG_ID lang_id, int type, int value) {

	STR	*dts;
	int	idx;
	unsigned char	offsets[4] = {0, 12, 24, 31};

	if ((type < DATETIME_TYPE_MONTH_SHORT) || (type > DATETIME_TYPE_DAY_LONG))
		return (CSTR) lang_not_valid_short;

	idx = offsets[type - 1] + value;

	if (idx >= DATETIME_STRING_SLOT)
		return (CSTR) lang_not_valid_short;

	dts = datetime_strings[lang_id];

	if (IS_NULL(dts)) {

		LANG_MSG_ID		msg_source[4] = {TIME_MONTHS_SHORT, TIME_MONTHS_LONG, TIME_DAYS_SHORT, TIME_DAYS_LONG};
		STR				msg = NULL, chunk = NULL;

		int	i, si;

		// caricamento dati
		dts = mem_calloc(DATETIME_STRING_SLOT, sizeof(STR));

		for (i = 0, si = 0; (i < DATETIME_STRING_SLOT) && (si < 4); ++i) {

			if (IS_NULL(msg)) {

				msg = lang_msg(lang_id, msg_source[si++]);
				chunk = strtok(msg, " \n");
			}
			else
				chunk = strtok(NULL, " \n");

			if (IS_NOT_NULL(chunk))
				dts[i] = str_duplicate(chunk);

			else {

				msg = NULL;
				--i;
			}
		}

		datetime_strings[lang_id] = dts;
	}

	return (CSTR) dts[idx];
}


/*********************************************************
 * lang_format_(local)time()                             *
 *                                                       *
 * Format a string in a strftime()-like way, but heed    *
 * the user's language setting for month and day names.  *
 * The string stored in the buffer will always be        *
 * null-terminated, even if the actual string was        *
 * longer than the buffer size.                          *
 * Assumption: No month or day name has a length         *
 * (including trailing null) greater than BUFSIZE.       *
 *********************************************************/

int lang_format_time(STR buffer, size_t bufferSize, LANG_ID lang_id, LANG_MSG_ID format_id, const struct tm *tm) {

	char	format_buffer[BUFSIZE];
	size_t 	used;

	if (IS_NULL(tm))
		return 0;

	str_copy_checked(lang_msg(lang_id, format_id), format_buffer, sizeof(format_buffer));

	// %a (TIME_DAYS_SHORT) -> DATETIME_TYPE_DAY_SHORT
	str_replace(format_buffer, sizeof(format_buffer), "%a", lang_get_time_string(lang_id, DATETIME_TYPE_DAY_SHORT, tm->tm_wday));

	// %A (TIME_DAYS_LONG) -> DATETIME_TYPE_DAY_LONG
	str_replace(format_buffer, sizeof(format_buffer), "%A", lang_get_time_string(lang_id, DATETIME_TYPE_DAY_LONG, tm->tm_wday));

	// %b (TIME_MONTHS_SHORT) -> DATETIME_TYPE_MONTH_SHORT
	str_replace(format_buffer, sizeof(format_buffer), "%b", lang_get_time_string(((format_id == TIME_FORMAT_MAILTIME) ? LANG_US : lang_id), DATETIME_TYPE_MONTH_SHORT, tm->tm_mon));

	// %B (TIME_MONTHS_LONG) -> DATETIME_TYPE_MONTH_LONG
	str_replace(format_buffer, sizeof(format_buffer), "%B", lang_get_time_string(lang_id, DATETIME_TYPE_MONTH_LONG, tm->tm_mon));


	used = strftime(buffer, bufferSize, format_buffer, tm);
	
	if (used == bufferSize)
		buffer[bufferSize - 1] = c_NULL;

	return used;
}

int lang_format_localtime(STR buffer, size_t bufferSize, LANG_ID lang_id, LANG_MSG_ID format_id, time_t c_time) {

	struct tm	tm;

	tm = *localtime(&c_time);
	return lang_format_time(buffer, bufferSize, lang_id, format_id, &tm);
}



/*********************************************************
 * Initialization                                        *
 *********************************************************/

BOOL lang_check_data_files(void) {

	LANG_ITEM 	*table;
	LANG_ID		lang_id;

	TRACE_FCLT(FACILITY_LANG_CHECK_FILE);
	for (lang_id = LANG_FIRST; lang_id <= LANG_LAST; lang_id++) {

		TRACE();
		table = &lang_tables[lang_id];
		TRACE();

		if (FlagSet(table->flags, LIF_LOAD_START) && !lang_check_data_file(lang_id)) {

			log_error(FACILITY_LANG_CHECK_FILE, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
				"ERROR: invalid signature found loading language %s", lang_get_shortname(lang_id));

			return FALSE;
		}
	}

	return TRUE;
}

void lang_start(void) {

	LANG_ITEM 		*table;
	LANG_ID			lang_id;
	struct stat		st;


	TRACE_FCLT(FACILITY_LANG_START);

	lang_loaded_count = 0;
	lang_memory_commit = 0;
	current_caller_lang = LANG_DEFAULT;

	TRACE();
	for (lang_id = LANG_FIRST; lang_id <= LANG_LAST; ++lang_id) {

		table = &lang_tables[lang_id];

		if (FlagSet(table->flags, LIF_LOAD_START)) {

			LOG_DEBUG_SNOOP("LANG: automatic loading of language \2%s\2 started...", table->lang_short_name);

			if (!lang_load(lang_id)) {

				TRACE();
				send_globops(NULL, "\2WARNING:\2 Unable to load language \2%s\2. The language is now marked as \2OFFLINE\2.", table->lang_short_name);
				LOG_DEBUG_SNOOP("LANG: lang_start(): error from lang_load() - Language \2%s\2 marked as OFFLINE", table->lang_short_name);

				AddFlag(table->flags, LIF_OFFLINE);
			}
		}

		datetime_strings[lang_id] = NULL;

		/* Initialize news. */

		snprintf(table->news_path, sizeof(table->news_path), "%s/%s/news/news", HELPSERV_DIR, table->lang_short_name);
		str_tolower(table->news_path);

		table->news_size = (stat(table->news_path, &st) == 0) ? st.st_size : 0;
	} 
}


void lang_unload_all(void) {
	
	LANG_ITEM 	*table;
	LANG_ID		lang_id;
	
	TRACE_FCLT(FACILITY_LANG_UNLOAD_ALL);

	for (lang_id = LANG_FIRST; lang_id <= LANG_LAST; lang_id++) {

		table = &lang_tables[lang_id];

		TRACE();

		if (FlagSet(table->flags, LIF_LOADED))
			lang_unload(lang_id);
	} 
}

BOOL lang_reload(LANG_ID lang_id) {

	LANG_ITEM	*table;
	CSTR		lang_name;


	TRACE_FCLT(FACILITY_LANG_RELOAD);

	lang_name = lang_get_shortname(lang_id);
	LOG_DEBUG_SNOOP("Reloading language \2%s\2 (%d) ...", lang_name, lang_id);

	if (!lang_check_data_file(lang_id)) {

		LOG_DEBUG_SNOOP("\2ERROR:\2 Invalid signature or file not found : \2%s\2 (%d). Reload interrupted.", lang_name, lang_id);
		return FALSE;
	}

	table = lang_get_table(lang_id);
	if (IS_NULL(table))
		LOG_DEBUG_SNOOP("Reload of language \2%s\2 failed: invalid LANG ID", lang_name);

	else {

		TRACE();
		if (FlagSet(table->flags, LIF_LOADED)) {
			LOG_DEBUG_SNOOP("Unloading language (\2%d\2 B) ...", table->memory_size);
			TRACE();
			lang_unload(lang_id);
		}

		TRACE();
		if (lang_load(lang_id)) {
			LOG_DEBUG_SNOOP("Language loaded (\2%d\2 B)", table->memory_size);
			return TRUE;
		} else {
			LOG_DEBUG_SNOOP("Reload of language \2%s\2 failed: lang_load() failed!", lang_name);
			send_globops(NULL, "\2WARNING:\2 Reload of language \2%s\2 failed.", lang_name);
			// fall...
		}
	}

	return FALSE;
}


unsigned int lang_get_flags(LANG_ID lang_id) {
	
	LANG_ITEM	*table;
	
	table = lang_get_table(lang_id);
	return IS_NOT_NULL(table) ? table->flags : 0;
}


void lang_set_flags(LANG_ID lang_id, int add, unsigned int flags) {
	
	LANG_ITEM	*table;
	
	table = lang_get_table(lang_id);

	if (IS_NOT_NULL(table)) {
	
		if (add)
			AddFlag(table->flags, flags);
		else
			RemoveFlag(table->flags, flags);
	}
}

#ifdef USE_SERVICES
LANG_ID FindNickLang(CSTR nickname, const User *user) {
	
	if (IS_NOT_NULL(nickname) && IS_NOT_NULL(user)) {

		NickInfo	*ni;


		if (IS_NULL(ni = findnick(nickname)))
			return LANG_DEFAULT;

		if (user_is_identified_to(user, nickname))
			return GetNickLang(ni);
		else
			return (user->current_lang);
	}

	return LANG_DEFAULT;
}

void rehash_news() {

	LANG_ITEM 		*table;
	LANG_ID			lang_id;
	struct stat		st;

	for (lang_id = LANG_FIRST; lang_id <= LANG_LAST; ++lang_id) {

		table = &lang_tables[lang_id];

		if (stat(table->news_path, &st) == 0) {

			if (table->news_size != (size_t)(st.st_size)) {

				table->news_size = (size_t)(st.st_size);

				if ((size_t)(st.st_size) > 0)
					nickserv_update_news(lang_id);
			}
		}
		else if (errno != ENOENT)
			log_error(FACILITY_LANG, __LINE__, LOG_TYPE_ERROR_RTL, LOG_SEVERITY_ERROR_SKIPPED,
				"rehash_news() - unable to stat() news file (%s)", table->news_path);
	}
}

BOOL lang_get_news(const LANG_ID lang_id) {

	LANG_ITEM *table = &lang_tables[lang_id];

	return (table->news_size > 0);
}

BOOL lang_send_news(const User *callerUser) {

	/* Note: MemoServ ensures callerUser->ni is non-NULL. */
	LANG_ID lang_id = GetNickLang(callerUser->ni);
	char	buffer[IRCBUFSIZE], *line;
	FILE	*f;

	if ((f = fopen(lang_tables[lang_id].news_path, "r"))) {

		send_notice_lang_to_user(s_MemoServ, callerUser, lang_id, MS_NEWS_HEADER, CONF_NETWORK_NAME);

		while (fgets(buffer, sizeof(buffer), f)) {

			line = strtok(buffer, "\n");
			send_notice_to_user(s_MemoServ, callerUser, "%s", line ? line : " ");
		}

		TRACE_MAIN();
		send_notice_lang_to_user(s_MemoServ, callerUser, lang_id, MS_NEWS_END_OF_NEWS);
		fclose(f);
		return TRUE;
	}

	return FALSE;
}
#endif

void lang_send_list(CSTR source, const User *dest) {

	LANG_ITEM 	*table;
	LANG_ID		lang_id;

	TRACE_FCLT(FACILITY_LANG_SEND_LIST);
	
	if (IS_NULL(source) || IS_EMPTY_STR(source) || IS_NULL(dest))
		return;

	send_notice_lang_to_user(source, dest, GetCallerLang(), LANG_LIST_HEADER);

	for (lang_id = LANG_FIRST; lang_id <= LANG_LAST; lang_id++) {

		table = &lang_tables[lang_id];

		TRACE();
		if (FlagSet(table->flags, LIF_LOADED | LIF_LOAD_DEFERRED))
			send_notice_to_user(source, dest, "%d) %s (%s)", lang_id+1, table->lang_name_loc, table->lang_name_eng);
	}

	send_notice_lang_to_user(source, dest, GetCallerLang(), END_OF_LIST);
}

/*********************************************************/

void handle_lang(CSTR source, User *callerUser, ServiceCommandData *data) {

	STR		cmd, param;
	BOOL	need_syntax = FALSE;


	if (IS_NULL(cmd = strtok(NULL, s_SPACE)))
		need_syntax = TRUE;

	else if (IS_NOT_NULL(param = strtok(NULL, s_SPACE)) && str_equals_nocase(param, "LIST"))
		lang_send_list(data->agent->nick, callerUser);

	else if (IS_NULL(param)) 
		send_notice_to_user(data->agent->nick, callerUser, "Invalid language ID");
		
	else if (str_equals_nocase(cmd, "RELOAD")) {

		LANG_ID	lang_id;
		char *err;


		lang_id = strtoul(param, &err, 10);

		if ((*err != '\0') || (lang_id == 0))
			send_notice_to_user(data->agent->nick, callerUser, "Invalid language ID");

		else {

			--lang_id;

			if (data->operMatch)
				send_globops(data->agent->nick, "\2%s\2 reloaded language \2%s\2", source, lang_get_shortname(lang_id));
			else
				send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) reloaded language \2%s\2", source, data->operName, lang_get_shortname(lang_id));

			if (lang_reload(lang_id)) {

				send_globops(data->agent->nick, "Reload complete");
				send_notice_to_user(data->agent->nick, callerUser, "Reload complete");
			}
			else {

				send_globops(data->agent->nick, "Reload \2FAILED!\2");
				send_notice_to_user(data->agent->nick, callerUser, "Reload \2FAILED!\2");
			}
		}
	}
	else if (str_equals_nocase(cmd, "OFFLINE")) {

		LANG_ID	lang_id;
		char *err;


		lang_id = strtoul(param, &err, 10);

		if ((*err != '\0') || (lang_id == 0))
			send_notice_to_user(data->agent->nick, callerUser, "Invalid language ID");

		else {

			--lang_id;

			if (lang_id == LANG_DEFAULT)
				send_notice_to_user(data->agent->nick, callerUser, "This is the default language and may not be marked as OFFLINE");

			else {

				if (FlagSet(lang_get_flags(lang_id), LIF_OFFLINE))
					send_notice_to_user(data->agent->nick, callerUser, "Language is already OFFLINE");

				else {

					lang_set_flags(lang_id, TRUE, LIF_OFFLINE);

					if (data->operMatch)
						send_globops(data->agent->nick, "\2%s\2 marked language \2%s\2 as OFFLINE", source, lang_get_shortname(lang_id));
					else
						send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) marked language \2%s\2 as OFFLINE", source, data->operName, lang_get_shortname(lang_id));

					send_notice_to_user(data->agent->nick, callerUser, "Language marked OFFLINE");
				}
			}
		}
	}
	else if (str_equals_nocase(cmd, "ONLINE")) {

		LANG_ID	lang_id;
		char *err;


		lang_id = strtoul(param, &err, 10);

		if ((*err != '\0') || (lang_id == 0))
			send_notice_to_user(data->agent->nick, callerUser, "Invalid language ID");

		else {

			--lang_id;
			if (FlagUnset(lang_get_flags(lang_id), LIF_OFFLINE))
				send_notice_to_user(data->agent->nick, callerUser, "Language is not marked OFFLINE");

			else {

				lang_set_flags(lang_id, FALSE, LIF_OFFLINE);

				if (data->operMatch)
					send_globops(data->agent->nick, "\2%s\2 marked language \2%s\2 as ONLINE", source, lang_get_shortname(lang_id));
				else
					send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) marked language \2%s\2 as ONLINE", source, data->operName, lang_get_shortname(lang_id));

				send_notice_to_user(data->agent->nick, callerUser, "Language marked ONLINE");
			}
		}
	}
	else if (str_equals_nocase(cmd, "REHASH")) {

		if (data->operMatch)
			send_globops(data->agent->nick, "\2%s\2 rehashed language configuration", source);
		else
			send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) rehashed language configuration", source, data->operName);

		lang_unload_all();
		lang_start();
	}
	else
		need_syntax = TRUE;

	if (need_syntax) {

		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2LANG\2 REHASH");
		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2LANG\2 RELOAD|OFFLINE|ONLINE langID|LIST");
		send_notice_to_user(data->agent->nick, callerUser, "Type \2/rs OHELP LANG\2 for more information.");
	}
}

