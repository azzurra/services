/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* logging.c - log routines
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/memory.h"
#include "../inc/lang.h"
#include "../inc/send.h"
#include "../inc/process.h"
#include "../inc/main.h"
#include "../inc/conf.h"
#include "../inc/timeout.h"
#include "../inc/logging.h"
#include "../inc/users.h"
#include "../inc/misc.h"


/*********************************************************
 * Global variables                                      *
 *********************************************************/

FACILITY			trace_main_facility;
FACILITY			trace_current_facility;
FACILITY_LINE		trace_main_line;
FACILITY_LINE		trace_current_line;

BOOL				log_rotation_started = FALSE;


/*********************************************************
 * Local variables                                       *
 *********************************************************/

typedef struct _log_file {
	CSTR	filename;
	CSTR	name;
	FILE	*file;
} LOG_FILE;


LOG_FILE	log_files[] = {

	/* index					filename		log name		file handle	*/

	/* LOG_GENERAL_PANIC			*/	{"panic",		"Panic",		NULL},
	/* LOG_GENERAL_ERRORS			*/	{"errors",		"Errors",		NULL},
	/* LOG_GENERAL_DEBUG			*/	{"debug",		"Debug",		NULL},

	/* LOG_SERVICES_NICKSERV_GENERAL	*/	{"nickserv",		"NickServ",		NULL},
	/* LOG_SERVICES_NICKSERV_ID		*/	{"nickserv_id",		"NickServ (ID)",	NULL},
	/* LOG_SERVICES_NICKSERV_ACCESS		*/	{"nickserv_access",	"NickServ (ACC)",	NULL},
	/* LOG_SERVICES_CHANSERV_GENERAL	*/	{"chanserv",		"ChanServ",		NULL},
	/* LOG_SERVICES_CHANSERV_ID		*/	{"chanserv_id",		"ChanServ (ID)",	NULL},
	/* LOG_SERVICES_CHANSERV_ACCESS		*/	{"chanserv_access",	"ChanServ (ACC)",	NULL},
	/* LOG_SERVICES_MEMOSERV		*/	{"memoserv",		"MemoServ",		NULL},
	/* LOG_SERVICES_OPERSERV		*/	{"operserv",		"OperServ",		NULL},
	/* LOG_SERVICES_ROOTSERV		*/	{"rootserv",		"RootServ",		NULL},
	/* LOG_SERVICES_SEENSERV			*/	{"seenserv",		"SeenServ",			NULL},
	/* LOG_SERVICES_STATSERV			*/	{"statserv",		"StatServ",			NULL}
};
#define log_files_count	(sizeof(log_files) / sizeof(LOG_FILE))


static BOOL		log_started = FALSE;

#define			LOG_BUFFER_SIZE		1024
static char		log_buffer[LOG_BUFFER_SIZE];


// last log_error() input buffer and trace status

typedef struct _LASTERROR_STATUS {

	time_t			time;

	char			log_last_error_inputbuffer[BUFSIZE];
	
	FACILITY		trace_main_facility;
	FACILITY		trace_current_facility;
	FACILITY_LINE	trace_main_line;
	FACILITY_LINE	trace_current_line;

	FACILITY		logerror_facility;
	FACILITY_LINE	logerror_line;
	LOG_TYPE		logerror_type;
	SEVERITY		logerror_severity;

} LASTERROR_STATUS;

static LASTERROR_STATUS		*log_last_error_status = NULL;


/*********************************************************
 * Local strings                                         *
 *********************************************************/

static CSTR		s_LOG_STDERR_LOGMSG	= "\nSTDERRMSG: %s\n[errno: %d | %s]\n\n";


/*********************************************************
 * Common / private code                                 *
 *********************************************************/

static FILE *log_open_file(unsigned int type, BOOL readonly, int day, int month, int year) {

	char	path[64];
	FILE	*file;
	CSTR	folder;


	if (type < 0 || type >= log_files_count)
		return NULL;

	folder = log_get_day_timestamp(day, month, year);

	if (!readonly) {

		snprintf(path, sizeof(path), "./logs/%s", folder);

		if ((mkdir(path, S_IRWXU) == -1) && (errno != EEXIST))
			return NULL;
	}

	snprintf(path, sizeof(path), "./logs/%s/%s.log", folder, log_files[type].filename);
	
	file = fopen(path, readonly ? s_OPENMODE_READONLY : s_OPENMODE_APPEND);

	if (IS_NOT_NULL(file))
		setbuf(file, NULL);

	return file;
}


static STDSTR log_get_signature(FACILITY facility, FACILITY_LINE line, LOG_TYPE type, SEVERITY severity) {

	// [F00000 L00000 T000 S000]

	static char		signature[32];

	snprintf(signature, sizeof(signature), "[F%05d L%05d T%03d S%03d]", facility, line, type, severity);
	return (STDSTR) signature;
}


static void log_save_last_error_status(FACILITY logerror_facility, FACILITY_LINE logerror_line, LOG_TYPE logerror_type, SEVERITY logerror_severity) {

	if (IS_NOT_NULL(log_last_error_status)) {

		log_last_error_status->time = time(NULL);
		memcpy(log_last_error_status->log_last_error_inputbuffer, serv_input_buffer, sizeof(log_last_error_status->log_last_error_inputbuffer));

		log_last_error_status->trace_main_facility = trace_main_facility;
		log_last_error_status->trace_current_facility = trace_current_facility;
		log_last_error_status->trace_main_line = trace_main_line;
		log_last_error_status->trace_current_line = trace_current_line;

		log_last_error_status->logerror_facility = logerror_facility;
		log_last_error_status->logerror_line = logerror_line;
		log_last_error_status->logerror_type = logerror_type;
		log_last_error_status->logerror_severity = logerror_severity;
	}
}


/*********************************************************
 * Public code                                           *
 *********************************************************/

CSTR log_get_day_timestamp(int day, int month, int year) {

	// aaaa-mm-gg

	static char		timestamp[12];

	snprintf(timestamp, sizeof(timestamp), "%04d-%02d-%02d", year, month, day);
	return (CSTR) timestamp;
}

CSTR log_get_timestamp(time_t logtime) {

	// [gg/mm/aaaa hh:mm.ss]

	static char		timestamp[22];
	struct tm		tm;
	
	if (logtime == 0)
		logtime = time(NULL);


	tm = *localtime(&logtime);

	strftime(timestamp, sizeof(timestamp), "[%d/%m/%Y %H:%M.%S]", &tm);
	timestamp[sizeof(timestamp) - 1] = c_NULL;
	
	return (CSTR) timestamp;
}


CSTR log_get_compact_timestamp(time_t logtime) {

	// aaaammgg-hhmmss

	static char		timestamp[16];
	struct tm	tm;
	
	if (logtime == 0)
		logtime = time(NULL);


	tm = *localtime(&logtime);

	strftime(timestamp, sizeof(timestamp), "%Y%m%d-%H%M%S", &tm);
	timestamp[sizeof(timestamp) - 1] = c_NULL;
	
	return (CSTR) timestamp;
}

CSTR log_get_trace_string(FACILITY main_facility, FACILITY_LINE main_line, FACILITY current_facility, FACILITY_LINE current_line) {

	// E%d MF%d ML%d CF%d CL%d

	static char		trace_string[64];

	snprintf(trace_string, sizeof(trace_string), "E%d MF%d ML%d CF%d CL%d", TRACE_ENABLED, main_facility, main_line, current_facility, current_line);
	return (CSTR) trace_string;
}

void trace_init() {

	trace_main_facility = FACILITY_UNDEFINED;
	trace_current_facility = FACILITY_UNDEFINED;
	trace_main_line = 0;
	trace_current_line = 0;

	dispatched = 0;
	to_dispatched = 0;
}


void log_done() {

	CSTR timestamp = log_get_timestamp(0);
	unsigned int i;

	snprintf(log_buffer, sizeof(log_buffer), "%s - Session End (closed)", timestamp);

	for (i = 0; i < log_files_count; i++) {

		if (IS_NOT_NULL(log_files[i].file)) {

			fputs(log_buffer, log_files[i].file);
			fputc(c_LF, log_files[i].file);
			
			fclose(log_files[i].file);
			log_files[i].file = NULL;
		}
	}

	if (IS_NOT_NULL(log_last_error_status)) {

		mem_free(log_last_error_status);
		log_last_error_status = NULL;
	}

	log_started = FALSE;
}


BOOL log_init() {

	unsigned int i;
	CSTR timestamp = log_get_timestamp(NOW);

	if (log_started)
		return TRUE;

	// # apertura file

	snprintf(log_buffer, sizeof(log_buffer), "%s - Session Start (opened)", timestamp);

	for (i = 0; i < log_files_count; i++) {

		log_files[i].file = log_open_file(i, FALSE, time_today_day, time_today_month, time_today_year);

		if (IS_NULL(log_files[i].file)) {

			log_stderr("log_init() - unable to open logs file: %s (%s.log)", log_files[i].name, log_files[i].filename);
			log_done();

			return FALSE;
		}

		fputs(log_buffer, log_files[i].file);
		fputc(c_LF, log_files[i].file);
	}

	if (IS_NULL(log_last_error_status))
		log_last_error_status = mem_calloc(1, sizeof(LASTERROR_STATUS)); // allocata e azzerata.

	return log_started = TRUE;
}

void log_rotate(BOOL force) {

	if (log_rotation_started)
		return;

	if ((NOW >= time_next_midnight) || force) {

		struct tm		*ltm;
		unsigned int	i;

		log_rotation_started = TRUE;

		ltm = localtime(&NOW);

		if (IS_NOT_NULL(ltm)) {

			CSTR	timestamp = log_get_timestamp(NOW);

			time_today_day = ltm->tm_mday;
			time_today_month = ltm->tm_mon + 1;
			time_today_year = ltm->tm_year + 1900;

			// # chiusura log correnti

			snprintf(log_buffer, sizeof(log_buffer), "%s - Session End (rotation)", timestamp);

			for (i = 0; i < log_files_count; i++) {

				if (IS_NOT_NULL(log_files[i].file)) {

					fputs(log_buffer, log_files[i].file);
					fputc(c_LF, log_files[i].file);
				
					fclose(log_files[i].file);
					log_files[i].file = NULL;
				}
			}

			// # apertura nuovi log

			snprintf(log_buffer, sizeof(log_buffer), "%s - Session Start (rotation)", timestamp);

			for (i = 0; i < log_files_count; i++) {

				log_files[i].file = log_open_file(i, FALSE, time_today_day, time_today_month, time_today_year);

				if (IS_NULL(log_files[i].file)) {

					log_stderr("log_rotate() - unable to open logs file: %s (%s.log)", log_files[i].name, log_files[i].filename);
					LOG_DEBUG_SNOOP("log_rotate() - unable to open logs file: %s (%s.log) - \2LOGGING DISABLED\2", log_files[i].name, log_files[i].filename);
					send_globops(NULL, "\2WARNING!\2 - unable to (re)open logs file: %s (%s.log) - \2LOGGING DISABLED\2", log_files[i].name, log_files[i].filename);
					log_rotation_started = FALSE;
					return;
				}

				fputs(log_buffer, log_files[i].file);
				fputc(c_LF, log_files[i].file);
			}

			time_next_midnight = NOW + (ONE_DAY - (ltm->tm_sec + (ltm->tm_min * ONE_MINUTE) + (ltm->tm_hour * ONE_HOUR)));
		}
		else {

			LOG_DEBUG_SNOOP("log_rotate() - localtime() failed! Rotation skipped.");
			time_next_midnight += ONE_DAY;
		}
	}

	log_rotation_started = FALSE;
}

/**
	Tipi di log:

  - snoop (#security)
  - errori (#bugs + errors.log)
  - servizi (services.log)
  - debug (debug.log)
  - panic (panic.log)
  - activity (activity.log)			SocksMonitor only
  - proxies (proxies.log)			SocksMonitor only
  - proxy replies (replies.log)		SocksMonitor only

**/

void log_error(FACILITY facility, FACILITY_LINE line, LOG_TYPE type, SEVERITY severity, CSTR fmt, ...) {

	if (IS_NOT_NULL(fmt) && !log_rotation_started) {

		va_list		args;
		STR			ptr;
		size_t		len;


		va_start(args, fmt);
		snprintf(log_buffer, sizeof(log_buffer), "%s %s ", log_get_timestamp(0), log_get_signature(facility, line, type, severity));

		len = str_len(log_buffer);
		ptr = log_buffer + len;

		vsnprintf(ptr, sizeof(log_buffer) - len, fmt, args);

		fputs(log_buffer, log_files[LOG_GENERAL_ERRORS].file);
		fputc(c_LF, log_files[LOG_GENERAL_ERRORS].file);

		if (global_running)
			send_cmd(":%s PRIVMSG %s :%s", s_DebugServ, CONF_DEBUG_CHAN, ptr);

		else {

			fputc('\n', stderr);
			fputs(log_buffer, stderr);
			fputc('\n', stderr);
		}
	}

	// salvataggio status corrente	
	log_save_last_error_status(facility, line, type, severity);
}

CSTR log_get_last_error_buffer(void) {

	return (IS_NOT_NULL(log_last_error_status) && (log_last_error_status->log_last_error_inputbuffer[0] != c_NULL)) ? (CSTR) log_last_error_status->log_last_error_inputbuffer : (CSTR) s_LOG_EMPTY;
}


CSTR log_get_last_error_timestamp(void) {

	return IS_NOT_NULL(log_last_error_status) ? (CSTR) log_get_timestamp(log_last_error_status->time) : (CSTR) s_LOG_EMPTY;
}


CSTR log_get_last_error_trace(void) {

	return IS_NOT_NULL(log_last_error_status) ? (CSTR) log_get_trace_string(log_last_error_status->trace_main_facility, log_last_error_status->trace_main_line, log_last_error_status->trace_current_facility, log_last_error_status->trace_current_line) : (CSTR) s_LOG_EMPTY;
}

CSTR log_get_last_error_signature(void) {

	return IS_NOT_NULL(log_last_error_status) ? (CSTR) log_get_signature(log_last_error_status->logerror_facility, log_last_error_status->logerror_line, log_last_error_status->logerror_type, log_last_error_status->logerror_severity) : (CSTR) s_LOG_EMPTY;
}


void log_debug(CSTR fmt, ...) {

	/* Note: do *NOT* call this directly. Use the LOG_DEBUG() macro instead. */

	va_list		args;

	va_start(args, fmt);
	log_buffer[0] = c_NULL;
	vsnprintf(log_buffer, sizeof(log_buffer), fmt, args);

	log_debug_direct(log_buffer);
}

void log_debug_direct(CSTR string) {

	if (IS_NOT_NULL(string) && !log_rotation_started) {

		fputs(log_get_timestamp(0), log_files[LOG_GENERAL_DEBUG].file);
		fputc(c_SPACE, log_files[LOG_GENERAL_DEBUG].file);

		fputs(string, log_files[LOG_GENERAL_DEBUG].file);
		fputc(c_LF, log_files[LOG_GENERAL_DEBUG].file);
	}
}


int logid_from_agentid(agentid_t agentID) {
	
	switch (agentID) {
		case AGENTID_NICKSERV:
			return LOG_SERVICES_NICKSERV_GENERAL;

		case AGENTID_CHANSERV:
			return LOG_SERVICES_CHANSERV_GENERAL;

		case AGENTID_MEMOSERV:
			return LOG_SERVICES_MEMOSERV;

		case AGENTID_OPERSERV:
			return LOG_SERVICES_OPERSERV;

		case AGENTID_ROOTSERV:
			return LOG_SERVICES_ROOTSERV;

		case AGENTID_STATSERV:
			return LOG_SERVICES_STATSERV;

		case AGENTID_SEENSERV:
			return LOG_SERVICES_SEENSERV;

		case AGENTID_GNOTICER:
		case AGENTID_HELPSERV:
		case AGENTID_DEBUGSERV:
		default:
			return LOG_GENERAL_ERRORS;
	}
}

void log_services(int services, CSTR fmt, ...) {

	if (IS_NOT_NULL(fmt) &&
		(services >= LOG_SERVICES_NICKSERV_GENERAL && services <= LOG_SERVICES_SEENSERV)
		&& !log_rotation_started
		) {

		va_list		args;
		size_t		len;


		va_start(args, fmt);
		log_buffer[0] = c_NULL;
		snprintf(log_buffer, sizeof(log_buffer), "%s ", log_get_timestamp(0));
		len = str_len(log_buffer);
		vsnprintf(log_buffer + len, sizeof(log_buffer) - len, fmt, args);

		fputs(log_buffer, log_files[services].file);
		fputc(c_LF, log_files[services].file);
	}
}


void log_panic(CSTR fmt, ...) {

	if (IS_NOT_NULL(fmt) && !log_rotation_started) {

		va_list		args;

		va_start(args, fmt);
		vfprintf(log_files[LOG_GENERAL_PANIC].file, fmt, args);
		fputc(c_LF, log_files[LOG_GENERAL_PANIC].file);
	}
}

void log_panic_direct(CSTR string) {

	if (IS_NOT_NULL(string) && !log_rotation_started) {

		fputs(string, log_files[LOG_GENERAL_PANIC].file);
		fputc(c_LF, log_files[LOG_GENERAL_PANIC].file);
	}
}


void log_snoop(CSTR source, CSTR fmt, ...) {

	/* Note: do *NOT* call this directly. Use the LOG_SNOOP() macro instead. */

	va_list		args;

	log_buffer[0] = c_NULL;
	va_start(args, fmt);
	vsnprintf(log_buffer, sizeof(log_buffer), fmt, args);

	send_cmd(":%s PRIVMSG %s :%s", source, CONF_SNOOP_CHAN, log_buffer);
}

void log_debug_snoop(CSTR fmt, ...) {

	/* Note: do *NOT* call this directly. Use the LOG_DEBUG_SNOOP() macro instead. */

	va_list		args;

	log_buffer[0] = c_NULL;
	va_start(args, fmt);
	vsnprintf(log_buffer, sizeof(log_buffer), fmt, args);

	send_cmd(":%s PRIVMSG %s :%s", s_DebugServ, CONF_DEBUG_CHAN, log_buffer);
}

void log_stderr(CSTR fmt, ...) {

	if (IS_NOT_NULL(fmt) && !log_rotation_started) {

		va_list		args;

		log_buffer[0] = c_NULL;
		va_start(args, fmt);
		vsnprintf(log_buffer, sizeof(log_buffer), fmt, args);

		// send the message on the debug snoop channel ...
		if (global_running)
			send_PRIVMSG(s_DebugServ, CONF_DEBUG_CHAN, s_LOG_STDERR_LOGMSG, log_buffer, errno, strerror(errno));

		// ... and on the stderr stream
		fprintf(stderr, s_LOG_STDERR_LOGMSG, log_buffer, errno, strerror(errno));
	}
}

void fatal_error(FACILITY facility, FACILITY_LINE line, CSTR fmt, ...) {

	char timebuf[64], buffer[IRCBUFSIZE];
	size_t len;
	va_list args;


	va_start(args, fmt);

	lang_format_localtime(timebuf, sizeof(timebuf), LANG_DEFAULT, TIME_FORMAT_FULLDATE, NOW);

	len = str_copy_checked("FATAL ERROR: ", buffer, sizeof(buffer));

	vsnprintf(buffer + len, sizeof(buffer) - len, fmt, args);

	/* Log to appropriate log file, also sends to console. */
	log_error(facility, line, LOG_TYPE_ERROR_FATAL, LOG_SEVERITY_ERROR_QUIT, buffer);

	/* Send a globop if we're still connected. */
	if (global_running)
		send_globops(NULL, "%s", buffer);

	exit(EXIT_FAILURE);
}

/*********************************************************
 * LOG SEARCH                                            *
 *********************************************************/

static BOOL log_search_file(CSTR agentNickname, const User *callerUser, int logType, STR dayString, CSTR search, unsigned long startLine, unsigned long endLine) {

	FILE		*file;
	STR			ptr, err;
	char		firstDay[12], lastDay[12], token[6];
	long int	dayStart = 0, monthStart = 0, yearStart = 0;
	long int	dayEnd = 0, monthEnd = 0, yearEnd = 0;
	int			day, month, year;
	unsigned long 	opened, line, count;
	BOOL		errors;


	if (IS_NULL(agentNickname) || IS_NULL(dayString) || IS_NULL(search)) {

		log_error(FACILITY_LOGGING, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_HALTED, s_LOG_ERR_PARAMETER, "log_search_file()", s_LOG_NULL, 
			IS_NULL(agentNickname) ? "agentNickname" : IS_NULL(dayString) ? "dayString" : "search" );

		send_notice_to_user(agentNickname, callerUser, "Search failed.");
		return FALSE;
	}

	if ((logType < 0) || (logType >= (int)log_files_count)) {

		send_notice_to_user(agentNickname, callerUser, "Invalid log file type.");
		return FALSE;
	}

	// # giorno da considerare
	// TODAY|AAAA-MM-GG[>TODAY|AAAA-MM-GG]

	/* Get the first date. */
	ptr = str_tokenize(dayString, firstDay, sizeof(firstDay), '>');

	/* Now get the last date. */
	if (IS_NULL(str_tokenize(ptr, lastDay, sizeof(lastDay), ' ')))
		memset(lastDay, 0, sizeof(lastDay));

	/* Parse the first date. */
	if (str_equals_nocase(firstDay, s_TODAY)) {

		dayStart = time_today_day;
		monthStart = time_today_month;
		yearStart = time_today_year;
	}
	else {

		errors = TRUE;

		ptr = str_tokenize(firstDay, token, sizeof(token), '-');

		if (IS_NOT_NULL(ptr) && IS_NOT_EMPTY_STR(token)) {

			yearStart = strtol(token, &err, 10);

			if (*err == '\0') {

				ptr = str_tokenize(ptr, token, sizeof(token), '-');

				if (IS_NOT_NULL(ptr) && IS_NOT_EMPTY_STR(token)) {

					monthStart = strtol(token, &err, 10);

					if (*err == '\0') {

						ptr = str_tokenize(ptr, token, sizeof(token), c_NULL);

						if (IS_NOT_NULL(ptr) && IS_NOT_EMPTY_STR(token)) {

							dayStart = strtol(token, &err, 10);

							if (*err == '\0')
								errors = FALSE;
						}
					}
				}
			}
		}

		if (errors) {

			send_notice_to_user(agentNickname, callerUser, "Invalid time format (1).");
			return FALSE;
		}

		if (!validate_date(yearStart, monthStart, dayStart)) {

			send_notice_to_user(agentNickname, callerUser, "Invalid time format: start date is not valid");
			return FALSE;
		}
	}

	if (IS_NOT_EMPTY_STR(lastDay)) {

		/* Parse the second date. */
		if (str_equals_nocase(lastDay, s_TODAY)) {

			dayEnd = time_today_day;
			monthEnd = time_today_month;
			yearEnd = time_today_year;
		}
		else {

			errors = TRUE;

			ptr = str_tokenize(lastDay, token, sizeof(token), '-');

			if (IS_NOT_NULL(ptr) && IS_NOT_EMPTY_STR(token)) {

				yearEnd = strtol(token, &err, 10);

				if (*err == '\0') {

					ptr = str_tokenize(ptr, token, sizeof(token), '-');

					if (IS_NOT_NULL(ptr) && IS_NOT_EMPTY_STR(token)) {

						monthEnd = strtol(token, &err, 10);

						if (*err == '\0') {

							ptr = str_tokenize(ptr, token, sizeof(token), c_NULL);

							if (IS_NOT_NULL(ptr) && IS_NOT_EMPTY_STR(token)) {

								dayEnd = strtol(token, &err, 10);

								if (*err == '\0')
									errors = FALSE;
							}
						}
					}
				}
			}

			if (errors) {

				send_notice_to_user(agentNickname, callerUser, "Invalid time format (2).");
				return FALSE;
			}

			if (!validate_date(yearEnd, monthEnd, dayEnd)) {

				send_notice_to_user(agentNickname, callerUser, "Invalid time format: end date is not valid");
				return FALSE;
			}
		}
	}

	if ((dayEnd != 0) && ((yearStart > yearEnd) ||
		((yearStart == yearEnd) && ((monthStart > monthEnd) || ((monthStart == monthEnd) && (dayStart > dayEnd)))))) {

		send_notice_to_user(agentNickname, callerUser, "Invalid time format: start date is greater than end date");
		return FALSE;
	}

	/* Did they input the same day as start AND end? */
	if ((dayStart == dayEnd) && (monthStart == monthEnd) && (yearStart == yearEnd))
		dayEnd = monthEnd = yearEnd = 0;

	// # inizio ricerca

	day = dayStart;
	month = monthStart;
	year = yearStart;

	if (endLine == 0)
		endLine = startLine + 50;
	else
		endLine = min(endLine, startLine + 50); // visualizzare al massimo 50 linee alla volta

	line = count = opened = 0;

	send_notice_to_user(agentNickname, callerUser, "Searching %s logfile(s) for: \2%s\2", log_files[logType].name, search);

	while (count < (endLine - startLine)) {

		// ricerca

		file = log_open_file(logType, TRUE, day, month, year);

		if (IS_NOT_NULL(file)) {

			++opened;

			send_notice_to_user(agentNickname, callerUser, "\2- %02d/%02d/%04d -\2", day, month, year);

			/* Also check if we are beyond the endLine */
			while (fgets(log_buffer, LOG_BUFFER_SIZE, file) && (line < endLine)) {

				if (str_match_wild_nocase(search, log_buffer)) {

					++line;

					if (line < startLine)
						continue;
					
					send_notice_to_user(agentNickname, callerUser, "LOG(\2%d\2): %s", line, log_buffer);

					++count;

				}
			}

			fclose(file);
		}
		
		/* If we only need to search through a single day's logs... */
		if (dayEnd == 0)
			break;

		/* If we reached the last requested day, end the search. */
		if ((year == yearEnd) && (month == monthEnd) && (day == dayEnd))
			break;

		/* Increase the date. */
		++day;

		switch (month) {

			case 4:
			case 6:
			case 9:
			case 11:
				if (day > 30) {

					++month;
					day = 1;
				}
				break;

			case 2:

				if (day > (year_is_leap(year) ? 29 : 28)) {

					++month;
					day = 1;
				}
				break;

			default:
				if (day > 31) {

					++month;
					day = 1;
				}
				break;
		}

		if (month > 12) {

			day = month = 1;
			++year;
		}
	}

	send_notice_to_user(agentNickname, callerUser, "End of search - \2%lu\2 matches shown.", count);

	return TRUE;	
}


static void log_handle_search_syntax(const User *callerUser, CSTR agentNickname, BOOL full) {

	if (full)
		send_notice_to_user(agentNickname, callerUser, "Syntax: \2LOG\2 SEARCH [TODAY|AAAA-MM-GG[>TODAY|AAAA-MM-GG] [NS|NSI|NSA|CS|CSI|CSA|MS|OS|RS|ST|SS|ERR|\2DEB\2|PANIC [start [[+]end]]]]] *text*");
	else
		send_notice_to_user(agentNickname, callerUser, "Syntax: \2LOG\2 SEARCH [TODAY|AAAA-MM-GG[>TODAY|AAAA-MM-GG] [\2NS\2|NSI|NSA|CS|CSI|CSA|MS|OS|RS|ST|SS [start [[+]end]]]]] *text*");
}

void handle_search(CSTR source, User *callerUser, ServiceCommandData *data) {

	/*
	LOG SEARCH [TODAY|AAAA-MM-GG[>TODAY|AAAA-MM-GG] [NS|NSI|NSA|CS|CSI|CSA|MS|OS|RS|ST|SS|ERR|DEB|PANIC|ACTIVITY|PROXY|SCAN [start [[+]end]]]]] *text*
	*/

	#define	MAX_PARAMS	5

	STR				prms[MAX_PARAMS] = {NULL, NULL, NULL, NULL, NULL};
	STR				search = NULL, days = NULL, type = NULL, start = NULL, end = NULL;
	int				i = 0, j, log_type;
	unsigned long	start_line, end_line;
	BOOL			full = (data->agent->agentID == AGENTID_DEBUGSERV);

	TRACE_FCLT(FACILITY_DEBUGSERV_LOG_SEARCH);


	while ((i < MAX_PARAMS) && IS_NOT_NULL((prms[i] = strtok(NULL, s_SPACE))))
		++i;

	TRACE();

	if (i < 1) {

		log_handle_search_syntax(callerUser, data->agent->nick, full);
		return;
	}
	else {

		TRACE();
		for (j = 0; j < MAX_PARAMS; ++j) {

			if (IS_NOT_NULL(prms[j]))
				prms[j] = str_duplicate(prms[j]);
		}

		--i;
		search = prms[i];

		if (i > 0) {

			days = prms[0];
			i--;

			if (i > 0) {

				type = prms[1];
				i--;

				if (i > 0) {

					start = prms[2];
					i--;

					if (i > 0) {

						end = prms[3];
						i--;
					}
				}
			}
		}
	}

	if (IS_NULL(days)) // default day-string
		days = str_duplicate(s_TODAY);

	if (IS_NULL(type)) {	// default type

		if (full)
			type = str_duplicate("DEB");
		else
			type = str_duplicate("NS");
	}

	if (IS_NULL(start)) // default start-line
		start = str_duplicate("0");
	
	if (IS_NULL(end)) // default end-line 
		end = str_duplicate("+50");

	// Tipo

	TRACE();

	log_type = -1;

	if (full) {

		if (str_equals_nocase(type, "ERR"))
			log_type = LOG_GENERAL_ERRORS;
		
		else if (str_equals_nocase(type, "DEB"))
			log_type = LOG_GENERAL_DEBUG;

		else if (str_equals_nocase(type, "PANIC"))
			log_type = LOG_GENERAL_PANIC;
	}

	if (log_type == -1) {

		if (str_equals_nocase(type, "NS"))
			log_type = LOG_SERVICES_NICKSERV_GENERAL;

		else if (str_equals_nocase(type, "NSI"))
			log_type = LOG_SERVICES_NICKSERV_ID;

		else if (str_equals_nocase(type, "NSA"))
			log_type = LOG_SERVICES_NICKSERV_ACCESS;


		else if (str_equals_nocase(type, "CS"))
			log_type = LOG_SERVICES_CHANSERV_GENERAL;

		else if (str_equals_nocase(type, "CSI"))
			log_type = LOG_SERVICES_CHANSERV_ID;

		else if (str_equals_nocase(type, "CSA"))
			log_type = LOG_SERVICES_CHANSERV_ACCESS;


		else if (str_equals_nocase(type, "MS"))
			log_type = LOG_SERVICES_MEMOSERV;

		else if (str_equals_nocase(type, "OS"))
			log_type = LOG_SERVICES_OPERSERV;

		else if (str_equals_nocase(type, "RS"))
			log_type = LOG_SERVICES_ROOTSERV;

		else if (str_equals_nocase(type, "SS"))
			log_type = LOG_SERVICES_SEENSERV;

		else if (str_equals_nocase(type, "ST"))
			log_type = LOG_SERVICES_STATSERV;
	}
	
	if (log_type == -1) {

		log_handle_search_syntax(callerUser, data->agent->nick, full);

		for (j = 0; j < MAX_PARAMS; ++j) {

			if (IS_NOT_NULL(prms[j]))
				mem_free(prms[j]);
		}

		return;
	}

	// Intervallo

	start_line = strtoul(start, NULL, 10);

	TRACE();
	if (end[0] == c_PLUS)
		end_line = start_line + strtoul(end + 1, NULL, 10);
	else
		end_line = strtoul(end, NULL, 10);


	// Ricerca
	TRACE();
	LOG_DEBUG_SNOOP("Command: LOG SEARCH %s %s \2%s\2 %d %d -- by %s (%s@%s)", type, days, search, start_line, end_line, callerUser->nick, callerUser->username, callerUser->host);
	log_search_file(data->agent->nick, callerUser, log_type, days, search, start_line, end_line);

	TRACE();
	mem_free(search);
	mem_free(days);
	mem_free(type);
	mem_free(start);
	mem_free(end);
	TRACE();

	#undef MAX_PARAMS
}
