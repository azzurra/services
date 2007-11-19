/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* logging.h - log routines include
* 
*/

#ifndef SRV_LOGGING_H
#define SRV_LOGGING_H


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "facility.h"
#include "users.h"
#include "options.h"


typedef	unsigned short int	FACILITY;		/* F00000 */
typedef unsigned int		FACILITY_LINE;	/* L00000 */
typedef unsigned char		LOG_TYPE;		/* T000   */
typedef	unsigned char		SEVERITY;		/* S000   */


#define LOG_TYPE_ERROR_ASSERTION		(LOG_TYPE) 1
#define LOG_TYPE_ERROR_SANITY			(LOG_TYPE) 2
#define LOG_TYPE_ERROR_EXCEPTION		(LOG_TYPE) 3
#define LOG_TYPE_ERROR_RTL				(LOG_TYPE) 4
#define LOG_TYPE_ERROR_FATAL			(LOG_TYPE) 5


#define LOG_SEVERITY_ERROR_RESUMED		(SEVERITY) 1
#define LOG_SEVERITY_ERROR_SKIPPED		(SEVERITY) 2
#define LOG_SEVERITY_ERROR_HALTED		(SEVERITY) 3
#define LOG_SEVERITY_ERROR_WARNING		(SEVERITY) 4
#define LOG_SEVERITY_ERROR_QUIT			(SEVERITY) 5
#define LOG_SEVERITY_ERROR_PROPAGATED	(SEVERITY) 6


/* Log types */

#define	LOG_GENERAL_PANIC				0
#define LOG_GENERAL_ERRORS				1
#define	LOG_GENERAL_DEBUG				2

#if defined(USE_SERVICES)
#define LOG_SERVICES_NICKSERV_GENERAL	3
#define LOG_SERVICES_NICKSERV_ID		4
#define LOG_SERVICES_NICKSERV_ACCESS	5
#define LOG_SERVICES_CHANSERV_GENERAL	6
#define LOG_SERVICES_CHANSERV_ID		7
#define LOG_SERVICES_CHANSERV_ACCESS	8
#define LOG_SERVICES_MEMOSERV			9
#define LOG_SERVICES_OPERSERV			10
#define LOG_SERVICES_ROOTSERV			11
#endif

#if defined(USE_STATS)
#define LOG_SERVICES_SEENSERV			3
#define LOG_SERVICES_STATSERV			4
#endif

#if defined(USE_SOCKSMONITOR)
#define LOG_SERVICES_SOCKSMONITOR		3
#define	LOG_PROXY_GENERAL				4
#define	LOG_PROXY_SCAN					5
#endif


#if defined(USE_SERVICES)
	#define LOG_SERVICES_GENERAL		LOG_SERVICES_OPERSERV
#elif defined(USE_STATS)
	#define LOG_SERVICES_GENERAL		LOG_SERVICES_STATSERV
#else
	#define LOG_SERVICES_GENERAL		LOG_SERVICES_SOCKSMONITOR
#endif



/* TRACEing */

extern FACILITY				trace_main_facility;
extern FACILITY				trace_current_facility;
extern FACILITY_LINE		trace_main_line;
extern FACILITY_LINE		trace_current_line;

extern void trace_init();

#ifdef ENABLE_TRACE

	#define TRACE_MAIN_FCLT(mainFacility)	{ trace_main_facility = (mainFacility); trace_main_line = __LINE__ ; trace_current_facility = FACILITY_UNDEFINED; trace_current_line = 0 ; }
	#define TRACE_MAIN()					{ trace_main_line = __LINE__ ; }
	#define TRACE_FCLT(facility)			{ trace_current_facility = (facility); trace_current_line = __LINE__ ; }
	#define TRACE()							{ trace_current_line = __LINE__ ; }

	#define	TRACE_ENABLED	1

#else

	#define TRACE_MAIN_FCLT(mainFacility)
	#define TRACE_MAIN()
	#define TRACE_FCLT(facility)
	#define TRACE()

	#define	TRACE_ENABLED	0

#endif

extern BOOL log_rotation_started;

/* Start and terminate the logging facility */
extern BOOL log_init(void);
extern void log_done(void);
extern void log_rotate(BOOL force);

/* Log errors on the errors log file (errors.log) and on the debug-snoop channel (default is #bugs) */
extern void log_error(FACILITY facility, FACILITY_LINE subcode, LOG_TYPE type, SEVERITY severity, CSTR fmt, ...);

/* Log debug messages on the debug log file (debugs.log) */
extern void log_debug(CSTR fmt, ...);
extern void log_debug_direct(CSTR string);

extern int logid_from_agentid(agentid_t agentID);

/* Log service messages on the services log file (services.log) */
extern void log_services(int services, CSTR fmt, ...);

/* Log panic messages on the panic error log file (panic.log) */
extern void log_panic(CSTR fmt, ...);
extern void log_panic_direct(CSTR string);

/* Send message to the services snoop channel (default is #security) */
extern void log_snoop(CSTR source, CSTR fmt, ...);

/* Send message to the debug snoop channel (default is #bugs) */
extern void log_debug_snoop(CSTR fmt, ...);

#ifdef USE_SOCKSMONITOR
/* Send message to the proxy snoop channel (default is #APM) */
extern void log_proxy(CSTR source, CSTR fmt, ...);
#endif

/* Send the libc error message on the debug snoop channel and on the stderr stream */
extern void log_stderr(CSTR fmt, ...);

/* Log the error both on the log file and on the stderr stream, send a globops, then die. */
extern void fatal_error(FACILITY facility, FACILITY_LINE line, CSTR fmt, ...);

extern CSTR log_get_day_timestamp(int day, int month, int year);
extern CSTR log_get_timestamp(time_t logtime);
extern CSTR log_get_compact_timestamp(time_t logtime);
extern CSTR log_get_trace_string(FACILITY main_facility, FACILITY_LINE main_line, FACILITY current_facility, FACILITY_LINE current_line);

extern CSTR log_get_last_error_buffer(void);
extern CSTR log_get_last_error_timestamp(void);
extern CSTR log_get_last_error_trace(void);
extern CSTR log_get_last_error_signature(void);

extern void handle_search(CSTR source, User *callerUser, ServiceCommandData *data);

extern time_t log_next_midnight_time;


/*********************************************************
 * Macros                                                *
 *********************************************************/

#define LOG_DEBUG(fmt, ...) \
	do { \
		if ((CONF_SET_DEBUG == TRUE) && IS_NOT_NULL(fmt) && (log_rotation_started == FALSE)) \
			log_debug((fmt) , ##__VA_ARGS__); \
	} while (0)

#define LOG_SNOOP(agent, fmt, ...) \
	do { \
		if ((global_running == TRUE) && (CONF_SET_SNOOP == TRUE) && IS_NOT_NULL(fmt)) \
			log_snoop((agent), (fmt) , ##__VA_ARGS__); \
	} while (0)

#define LOG_DEBUG_SNOOP(fmt, ...) \
	do { \
		if ((global_running == TRUE) && (CONF_SET_SNOOP == TRUE) && IS_NOT_NULL(fmt)) \
			log_debug_snoop((fmt) , ##__VA_ARGS__); \
	} while (0)

#define LOG_PROXY(agent, fmt, ...) \
	do { \
		if ((global_running == TRUE) && (CONF_SET_SNOOP == TRUE) && IS_NOT_NULL(fmt)) \
			log_proxy((agent), (fmt) , ##__VA_ARGS__); \
	} while (0)

#endif /* SRV_LOGGING_H */
