/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* signals.c - libc signals handling
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/logging.h"
#include "../inc/signals.h"
#include "../inc/main.h"
#include "../inc/send.h"
#include "../inc/conf.h"
#include "../inc/process.h"		/* For to_dispatched */


/*********************************************************
 * Private code                                          *
 *********************************************************/

char *signals_to_string(int signum) {

	static char buffer[32];

	switch (signum) {

		case SIG_OUT_OF_MEMORY: /* SIGUSR1 */
			strcpy(buffer, "Out of memory");
			break;

		case SIG_REHASH: /* SIGUSR2 */
			strcpy(buffer, "Rehash");
			break;

		case SIGHUP:
			strcpy(buffer, "Hangup");
			break;
		
		case SIGINT:
			strcpy(buffer, "Interrupt");
			break;
		
		case SIGQUIT:
			strcpy(buffer, "Quit");
			break;

		#ifdef SIGILL
		case SIGILL:
			strcpy(buffer, "Illegal instruction");
			break;
		#endif

		#ifdef SIGABRT
		case SIGABRT:
			strcpy(buffer, "Abort");
			break;
		#endif

		#if defined(SIGIOT) && (!defined(SIGABRT) || SIGIOT != SIGABRT)
		case SIGIOT:
			strcpy(buffer, "IOT trap");
			break;
		#endif

		#ifdef SIGBUS
		case SIGBUS:
			strcpy(buffer, "Bus error");
			break;
		#endif

		case SIGFPE:
			strcpy(buffer, "Floating point exception");
			break;
		
		case SIGKILL:
			strcpy(buffer, "Killed");
			break;
		
		case SIGSEGV:
			strcpy(buffer, "Segmentation fault");
			break;
		/*
		case SIGUSR2:
			strcpy(buffer, "User signal 2");
			break;*/
		
		case SIGPIPE:
			strcpy(buffer, "Broken pipe");
			break;
		
		case SIGALRM:
			strcpy(buffer, "Alarm clock");
			break;
		
		case SIGTERM:
			strcpy(buffer, "Terminated");
			break;
		
		case SIGSTOP:
			strcpy(buffer, "Suspended (signal)");
			break;
		
		case SIGTSTP:
			strcpy(buffer, "Suspended");
			break;
		
		case SIGIO:
			strcpy(buffer, "I/O error");
			break;
		
		default:
			sprintf(buffer, "Signal %d\n", signum);
			break;
	}

	return buffer;
}

/*********************************************************/

static void signals_handler(int signum) {
	
	STR		signal_desc = signals_to_string(signum);


	// reset the signal to the default behavior (no infinite loop if something bad happen here :D)
	
	if (signum != SIG_REHASH)
		signal(signum, SIG_DFL);

	if (signum != SIGHUP)
		LOG_DEBUG_SNOOP("\2WARNING\2 : catched \2%s\2 signal", signal_desc);
	
	if (global_running) {

		switch (signum) {

			case SIGHUP: // update and restart

				LOG_DEBUG_SNOOP("Catched SIGHUP : \2restart\2 in progress...");
				log_debug_direct("SIGNAL: SIGHUP - restart [SAVE: YES]");

				global_force_save = TRUE;
				global_force_quit = quit_and_restart;

				signal(signum, SIG_IGN);
				return;


			case SIGINT: // save and quit

				LOG_DEBUG_SNOOP("Catched SIGINT : \2shutdown\2 in progress...");
				log_debug_direct("SIGNAL: SIGINT - shutdown [SAVE: YES]");

				global_force_save = TRUE;
				global_force_quit = force_quit;

				signal(signum, SIG_IGN);
				return;


			case SIGTERM: // quit without saving

				LOG_DEBUG_SNOOP("Catched SIGTERM : \2quit\2 in progress...");
				log_debug_direct("SIGNAL: SIGTERM - quit [SAVE: NO]");

				global_force_save = FALSE;
				global_force_quit = force_quit;
				/*
				signal(signum, SIG_DFL);
				break; // re-raise the signal and quit
				*/

				send_cmd("SQUIT %s :%s", CONF_SERVICES_NAME, signal_desc);
				services_cleanup();
				exit(1);


			case SIG_REHASH:

				LOG_DEBUG_SNOOP("Catched SIGUSR2 : \2REHASH\2 in progress...");
				conf_rehash();

				//signal(signum, signals_handler);
				return;


			default: {

				// timestamp and signal
				log_panic("%s %s", log_get_timestamp(NOW), signal_desc);
				// input buffer
				log_panic_direct(serv_input_buffer);
				// trace
				log_panic_direct(log_get_trace_string(trace_main_facility, trace_main_line, trace_current_facility, trace_current_line));

				log_error(FACILITY_PANIC, __LINE__, LOG_TYPE_ERROR_EXCEPTION, LOG_SEVERITY_ERROR_QUIT, "PANIC! IB=%s", serv_input_buffer);
				
				log_error(FACILITY_PANIC, __LINE__, LOG_TYPE_ERROR_EXCEPTION, LOG_SEVERITY_ERROR_QUIT,
					"PANIC! D%dT%d - Trace %s", dispatched, to_dispatched, log_get_trace_string(trace_main_facility, trace_main_line, trace_current_facility, trace_current_line));

				/* Cut off if this would make IRC command >510 characters. */
				if (str_len(serv_input_buffer) > 445) {

					serv_input_buffer[443] = '>';
					serv_input_buffer[444] = '>';
					serv_input_buffer[445] = 0;
				}
				
				send_globops(NULL, "PANIC! IB=%s", serv_input_buffer);
				send_globops(NULL, "PANIC! D%dT%d - Trace %s", dispatched, to_dispatched, log_get_trace_string(trace_main_facility, trace_main_line, trace_current_facility, trace_current_line));

				send_cmd("SQUIT %s :%s", CONF_SERVICES_NAME, signal_desc);
			}
		}
	}

	// re-raise the signal
	raise(signum);

	/* R.I.P. */
}

/*********************************************************/

void signals_save_last_core(void) {

	CSTR	ts = log_get_compact_timestamp(0);
	BOOL	core_found = TRUE;

	#define EXE_NAME	"services"
	#define CORE_NAME	"./services.core"
	#define CORE_FMT	"./services.core-%s"

	// "./core"
	snprintf(misc_buffer, sizeof(misc_buffer), CORE_FMT, ts);
	if (rename("./core", misc_buffer) != 0)
		// ./core non esiste, provare con ./<programname>.core (FreeBSD)
		core_found = rename(CORE_NAME, misc_buffer) == 0;

	if (core_found) {

		snprintf(misc_buffer, sizeof(misc_buffer), "cp ../%s ./%s-%s", EXE_NAME, EXE_NAME, ts);
		system(misc_buffer);
	}

	#undef EXE_NAME
	#undef CORE_NAME
	#undef CORE_FMT
}


/*********************************************************
 * Public code                                           *
 *********************************************************/

void signals_init(void) {

	signal(SIGSEGV,	signals_handler);	// segmentation violation (invalid access to valid memory)
	signal(SIGBUS,	signals_handler);	// invalid pointer is dereferenced (access to an invalid address)
	signal(SIGILL,	signals_handler);	// illegal instruction
	signal(SIGABRT,	signals_handler);	// an error detected by the program itself and reported by calling 'abort'
	signal(SIGIOT,	signals_handler);	// SIGABRT
	signal(SIGFPE,	signals_handler);	// fatal arithmetic error
	signal(SIGTRAP,	signals_handler);	// generated by the machine's breakpoint instruction

	signal(SIG_OUT_OF_MEMORY,	signals_handler);	// This is our "out-of-memory" panic switch
	signal(SIG_REHASH, signals_handler);

	signal(SIGINT,  signals_handler);	// program-interrupt signal (ctrl+c) -> save database and QUIT (same as /rs SHUTDOWN)
	signal(SIGTERM,	signals_handler);	// temination signal (eg. via kill) -> quit without saving (same as /rs QUIT)
	signal(SIGQUIT,	signals_handler);	// program-quit signal (ctrl+\) - core forced

	signal(SIGHUP,	signals_handler);	// used as "save databases and restart" messages

	signal(SIGTTIN, signals_handler);
	signal(SIGTTOU, signals_handler);

	signal(SIGALRM,	SIG_IGN);		/* Used by sgets() for read timeout */
	signal(SIGCHLD,	SIG_IGN);		// This signal is sent to a parent process whenever one of its child processes terminates or stops
	signal(SIGWINCH, SIG_IGN);		// Window size change
	signal(SIGPIPE, SIG_IGN);		// Broken pipe /* We don't care about broken pipes */
	signal(SIGTSTP, SIG_IGN);

	signals_save_last_core();
}
