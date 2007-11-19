/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* process.c - Incoming message parsing
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/process.h"
#include "../inc/memory.h"
#include "../inc/logging.h"
#include "../inc/conf.h"
#include "../inc/main.h"


/*********************************************************
 * Global variables                                      *
 *********************************************************/

BOOL		dispatched;		/* Impostato a 1 prima di chiamare il gestore del comando. */
BOOL		to_dispatched;	/* Impostato a 1 prima di chiamare il gestore dei timeout. */

STR			debug_monitor_inputbuffer_filter = NULL;
BOOL		debug_inject = FALSE;

unsigned long int total_recvM = 0;


/*********************************************************
 * Local variables                                       *
 *********************************************************/

STR			debug_inject_buffer = NULL;

static char *argv[IRCD_MAX_PARAMS];


/*********************************************************
 * Initialization/Cleanup routines                       *
 *********************************************************/

void process_init() {

	int argc;

	for (argc = 0; argc < IRCD_MAX_PARAMS; ++argc)
		argv[argc] = mem_calloc(1, IRCBUFSIZE);
}

void process_terminate() {

	int argc;

	for (argc = 0; argc < IRCD_MAX_PARAMS; ++argc)
		mem_free(argv[argc]);
}


/*********************************************************
 * Private code                                          *
 *********************************************************/

/*********************************************************
 * process_split_message()                               *
 *                                                       *
 * Split a buffer into arguments and store the arguments *
 * in an argument vector pointed to by argv; return      *
 * the argument count. Treat a parameter with a leading  *
 * ':' as the last parameter of the line, per the IRC    *
 * RFC.                                                  *
 *********************************************************/

static __inline__ int process_split_message(const char *buffer) {

	int		argc = 0;
	char	*ptr, c, lastchar = c_SPACE;

	TRACE_FCLT(FACILITY_PROCESS_SPLIT_MESSAGE);

	ptr = argv[argc];

	if (*buffer != ':')
		lastchar = *buffer;

	TRACE();

	while (1) {

		switch (c = *buffer++) {

			case ' ':
				/* Space. End current param and move on to the next. */
				*ptr = '\0';
				ptr = argv[++argc];

				/* Watch out for more than one space in a row. */
				while (*buffer == c_SPACE)
					++buffer;

				break;

			case '\0':
				/* We hit the end of the string. No colons though... probably a MODE. */
				*ptr = '\0';
				return (argc + 1);

			case ':':
				if (lastchar == c_SPACE) {

					/* This is the last parameter. Copy the remaining buffer into it and we're done. */
					while (*buffer != '\0')
						*ptr++ = *buffer++;

					/* Get rid of the extra spaces at the end, if any.
					   Commented: breaks users' real names.
					while (*(ptr - 1) == c_SPACE)
						--ptr;
					*/

					*ptr = '\0';

					return (argc + 1);
				}

				/* This colon is not at the beginning of a param, so it's in a key. Fall... */

			default:
				/* Copy this char into the current param buffer. */
				*ptr++ = c;
				break;
		}

		lastchar = c;
	}
}


/*********************************************************
 * Public code                                           *
 *********************************************************/

/*********************************************************
 * process_parse()                                       *
 *                                                       *
 * Main processing routine. Takes the string in          *
 * "serv_input_buffer" (global variable) and does        *
 * something appropriate with it.                        *
 *********************************************************/

void process_parse() {

	char	source[HOSTSIZE];
	char	command[IRCBUFSIZE];
	char	*ptr, *buffer;
	Message	*msg;

	TRACE_MAIN_FCLT(FACILITY_PROCESS);

	memset(source, 0, sizeof(source));

	LOG_DEBUG("Received: %s", serv_input_buffer);

	++total_recvM;

	TRACE_MAIN();

	/* Stiamo monitorando il buffer di input? */
	if (conf_monitor_inputbuffer == TRUE) {

		if (IS_NULL(debug_monitor_inputbuffer_filter) || str_match_wild_nocase(debug_monitor_inputbuffer_filter, serv_input_buffer))
			LOG_DEBUG_SNOOP("IB: %s", serv_input_buffer);
	}

	buffer = serv_input_buffer;

	TRACE_MAIN();

	/* Split the buffer into pieces. */
	if (*buffer == c_COLON) {

		ptr = source;

		++buffer;
		TRACE_MAIN();

		while (*buffer != c_SPACE && *buffer != c_NULL)
			*ptr++ = *buffer++;

		*ptr = c_NULL;
	}

	TRACE_MAIN();

	if (IS_NULL(buffer) || IS_EMPTY_STR(buffer)) {

		LOG_DEBUG_SNOOP("Invalid IB: %s", serv_input_buffer);
		return;
	}

	TRACE_MAIN();

	while (*buffer == c_SPACE)
		++buffer;

	memset(command, 0, sizeof(command));

	ptr = command;

	while (*buffer != c_SPACE && *buffer != c_NULL)
		*ptr++ = *buffer++;

	*ptr = c_NULL;

	if (IS_EMPTY_STR(command)) {

		LOG_DEBUG_SNOOP("No command in IB: %s", serv_input_buffer);
		return;
	}

	/* No need to fill argv's if this message is unknown... */
	if (IS_NOT_NULL(msg = find_message(command))) {

		/* ...or if it's going to be ignored. */
		if (IS_NOT_NULL(msg->func)) {

			int i, argc;

			/* Skip leading spaces, if any. */
			while (*buffer == c_SPACE)
				++buffer;

			TRACE_MAIN();
			if (IS_NOT_NULL(buffer) && IS_NOT_EMPTY_STR(buffer))
				argc = process_split_message(buffer);
			else
				argc = 0;	/* This is valid (BURST, etc.)! */

			dispatched = TRUE;

			TRACE_MAIN_FCLT(FACILITY_DISPATCHED);

			++(msg->usage_count);
			msg->func(source, argc, argv);

			TRACE_MAIN();
			dispatched = FALSE;

			/* Clear args we used. */
			for (i = 0; i < argc; ++i)
				memset(argv[i], 0, IRCBUFSIZE);
		}
	}
	else
		LOG_DEBUG_SNOOP("Unknown message from server: %s", serv_input_buffer);
}


/*********************************************************
 * This function is called by DebugServ when injecting a *
 * command manually.                                     *
 *********************************************************/

void process_debug_inject(CSTR buffer) {

	if (IS_NULL(buffer) || IS_EMPTY_STR(buffer))
		return;

	if (IS_NOT_NULL(debug_inject_buffer))
		mem_free(debug_inject_buffer);

	debug_inject_buffer = str_duplicate(buffer);
	debug_inject = TRUE;
}


/*********************************************************
 * This function is called by the main loop and checks   *
 * if there is a command to inject. If there is one, it  *
 * is passed on to the parser.                           *
 *********************************************************/

void process_check_debug_inject() {

	if (IS_NOT_NULL(debug_inject_buffer)) {

		str_copy_checked(debug_inject_buffer, serv_input_buffer, sizeof(serv_input_buffer));
		process_parse();

		mem_free(debug_inject_buffer);
		debug_inject_buffer = NULL;
		debug_inject = FALSE;
	}
}
