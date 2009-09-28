/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* main.c - startup file
*
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
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
#include "../inc/process.h"
#include "../inc/sockutil.h"
#include "../inc/datafiles.h"
#include "../inc/lang.h"
#include "../inc/users.h"
#include "../inc/channels.h"
#include "../inc/misc.h"
#include "../inc/crypt_userhost.h"
#include "../inc/signals.h"
#include "../inc/oper.h"
#include "../inc/conf.h"
#include "../inc/regions.h"
#include "../inc/main.h"
#include "../inc/akill.h"
#include "../inc/debugserv.h"
#include "../inc/timeout.h"

#ifdef USE_SERVICES
#include "../inc/nickserv.h"
#include "../inc/helpserv.h"
#include "../inc/chanserv.h"
#include "../inc/memoserv.h"
#include "../inc/operserv.h"
#include "../inc/rootserv.h"
#include "../inc/spam.h"
#include "../inc/trigger.h"
#include "../inc/ignore.h"
#include "../inc/sxline.h"
#include "../inc/reserved.h"
#include "../inc/blacklist.h"
#include "../inc/tagline.h"
#endif

#ifdef USE_SOCKSMONITOR
#include "../inc/cybcop.h"
#endif

#ifdef USE_STATS
#include "../inc/seenserv.h"
#include "../inc/statserv.h"
#endif

#ifdef HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif


/*********************************************************
 * Global Variables                                      *
 *********************************************************/

BOOL				global_running = FALSE;		/* service up and running */
BOOL				global_force_save = FALSE;	/* forzare il salvataggio dei dati */
force_quit_values	global_force_quit = dont_quit;	/* forzare il quit o il restart dei servizi */

/* Set to TRUE if we are to quit */
BOOL quitting = FALSE;

/* Global buffer for general usage */
char misc_buffer[MISC_BUFFER_SIZE];

/* Input buffer - global, so we can dump it if something goes wrong */
char serv_input_buffer[BUFSIZE];

/* CAPABs enabled */
char CAPAB[IRCBUFSIZE];

/* At what time were we started? */
time_t start_time;

/* What C-time is it? */
time_t NOW;

/* Are we synched to network data? */
BOOL synched = FALSE;


/*********************************************************
 * Local Variables                                       *
 *********************************************************/

/* When should we backup our databases? */
int global_force_backup_count = 0;

/* Contains a message as to why services is terminating */
static char QUIT_MESSAGE[BUFSIZE];

/* How many database expirations did we go through? */
static unsigned long int expire_count = 1;

/* When is our next database update due? */
static time_t next_database_update;

/* Next routine check. */
static time_t next_expire_check;

#if defined(USE_SERVICES)
static time_t next_timeout_check;
#endif

#if defined(USE_STATS)
static time_t next_hour_check;
#endif


/*********************************************************
 * Initialization/cleanup routines:                      *
 *********************************************************/

/* Remove our PID file. Done at exit. */

static __inline__ void remove_pidfile(void) {

	remove(PID_FILE);
}

/*********************************************************/

/* Create our PID file and write the PID to it. */

static void write_pidfile(void) {

	FILE *pidfile;

	TRACE_FCLT(FACILITY_MAIN_WRITE_PIDFILE);

	pidfile = fopen(PID_FILE, "w");

	if (pidfile) {

		TRACE();
		fprintf(pidfile, "%d\n", getpid());
		fclose(pidfile);
		atexit(remove_pidfile);
	}
	else {

		TRACE();
		fprintf(stderr, "Warning: cannot write to PID file %s", PID_FILE);
		log_stderr("Warning: cannot write to PID file %s", PID_FILE);
	}
}

/*********************************************************/

static void capab_init(void) {

	memset(CAPAB, 0, sizeof(CAPAB));

	strcat(CAPAB, "CAPAB");

#ifdef ENABLE_CAPAB_TS3
	strcat(CAPAB, " TS3");
#endif
#ifdef ENABLE_CAPAB_NOQUIT
	strcat(CAPAB, " NOQUIT");
#endif
#ifdef ENABLE_CAPAB_SSJOIN
	strcat(CAPAB, " SSJOIN");
#endif
#ifdef ENABLE_CAPAB_BURST
	strcat(CAPAB, " BURST");
#endif
#ifdef ENABLE_CAPAB_UNCONNECT
	strcat(CAPAB, " UNCONNECT");
#endif
#ifdef ENABLE_CAPAB_ZIP
	strcat(CAPAB, " ZIP");
#endif
#ifdef ENABLE_CAPAB_NICKIP
	strcat(CAPAB, " NICKIP");
#endif
#ifdef ENABLE_CAPAB_TSMODE
	strcat(CAPAB, " TSMODE");
#endif
#ifdef ENABLE_CAPAB_DKEY
	strcat(CAPAB, " DKEY");
#endif
}

/*********************************************************/

/* Overall initialization routine. */

static BOOL initialize() {

	int pid;

	TRACE_MAIN_FCLT(FACILITY_MAIN_INIT);

	/* Chdir to Services data directory. */
	if (chdir(SERVICES_DIR) < 0) {

		fprintf(stderr, "chdir(%s): %s\n", SERVICES_DIR, strerror(errno));
		return FALSE;
	}

	if (chdir("./logs") < 0)
		system("mkdir ./logs");

	else {

		if (chdir("..") < 0) {

			fprintf(stderr, "Directory Structure Error... Aborting\n");
			return FALSE;
		}
	}

	time_init();

	/* Open logfile. */
	log_init();

	crypt_init();
	user_init();

	#ifdef USE_SERVICES	
	fprintf(stderr, "\nAzzurra IRC Services starting...");
	#endif

	#ifdef USE_SOCKSMONITOR
	fprintf(stderr, "\nAzzurra IRC Socks Monitor Services starting...");	
	#endif

	#ifdef USE_STATS
	fprintf(stderr, "\nAzzurra IRC Statistical Services starting...");
	#endif

	/* Load language files first. */
	if (!lang_load_conf())
		return FALSE;

	if (!lang_check_data_files())
		return FALSE;

	lang_start();
	TRACE_MAIN();

	region_init();

	/* Detach ourselves. */

	if ((pid = fork()) < 0) {

		perror("fork()");
		return FALSE;
	}
	else if (pid != 0) {

		fprintf(stderr, "\nRunning in background (pid: %d)\n\n", pid);
		exit(EXIT_SUCCESS);
	}

	if (setpgid(0, 0) < 0) {

		perror("setpgid()");
		return FALSE;
	}

	TRACE_MAIN();
	/* Write our PID to the PID file. */
	write_pidfile();

	TRACE_MAIN();
	/* Announce ourselves to the logfile. */
	if (CONF_SET_DEBUG || CONF_SET_READONLY) {

		#ifdef USE_SERVICES
		LOG_DEBUG("Services starting up (options:%s%s)", CONF_SET_DEBUG ? " debug" : "", CONF_SET_READONLY ? " readonly" : "");
		#endif

		#ifdef USE_SOCKSMONITOR
		LOG_DEBUG("Socks Monitor services starting up (options:%s%s)", CONF_SET_DEBUG ? " debug" : "", CONF_SET_READONLY ? " readonly" : "");
		#endif

		#ifdef USE_STATS
		LOG_DEBUG("Statistic services starting up (options:%s%s)", CONF_SET_DEBUG ? " debug" : "", CONF_SET_READONLY ? " readonly" : "");
		#endif
	}
	else {

		#ifdef USE_SERVICES
		LOG_DEBUG("Services starting up (normal mode)");
		#endif

		#ifdef USE_SOCKSMONITOR
		LOG_DEBUG("Socks Monitor services starting up (options:%s%s)", CONF_SET_DEBUG ? " debug" : "", CONF_SET_READONLY ? " readonly" : "");
		#endif

		#ifdef USE_STATS
		LOG_DEBUG("Statistic services starting up (options:%s%s)", CONF_SET_DEBUG ? " debug" : "", CONF_SET_READONLY ? " readonly" : "");
		#endif
	}

	TRACE_MAIN();
	start_time = NOW;

	/* If in read-only mode, close the logfile again. */
	if (CONF_SET_READONLY)
		log_done();

	#if defined(USE_SERVICES) || defined(USE_STATS)
	/* Allocating SJOIN memory */
	chan_init();
	#endif

	TRACE_MAIN();
	/* Set signal handlers. */
	signals_init();

	TRACE_MAIN();
	/* Read Configuration File */
	LOG_DEBUG("Searching for %s file", CONFIG_FILE);
	init_conf(FALSE);
	LOG_DEBUG("Successfully loaded services configuration");

	debugserv_init();

	#ifdef USE_SERVICES

	TRACE_MAIN();
	helpserv_init();
	nickserv_init();
	chanserv_init();
	memoserv_init();
	operserv_init();
	rootserv_init();
	spam_init();

	/* Load up databases */
	TRACE_MAIN();
	load_ns_dbase();
	TRACE_MAIN();
	load_cs_dbase();
	TRACE_MAIN();
	load_suspend_db();
	TRACE_MAIN();
	load_ms_dbase();
	TRACE_MAIN();
	rootserv_db_load();
	TRACE_MAIN();
	spam_db_load();
	TRACE_MAIN();
	trigger_db_load();
	TRACE_MAIN();
	ignore_db_load();
	TRACE_MAIN();
	sxline_db_load(SXLINE_TYPE_GLINE);
	TRACE_MAIN();
	sxline_db_load(SXLINE_TYPE_QLINE); 
	TRACE_MAIN();
	reserved_db_load(); 
	TRACE_MAIN();
	blacklist_db_load(); 
	TRACE_MAIN();
	tagline_db_load();
	#endif


	#ifdef USE_SOCKSMONITOR

	/* Initialize Socks Monitor */
	monitor_init();
	TRACE_MAIN();

	/* Load up databases */
	load_monitor_db();
	TRACE_MAIN();

	load_apm_dbase();
	TRACE_MAIN();
	#endif


	#if defined(USE_SERVICES) || defined(USE_SOCKSMONITOR)
	akill_db_load();
	TRACE_MAIN();
	#endif


	#ifdef USE_STATS
	statserv_init(start_time);
	seenserv_init(start_time);
	TRACE_MAIN();

	statserv_chanstats_db_load();
	TRACE_MAIN();

	statserv_servstats_db_load();
	TRACE_MAIN();

	seenserv_db_load();
	TRACE_MAIN();
	#endif

	regions_db_load();
	TRACE_MAIN();

	oper_db_load();
	TRACE_MAIN();

	LOG_DEBUG("Databases loaded");

	/* Connect to the remote server */
	if (!socket_connect(CONF_REMOTE_SERVER, CONF_REMOTE_PORT)) {

		log_stderr("Error %d connecting to %s:%u [%s]", errno, CONF_REMOTE_SERVER, CONF_REMOTE_PORT, strerror(errno));
		return FALSE;
	}

	capab_init();
	servers_init();
	process_init();

	TRACE_MAIN();

	send_cmd("PASS %s :TS", CONF_REMOTE_PASSWORD);
	send_cmd("SVINFO 5 3 0 :%ld", time(NULL));
	send_cmd(CAPAB);
	send_cmd("SERVER %s 1 :%s", CONF_SERVICES_NAME, CONF_SERVICES_DESC);

	TRACE_MAIN();

	switch (socket_read(serv_input_buffer, sizeof(serv_input_buffer))) {

		default:
		case socketError:
			/* We got an error when trying to read from our socket. Report it and quit. */
			log_stderr("Read error %d reading from server: %s", errno, strerror(errno));
			return FALSE;

		case socketTimeout:
			/* Connection timed out. Report it and quit. */
			log_stderr("Connection timed out while trying to read from server.");
			return FALSE;

		case socketSuccess:
			/* Make sure our uplink did not reject us. */
			if (str_equals_partial(serv_input_buffer, "ERROR", 5)) {

				log_stderr("Error returned from remote server: %s", serv_input_buffer);
				return FALSE;
			}
			break;
	}

	#ifdef USE_SERVICES	
	/* Send SQLines and SGLines. */
	sxline_burst_send();
	TRACE_MAIN();

	/* Send SPAM Lines. */
	spam_burst_send();
	TRACE_MAIN();
	#endif

	/* Success! - wee! */
	memset(QUIT_MESSAGE, 0, sizeof(QUIT_MESSAGE));
	LOG_DEBUG("Services successfully loaded");

	return TRUE;
}

/*********************************************************/

void services_cleanup() {

	TRACE_MAIN();

	#ifdef USE_SERVICES
	memoserv_terminate();
	chanserv_terminate();
	nickserv_terminate();
	rootserv_terminate();
	spam_terminate();
	reserved_terminate();
	#endif

	TRACE_MAIN();

	#ifdef USE_STATS
	seenserv_terminate();
	statserv_terminate();
	#endif

	TRACE_MAIN();

	#if defined(USE_SERVICES) || defined(USE_STATS)
	chan_terminate();
	#endif

	TRACE_MAIN();

	#ifdef USE_SOCKSMONITOR
	free_apm_list();
	#endif

	TRACE_MAIN();
	lang_unload_all();

	user_terminate();
	crypt_done();

	TRACE_MAIN();
	log_done();

	region_terminate();
	process_terminate();
}

/*********************************************************/

/* Main routine. */

#if defined(USE_SERVICES) && !defined(NEW_SOCK)

void *old_alarm_handler = NULL;

static void timeout_check_handler(int sig_unused) {

	TRACE_FCLT(FACILITY_MAIN_TIMEOUT_CHECK_HANDLER);

	to_dispatched = TRUE; /* controllo timeout */

	timeout_check(NOW);

	akill_expire();
	ignore_expire();

	next_timeout_check = NOW + CONF_TIMEOUT_CHECK;

	CONF_TIMEOUT_STARTUP_DELTA = 0;
	alarm(CONF_TIMEOUT_CHECK);

	to_dispatched = FALSE;
}
#endif

/*********************************************************/

void database_expire(const time_t now) {

	if (CONF_DISPLAY_UPDATES)
		send_globops(NULL, "Running Database Store & Expire #%d", expire_count);

	++expire_count;

	#ifdef USE_SERVICES			
	TRACE_MAIN();
	expire_nicks();
	TRACE_MAIN();
	expire_chans();
	TRACE_MAIN();
	ignore_expire();
	TRACE_MAIN();
	expire_memos();
	#endif

	#ifdef USE_SOCKSMONITOR
	TRACE_MAIN();
	proxy_expire(now);
	#endif

	#ifdef USE_STATS
	TRACE_MAIN();
	expire_stats();
	TRACE_MAIN();
	seenserv_expire_records();
	#endif

	#if defined(USE_SERVICES) || defined(USE_SOCKSMONITOR)
	TRACE_MAIN();
	akill_expire();
	#endif
}

/*********************************************************/

void database_store() {

	TRACE_MAIN();
	regions_db_save();

	#ifdef USE_SERVICES			
	TRACE_MAIN();
	save_ns_dbase();
	TRACE_MAIN();
	save_cs_dbase();
	TRACE_MAIN();
	save_suspend_db();
	TRACE_MAIN();
	save_ms_dbase();
	TRACE_MAIN();
	sxline_burst_send();
	TRACE_MAIN();
	spam_burst_send();
	TRACE_MAIN();
	rootserv_db_save();
	TRACE_MAIN();
	spam_db_save();
	TRACE_MAIN();
	trigger_db_save();
	TRACE_MAIN();
	ignore_db_save();
	TRACE_MAIN();
	sxline_db_save(SXLINE_TYPE_GLINE); 
	TRACE_MAIN();
	sxline_db_save(SXLINE_TYPE_QLINE);
	TRACE_MAIN();
	reserved_db_save();
	TRACE_MAIN();
	blacklist_db_save();
	TRACE_MAIN();
	tagline_db_save();
	#endif

	#if defined(USE_SERVICES) || defined(USE_SOCKSMONITOR)
	TRACE_MAIN();
	akill_db_save();
	#endif

	#ifdef USE_SOCKSMONITOR
	TRACE_MAIN();
	save_monitor_db();
	TRACE_MAIN();
	save_apm_dbase();
	#endif

	#ifdef USE_STATS
	TRACE_MAIN();
	statserv_servstats_db_save();
	TRACE_MAIN();
	statserv_chanstats_db_save();
	TRACE_MAIN();
	seenserv_db_save();
	#endif

	TRACE_MAIN();
	oper_db_save();

	TRACE_MAIN();

	if ((CONF_DATABASE_BACKUP_FREQUENCY > 0) && (++global_force_backup_count > CONF_DATABASE_BACKUP_FREQUENCY)) {

		global_force_backup_count = 0;
		backup_database();
	}
}

/*********************************************************/

int main(int ac, char **av, char **envp) {

	#ifdef HAVE_SYS_RESOURCE_H
	struct rlimit rlim; /* Resource limits. */

	/* Set corefilesize to maximum. */
	if (!getrlimit(RLIMIT_CORE, &rlim)) {

		rlim.rlim_cur = rlim.rlim_max;
		setrlimit(RLIMIT_CORE, &rlim);
	}
	#endif

	/* Were we run with a path? */
	if (av[0][0] != '.' && strchr(av[0], '/')) {

		char *ptr;
		char buf[MAX_PATH];

		str_copy_checked(av[0], buf, sizeof(buf));

		ptr = strrchr(buf, '/');

		*ptr = '\0';

		chdir(buf);
	}

	time(&NOW);

	/* Initialization stuff. */
	trace_init();

	TRACE_MAIN_FCLT(FACILITY_MAIN);

	if (!initialize())
		return EXIT_FAILURE;

	TRACE_MAIN();

	/* We have a line left over from earlier, so process it first. */
	process_parse();
	
	next_database_update = NOW + CONF_DATABASE_UPDATE_FREQUENCY;
	next_expire_check = NOW + ONE_MINUTE;

	#ifdef USE_STATS
	next_hour_check = NOW + ONE_HOUR;
	#endif

	TRACE_MAIN();

	/* Inizializzazione conclusa */
	global_running = TRUE;

	#if !defined(NEW_SOCK) && defined(USE_SERVICES)
	if ((old_alarm_handler = signal(SIGALRM, timeout_check_handler)) == SIG_ERR)
		fprintf(stderr, "main() signal(SIGALRM, timeout_check_handler) == SIG_ERR !!!\n");

	alarm(CONF_TIMEOUT_STARTUP_DELTA); /* per i primi 3 minuti non controllare i timeout */
	#endif

	TRACE_MAIN();

	/*** Main loop. ***/
	while (quitting == FALSE) {

		time(&NOW);

		TRACE_MAIN_FCLT(FACILITY_MAIN_LOOP);

		*serv_input_buffer = 0;

		if (!CONF_SET_READONLY && (global_force_save || NOW >= next_database_update)) {

			/* First, check for expired nicks/channels */

			TRACE_MAIN();

			LOG_DEBUG("debug: Running expire routines");
			database_expire(NOW);

			TRACE_MAIN();
			LOG_DEBUG("!! Database Expire Completed, now saving databases");
			
			/* Now actually save stuff */
			database_store();
			
			TRACE_MAIN();

			LOG_DEBUG("!! Databases Stored");

			global_force_save = FALSE;

			next_database_update = NOW + CONF_DATABASE_UPDATE_FREQUENCY;

			#ifdef USE_SERVICES
			tagline_show(NOW);
			#else
			send_globops(NULL, "Completed Database Write (%d secs)", (time(NULL) - NOW));
			#endif
		}

		TRACE_MAIN();

		if (global_force_quit != dont_quit)
			break; /* uscire dal loop principale */

		TRACE_MAIN();

		#ifdef USE_STATS
		if (NOW >= next_hour_check) {

			TRACE_MAIN();

			update_hour();
			next_hour_check = NOW + ONE_HOUR;
		}
		#endif

		#if defined(NEW_SOCK) && defined(USE_SERVICES)
		if (NOW >= next_timeout_check) {

			to_dispatched = TRUE;
			timeout_check(NOW);
			to_dispatched = FALSE;

			next_timeout_check = NOW + CONF_TIMEOUT_CHECK;
		}
		#endif

		if (NOW >= next_expire_check) {

			#if defined(USE_SERVICES) || defined(USE_SOCKSMONITOR)
			akill_expire();
			#endif

			#ifdef USE_SOCKSMONITOR
			proxy_expire(NOW);
			#endif

			#ifdef USE_SERVICES
			ignore_expire();
			#endif

			#ifdef USE_STATS
			update_server_averages();
			update_averages();
			#endif

			next_expire_check = NOW + ONE_MINUTE;
		}

		TRACE_MAIN();
		time_check(NOW);

		TRACE_MAIN();
		switch (socket_read(serv_input_buffer, sizeof(serv_input_buffer))) {

			default:
			case socketError:
				/* We got an error when trying to read from our socket. Report it and quit. */
				snprintf(QUIT_MESSAGE, sizeof(QUIT_MESSAGE), "Read error %d from server: %s", errno, strerror(errno));
				fprintf(stderr, "\nQuitting: %s\n", QUIT_MESSAGE);

				/* Save our data before quitting. */
				database_store();

				/* Prepare for quitting. */
				global_running = FALSE;
				quitting = TRUE;
				break;

			case socketTimeout:
				/* Nothing to read from our socket (i.e. nothing happened on the network). Ignore and repeat. */
				break;

			case socketSuccess:
				/* Data received successfully. Pass it on to the parser. */
				TRACE_MAIN();
				process_parse();

				TRACE_MAIN();
				if (debug_inject)
					process_check_debug_inject();

				TRACE_MAIN();
				break;
		}
	}

	/* Quitting... */

	TRACE_MAIN();

	#if !defined(NEW_SOCK) && defined(USE_SERVICES)
	/* Disattivazione timeout-checker */
	alarm(0);

	if (signal(SIGALRM, old_alarm_handler) == SIG_ERR)
		fprintf(stderr, "main() signal(SIGALRM, old_alarm_handler) == SIG_ERR !!!\n");
	#endif

	TRACE_MAIN();

	/* Check for restart instead of exit. */
	if (global_force_quit == quit_and_restart) {

		TRACE_MAIN();

		LOG_DEBUG("Restarting");

		TRACE_MAIN();

		if (!*QUIT_MESSAGE)
			snprintf(QUIT_MESSAGE, sizeof(QUIT_MESSAGE), "Catched SIGHUP: restarting services.");

		TRACE_MAIN();

		send_cmd("SQUIT %s :%s", CONF_SERVICES_NAME, QUIT_MESSAGE);

		TRACE_MAIN();

		sleep(1);

		socket_disconnect();

		if (chdir("..") < 0)
			fatal_error(FACILITY_MAIN, __LINE__, "Unknown error in directory structure (attemped re-loading binary)");

		TRACE_MAIN();

		execve(SERVICES_BIN, av, envp);

		TRACE_MAIN();

		log_stderr("Restart failed");
		return EXIT_FAILURE;
	}

	TRACE_MAIN_FCLT(FACILITY_MAIN);

	/* Disconnect and exit. */

	if (IS_EMPTY_STR(QUIT_MESSAGE))
		snprintf(QUIT_MESSAGE, sizeof(QUIT_MESSAGE), "Terminating, reason unknown.");

	TRACE_MAIN();

	LOG_DEBUG("Quitting: %s", QUIT_MESSAGE);

	TRACE_MAIN();

	if (global_running) {

		send_cmd("SQUIT %s :%s", CONF_SERVICES_NAME, QUIT_MESSAGE);
		sleep(1);
	}

	TRACE_MAIN();

	socket_disconnect();

	TRACE_MAIN();

	/* Free up memory. */
	services_cleanup();

	TRACE_MAIN();
	return EXIT_SUCCESS;
}

/*********************************************************/

void handle_quit(const char *source, User *callerUser, ServiceCommandData *data) {

	if (data->operMatch) {

		LOG_SNOOP(data->agent->nick, "%s Q -- by %s (%s@%s)", data->agent->shortNick, callerUser->nick, callerUser->username, callerUser->host);
		log_services(data->agent->logID, "Q -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);

		snprintf(QUIT_MESSAGE, sizeof(QUIT_MESSAGE), "QUIT command received from \2%s\2", callerUser->nick);
	}
	else {

		LOG_SNOOP(data->agent->nick, "%s Q -- by %s (%s@%s) through %s", data->agent->shortNick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
		log_services(data->agent->logID, "Q -- by %s (%s@%s) through %s", callerUser->nick, callerUser->username, callerUser->host, data->operName);

		snprintf(QUIT_MESSAGE, sizeof(QUIT_MESSAGE), "QUIT command received from \2%s\2 (through \2%s\2)", callerUser->nick, data->operName);
	}

	send_notice_to_user(data->agent->nick, callerUser, "Quitting services.");
	quitting = TRUE;
}

/*********************************************************/

void handle_shutdown(const char *source, User *callerUser, ServiceCommandData *data) {

	if (data->operMatch) {

		LOG_SNOOP(data->agent->nick, "%s S -- by %s (%s@%s)", data->agent->shortNick, callerUser->nick, callerUser->username, callerUser->host);
		log_services(data->agent->logID, "S -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);

		snprintf(QUIT_MESSAGE, sizeof(QUIT_MESSAGE), "SHUTDOWN command received from \2%s\2", callerUser->nick);
	}
	else {

		LOG_SNOOP(data->agent->nick, "%s S -- by %s (%s@%s) through %s", data->agent->shortNick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
		log_services(data->agent->logID, "S -- by %s (%s@%s) through %s", callerUser->nick, callerUser->username, callerUser->host, data->operName);

		snprintf(QUIT_MESSAGE, sizeof(QUIT_MESSAGE), "SHUTDOWN command received from \2%s\2 (through \2%s\2)", callerUser->nick, data->operName);
	}

	send_notice_to_user(data->agent->nick, callerUser, "Shutting down services.");

	global_force_save = TRUE;
	global_force_quit = force_quit;
}

/*********************************************************/

void handle_restart(const char *source, User *callerUser, ServiceCommandData *data) {

	if (data->operMatch) {

		LOG_SNOOP(data->agent->nick, "%s RS -- by %s (%s@%s) [DataBase Saved]", data->agent->shortNick, callerUser->nick, callerUser->username, callerUser->host);
		log_services(data->agent->logID, "RS -- by %s (%s@%s)", callerUser->nick, callerUser->username, callerUser->host);

		snprintf(QUIT_MESSAGE, sizeof(QUIT_MESSAGE), "RESTART command received from \2%s\2", callerUser->nick);
	}
	else {

		LOG_SNOOP(data->agent->nick, "%s RS -- by %s (%s@%s) through %s [DataBase Saved]", data->agent->shortNick, callerUser->nick, callerUser->username, callerUser->host, data->operName);
		log_services(data->agent->logID, "RS -- by %s (%s@%s) through %s [DataBase Saved]", callerUser->nick, callerUser->username, callerUser->host, data->operName);

		snprintf(QUIT_MESSAGE, sizeof(QUIT_MESSAGE), "RESTART command received from \2%s\2 (through \2%s\2)", callerUser->nick, data->operName);
	}

	send_notice_to_user(data->agent->nick, callerUser, "Restarting services.");
	raise(SIGHUP);
}

/*********************************************************/

void handle_update(const char *source, User *callerUser, ServiceCommandData *data) {

	if (CONF_SET_READONLY) {

		send_notice_to_user(data->agent->nick, callerUser, "Unable to update while in read-only mode.");
		return;
	}

	if (data->operMatch) {

		LOG_SNOOP(data->agent->nick, "%s U -- by %s (%s@%s)", data->agent->shortNick, source, callerUser->username, callerUser->host);
		log_services(data->agent->logID, "U -- by %s (%s@%s)", source, callerUser->username, callerUser->host);

		send_globops(data->agent->nick, "\2%s\2 forced a database update", source);
	}
	else {

		LOG_SNOOP(data->agent->nick, "%s U -- by %s (%s@%s) through %s", data->agent->shortNick, source, callerUser->username, callerUser->host, data->operName);
		log_services(data->agent->logID, "U -- by %s (%s@%s) through %s", source, callerUser->username, callerUser->host, data->operName);

		send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) forced a database update", source, data->operName);
	}

	send_notice_to_user(data->agent->nick, callerUser, "Updating databases.");
	global_force_save = TRUE;
}

/*********************************************************/

void handle_uptime(const char *source, User *callerUser, ServiceCommandData *data) {

	char buffer[IRCBUFSIZE];

	if (data->operMatch) {

		LOG_SNOOP(data->agent->nick, "%s Up -- by %s (%s@%s)", data->agent->shortNick, source, callerUser->username, callerUser->host);
		log_services(data->agent->logID, "Up -- by %s (%s@%s)", source, callerUser->username, callerUser->host);
	}
	else {

		LOG_SNOOP(data->agent->nick, "%s Up -- by %s (%s@%s) through %s", data->agent->shortNick, source, callerUser->username, callerUser->host, data->operName);
		log_services(data->agent->logID, "Up -- by %s (%s@%s) through %s", source, callerUser->username, callerUser->host, data->operName);
	}

	send_notice_to_user(data->agent->nick, callerUser, "Current Uptime: %s", convert_time(buffer, sizeof(buffer), (NOW - start_time), LANG_DEFAULT));
}
