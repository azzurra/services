/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* datafiles.c - database files handling routines
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
#include "../inc/send.h"
#include "../inc/memory.h"
#include "../inc/datafiles.h"


/*********************************************************/

/* Return the version number on the file. Panic if there is no version
* number or the number doesn't make sense (i.e. less than 1 or greater
* than FILE_VERSION).
*/

int get_file_version(FILE *f, const char *filename) {

	int version = fgetc(f)<<24 | fgetc(f)<<16 | fgetc(f)<<8 | fgetc(f);

	if (ferror(f))
		fatal_error(FACILITY_DATABASE, __LINE__, "Error reading version number on %s", filename);

	else if (version > FILE_VERSION || version < 1)
		fatal_error(FACILITY_DATABASE, __LINE__, "Invalid version number (%d) on %s", version, filename);

	return version;
}

/*********************************************************/

/* Write the current version number to the file. Return 0 on error, 1 on success. */

int write_file_version(FILE *f, const char *filename) {

	if (fputc(FILE_VERSION>>24 & 0xFF, f) < 0 || fputc(FILE_VERSION>>16 & 0xFF, f) < 0 ||
		fputc(FILE_VERSION>> 8 & 0xFF, f) < 0 || fputc(FILE_VERSION & 0xFF, f) < 0) {

		log_stderr("Error writing version number on %s", filename);
		return 0;
	}

	return 1;
}

/*********************************************************/

FILE *open_db_read(const char *service, const char *filename) {

	FILE *f = fopen(filename, "r");

	if (!f) {

		if (errno != ENOENT)
			log_stderr("Can't read %s database %s", service, filename);

		return NULL;
	}

	return f;
}

/*********************************************************/

FILE *open_db_write(const char *service, const char *filename) {

	char namebuf[MAX_PATH + 1];
	FILE *f;

	memset(namebuf, 0, MAX_PATH + 1);
	snprintf(namebuf, sizeof(namebuf), "%s.save", filename);

	if (!*namebuf || str_equals(namebuf, filename)) {

		errno = ENAMETOOLONG;
		log_stderr("Can't back up %s database %s", service, filename);
		return NULL;
	}
	unlink(namebuf);

	if (rename(filename, namebuf) < 0 && errno != ENOENT) {

		static unsigned int walloped = 0;

		if (!walloped) {

			walloped++;
			send_globops(NULL, "Can't back up %s database %s", service, filename);
		}

		log_stderr("Can't back up %s database %s", service, filename);

#ifndef NO_BACKUP_OKAY
		return NULL;
#endif
	}

	f = fopen(filename, "w");

	if (!f || !write_file_version(f, filename)) {

		static unsigned int walloped = 0;

		if (!walloped) {

			walloped++;
			send_globops(NULL, "Can't write to %s database %s", service, filename);
		}

		log_stderr("Can't write to %s database %s", service, filename);

		if (f) {

			fclose(f);
			unlink(filename);
		}

		if (rename(namebuf, filename) < 0
#ifdef NO_BACKUP_OKAY
			&& errno != ENOENT
#endif
			) {

			/* Better quit; something might be seriously wrong */
			fatal_error(FACILITY_DATABASE, __LINE__, "Cannot restore backup copy of %s", filename);
		}

		return NULL;
	}

	return f;
}

/*********************************************************/

/* Close a database file. If the file was opened for write, remove the
* backup we (may have) created earlier.
*/

void close_db(FILE *dbfile, const char *filename) {

	int flags;

	flags = fcntl(fileno(dbfile), F_GETFL);

	if ((flags != -1) && (((flags & O_ACCMODE) == O_WRONLY) || ((flags & O_ACCMODE) == O_RDWR))) {

		char namebuf[MAX_PATH+1];

		snprintf(namebuf, sizeof(namebuf), "%s.save", filename);

		if (*namebuf && str_not_equals(namebuf, filename))
			remove(namebuf);
	}

	fclose(dbfile);
}

/*********************************************************/

void backup_database() {

	if (chdir("./backup") < 0) {

		system("mkdir ./backup");
		chdir("./backup");
	}

	system("cp -f ../*.db .");
	chdir("..");

	send_globops(NULL, "Database Back-Up Complete");
	return;
}

/*********************************************************/

/* read_string, write_string:
 *	Read a string from a file, or write a string to a file, with the
 *	string length prefixed as a two-byte big-endian integer. The
 *	filename is passed in so that it can be reported in the log file
 *	(and possibly with globops) if an error occurs.
 */

char *read_string(FILE *f, const char *filename) {

	char *string;
	size_t len;

	len = fgetc(f) * 256 + fgetc(f);

	string = mem_malloc(len);

	if (len != fread(string, 1, len, f))
		fatal_error(FACILITY_DATABASE, __LINE__, "Read error on file: %s", filename);

	return string;
}

/*********************************************************/

char *write_string(const char *string, FILE *f, const char *filename) {

	size_t len;

	len = str_len(string) + 1;		/* Include trailing null */

	fputc(len / 256, f);
	fputc(len & 255, f);

	if (len != fwrite(string, 1, len, f))
		fatal_error(FACILITY_DATABASE, __LINE__, "Write error on file: %s", filename);

	return (char *)string;
}

