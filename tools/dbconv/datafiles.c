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

#include "dbconv.h"

/*********************************************************/

/* Return the version number on the file. Panic if there is no version
* number or the number doesn't make sense (i.e. less than 1 or greater
* than FILE_VERSION).
* first byte will be used for flags, we don't need 4byte for a version --Sonic
*/

int get_file_version(FILE *f, const char *filename, uint8_t *flags) {

    *flags = fgetc(f);
    int version = fgetc(f)<<16 | fgetc(f)<<8 | fgetc(f);

    if (ferror(f))
        mowgli_log_fatal("Error reading version number on %s", filename);

    else if (version > FILE_VERSION_MAX || version < 1)
        mowgli_log_fatal("Invalid version number (%d) on %s", version, filename);

    return version;
}

/*********************************************************/

FILE *open_db_read(const char *service, const char *filename) {

    FILE *f = fopen(filename, "r");

    if (!f) {

        if (errno != ENOENT)
            mowgli_log_error("Can't read %s database %s", service, filename);

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

    fclose(dbfile);
}

/*********************************************************/

/* read_string, write_string:
 *  Read a string from a file, or write a string to a file, with the
 *  string length prefixed as a two-byte big-endian integer. The
 *  filename is passed in so that it can be reported in the log file
 *  (and possibly with globops) if an error occurs.
 */

char *read_string(FILE *f, const char *filename) {

    char *string;
    size_t len;

    len = fgetc(f) * 256 + fgetc(f);

    string = mowgli_alloc(len);

    if (len != fread(string, 1, len, f))
        mowgli_log_fatal("Read error on file: %s", filename);

    return string;
}
