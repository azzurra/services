/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* datafiles.h - Database support
*
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
*
*/


#ifndef DBCONV_DATAFILES_H
#define DBCONV_DATAFILES_H

#define DATAFILE64 0x80

/*********************************************************
 * Public code                                           *
 *********************************************************/

extern int get_file_version(FILE *f, const char *filename, uint8_t *flags);
extern FILE *open_db_read(const char *service, const char *filename);
extern void close_db(FILE *dbfile, const char *filename);
extern char *read_string(FILE *f, const char *filename);

#endif /* DBCONV_DATAFILES_H */
