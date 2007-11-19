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


#ifndef SRV_DATAFILES_H
#define SRV_DATAFILES_H


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern int get_file_version(FILE *f, const char *filename);
extern int write_file_version(FILE *f, const char *filename, int version);
extern FILE *open_db_read(const char *service, const char *filename);
extern FILE *open_db_write(const char *service, const char *filename, int version);
extern void close_db(FILE *dbfile, const char *filename);
extern void backup_database(void);
extern char *read_string(FILE *f, const char *filename);
extern char *write_string(const char *string, FILE *f, const char *filename);


#endif /* SRV_DATAFILES_H */
