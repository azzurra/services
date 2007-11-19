/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* storage.h - Storage services
* 
*/

#ifndef SRV_STORAGE_H
#define SRV_STORAGE_H


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef int						STGHANDLE;
typedef unsigned short int		STGVERSION;


enum _STG_RESULT {	stgSuccess = 0, stgBeginOfSection, stgEndOfSection, stgUnknownError, stgBadParam, stgNotFound, 
					stgBadFD, stgOutOfSpace, stgAccessDenied, stgReadOnly, stgWriteOnly, stgReadError, stgWriteError, 
					stgInvalidStorage, stgBadSize, stgBadRecord, stgOldStorage, stgCantBackup, stgCantRestore, 
					stgCRCError, stgEndOfData };

typedef enum _STG_RESULT	STG_RESULT;


/*********************************************************
 * Constants                                             *
 *********************************************************/

// Storage creation flags
#define SF_NOFLAGS			0x00000000
#define SF_READ_ACCESS		0x00000001
#define SF_WRITE_ACCESS		0x00000002
#define SF_CRC_CHECK		0x00000010


#define	STG_INVALID_VERSION	((STGVERSION) 0)

#define STG_INVALID_HANDLE	((STGHANDLE) 0)


/*********************************************************
 * Global variables                                      *
 *********************************************************/

STG_RESULT	stg_last_error;


/*********************************************************
 * Public code                                           *
 *********************************************************/

STG_RESULT stg_open(CSTR path, STGHANDLE *handle);
STG_RESULT stg_create(CSTR path, flags_t flags, STGVERSION version, STGHANDLE *handle);
STG_RESULT stg_close(STGHANDLE handle, CSTR path);

__inline__ STGVERSION stg_data_version(STGHANDLE handle);

__inline__ STG_RESULT stg_start_section(STGHANDLE handle);
__inline__ STG_RESULT stg_end_section(STGHANDLE handle);

STG_RESULT stg_read_record(STGHANDLE handle, PBYTE record, size_t record_size);
STG_RESULT stg_write_record(STGHANDLE handle, PBYTE record, size_t record_size);

STG_RESULT stg_read_string(STGHANDLE handle, char **string, size_t *length);
__inline__ STG_RESULT stg_write_string(STGHANDLE handle, char *string);
STG_RESULT stg_write_strings(STGHANDLE handle, char **strings, size_t strings_count, int *error_index);


STG_RESULT stg_run_backup(void);


#define stg_get_last_error()		stg_last_error
#define stg_reset_last_error()		stg_last_error = stgSuccess


CSTR stg_result_to_string(STG_RESULT result);
void stg_report_sysinfo(CSTR sourceNick, CSTR caller);


#endif /* SRV_STORAGE_H */
