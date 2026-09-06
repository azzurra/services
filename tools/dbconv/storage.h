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

#ifndef DBCONV_STORAGE_H
#define DBCONV_STORAGE_H


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef long                STGHANDLE;
typedef unsigned short int  STGVERSION;


enum _STG_RESULT {  stgSuccess = 0, stgBeginOfSection, stgEndOfSection, stgUnknownError, stgBadParam, stgNotFound,
                    stgBadFD, stgOutOfSpace, stgAccessDenied, stgReadOnly, stgWriteOnly, stgReadError, stgWriteError,
                    stgInvalidStorage, stgBadSize, stgBadRecord, stgOldStorage, stgCantBackup, stgCantRestore,
                    stgCRCError, stgEndOfData };

typedef enum _STG_RESULT STG_RESULT;


/*********************************************************
 * Constants                                             *
 *********************************************************/

// Storage creation flags
#define SF_NOFLAGS          0x00000000
#define SF_READ_ACCESS      0x00000001
#define SF_WRITE_ACCESS     0x00000002
#define SF_CRC_CHECK        0x00000010
#define SF_64BIT_RECORDS    0x00000020

#define STG_INVALID_VERSION ((STGVERSION) 0)

#define STG_INVALID_HANDLE  ((STGHANDLE) 0)


/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern STG_RESULT   stg_last_error;


/*********************************************************
 * Public code                                           *
 *********************************************************/

STG_RESULT stg_open(const char *path, STGHANDLE *handle);
STG_RESULT stg_close(STGHANDLE handle, const char *path);

STGVERSION stg_data_version(STGHANDLE handle);
bool stg_is64bit(STGHANDLE handle);
STG_RESULT stg_start_section(STGHANDLE handle);
STG_RESULT stg_end_section(STGHANDLE handle);

STG_RESULT stg_read_record(STGHANDLE handle, unsigned char *record, size_t record_size);

STG_RESULT stg_read_string(STGHANDLE handle, char **string, size_t *length);

#define stg_get_last_error()        stg_last_error
#define stg_reset_last_error()      stg_last_error = stgSuccess


const char *stg_result_to_string(STG_RESULT result);

#endif /* DBCONV_STORAGE_H */
