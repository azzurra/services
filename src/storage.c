/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* storage.c - Storage services
* 
*/

/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/memory.h"
#include "../inc/send.h"
#include "../inc/misc.h"
#include "../inc/storage.h"


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef struct _StorageHeader {

	char				signature[6];	/* STORAGE_SIGNATURE */
	STGVERSION			version;		/* STORAGE_CURRENT_VERSION */
	STGVERSION			data_version;
	flags_t				flags;			/* SF_* */
	time_t				last_save;

} StorageHeader;


typedef struct _StorageDescriptor {

	FILE			*fd;
	StorageHeader	header;
	flags_t			flags;

} StorageDescriptor;


typedef struct _RecordDescriptor {

	unsigned char		signature;
	tiny_flags_t		flags; // SRF_*
	unsigned short int	size;
	unsigned long int	crc;

} RecordDescriptor;



/*********************************************************
 * Constants                                             *
 *********************************************************/

#define STORAGE_SIGNATURE					"ASSTG"

#define	STORAGE_CURRENT_VERSION				10
#define	STORAGE_MIN_VERSION					10
#define	STORAGE_MAX_VERSION					STORAGE_CURRENT_VERSION

#define STORAGE_COMPATIBILITY_VERSION		7

#define STORAGE_RECORD_SIGNATURE_V1			93
#define STORAGE_CURRENT_RECORD_SIGNATURE	STORAGE_RECORD_SIGNATURE_V1

// RecordDescriptor.flags
#define RDF_TYPE_RECORD			0x01 // ------01
#define RDF_TYPE_START_SECTION	0x02 // ------10
#define RDF_TYPE_END_SECTION	0x03 // ------11
#define RDF_TYPE_MASK			0x03
#define RDF_CRC_CHECK			0x04 // -----1--


/*********************************************************
 * Global variables                                      *
 *********************************************************/

STG_RESULT	stg_last_error = stgSuccess;



/*********************************************************
 * Local variables                                       *
 *********************************************************/

#define stgVersionToSignature(v) (unsigned long int)((v << 24) | ((v & 0x0000FF00) << 8) | ((v & 0x00FF0000) >> 8) | ((v & 0xFF000000) >> 24))

static unsigned long int	stgCurrentVersionSignature = stgVersionToSignature(STORAGE_CURRENT_VERSION);
static unsigned long int	stgCompatibilityVersionSignature = stgVersionToSignature(STORAGE_COMPATIBILITY_VERSION);



/*********************************************************
 * Private code                                          *
 *********************************************************/


static STG_RESULT stg_write_section(STGHANDLE handle, BOOL start) {

	STG_RESULT	result = stgBadParam;

	if ((handle != 0)) {

		RecordDescriptor	rd = {STORAGE_CURRENT_RECORD_SIGNATURE, 0, 0, 0};
		StorageDescriptor	*sd = (StorageDescriptor *)handle;

		rd.flags = start ? RDF_TYPE_START_SECTION : RDF_TYPE_END_SECTION;

		result = (fwrite(&rd, sizeof(RecordDescriptor), 1, sd->fd) == 1) ? stgSuccess : stgWriteError;
	}

	return result;
}


/*********************************************************
 * Public code                                           *
 *********************************************************/


STG_RESULT stg_open(const char *path, STGHANDLE *handle) {

	STG_RESULT	result = stgBadParam;

	if (IS_NOT_NULL(path) && IS_NOT_NULL(handle)) {

		StorageDescriptor	*sd;

		*handle = STG_INVALID_HANDLE;

		sd = mem_calloc(1, sizeof(StorageDescriptor));

		sd->fd = fopen(path, s_OPENMODE_READONLY);

		if (IS_NOT_NULL(sd->fd)) {

			unsigned long int	storage_version;

			// storage version
			if (fread(&storage_version, sizeof(storage_version), 1, sd->fd) == 1) {

				if (storage_version == stgCurrentVersionSignature) {

					result = stg_read_record((STGHANDLE)sd, (PBYTE)&(sd->header), sizeof(StorageHeader));

					if (result == stgSuccess) {

						if ((sd->header.version < STORAGE_MIN_VERSION) || (sd->header.version > STORAGE_MAX_VERSION) ||
							str_not_equals(sd->header.signature, STORAGE_SIGNATURE))
							return stg_last_error = stgInvalidStorage;

						else {

							sd->flags = sd->header.flags;
							AddFlag(sd->flags, SF_READ_ACCESS);
							*handle = (STGHANDLE)sd;
							return stg_last_error = stgSuccess;	// done
						}
					}
					else
						return stg_last_error = stgReadError;
				}
				else {

					if (storage_version == stgCompatibilityVersionSignature) {
						
						*handle = (STGHANDLE)sd;
						return stg_last_error = stgOldStorage; // done
					}
					else
						return stg_last_error = stgInvalidStorage;
				}

			}
			else
				return stg_last_error = stgReadError;
		}
		else {

			switch (errno) {

				case EACCES:
					result = stgAccessDenied;
					break;

				case ENOENT:
					result = stgNotFound;
					break;

				case EINVAL:
				case EMFILE:
					result = stgReadError;
					break;

				default:
					result = stgUnknownError;
					break;
			}
		}
	}

	return stg_last_error = result;
}

STG_RESULT stg_create(const char *path, flags_t flags, STGVERSION version, STGHANDLE *handle) {

	STG_RESULT	result = stgBadParam;

	if (IS_NOT_NULL(path) && IS_NOT_NULL(handle) && (version != STG_INVALID_VERSION)) {

		StorageDescriptor	*sd;
		char				renamed_path[MAX_PATH + 1];


		*handle = STG_INVALID_HANDLE;

		snprintf(renamed_path, sizeof(renamed_path), "%s.save", path);
		if (!*renamed_path || str_equals(renamed_path, path)) {

			errno = ENAMETOOLONG;
			result = stgCantBackup;

		} else {

			unlink(renamed_path); // removing old backup (if any...)

			if ((rename(path, renamed_path) < 0) && (errno != ENOENT)) // saving old data
				result = stgCantBackup;

			else {

				// old data saved

				sd = mem_calloc(1, sizeof(StorageDescriptor));

				sd->fd = fopen(path, s_OPENMODE_WRITEONLY);
				if (IS_NOT_NULL(sd->fd)) {

					// storage version
					if (fwrite(&stgCurrentVersionSignature, sizeof(stgCurrentVersionSignature), 1, sd->fd) == 1) {

						sd->flags = flags | SF_WRITE_ACCESS;

						str_copy_checked(STORAGE_SIGNATURE, sd->header.signature, sizeof(sd->header.signature));
						sd->header.version = STORAGE_CURRENT_VERSION;
						sd->header.data_version = version;
						sd->header.flags = flags;
						sd->header.last_save = time(NULL);

						*handle = (STGHANDLE)sd;
						result = stg_write_record(*handle,(PBYTE) &(sd->header), sizeof(StorageHeader));

						if (result != stgSuccess) {

							fclose(sd->fd);
							unlink(path);

							// restoring old data ...
							if (rename(renamed_path, path) < 0)
								// failed !
								result = stgCantRestore;
						}
						// done
						return stg_last_error = result;

					} else
						result = stgWriteError;

				} else {
					switch (errno) {

						case EACCES:
							result = stgAccessDenied;
							break;

						case ENOENT:
							result = stgNotFound;
							break;

						case EEXIST:
						case EINVAL:
						case EMFILE:
							result = stgWriteError;
							break;

						default:
							result = stgUnknownError;
							break;
					}
				}
			}
		}
	}

	return stg_last_error = result;
}


STG_RESULT stg_close(STGHANDLE handle, const char *path) {

	STG_RESULT	result = stgBadParam;

	if (handle != 0) {

		StorageDescriptor	*sd = (StorageDescriptor *)handle;

		if (FlagSet(sd->flags, SF_WRITE_ACCESS)) {

			char	renamed_path[MAX_PATH + 1];

			snprintf(renamed_path, sizeof(renamed_path), "%s.save", path);
			if (*renamed_path && str_not_equals(renamed_path, path))
				remove(renamed_path);
		}

		fclose(sd->fd);
		mem_free(sd);

		result = stgSuccess;	// done
	}

	return stg_last_error = result;
}


__inline__ STGVERSION stg_data_version(STGHANDLE handle) {
	return (handle != 0) ? ((StorageDescriptor *)handle)->header.data_version : STG_INVALID_VERSION;
}


__inline__ STG_RESULT stg_start_section(STGHANDLE handle) {
	return stg_last_error = stg_write_section(handle, TRUE);
}

__inline__ STG_RESULT stg_end_section(STGHANDLE handle) {
	return stg_last_error = stg_write_section(handle, FALSE);
}


STG_RESULT stg_read_record(STGHANDLE handle, PBYTE record, size_t record_size) {

	STG_RESULT	result = stgBadParam;

	if ((handle != 0)) {

		RecordDescriptor	rd;
		StorageDescriptor	*sd = (StorageDescriptor *)handle;
		int					bytes_read;


		bytes_read = fread(&rd, sizeof(RecordDescriptor), 1, sd->fd);

		if (bytes_read != 1)
			return stg_last_error = feof(sd->fd) ? stgEndOfData : stgReadError;	// done

		else {
			if ((bytes_read == 1) && (rd.signature == STORAGE_CURRENT_RECORD_SIGNATURE)) {


				switch (rd.flags & RDF_TYPE_MASK) {

					case RDF_TYPE_START_SECTION:
						return stg_last_error = stgBeginOfSection;


					case RDF_TYPE_END_SECTION:
						return stg_last_error = stgEndOfSection;


					case RDF_TYPE_RECORD:

						if (IS_NOT_NULL(record) && (record_size > 0)) {
							if (rd.size == record_size) {

								bytes_read = fread(record, record_size, 1, sd->fd);
								if (bytes_read != 1)
									result = feof(sd->fd) ? stgEndOfData : stgReadError;	// done

								else {

									if (bytes_read == 1) {

										if (FlagSet(rd.flags, RDF_CRC_CHECK)) {

											unsigned long int	crc = CRC32_INITIAL_VALUE;

											crc32(record, record_size, &crc);
											result = (crc == rd.crc) ? stgSuccess : stgCRCError;	// done
										
										} else
											result = stgSuccess;	// done

										return stg_last_error = result;
									

									} else
										result = stgBadFD;
								}
							} else
								result = stgBadSize;
						} else
							result = stgBadRecord;

						break;

					default:
						result = stgBadRecord;
				}
			} else
				result = stgBadRecord;
		}
	}

	return stg_last_error = result;
}

STG_RESULT stg_write_record(STGHANDLE handle, PBYTE record, size_t record_size) {

	if ((handle != 0) && IS_NOT_NULL(record) && (record_size > 0)) {

		RecordDescriptor	rd = {STORAGE_CURRENT_RECORD_SIGNATURE, RDF_TYPE_RECORD, 0, 0};
		StorageDescriptor	*sd = (StorageDescriptor *)handle;
		BOOL				write_done;


		rd.size = record_size;
		if (FlagSet(sd->flags, SF_CRC_CHECK)) {

			rd.crc = CRC32_INITIAL_VALUE;
			crc32(record, record_size, &(rd.crc));

			AddFlag(rd.flags, RDF_CRC_CHECK);
		}

		write_done = (fwrite(&rd, sizeof(RecordDescriptor), 1, sd->fd) == 1);
		if (write_done)
			write_done = fwrite(record, record_size, 1, sd->fd) == 1;

		if (write_done)
			return stg_last_error = stgSuccess;	// done
		else {

			switch (errno) {

				case EBADF:
					return stg_last_error = stgBadFD;

				case ENOSPC:
					return stg_last_error = stgOutOfSpace;

				default:
					return stg_last_error = stgWriteError;
			}
		}
	} else
		return stg_last_error = stgBadParam;
}

STG_RESULT stg_read_string(STGHANDLE handle, char **string, size_t *length) {

	STG_RESULT	result = stgBadParam;

	if ((handle != 0) && IS_NOT_NULL(string)) {

		RecordDescriptor	rd;
		StorageDescriptor	*sd = (StorageDescriptor *)handle;
		BOOL				read_done;
		char				*data;


		read_done = (fread(&rd, sizeof(RecordDescriptor), 1, sd->fd) == 1);

		if (read_done && (rd.signature == STORAGE_CURRENT_RECORD_SIGNATURE)) {

			if (IS_NOT_NULL(length))
				*length = rd.size;

			data = mem_malloc(rd.size);
			read_done = (fread(data, rd.size, 1, sd->fd) == 1);

			if (read_done) {

				*string = data;

				if (FlagSet(sd->flags, SF_CRC_CHECK)) {

					unsigned long int	crc = CRC32_INITIAL_VALUE;

					crc32((PBYTE)data, rd.size, &crc);
					result = (crc == rd.crc) ? stgSuccess : stgCRCError;	// done
				
				} else
					result = stgSuccess;	// done

				return stg_last_error = result;

			} else
				result = stgBadFD;
		} else
			result = stgBadRecord;
	}

	return stg_last_error = result;
}

__inline__ STG_RESULT stg_write_string(STGHANDLE handle, char *string) {

	return stg_write_record(handle, (PBYTE)string, str_len(string) + 1);
}

STG_RESULT stg_write_strings(STGHANDLE handle, char **strings, size_t strings_count, int *error_index) {

	if ((handle != 0) && IS_NOT_NULL(strings) && (strings_count > 0) && IS_NOT_NULL(error_index)) {

		RecordDescriptor	rd = {STORAGE_CURRENT_RECORD_SIGNATURE, RDF_TYPE_RECORD, 0, 0};
		StorageDescriptor	*sd = (StorageDescriptor *)handle;
		unsigned int		idx;
		char				*string;

		BOOL	write_done;

		for (idx = 0; idx < strings_count; ++idx) {
			
			string = strings[idx];
			
			if (IS_NOT_NULL(string)) {
				
				rd.size = str_len(string) + 1;
				if (FlagSet(sd->flags, SF_CRC_CHECK)) {

					rd.crc = CRC32_INITIAL_VALUE;
					crc32((PBYTE)string, rd.size, &(rd.crc));

					AddFlag(rd.flags, RDF_CRC_CHECK);
				
				} else
					rd.crc = 0;

				write_done = (fwrite(&rd, sizeof(RecordDescriptor), 1, sd->fd) == 1);
				if (write_done)
					write_done = fwrite(string, rd.size, 1, sd->fd) == 1;

				if (!write_done) {

					*error_index = idx;

					switch (errno) {

						case EBADF:
							return stg_last_error = stgBadFD;

						case ENOSPC:
							return stg_last_error = stgOutOfSpace;

						default:
							return stg_last_error = stgWriteError;
					}
				}
			}
		}

		return stg_last_error = stgSuccess; // done

	} else
		return stg_last_error = stgBadParam;
}


STG_RESULT stg_run_backup(void) {

	if (chdir("./backup") < 0) {

		system("mkdir ./backup");
		chdir("./backup");
	}

	system("cp -f ../*.db .");
	chdir("..");

	send_globops(NULL, "Database Back-Up Complete");

	return stg_last_error = stgSuccess;
}


const char *stg_result_to_string(STG_RESULT result) {

	static char	buffer[36];

	switch (result) {

		case stgSuccess:
			str_copy_checked("No errors", buffer, sizeof(buffer));
			break;

		case stgBeginOfSection:
			str_copy_checked("No errors", buffer, sizeof(buffer));
			break;

		case stgEndOfSection:
			str_copy_checked("No errors", buffer, sizeof(buffer));
			break;

		case stgUnknownError:
			str_copy_checked("Unknown error", buffer, sizeof(buffer));
			break;

		case stgBadParam:
			str_copy_checked("Bad parameter(s)", buffer, sizeof(buffer));
			break;

		case stgNotFound:
			str_copy_checked("Path not found", buffer, sizeof(buffer));
			break;

		case stgBadFD:
			str_copy_checked("Bad file descriptor", buffer, sizeof(buffer));
			break;

		case stgOutOfSpace:
			str_copy_checked("Out of disk space", buffer, sizeof(buffer));
			break;

		case stgAccessDenied:
			str_copy_checked("Access denied", buffer, sizeof(buffer));
			break;

		case stgReadOnly:
			str_copy_checked("Read-only storage", buffer, sizeof(buffer));
			break;

		case stgWriteOnly:
			str_copy_checked("Write-only storage", buffer, sizeof(buffer));
			break;

		case stgReadError:
			str_copy_checked("Read error", buffer, sizeof(buffer));
			break;

		case stgWriteError:
			str_copy_checked("Write error", buffer, sizeof(buffer));
			break;

		case stgInvalidStorage:
			str_copy_checked("Invalid storage", buffer, sizeof(buffer));
			break;

		case stgBadSize:
			str_copy_checked("Record size mismatch", buffer, sizeof(buffer));
			break;

		case stgBadRecord:
			str_copy_checked("Invalid record", buffer, sizeof(buffer));
			break;

		case stgOldStorage:
			str_copy_checked("Old storage format", buffer, sizeof(buffer));
			break;

		case stgCantBackup:
			str_copy_checked("Unable to backup previous storage", buffer, sizeof(buffer));
			break;

		case stgCantRestore:
			str_copy_checked("Unable to restore previous storage", buffer, sizeof(buffer));
			break;

		case stgCRCError:
			str_copy_checked("CRC error on data", buffer, sizeof(buffer));
			break;

		case stgEndOfData:
			str_copy_checked("No more data on the storage", buffer, sizeof(buffer));
			break;

		default:
			str_copy_checked("Unknow status value", buffer, sizeof(buffer));
			break;
	}

	return (CSTR) buffer;
}


void stg_report_sysinfo(CSTR sourceNick, const char *caller) {

	send_notice_to_nick(sourceNick, caller, "Storage info: Version \2%d\2 - Compatibility version \2%d\2 - Signature \2%s\2 - Record signature\2 0x%04X\2", STORAGE_CURRENT_VERSION, STORAGE_COMPATIBILITY_VERSION, STORAGE_SIGNATURE, STORAGE_CURRENT_RECORD_SIGNATURE);
}



