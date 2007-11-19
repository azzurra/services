/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* regions.c
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/logging.h"
#include "../inc/cidr.h"
#include "../inc/regions.h"
#include "../inc/memory.h"
#include "../inc/storage.h"
#include "../inc/misc.h"
#include "../inc/send.h"
#include "../inc/conf.h"
#include "../inc/main.h"		/* For 'synched'. */


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef	struct _Region	Region;
struct _Region {

	REGION_ID		id;
	unsigned long	flags;	/* RF_* */
	unsigned long   hits;

	CIDR_IP			cidr;
	char			*host_mask;

	Creator			creator;
	char			*reason;

	Region			*next, *prev;
};


// Error reporting
typedef struct _RegionError {

	union {

		CIDR_RESULT		cidr_error;
		result_t		host_error;

	} value;
	
} RegionError;


// Region names
typedef struct _RegionInfo {

	REGION_ID		id;
	const char		*long_name;
	const char		*short_name;
	unsigned long	flags; /* RIF_* */

} RegionInfo;


/*********************************************************
 * Constants                                             *
 *********************************************************/

// Region.flags
#define	RF_UNKNOWN			0x00000000
#define	RF_CIDR				0x00000001
#define	RF_HOST				0x00000002
#define	RF_HOST_IS_WILD		0x00000004

// RegionInfo.flags
#define RIF_NOFLAG				0x00000000
#define	RIF_LANG_AVAILABLE		0x00000001


/*********************************************************
 * Local data                                            *
 *********************************************************/

static Region	*regions_by_cidr[256];
static Region	*regions_by_host[256];
static BOOL		regions_modified;


static RegionInfo regions_info[REGION_COUNT] = {

	/* REGION_IT */ { REGION_IT, "Italian",		"IT", RIF_LANG_AVAILABLE },
	/* REGION_US */ { REGION_US, "English",		"US", RIF_LANG_AVAILABLE },
	/* REGION_ES */ { REGION_ES, "Spanish",		"ES", RIF_LANG_AVAILABLE },
	/* REGION_FR */ { REGION_FR, "French",		"FR", RIF_LANG_AVAILABLE },
	/* REGION_DE */ { REGION_DE, "Deutsch",		"DE", RIF_NOFLAG },
	/* REGION_JP */ { REGION_JP, "Japanese",	"JP", RIF_NOFLAG }
};

#define	REGIONS_DB	"regions.db"

#define	REGION_REASON_MAXLEN	200


/*********************************************************
 * Private code                                          *
 *********************************************************/

static REGION_ID region_from_string(CSTR string, BOOL allowNumber) {

	if (IS_NOT_NULL(string)) {

		REGION_ID	id;


		if (allowNumber) {

			char *error = NULL;


			id = strtoul(string, &error , 10);

			if (IS_NOT_NULL(error) && (*error == c_NULL))	// e' un numero
				return ((id >= REGION_FIRST) && (id <= REGION_LAST)) ? id : REGION_INVALID;
		}

		for (id = REGION_FIRST; id <= REGION_LAST; ++id) {

			if (str_equals_nocase(string, regions_info[id].short_name) ||
				str_equals_nocase(string, regions_info[id].long_name))
				return id;
		}
	}

	return REGION_INVALID;
}


Region *region_create(REGION_ID id, const char *value, REGION_TYPE type, const char *creator_name, const char *reason, RegionError *error) {

	if (IS_NOT_NULL(value) && IS_NOT_NULL(error) && IS_NOT_NULL(creator_name) && IS_NOT_NULL(reason)) {

		Region	*region;

		switch (type) {

			case REGIONTYPE_IP: {

				region = mem_calloc(1, sizeof(Region));
				region->id = id;

				AddFlag(region->flags, RF_CIDR);
				error->value.cidr_error = cidr_ip_fill(value, &(region->cidr), TRUE);

				if (error->value.cidr_error != cidrSuccess) {

					mem_free(region);
					region = NULL;
				}
				else {

					region->host_mask = str_duplicate(value);
					region->reason = str_duplicate(reason);
					str_creator_init(&(region->creator));
					str_creator_set(&(region->creator), creator_name, 0);
				}

				return region;
			}

			case REGIONTYPE_HOST: {

				char	*ptr;

				ptr = strrchr(value, c_DOT);

				if (IS_NULL(strrchr(value, '/')) /* no CIDR here */ &&
					IS_NOT_NULL(ptr) && validate_tld(ptr + 1, TRUE) /* valid .tld? */ ) {

					region = mem_calloc(1, sizeof(Region));
					region->id = id;

					AddFlag(region->flags, RF_HOST);

					region->host_mask = str_duplicate(value);
					region->reason = str_duplicate(reason);

					str_creator_init(&(region->creator));
					str_creator_set(&(region->creator), creator_name, 0);

					error->value.host_error = RESULT_SUCCESS;

					ptr = region->host_mask;

					while (1) {

						switch (*ptr++) {
							case '\0':
								return region;

							case '*':
							case '?':
								AddFlag(region->flags, RF_HOST_IS_WILD);
								return region;
						}
					}
				}
				else {

					error->value.host_error = RESULT_VALUEERROR;
					region = NULL;
				}
			}
		} // switch (type)
	}
	
	return NULL;
}


void region_delete(Region *region) {

	if (IS_NOT_NULL(region)) {

		mem_free(region->host_mask);
		mem_free(region->reason);
		str_creator_free(&(region->creator));
		mem_free(region);
	}
}


BOOL region_list_add(Region *region) {

	if (IS_NOT_NULL(region)) {

		unsigned char	hash;

		if (FlagSet(region->flags, RF_CIDR)) {

			hash = region->cidr.ip & 0xFF;

			region->prev = NULL;
			region->next = regions_by_cidr[hash];

			if (IS_NOT_NULL(regions_by_cidr[hash]))
				regions_by_cidr[hash]->prev = region;

			regions_by_cidr[hash] = region;

			regions_modified = TRUE;
			return TRUE;

		}
		else if (FlagSet(region->flags, RF_HOST)) {

			char	*tld;

			if (IS_NOT_NULL(region->host_mask) &&
				IS_NOT_NULL(tld = strrchr(region->host_mask, c_DOT))) {

					hash = str_char_tolower(*(++tld));

					region->prev = NULL;
					region->next = regions_by_host[hash];

					if (IS_NOT_NULL(regions_by_host[hash]))
						regions_by_host[hash]->prev = region;

					regions_by_host[hash] = region;

					regions_modified = TRUE;
					return TRUE;
			}
			else
				log_error(FACILITY_REGION_LIST_ADD, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
					"region_list_add() - %s host", IS_NULL(region->host_mask) ? "NULL" : "INVALID" );
				// fall and fail ...
		}
		else
			log_error(FACILITY_REGION_LIST_ADD, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
				"region_list_add() - Invalid region-type flag (%d)", region->flags & 0x03);
			// fall and fail ...
	}

	return FALSE;
}


void region_list_remove(Region *region) {

	if (IS_NOT_NULL(region)) {

		unsigned char	hash;


		if (IS_NOT_NULL(region->next))
			region->next->prev = region->prev;

		if (FlagSet(region->flags, RF_CIDR)) {

			hash = region->cidr.ip & 0xFF;

			if (IS_NOT_NULL(region->prev))
				region->prev->next = region->next;
			else
				regions_by_cidr[hash] = region->next;

			regions_modified = TRUE;

			// fall ...
		}
		else if (FlagSet(region->flags, RF_HOST)) {

			char	*tld;

			if (IS_NOT_NULL(region->host_mask) &&
				IS_NOT_NULL(tld = strrchr(region->host_mask, c_DOT))) {

				hash = str_char_tolower(*(++tld));

				if (IS_NOT_NULL(region->prev))
					region->prev->next = region->next;
				else
					regions_by_host[hash] = region->next;

				regions_modified = TRUE;

				// fall ...
			}
			else
				log_error(FACILITY_REGION_LIST_REMOVE, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
					"region_list_remove() - %s host", IS_NULL(region->host_mask) ? "NULL" : "INVALID" );
				// fall and fail ...
		}
		else
			log_error(FACILITY_REGION_LIST_REMOVE, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
				"region_list_remove() - Invalid region-type flag (%d)", region->flags & 0x03);
			// fall and fail ...
	}
}


Region *region_list_find_by_hostmask(const char *host_mask, REGION_TYPE type, RegionError *error) {

	if (IS_NOT_NULL(host_mask) && IS_NOT_NULL(error)) {

		Region			*region;
		unsigned char	hash;

		switch (type) {

			case REGIONTYPE_IP: {

				CIDR_IP			cidr;

				error->value.cidr_error = cidr_ip_fill(host_mask, &cidr, TRUE);

				if (error->value.cidr_error == cidrSuccess) {

					hash = cidr.ip & 0xFF;

					for (region = regions_by_cidr[hash]; IS_NOT_NULL(region); region = region->next) {

						if ((region->cidr.ip == cidr.ip) && (region->cidr.mask == cidr.mask))
							return region;
					}
				}

				// fall and fail ...
				break;
			}

			case REGIONTYPE_HOST: {

				char	*tld;

				error->value.host_error = RESULT_VALUEERROR;

				if (IS_NOT_NULL(tld = strrchr(host_mask, c_DOT))) {

					hash = str_char_tolower(*(++tld));

					for (region = regions_by_host[hash]; IS_NOT_NULL(region); region = region->next) {

						if (str_equals_nocase(region->host_mask, host_mask)) {

							error->value.host_error = RESULT_SUCCESS;
							return region;
						}
					}

					error->value.host_error = RESULT_NOTFOUND;
				}

				// fall and fail ...
				break;
			}

			default:
				error->value.host_error = RESULT_BADPARAMETER;

		} // switch (type)
	}

	return NULL;
}


/*********************************************************
 * Public code                                           *
 *********************************************************/

BOOL region_init(void) {

	int		idx;

	for (idx = 0; idx < 256; ++idx) {

		regions_by_cidr[idx] = NULL;
		regions_by_host[idx] = NULL;
	}

	regions_modified = FALSE;
	return TRUE;
}


void region_terminate(void) {
	
	int		idx;
	Region	*region;


	for (idx = 0; idx < 256; ++idx) {

		while (IS_NOT_NULL(regions_by_cidr[idx])) {

			region = regions_by_cidr[idx];
			region_list_remove(region);
			region_delete(region);
		}
	}

	for (idx = 0; idx < 256; ++idx) {

		while (IS_NOT_NULL(regions_by_host[idx])) {

			region = regions_by_host[idx];
			region_list_remove(region);
			region_delete(region);
		}
	}
}


REGION_ID region_match(unsigned long ip, const char *host, REGION_TYPE behavior) {

	Region			*region;
	unsigned char	hash;


	if (FlagSet(behavior, REGIONTYPE_HOST)) { // or REGIONTYPE_BOTH

		char	*tld;

		if (IS_NOT_NULL(host) &&
			IS_NOT_NULL(tld = strrchr(host, c_DOT))) {

			hash = str_char_tolower(*(++tld));
			region = regions_by_host[hash];

			while (region) {

				if (FlagSet(region->flags, RF_HOST_IS_WILD)) {

					if (str_match_wild_nocase(region->host_mask, host)) {

						if (synched)
							++(region->hits);

						return region->id; // found
					}
				}
				else {

					if (str_equals_nocase(region->host_mask, host)) {

						if (synched)
							++(region->hits);

						return region->id; // found
					}
				}

				region = region->next;
			}
			// fall ...
		}
		else
			log_error(FACILITY_REGION_MATCH, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_PROPAGATED,
				"region_match(): Invalid host in a host-match: %s", host);
			// fall ...
	}

	if (FlagSet(behavior, REGIONTYPE_IP)) { // or REGIONTYPE_BOTH

		hash = ip & 0xFF;

		region = regions_by_cidr[hash];

		while (IS_NOT_NULL(region)) {

			if (cidr_match(&(region->cidr), ip)) {

				if (synched)
					++(region->hits);

				return region->id; // found
			}

			region = region->next;
		}
		// fall ...
	}

	return REGION_INVALID;
}


BOOL regions_db_load(void) {

	STGHANDLE	stg = 0;
	STG_RESULT	result;

	Region		*region;
	int			i, type;


	TRACE_FCLT(FACILITY_REGIONS_DB_LOAD);

	result = stg_open(REGIONS_DB, &stg);

	switch (result) {

		case stgSuccess: { // OK -> loading data

			STGVERSION	version;
			BOOL		in_section;
			BOOL		read_done;

			version = stg_data_version(stg);

			switch (version) {

				case REGIONS_DB_CURRENT_VERSION:

					for (type = 0; type < 2; ++type) {

						// load CIDRs in the first loop, HOSTs in the second one

						for (i = 0; i < 256; ++i) {

							// start-of-section marker
							result = stg_read_record(stg, NULL, 0);

							if (result == stgBeginOfSection) {

								in_section = TRUE;

								while (in_section) {

									region = mem_malloc(sizeof(Region));

									result = stg_read_record(stg, (PBYTE)region, sizeof(Region));

									switch (result) {

										case stgEndOfSection: // end-of-section
											in_section = FALSE;
											mem_free(region);
											break;
										
										case stgSuccess: // a valid region

											read_done = TRUE;

											if (region->host_mask)
												read_done &= (result = stg_read_string(stg, &(region->host_mask), NULL)) == stgSuccess;

											if (read_done && IS_NOT_NULL(region->creator.name))
												read_done &= (result = stg_read_string(stg, &(region->creator.name), NULL)) == stgSuccess;

											if (read_done && IS_NOT_NULL(region->reason))
												read_done &= (result = stg_read_string(stg, &(region->reason), NULL)) == stgSuccess;

											if (!read_done)
												fatal_error(FACILITY_REGIONS_DB_LOAD, __LINE__, "Read error on %s (2) - %s", REGIONS_DB, stg_result_to_string(result));

											region->next = region->prev = NULL;
											region_list_add(region);
											break;

										default: // some error
											fatal_error(FACILITY_REGIONS_DB_LOAD, __LINE__, "Read error on %s - %s", REGIONS_DB, stg_result_to_string(result));
									}
								}
							}
							else
								fatal_error(FACILITY_REGIONS_DB_LOAD, __LINE__, "Read error on %s : invalid format", REGIONS_DB);
						}
					}

					regions_modified = FALSE;
					stg_close(stg, REGIONS_DB);
					return TRUE;

				default:
					fatal_error(FACILITY_REGIONS_DB_LOAD, __LINE__, "Unsupported version number (%d) on %s", version, REGIONS_DB);
			}
		}

		case stgNotFound: // no data to load
			return TRUE;

		default: // error!
			stg_close(stg, REGIONS_DB);

			fatal_error(FACILITY_REGIONS_DB_LOAD, __LINE__, "Error opening %s - %s", REGIONS_DB, stg_result_to_string(result));
			return FALSE;
	}
}


BOOL regions_db_save(void) {

	STGHANDLE	stg;
	STG_RESULT	result;
	BOOL		write_done;

	Region		*region;
	int			i;


	TRACE_FCLT(FACILITY_REGIONS_DB_SAVE);

	if (!regions_modified)
		return TRUE;

	result = stg_create(REGIONS_DB, SF_NOFLAGS, REGIONS_DB_CURRENT_VERSION, &stg);

	if (result != stgSuccess) {

		log_error(FACILITY_REGIONS_DB_SAVE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"regions_db_save(): Could not create database file %s: %s [Error %d: %s]", REGIONS_DB, stg_result_to_string(result), errno, strerror(errno));

		return FALSE;
	}

	// CIDR

	for (i = 0; i < 256; ++i) {

		result = stg_start_section(stg);

		if (result != stgSuccess)
			fatal_error(FACILITY_REGIONS_DB_SAVE, __LINE__, "Write error on %s - %s", REGIONS_DB, stg_result_to_string(result));

		for (region = regions_by_cidr[i]; region; region = region->next) {

			result = stg_write_record(stg, (PBYTE)region, sizeof(Region));

			if (result != stgSuccess)
				fatal_error(FACILITY_REGIONS_DB_SAVE, __LINE__, "Write error on %s - %s", REGIONS_DB, stg_result_to_string(result));

			write_done = TRUE;

			if (region->host_mask)
				write_done &= (result = stg_write_string(stg, region->host_mask)) == stgSuccess;

			if (write_done && IS_NOT_NULL(region->creator.name))
				write_done &= (result = stg_write_string(stg, region->creator.name)) == stgSuccess;

			if (write_done && IS_NOT_NULL(region->reason))
				write_done &= (result = stg_write_string(stg, region->reason)) == stgSuccess;

			if (!write_done)
				fatal_error(FACILITY_REGIONS_DB_SAVE, __LINE__, "Write error on %s - %s", REGIONS_DB, stg_result_to_string(result));
		}

		result = stg_end_section(stg);

		if (result != stgSuccess)
			fatal_error(FACILITY_REGIONS_DB_SAVE, __LINE__, "Write error on %s - %s", REGIONS_DB, stg_result_to_string(result));
	}

	// HOST

	for (i = 0; i < 256; ++i) {

		result = stg_start_section(stg);

		if (result != stgSuccess)
			fatal_error(FACILITY_REGIONS_DB_SAVE, __LINE__, "Write error on %s - %s", REGIONS_DB, stg_result_to_string(result));

		for (region = regions_by_host[i]; region; region = region->next) {

			result = stg_write_record(stg, (PBYTE)region, sizeof(Region));

			if (result != stgSuccess)
				fatal_error(FACILITY_REGIONS_DB_SAVE, __LINE__, "Write error on %s - %s", REGIONS_DB, stg_result_to_string(result));

			write_done = TRUE;

			if (region->host_mask)
				write_done &= (result = stg_write_string(stg, region->host_mask)) == stgSuccess;

			if (write_done && IS_NOT_NULL(region->creator.name))
				write_done &= (result = stg_write_string(stg, region->creator.name)) == stgSuccess;

			if (write_done && IS_NOT_NULL(region->reason))
				write_done &= (result = stg_write_string(stg, region->reason)) == stgSuccess;

			if (!write_done)
				fatal_error(FACILITY_REGIONS_DB_SAVE, __LINE__, "Write error on %s - %s", REGIONS_DB, stg_result_to_string(result));
		}

		result = stg_end_section(stg);

		if (result != stgSuccess)
			fatal_error(FACILITY_REGIONS_DB_SAVE, __LINE__, "Write error on %s - %s", REGIONS_DB, stg_result_to_string(result));
	}

	regions_modified = FALSE;

	stg_close(stg, REGIONS_DB);
	return TRUE;
}

void handle_regions(const char *source, User *callerUser, ServiceCommandData *data) {
	/*
	REGIONS ADDCIDR mask region reason
	REGIONS ADDHOST mask region reason
	REGIONS DELCIDR mask
	REGIONS DELHOST mask
	REGIONS CHREASON mask new-reason
	REGIONS	MTEST cidr ip
	REGIONS LIST [region] [first [last]] [mask]
	REGIONS RLIST
	*/

	char			*action;
	BOOL			needSyntax = FALSE;


	if (IS_NULL(action = strtok(NULL, s_SPACE)))
		needSyntax = TRUE;

	else if (str_equals_nocase(action, "ADDCIDR")) {

		char *mask, *region_string, *reason;


		if (IS_NOT_NULL(mask = strtok(NULL, s_SPACE)) &&
			IS_NOT_NULL(region_string = strtok(NULL, s_SPACE)) &&
			IS_NOT_NULL(reason = strtok(NULL, s_NULL))) {

			if (str_len(reason) > REGION_REASON_MAXLEN)
				send_notice_to_user(data->agent->nick, callerUser, "\2ERROR:\2 Reasons may not exceed \2%d\2 characters in length.", REGION_REASON_MAXLEN);

			else if (!validate_string(reason))
				send_notice_to_user(data->agent->nick, callerUser, "\2ERROR:\2 Invalid reason supplied.");

			else {

				Region		*region;
				REGION_ID	region_id;
				RegionError error;


				region_id = region_from_string(region_string, TRUE);

				if (region_id != REGION_INVALID) {

					region = region_list_find_by_hostmask(mask, REGIONTYPE_IP, &error);

					if (IS_NULL(region)) {

						region = region_create(region_id, mask, REGIONTYPE_IP, data->operName, reason, &error);

						if (IS_NOT_NULL(region) && (error.value.cidr_error == cidrSuccess)) {

							region_list_add(region);

							send_notice_to_user(data->agent->nick, callerUser, "Region added.");

							if (data->operMatch)
								send_globops(data->agent->nick, "\2%s\2 added CIDR for \2%s\2 to region \2%s\2", source, mask, region_string);
							else
								send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) added CIDR for \2%s\2 to region \2%s\2", source, data->operName, mask, region_string);
						}
						else
							send_notice_to_user(data->agent->nick, callerUser, "Error creating CIDR-based region: %s", cidr_error_to_string(error.value.cidr_error));
					}
					else
						send_notice_to_user(data->agent->nick, callerUser, "Region already in list");
				}
				else
					send_notice_to_user(data->agent->nick, callerUser, "Invalid region specified. See \2REGIONS RLIST\2 for valid values.");
			}
		}
		else
			needSyntax = TRUE;
	}
	else if (str_equals_nocase(action, "ADDHOST")) {

		char *mask, *region_string, *reason;


		if (IS_NOT_NULL(mask = strtok(NULL, " ")) &&
			IS_NOT_NULL(region_string = strtok(NULL, s_SPACE)) &&
			IS_NOT_NULL(reason = strtok(NULL, s_NULL))) {

			if (str_len(reason) > REGION_REASON_MAXLEN)
				send_notice_to_user(data->agent->nick, callerUser, "\2ERROR:\2 reasons may not exceed \2%d\2 characters in length.", REGION_REASON_MAXLEN);

			else if (!validate_string(reason))
				send_notice_to_user(data->agent->nick, callerUser, "\2ERROR:\2 Invalid reason supplied.");

			else {

				Region		*region;
				REGION_ID	region_id;
				RegionError error;


				region_id = region_from_string(region_string, TRUE);

				if (region_id != REGION_INVALID) {

					region = region_list_find_by_hostmask(mask, REGIONTYPE_HOST, &error);

					if (IS_NULL(region)) {

						region = region_create(region_id, mask, REGIONTYPE_HOST, data->operName, reason, &error);

						if (IS_NOT_NULL(region) && (error.value.host_error == RESULT_SUCCESS)) {

							region_list_add(region);

							send_notice_to_user(data->agent->nick, callerUser, "Region added.");

							if (data->operMatch)
								send_globops(data->agent->nick, "\2%s\2 added host \2%s\2 to region \2%s\2", source, mask, region_string);
							else
								send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) added host \2%s\2 to region \2%s\2", source, data->operName, mask, region_string);
						}
						else
							send_notice_to_user(data->agent->nick, callerUser, error.value.host_error == RESULT_VALUEERROR ? "Invalid host" : "Error creating HOST-based region");
					}
					else
						send_notice_to_user(data->agent->nick, callerUser, "Region already in list");
				}
				else
					send_notice_to_user(data->agent->nick, callerUser, "Invalid region specified. See \2REGIONS RLIST\2 for valid values.");
			}
		}
		else
			needSyntax = TRUE;
	}
	else if (str_equals_nocase(action, "DELCIDR")) {

		Region		*region;
		RegionError error;
		char 		*mask;


		if (IS_NOT_NULL(mask = strtok(NULL, " "))) {

			region = region_list_find_by_hostmask(mask, REGIONTYPE_IP, &error);

			if (IS_NOT_NULL(region) && (error.value.cidr_error == cidrSuccess)) {

				if (data->operMatch)
					send_globops(data->agent->nick, "\2%s\2 removed CIDR for \2%s\2 from region \2%d\2", source, region->host_mask, region->id);
				else
					send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) removed CIDR for \2%s\2 from region \2%d\2", source, data->operName, region->host_mask, region->id);

				region_list_remove(region);
				region_delete(region);
				send_notice_to_user(data->agent->nick, callerUser, "Region removed.");
			}
			else
				send_notice_to_user(data->agent->nick, callerUser, "Error removing CIDR-based region: %s", cidr_error_to_string(error.value.cidr_error));
		}
		else
			needSyntax = TRUE;
	}
	else if (str_equals_nocase(action, "DELHOST")) {

		Region		*region;
		RegionError error;
		char 		*mask;


		if (IS_NOT_NULL(mask = strtok(NULL, " "))) {

			region = region_list_find_by_hostmask(mask, REGIONTYPE_HOST, &error);

			if (IS_NOT_NULL(region) && (error.value.host_error == RESULT_SUCCESS)) {

				if (data->operMatch)
					send_globops(data->agent->nick, "\2%s\2 removed host \2%s\2 from region \2%d\2", source, region->host_mask, region->id);
				else
					send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) removed host \2%s\2 from region \2%d\2", source, data->operName, region->host_mask, region->id);

				region_list_remove(region);
				region_delete(region);
				send_notice_to_user(data->agent->nick, callerUser, "Region removed.");
			}
			else
				send_notice_to_user(data->agent->nick, callerUser, "Error removing HOST-based region");
		}
		else
			needSyntax = TRUE;
	}
	else if (str_equals_nocase(action, "CHREASON")) {

		Region		*region;
		RegionError	error;
		char		*mask, *reason;


		if (IS_NOT_NULL(mask = strtok(NULL, " ")) && IS_NOT_NULL(reason = strtok(NULL, s_NULL))) {

			if (str_len(reason) > REGION_REASON_MAXLEN)
				send_notice_to_user(data->agent->nick, callerUser, "\2ERROR:\2 reasons may not exceed \2%d\2 characters in length.", REGION_REASON_MAXLEN);

			else if (!validate_string(reason))
				send_notice_to_user(data->agent->nick, callerUser, "\2ERROR:\2 Invalid reason supplied.");

			else {

				region = region_list_find_by_hostmask(mask, IS_NULL(strrchr(mask, c_SLASH)) ? REGIONTYPE_HOST : REGIONTYPE_IP, &error);

				if (IS_NOT_NULL(region)) {

					mem_free(region->reason);
					region->reason = str_duplicate(reason);
					send_notice_to_user(data->agent->nick, callerUser, "Reason changed");
				}
				else
					send_notice_to_user(data->agent->nick, callerUser, "Region not found");
			}
		}
		else
			needSyntax = TRUE;
	}
	else if (str_equals_nocase(action, "MTEST")) {

		CIDR_IP			cidr;
		CIDR_RESULT		cidr_result;
		char			*mask, *ip_string;
		unsigned long	ip;


		if (IS_NOT_NULL(mask = strtok(NULL, s_SPACE)) && IS_NOT_NULL(ip_string = strtok(NULL, s_SPACE))) {

			cidr_result = cidr_ip_fill(mask, &cidr, TRUE);

			if (cidr_result == cidrSuccess) {

				if ((ip = inet_addr(ip_string)) != 0xFFFFFFFF)
					send_notice_to_user(data->agent->nick, callerUser, "%s %s %s", mask, (cidr_match(&cidr, ip) ? "matches" : "does not match"), ip_string);
				else
				send_notice_to_user(data->agent->nick, callerUser, "Invalid IP");
			}
			else
				send_notice_to_user(data->agent->nick, callerUser, "Invalid CIDR: %s", cidr_error_to_string(cidr_result));
		}
		else
			needSyntax = TRUE;
	}
	else if (str_equals_nocase(action, "LIST")) {

		char		timebuf[64];
		char		*pattern;
		int			regionIdx, startIdx = 0, endIdx = 30, sentIdx = 0, idx;
		REGION_ID	region_id = REGION_INVALID;
		Region		*region;


		if (IS_NOT_NULL(pattern = strtok(NULL, " "))) {

			char *err;
			long int value;


			/* Check if the first param is a valid region. */
			region_id = region_from_string(pattern, FALSE);

			if (region_id != REGION_INVALID)
				pattern = strtok(NULL, " ");

			if (IS_NOT_NULL(pattern)) {

				value = strtol(pattern, &err, 10);

				if ((value >= 0) && (*err == '\0')) {

					startIdx = value;

					if (IS_NOT_NULL(pattern = strtok(NULL, " "))) {

						value = strtol(pattern, &err, 10);

						if ((value >= 0) && (*err == '\0')) {

							endIdx = value;

							pattern = strtok(NULL, " ");
						}
					}
				}
			}
		}

		if (endIdx < startIdx)
			endIdx = (startIdx + 30);

		if (region_id != REGION_INVALID) {

			if (IS_NULL(pattern))
				send_notice_to_user(data->agent->nick, callerUser, "Regions list (showing entries %d-%d of region %s):", startIdx, endIdx, regions_info[region_id].short_name);
			else
				send_notice_to_user(data->agent->nick, callerUser, "Regions list (showing entries %d-%d of region %s matching %s):", startIdx, endIdx, regions_info[region_id].short_name, pattern);
		}
		else {

			if (IS_NULL(pattern))
				send_notice_to_user(data->agent->nick, callerUser, "Regions list (showing entries %d-%d):", startIdx, endIdx);
			else
				send_notice_to_user(data->agent->nick, callerUser, "Regions list (showing entries %d-%d matching %s):", startIdx, endIdx, pattern);
		}

		idx = 0;

		/* Go through the CIDR list. */
		for (regionIdx = 0; regionIdx < 256; ++regionIdx) {

			for (region = regions_by_cidr[regionIdx]; region; region = region->next) {

				++idx;

				if ((region_id != REGION_INVALID) && (region->id != region_id))
					continue;

				if (IS_NOT_NULL(pattern) && !str_match_wild_nocase(pattern, region->host_mask))
					continue;

				++sentIdx;

				if (sentIdx < startIdx)
					continue;

				lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, region->creator.time);
				send_notice_to_user(data->agent->nick, callerUser, "%d) %s - [CIDR] \2%s\2 [%lu] by %s (%s) : %s", idx, regions_info[region->id].short_name, region->host_mask, region->hits, region->creator.name, timebuf, region->reason);

				if (sentIdx >= endIdx)
					break;
			}

			if (sentIdx >= endIdx)
				break;
		}

		if (sentIdx < endIdx) {

			/* Now go through the host list. */

			for (regionIdx = 0; regionIdx < 256; ++regionIdx) {

				for (region = regions_by_host[regionIdx]; IS_NOT_NULL(region); region = region->next) {

					++idx;

					if ((region_id != REGION_INVALID) && (region->id != region_id))
						continue;

					if (IS_NOT_NULL(pattern) && !str_match_wild_nocase(pattern, region->host_mask))
						continue;

					++sentIdx;

					if (sentIdx < startIdx)
						continue;

					lang_format_localtime(timebuf, sizeof(timebuf), GetCallerLang(), TIME_FORMAT_DATETIME, region->creator.time);
					send_notice_to_user(data->agent->nick, callerUser, "%d) %s - [Host] \2%s\2 [%lu] by %s (%s) : %s", idx, regions_info[region->id].short_name, region->host_mask, region->hits, region->creator.name, timebuf, region->reason);

					if (sentIdx >= endIdx)
						break;
				}

				if (sentIdx >= endIdx)
					break;
			}
		}

		send_notice_to_user(data->agent->nick, callerUser, "*** \2End of List\2 ***");
	}
	else if (str_equals_nocase(action, "RLIST")) {

		REGION_ID	region_id;


		send_notice_to_user(data->agent->nick, callerUser, "Supported regions:");

		for (region_id = REGION_FIRST; region_id <= REGION_LAST; ++region_id)
			send_notice_to_user(data->agent->nick, callerUser, "%d) \2%s\2 [%s]", region_id, regions_info[region_id].long_name, regions_info[region_id].short_name);

		send_notice_to_user(data->agent->nick, callerUser, "*** \2End of List\2 ***");
	}
	else
		needSyntax = TRUE;


	if (needSyntax) {

		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2REGIONS\2 ADDCIDR mask region reason");
		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2REGIONS\2 ADDHOST mask region reason");
		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2REGIONS\2 DELCIDR mask");
		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2REGIONS\2 DELHOST mask");
		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2REGIONS\2 CHREASON mask new-reason");
		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2REGIONS\2 MTEST cidr ip");
		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2REGIONS\2 LIST [region] [first [last]] [pattern]");
		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2REGIONS\2 RLIST");
	}
}
