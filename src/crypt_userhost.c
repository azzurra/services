/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* crypt_userhost.c - Mascheramento hostname utenti
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
#include "../inc/conf.h"
#include "../inc/misc.h"
#include "../inc/crypt_shs1.h"
#include "../inc/crypt_userhost.h"
#include "../inc/main.h"
#include "../inc/users.h"


/*********************************************************
 * Usermode +x support.                                  *
 *********************************************************/

static size_t	hidehost_buffer_size = 0;
static size_t	hidehost_crypt_buffer_size = 0;
static size_t	hidehost_key_size = 0;

static STR		hidehost_buffer = NULL;
static STR		hidehost_crypt_buffer = NULL;
static STR		hidehost_key = NULL;

#define	HIDEHOST_CHECKSUM_LEN		9

#define HIDEHOST_MAX_KEY_LEN		1024
#define HIDEHOST_MIN_KEY_LEN		64


/*********************************************************
 * Host encryption key support                           *
 *********************************************************/

void crypt_init() {

	hidehost_buffer = hidehost_key = NULL;
	hidehost_buffer_size = hidehost_key_size = 0;

	TRACE();
	hidehost_crypt_buffer_size = CRYPT_SHA1_DIGEST_LEN + 1;
	hidehost_crypt_buffer = (STR) mem_calloc(hidehost_crypt_buffer_size, sizeof(char));
}

void crypt_done() {

	mem_free(hidehost_buffer);
	mem_free(hidehost_key);
	mem_free(hidehost_crypt_buffer);
}


BOOL crypt_change_key(CSTR newKey) {

	if (IS_NOT_NULL(newKey) && IS_NOT_EMPTY_STR(newKey)) {

		if (IS_NOT_NULL(hidehost_key))
			mem_free(hidehost_key);

		hidehost_key = str_duplicate(newKey);
		hidehost_key_size = strlen(hidehost_key);
		return TRUE;
	}

	return FALSE;
}

BOOL crypt_load_key() {

	int		file;
	BOOL	errors = TRUE;


	if ((file = open("../crypt.key", O_RDONLY))) {
		
		struct stat		st;
		STR				key;

		if (fstat(file, &st) == 0)	{
			
			int size = st.st_size;

			if (size > HIDEHOST_MIN_KEY_LEN)	{
				
				if (size > HIDEHOST_MAX_KEY_LEN)
					size = HIDEHOST_MAX_KEY_LEN;

				key = mem_malloc(size + 1);
				read(file, (void *) key, size);
				key[size] = c_NULL;

				if (!crypt_change_key(key))
					fatal_error(FACILITY_CRYPT, __LINE__, "Unable to set loaded key!");
				else
					errors = FALSE;

				mem_free(key);
			}
			else
				fatal_error(FACILITY_CRYPT, __LINE__, "Host encryption key is too short! (%d < %d)", size, HIDEHOST_MIN_KEY_LEN);
		}
		else
			fatal_error(FACILITY_CRYPT, __LINE__, "Failed to stat host encryption key file!");

		close(file);
	}
	else
		fatal_error(FACILITY_CRYPT, __LINE__, "Cannot open host encryption key file!");

	return !errors;
}

BOOL crypt_save_key() {

	FILE	*file;
	BOOL	errors = FALSE;


	file = fopen("../crypt.key", s_OPENMODE_WRITEONLY);

	if (IS_NOT_NULL(file)) {

		if (1 != fwrite(hidehost_key, hidehost_key_size, 1, file)) {

			errors = TRUE;
			LOG_DEBUG_SNOOP("\2WARNING\2 Unable to store the encryption key!");
		}

		fclose(file);
	}
	else {

		errors = TRUE;
		LOG_DEBUG_SNOOP("\2WARNING\2 Unable to open the encryption key file!");
	}

	return !errors;
}

void handle_cryptkey(CSTR source, User *callerUser, ServiceCommandData *data) {

	STR		newKey = strtok(NULL, s_NULL);
	size_t	keyLen;


	TRACE_MAIN_FCLT(FACILITY_CRYPT_HANDLE_CRYPTKEY);

	if (IS_NULL(newKey))
		send_notice_to_user(data->agent->nick, callerUser, "Syntax: \2CRYPTKEY\2 newkey");

	else if ((keyLen = str_len(newKey)) < HIDEHOST_MIN_KEY_LEN)
		send_notice_to_user(data->agent->nick, callerUser, "The key is too short [%d < %d]", keyLen, HIDEHOST_MIN_KEY_LEN);

	else if (keyLen > HIDEHOST_MAX_KEY_LEN)
		send_notice_to_user(data->agent->nick, callerUser, "The key is too long [%d > %d]", keyLen, HIDEHOST_MAX_KEY_LEN);

	else {

		if (crypt_change_key(newKey)) {

			send_cmd("CLOAKEY :%s", newKey);

			if (data->operMatch) {

				LOG_SNOOP(data->agent->nick, "%s K -- by %s (%s@%s)", data->agent->shortNick, source, callerUser->username, callerUser->host);
				log_services(data->agent->logID, "K -- by %s (%s@%s)", source, callerUser->username, callerUser->host);

				send_globops(data->agent->nick, "\2%s\2 forced a database update", source);
			}
			else {

				LOG_SNOOP(data->agent->nick, "%s K -- by %s (%s@%s) through %s", data->agent->shortNick, source, callerUser->username, callerUser->host, data->operName);
				log_services(data->agent->logID, "K -- by %s (%s@%s) through %s", source, callerUser->username, callerUser->host, data->operName);

				send_globops(data->agent->nick, "\2%s\2 (through \2%s\2) forced a database update", source, data->operName);
			}

			send_globops(data->agent->nick, "Encryption key changed by \2%s\2", source);

			if (!crypt_save_key()) {

				send_globops(data->agent->nick, "\2WARNING:\2 Unable to store the encryption key!");
				send_notice_to_user(data->agent->nick, callerUser, "Unable to store the encryption key!");
			}
			else
				send_notice_to_user(data->agent->nick, callerUser, "Encryption key changed and stored.");
		}
		else {

			log_error(FACILITY_CRYPT_HANDLE_CRYPTKEY, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_HALTED,
				"%s - Failed to change encryption key as requested by \2%s\2", data->agent->nick, source);

			send_notice_to_user(data->agent->nick, callerUser, "Failed to change encryption key.");
		}
	}
}


/*********************************************************
 * FNV hashing support                                   *
 *********************************************************/

#define FNV_prime 16777619UL

long crypt_hash_FNV(CSTR string, size_t size) {

	long	hash = 0;
	size_t	i = 0;

	for (; i < size; i++)
		hash = ((hash * FNV_prime ) ^ (string[i]));

	return hash;
}


/*********************************************************
 * SHA1 hash                                             *
 *********************************************************/

long crypt_hash_SHA1(CSTR string, size_t size, STR buffer, size_t bufferSize) {

	SHS1_INFO	digest;

	if (bufferSize <= CRYPT_SHA1_DIGEST_LEN) {

		log_error(FACILITY_CRYPT, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			"crypt_hash_SHA1() - Buffer too small!");

		return 0;
	}

	shs1Init(&digest);
	shs1Update(&digest, (BYTE *) string, size);
	shs1Update(&digest, (BYTE *) hidehost_key, hidehost_key_size);
	SHS1COUNT(&digest, (ULONG) hidehost_key_size + size);
	shs1Final(&digest);

	snprintf(buffer, bufferSize, "%08lx%08lx%08lx%08lx%08lx", digest.digest[0], digest.digest[1], digest.digest[2], digest.digest[3], digest.digest[4]);

	/* Note: strlen(buffer) == CRYPT_SHA1_DIGEST_LEN */
	return crypt_hash_FNV(buffer, CRYPT_SHA1_DIGEST_LEN);
}


/*********************************************************
 * crypt_userhost()                                      *
 *********************************************************/

STR crypt_userhost(CSTR real, HOST_TYPE htype, short int dotsCount) {

	size_t			len, virlen;
	long			hash;
	char			*ptr;

	#define MAX_DSN_HOST_LEN	64


	TRACE_FCLT(FACILITY_CRYPT_USERHOST);

	if (IS_NULL(real) || IS_EMPTY_STR(real)) {

		log_error(FACILITY_CRYPT_USERHOST, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "user_hidehost()", s_LOG_NULL, "real");

		return str_duplicate(s_NULL);
	}

	TRACE();

	// allocazione buffer

	TRACE();
	len = str_len(real);
	virlen = len + CRYPT_NETNAME_LEN + HIDEHOST_CHECKSUM_LEN + 2;

	if (virlen > hidehost_buffer_size) {

		hidehost_buffer = (STR) mem_realloc(hidehost_buffer, virlen);
		hidehost_buffer_size = virlen;
	}

	// generazione crypt

	hash = crypt_hash_SHA1(real, len, hidehost_crypt_buffer, hidehost_crypt_buffer_size);

	// creazione stringa "criptata"

	TRACE();

	if (htype == htHostname) {

		if (dotsCount == 1)
			snprintf(hidehost_buffer, hidehost_buffer_size, CRYPT_NETNAME "%c%lX.%s", (hash < 0 ? c_EQUAL : c_MINUS), (hash < 0 ? -hash : hash), real);
		
		else if (dotsCount > 1) {
			
			ptr = strchr(real, c_DOT);

			while (strlen(ptr) > (MAX_DSN_HOST_LEN - CRYPT_NETNAME_LEN - HIDEHOST_CHECKSUM_LEN))
				ptr = strchr(++ptr, c_DOT);

			snprintf(hidehost_buffer, hidehost_buffer_size, CRYPT_NETNAME "%c%lX.%s", (hash < 0 ? c_EQUAL : c_MINUS), (hash < 0 ? -hash : hash), ptr + 1);

		} else // LOCALHOST
			snprintf(hidehost_buffer, hidehost_buffer_size, "%s%c%lX", real, (hash < 0 ? c_EQUAL : c_MINUS), (hash < 0 ? -hash : hash));

	} else {

		char ipmask[16];

		strncpy(ipmask, real, sizeof(ipmask));
		ipmask[sizeof(ipmask) - 1] = c_NULL;
		
		if (IS_NOT_NULL(ptr = strchr(ipmask, c_DOT))) {

			if (IS_NOT_NULL(ptr = strchr(ptr + 1, c_DOT)))
				*ptr = c_NULL;
		}

		if (IS_NULL(ptr))
			snprintf(hidehost_buffer, hidehost_buffer_size, CRYPT_NETNAME "%c%lX", hash < 0 ? c_EQUAL : c_MINUS, hash < 0 ? -hash : hash);
		else
			snprintf(hidehost_buffer, hidehost_buffer_size, "%s." CRYPT_NETNAME "%c%lX", ipmask, hash < 0 ? c_EQUAL : c_MINUS, hash < 0 ? -hash : hash);
	}

	TRACE();

	return str_duplicate(hidehost_buffer);
}




void crypt_ds_dump(CSTR sourceNick, const User *callerUser, STR request) {

	/*
	DS DUMP CRYPT HELP
	DS DUMP CRYPT KEY|HOSTBUFF|HOSTCRYPT
	*/

	STR		cmd = strtok(request, s_SPACE);
	BOOL	needSyntax = FALSE;

	if (IS_NOT_NULL(cmd)) {

		if (str_equals_nocase(cmd, "HELP")) {

			// HELP !

		} else if (str_equals_nocase(cmd, "HOSTBUFF")) {
			send_notice_to_user(sourceNick, callerUser, "DUMP: [%d] %s", hidehost_buffer_size, str_get_valid_display_value(hidehost_buffer));

		} else if (str_equals_nocase(cmd, "HOSTCRYPT")) {
			send_notice_to_user(sourceNick, callerUser, "DUMP: [%d] %s", hidehost_crypt_buffer_size, str_get_valid_display_value(hidehost_crypt_buffer));

		} else if (str_equals_nocase(cmd, "KEY")) {
			send_notice_to_user(sourceNick, callerUser, "DUMP: [%d] %s", hidehost_key_size, str_get_valid_display_value(hidehost_key));

		} else
			needSyntax = TRUE;

	} else
		needSyntax = TRUE;

	if (needSyntax)
		send_notice_to_user(sourceNick, callerUser, "Syntax: \2DUMP\2 CRYPT KEY|HOSTBUFF|HOSTCRYPT");
}
