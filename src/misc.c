/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* misc.c - Misc stuff
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
#include "../inc/lang.h"
#include "../inc/conf.h"
#include "../inc/main.h"
#include "../inc/misc.h"
#include "../inc/timeout.h"
#include "../inc/ignore.h"
#include "../inc/trigger.h"

/*********************************************************/

void update_invalid_password_count(User *user, CSTR service, CSTR target) {

	BOOL isExempt;


	TRACE_FCLT(FACILITY_MISC_UPDATE_INVALID_PASSWORD_COUNT);

	if (IS_NULL(user))
		return;

	if (CONF_INVALID_PASSWORD_MAX_ATTEMPTS <= 0)
		return;

	isExempt = (user_is_ircop(user) || is_services_valid_oper(user) || user_is_services_agent(user));

	if (NOW >= user->invalid_pw_reset_time) {

		// E' trascorso il tempo necessario all'azzeramento del conteggio di tentativi falliti.
		user->invalid_pw_count = 0;

		// E' trascorso anche il tempo necessario ad abbassare il livello?
		if ((NOW - user->invalid_pw_reset_time >= (2 * ONE_HOUR)))
			user->invalid_pw_current_level = INVALID_PW_LEVEL_0;
	}

	// Aggiungere un nuovo messaggio al conteggio attuale.
	++(user->invalid_pw_count);

	// Nuovo azzeramento previsto.
	user->invalid_pw_reset_time = NOW + CONF_INVALID_PASSWORD_RESET;

	// Avanzarlo di livello?
	if (user->invalid_pw_count >= CONF_INVALID_PASSWORD_MAX_ATTEMPTS) {

		++(user->invalid_pw_current_level);

		switch (user->invalid_pw_current_level) {

			default:
			case INVALID_PW_LEVEL_2:

				/* Second attempt, ignore user for 3 hours and reset both count and level. */

				user->invalid_pw_count = 0;
				user->invalid_pw_current_level = INVALID_PW_LEVEL_0;

				if (!isExempt) {

					CIDR_IP cidr;
					BOOL isTriggered, haveCIDR = FALSE;
					char *username, *host;


					isTriggered = (trigger_match(user->username, user->host, user->ip, 0, NULL, NULL) == triggerFound);

					/* Let the user now they're now ignored. */
					send_notice_lang_to_user(service, user, GetCallerLang(), INVALID_PASSWORD_SECOND_WARNING, CONF_INVALID_PASSWORD_SECOND_IGNORE);
					send_notice_lang_to_user(service, user, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);

					/* Notify opers about it. */
					send_globops(s_OperServ, "Password hack attempt detected by \2%s\2 (%s@%s) [Last target: %s] [Ignored: %d minutes] [Triggered: %s]", user->nick, user->username, user->host, target, CONF_INVALID_PASSWORD_SECOND_IGNORE, isTriggered ? "Yes" : "No");

					/* Actually ignore the user. */
					username = (isTriggered ? str_duplicate(user->username) : NULL);

					if (user->ip != 0) {

						cidr_ip_fill_direct(user->ip, 32, &cidr);
						haveCIDR = TRUE;
						host = str_duplicate(get_ip(user->ip));
					}
					else
						host = str_duplicate(user->host);

					ignore_create_record(s_OperServ, NULL, username, host, "Password hack detected.", FALSE, (CONF_INVALID_PASSWORD_SECOND_IGNORE * ONE_MINUTE), haveCIDR, cidr);
				}
				else
					send_globops(s_OperServ, "Password hack attempt detected by \2%s\2 (%s@%s) [Last target: %s]", user->nick, user->username, user->host, target);

				break;


			case INVALID_PW_LEVEL_1:

				/* First attempt, ignore user and reset the password count. */

				user->invalid_pw_count = 0;

				if (!isExempt) {

					CIDR_IP cidr;
					BOOL isTriggered, haveCIDR = FALSE;
					char *username, *host;


					isTriggered = (trigger_match(user->username, user->host, user->ip, 0, NULL, NULL) == triggerFound);

					/* Let the user now they're now ignored. */
					send_notice_lang_to_user(service, user, GetCallerLang(), INVALID_PASSWORD_FIRST_WARNING, CONF_INVALID_PASSWORD_FIRST_IGNORE);
					send_notice_lang_to_user(service, user, GetCallerLang(), RECEIVE_NETWORK_ASSISTANCE, CONF_NETWORK_NAME);

					/* Notify opers about it. */
					send_globops(s_OperServ, "Too many invalid password attempts by \2%s\2 (%s@%s) [Last target: %s] [Ignore: %d minutes] [Triggered: %s]", user->nick, user->username, user->host, target, CONF_INVALID_PASSWORD_FIRST_IGNORE, isTriggered ? "Yes" : "No");

					/* Actually ignore the user. */
					username = (isTriggered ? str_duplicate(user->username) : NULL);

					if (user->ip != 0) {

						cidr_ip_fill_direct(user->ip, 32, &cidr);
						haveCIDR = TRUE;
						host = str_duplicate(get_ip(user->ip));
					}
					else
						host = str_duplicate(user->host);

					ignore_create_record(s_OperServ, NULL, username, host, "Too many invalid password attempts.", FALSE, (CONF_INVALID_PASSWORD_FIRST_IGNORE * ONE_MINUTE), haveCIDR, cidr);
				}
				else
					send_globops(s_OperServ, "Too many invalid password attempts by \2%s\2 (%s@%s) [Last target: %s]", user->nick, user->username, user->host, target);

				break;


			case INVALID_PW_LEVEL_0:
				/* Nothing to do here. */
				break;
		}
	}
}
/* generate a true pseudo-random seed. 
 * If it fails to retrive informations from /dev/urandom then use the current time as a seed.
 * Time() is not pseudo-random anymore but at lease it generates a seed when /dev/urandom don't.
 */
 
int randomseed()
{
        int fd;
        int seed;
        
          if((fd = open("/dev/urandom", O_RDONLY)) < 0)
                return time(NULL);

        if(read(fd,&seed,sizeof(int)) < 0)
        {
                close(fd);
                return time(NULL);
        }

        close(fd);
        return seed;
}

BOOL validate_email(CSTR email, BOOL allowWild) {

	int			hostIdx, hostlen;
	char		*host, *tld;
	const char	*username, *ptr;

	if (IS_NULL(email)) {

		log_error(FACILITY_MISC_VALIDATE_EMAIL, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_HALTED,
			s_LOG_ERR_PARAMETER, "validate_email()", s_LOG_NULL, "email");

		return FALSE;
	}

	if (IS_NULL(host = strrchr(email, '@')))
		return FALSE;

	username = email;

	/* Case '@host.tld' */
	if (username == host)
		return FALSE;

	if ((host - username) > 40)
		return FALSE;

	for (ptr = username; ptr < host; ++ptr) {
		if ((*ptr != '-') && (*ptr != '.') && (*ptr != '_')
		    && (allowWild ? (*ptr != '*') : 1)
		    && (allowWild ? (*ptr != '?') : 1)
		    && (!isalnum(*ptr)))
			return FALSE;
	}

	if (*(++host) == '.')
		return FALSE;

	hostlen = str_len(host);

	if (hostlen > HOSTMAX)
		return FALSE;

	for (hostIdx = 0; hostIdx < hostlen; ++hostIdx) {
		if ((host[hostIdx] != '-') && (host[hostIdx] != '.') && !isalnum(host[hostIdx]))
			return FALSE;
	}

	if (IS_NULL(tld = strrchr(email, '.')))
		return FALSE;

	if (strstr(host, ".."))
		return FALSE;

	return validate_tld(tld + 1, FALSE);
}


BOOL validate_tld(CSTR tld, BOOL allowFW) {

	size_t	tldlen;

	if (IS_NULL(tld))
		return FALSE;

	tldlen = str_len(tld);

	if (tldlen < 2 || tldlen > 6)
		return FALSE;

	switch (tldlen) {

		case 6:
			return (str_equals_nocase(tld, "museum") || str_equals_nocase(tld, "travel"));

		case 4:
			return ( str_equals_nocase(tld, "info") || str_equals_nocase(tld, "aero") ||
					 str_equals_nocase(tld, "coop") || str_equals_nocase(tld, "name") ||
			      		 str_equals_nocase(tld, "mobi") || str_equals_nocase(tld, "jobs") ||
			      		 str_equals_nocase(tld, "asia") ) ;

		case 3:
			return ( str_equals_nocase(tld, "com") || str_equals_nocase(tld, "org") ||
					 str_equals_nocase(tld, "cat") || str_equals_nocase(tld, "net") ||
					 str_equals_nocase(tld, "biz") || str_equals_nocase(tld, "edu") ||
					 str_equals_nocase(tld, "int") || str_equals_nocase(tld, "mil") ||
					 str_equals_nocase(tld, "gov") || str_equals_nocase(tld, "thc") ||
			      		 str_equals_nocase(tld, "lan") || str_equals_nocase(tld, "pro") ||
					 str_equals_nocase(tld, "tel"));

		case 2: {
			switch (str_char_tolower(tld[0])) {
				case 'a':
					switch (str_char_tolower(tld[1])) {
						case 'c':
						case 'd':
						case 'e':
						case 'f':
						case 'g':
						case 'i':
						case 'l':
						case 'm':
						case 'n':
						case 'o':
						case 'q':
						case 'r':
						case 's':
						case 't':
						case 'u':
						case 'w':
						case 'x':
						case 'z':
							return TRUE;

						default:
							return FALSE;
					}

				case 'b':
					switch (str_char_tolower(tld[1])) {
						case 'a':
						case 'b':
						case 'd':
						case 'e':
						case 'f':
						case 'g':
						case 'h':
						case 'i':
						case 'j':
						case 'l':
						case 'm':
						case 'n':
						case 'o':
						case 'r':
						case 's':
						case 't':
						case 'v':
						case 'w':
						case 'y':
						case 'z':
							return TRUE;

						default:
							return FALSE;
					}

				case 'c':
					switch (str_char_tolower(tld[1])) {
						case 'a':
						case 'c':
						case 'd':
						case 'f':
						case 'g':
						case 'h':
						case 'i':
						case 'k':
						case 'l':
						case 'm':
						case 'n':
						case 'o':
						case 'r':
						case 'u':
						case 'v':
						case 'x':
						case 'y':
						case 'z':
							return TRUE;

						default:
							return FALSE;
					}

				case 'd':
					switch (str_char_tolower(tld[1])) {
						case 'e':
						case 'j':
						case 'k':
						case 'm':
						case 'o':
						case 'z':
							return TRUE;

						default:
							return FALSE;
					}

				case 'e':
					switch (str_char_tolower(tld[1])) {
						case 'c':
						case 'e':
						case 'g':
						case 'h':
						case 'r':
						case 's':
						case 't':
						case 'u':
							return TRUE;

						default:
							return FALSE;
					}

				case 'f':
					switch (str_char_tolower(tld[1])) {
						case 'i':
						case 'j':
						case 'k':
						case 'm':
						case 'o':
						case 'r':
							return TRUE;

						case 'w':
							if (allowFW)
								return TRUE;
							/* Fall... */

						default:
							return FALSE;
					}

				case 'g':
					switch (str_char_tolower(tld[1])) {
						case 'a':
						case 'b':
						case 'd':
						case 'e':
						case 'f':
						case 'g':
						case 'h':
						case 'i':
						case 'l':
						case 'm':
						case 'n':
						case 'p':
						case 'q':
						case 'r':
						case 's':
						case 't':
						case 'u':
						case 'w':
						case 'y':
							return TRUE;

						default:
							return FALSE;
					}

				case 'h':
					switch (str_char_tolower(tld[1])) {
						case 'k':
						case 'm':
						case 'n':
						case 'r':
						case 't':
						case 'u':
							return TRUE;

						default:
							return FALSE;
					}

				case 'i':
					switch (str_char_tolower(tld[1])) {
						case 'd':
						case 'e':
						case 'l':
						case 'm':
						case 'n':
						case 'o':
						case 'q':
						case 'r':
						case 's':
						case 't':
							return TRUE;

						default:
							return FALSE;
					}

				case 'j':
					switch (str_char_tolower(tld[1])) {
						case 'e':
						case 'm':
						case 'o':
						case 'p':
							return TRUE;

						default:
							return FALSE;
					}

				case 'k':
					switch (str_char_tolower(tld[1])) {
						case 'e':
						case 'g':
						case 'h':
						case 'i':
						case 'm':
						case 'n':
						case 'p':
						case 'r':
						case 'w':
						case 'y':
						case 'z':
							return TRUE;

						default:
							return FALSE;
					}

				case 'l':
					switch (str_char_tolower(tld[1])) {
						case 'a':
						case 'b':
						case 'c':
						case 'i':
						case 'k':
						case 'r':
						case 's':
						case 't':
						case 'u':
						case 'v':
						case 'y':
							return TRUE;

						default:
							return FALSE;
					}

				case 'm':
					switch (str_char_tolower(tld[1])) {
						case 'a':
						case 'c':
						case 'd':
						case 'e':
						case 'f':
						case 'g':
						case 'h':
						case 'k':
						case 'l':
						case 'm':
						case 'n':
						case 'o':
						case 'p':
						case 'q':
						case 'r':
						case 's':
						case 't':
						case 'u':
						case 'v':
						case 'w':
						case 'x':
						case 'y':
						case 'z':
							return TRUE;

						default:
							return FALSE;
					}

				case 'n':
					switch (str_char_tolower(tld[1])) {
						case 'a':
						case 'c':
						case 'e':
						case 'f':
						case 'g':
						case 'i':
						case 'l':
						case 'o':
						case 'p':
						case 'r':
						case 'u':
						case 'z':
							return TRUE;

						default:
							return FALSE;
					}

				case 'o':
					switch (str_char_tolower(tld[1])) {
						case 'm':
							return TRUE;

						default:
							return FALSE;
					}

				case 'p':
					switch (str_char_tolower(tld[1])) {
						case 'a':
						case 'e':
						case 'f':
						case 'g':
						case 'h':
						case 'k':
						case 'l':
						case 'm':
						case 'n':
						case 'r':
						case 's':
						case 't':
						case 'w':
						case 'y':
							return TRUE;

						default:
							return FALSE;
					}

				case 'q':
					switch (str_char_tolower(tld[1])) {
						case 'a':
							return TRUE;
						default:
							return FALSE;
					}

				case 'r':
					switch (str_char_tolower(tld[1])) {
						case 'e':
						case 'o':
						case 's':
						case 'u':
						case 'w':
							return TRUE;

						default:
							return FALSE;
					}

				case 's':
					switch (str_char_tolower(tld[1])) {
						case 'a':
						case 'b':
						case 'c':
						case 'd':
						case 'e':
						case 'g':
						case 'h':
						case 'i':
						case 'j':
						case 'k':
						case 'l':
						case 'm':
						case 'n':
						case 'o':
						case 'r':
						case 't':
						case 'u':
						case 'v':
						case 'y':
						case 'z':
							return TRUE;

						default:
							return FALSE;
					}

				case 't':
					switch (str_char_tolower(tld[1])) {
						case 'c':
						case 'd':
						case 'f':
						case 'g':
						case 'h':
						case 'j':
						case 'k':
						case 'l':
						case 'm':
						case 'n':
						case 'o':
						case 'p':
						case 'r':
						case 't':
						case 'v':
						case 'w':
						case 'z':
							return TRUE;

						default:
							return FALSE;
					}

				case 'u':
					switch (str_char_tolower(tld[1])) {
						case 'a':
						case 'g':
						case 'k':
						case 'm':
						case 's':
						case 'y':
						case 'z':
							return TRUE;

						default:
							return FALSE;
					}

				case 'v':
					switch (str_char_tolower(tld[1])) {
						case 'a':
						case 'c':
						case 'e':
						case 'g':
						case 'i':
						case 'n':
						case 'u':
							return TRUE;

						default:
							return FALSE;
					}

				case 'w':
					switch (str_char_tolower(tld[1])) {
						case 'f':
						case 's':
							return TRUE;

						default:
							return FALSE;
					}

				case 'y':
					switch (str_char_tolower(tld[1])) {
						case 'e':
						case 't':
							return TRUE;

						default:
							return FALSE;
					}

				case 'z':
					switch (str_char_tolower(tld[1])) {
						case 'a':
						case 'm':
						case 'w':
							return TRUE;

						default:
							return FALSE;
					}

				default:
					return FALSE;
			}

			return TRUE;
		} // case 2:
	
		default:
			return FALSE;
	}
}

/*********************************************************/

BOOL string_has_ccodes(const char *string) {

	register unsigned char c;

	if (IS_NULL(string))
		return FALSE;

	while (*string) {

		c = *(string++);

		if ((c < 32) || (c == 160))
			return TRUE;
	}

	return FALSE;
}

/**********************************************************/

char *terminate_string_ccodes(char *string) {

	char *ptr;
	unsigned char c;
	BOOL bold, colors, reverse, underline;


	if (IS_NULL(string))
		return NULL;

	ptr = string;

	bold = colors = reverse = underline = FALSE;

	while (*ptr) {

		switch (c = *ptr++) {

			case 2:
				/* Bold code. First one opens, next closes. */
				if (bold == TRUE)
					bold = FALSE;
				else
					bold = TRUE;

				break;


			case 3:
				/* Color code. */
				if (isdigit(*ptr))
					colors = TRUE;		/* This changes colors, always. */
				else
					colors = FALSE;		/* This terminates all previous colors. */

				break;


			case 15:
				/* Plain code. Removes all previous control codes. */
				bold = FALSE;
				colors = FALSE;
				reverse = FALSE;
				underline = FALSE;

				break;


			case 22:
				/* Reverse code. First one opens, next closes. */
				if (reverse == TRUE)
					reverse = FALSE;
				else
					reverse = TRUE;

				break;


			case 31:
				/* Underline code. First one opens, next closes. */
				if (underline == TRUE)
					underline = FALSE;
				else
					underline = TRUE;

				break;

			default:
				break;
		}
	}

	/* ptr now points to the end of the string. */

	/* Kill trailing spaces, if any. */
	while (*(ptr - 1) == c_SPACE)
		--ptr;

	/* Now close control codes. */
	if (bold)
		*ptr++ = (char) 2;

	if (colors)
		*ptr++ = (char) 3;

	if (reverse)
		*ptr++ = (char) 22;

	if (underline)
		*ptr++ = (char) 31;

	*ptr = '\0';

	return string;
}

/**********************************************************/

BOOL validate_string(CSTR string) {

	const char *ptr;
	unsigned char c;
	int valid = 0;


	if (IS_NULL(string))
		return FALSE;

	ptr = string;

	while (*ptr) {

		switch (c = *ptr++) {

			case 3:
				/* Color code. */
				if (isdigit(*ptr)) {

					/* Catch all "<ctrl+K>number[number][,number[number]]" characters. */
					++ptr;

					if (isdigit(*ptr))
						++ptr;

					if (*ptr == c_COMMA) {

						++ptr;

						if (isdigit(*ptr)) {

							++ptr;

							if (isdigit(*ptr))
								++ptr;
						}
					}
				}

				break;


			default:
				if ((c < 32) || (c == 160))
					continue;

				++valid;
				break;
		}
	}

	return (valid > 0);
}

/**********************************************************/

BOOL year_is_leap(const int year) {

	return (((year % 400) == 0) || (((year % 4) == 0) && ((year % 100) != 0)));
}

/**********************************************************/

int mask_contains_crypt(const char *mask) {

	char *host, *ptr;
	char token[BUFSIZE], cloak[128], hidehost[32], hex[32];
	int classA, classB;

	if (IS_NULL(host = strchr(mask, '@'))) {

		if (str_match_wild_nocase("*" CRYPT_NETNAME "*", mask))
			return 2;
		else
			return FALSE;
	}
	else
		++host;		/* Skip leading @ */

	if (sscanf(host, "%d.%d.%s", &classA, &classB, cloak) != 3) {

		memset(cloak, 0, sizeof(cloak));

		if ((ptr = str_tokenize(host, token, sizeof(token), c_DOT)))
			str_copy_checked(token, cloak, sizeof(cloak));
	}

	if (IS_EMPTY_STR(cloak))
		return FALSE;

	memset(hidehost, 0, sizeof(hidehost));

	if ((ptr = str_tokenize(cloak, token, sizeof(token), strchr(cloak, '=') ? '=' : '-')))
		str_copy_checked(token, hidehost, sizeof(hidehost));

	if (IS_EMPTY_STR(hidehost))
		return FALSE;

	memset(hex, 0, sizeof(hex));

	if ((ptr = str_tokenize(ptr, token, sizeof(token), c_SPACE)))
		str_copy_checked(token, hex, sizeof(hex));

	if (IS_EMPTY_STR(hex))
		return FALSE;

	if (str_equals_nocase(hidehost, CRYPT_NETNAME) && str_spn(hex, "0123456789ABCDEF"))
		return TRUE;

	return FALSE;
}


/*********************************************************
 * This function makes sure this mask is valid, i.e. it  *
 * cannot be used to get IPs through the use of WHY.     *
 * If input contains one or more stars (*) output will   *
 * only allow one, leading if it's a host, trailing if   *
 * it's an IP.                                           *
 *                                                       *
 * Return values:                                        *
 *                                                       *
 *     0: Mask was accepted and not modified.            *
 *     1: Mask was accepted after being modified.        *
 *     2: Invalid mask.                                  *
 *     3: Mask contains '?' characters. Not accepted.    *
 *********************************************************/

int validate_access(char *mask) {

	char *string, *token_ptr, token[BUFSIZE], *ptr, buffer[MASKMAX];
	int i, len = 0, dots = 0, stars = 0;
	BOOL isHost = FALSE, wasChanged;

	/* IPv6 is good. For now. */
	if (strchr(mask, ':'))
		return 0;

	string = strchr(mask, '@');

	/* No '@' or nothing after it? Fake mask. */
	if (IS_NULL(string) || !*(++string))
		return 2;

	len = str_len(string);

	for (i = 0; i < len; i++) {

		switch (string[i]) {

		case '?':
			/* ?'s are not allowed. Return error. */
			return 3;

		case '.':
			dots++;
			break;

		case '*':
			stars++;
			break;

		case '0':
		case '1':
		case '2':
		case '3':
		case '4':
		case '5':
		case '6':
		case '7':
		case '8':
		case '9':
			break;

		default:
			isHost = TRUE;
			break;
		}
	}

	/* No dots? Most likely fake. */
	if (dots == 0) {

		/* Allow '*' as host for *!*@* and the like. */
		if (stars == len)
			return 0;

		return 2;
	}

	/* No stars? Leave it as it is, it's good enough. */
	if (stars == 0)
		return 0;

	token_ptr = str_tokenize(mask, token, sizeof(token), c_AT);

	len = str_len(token);
	memcpy(buffer, token, len);
	ptr = buffer + len;

	*(ptr++) = c_AT;

	if (isHost) {

		/* This is a host. We only allow one, leading star. */
		int tokens = 0;

		token_ptr = str_tokenize(token_ptr, token, sizeof(token), c_DOT);

		/* Skip to the first token with no star. Replace anything before it with one star. */
		while (IS_NOT_NULL(token_ptr) && strchr(token, '*')) {

			stars -= strspn(token, "*");
			token_ptr = str_tokenize(token_ptr, token, sizeof(token), c_DOT);
		}

		/* At this point we should have no more stars. */
		if (stars != 0)
			return 2;

		/* Add the leading star and dot. */
		*(ptr++) = c_STAR;
		*(ptr++) = c_DOT;

		/* Copy the good token we got, plus a dot. */
		len = str_len(token);
		memcpy(ptr, token, len);
		ptr += len;
		*(ptr++) = c_DOT;

		/* Copy the rest. */
		token_ptr = str_tokenize(token_ptr, token, sizeof(token), c_DOT);

		while (IS_NOT_NULL(token_ptr)) {

			++tokens;
			len = str_len(token);
			memcpy(ptr, token, len);
			ptr += len;

			/* Add a trailing dot, we are going to add one too many this way. */
			*(ptr++) = c_DOT;

			token_ptr = str_tokenize(token_ptr, token, sizeof(token), c_DOT);
		}

		/* Did we end up with *.tld? Dame desu. */
		if (tokens < 1)
			return 2;

		/* Terminate the string at the last dot we added. */
		ptr[str_len(ptr) - 1] = c_NULL;

		/* Mask is good now. Yatta. */
		wasChanged = str_not_equals_nocase(buffer, mask);
		str_copy_checked(buffer, mask, MASKMAX);
		return wasChanged;
	}
	else {

		/* This is a V4 IP. The only classes accepted are A.B.* or broader (i.e. A.*). */

		switch (dots) {

		case 1:
			/* First and second IP classes are not masked so anything is good. */
			for (i = 0; i < 2; ++i) {

				token_ptr = str_tokenize(token_ptr, token, sizeof(token), c_DOT);

				string = token;

				len = str_len(token);

				/* Block masks with a star in the first field. Allow 1.* though. */
				if ((i == 0) && str_spn(string, "*"))
					return 2;

				/* 1.2*3*4 is bad. Cut after first star. */
				else if ((i == 1) && (str_count(string, '*') > 1)) {

					while (len > 0) {

						*(ptr++) = *string;

						if (*token == '*')
							break;

						++string;
						--len;
					}
				}
				else {

					memcpy(ptr, token, len);
					ptr += len;
				}

				if (i == 0)
					*(ptr++) = c_DOT;
			}
			break;

		case 2:
		case 3:
			/* Copy the first two classes, force the third to be a star. Ignore the rest. */
			for (i = 0; i < 2; ++i) {

				token_ptr = str_tokenize(token_ptr, token, sizeof(token), c_DOT);

				len = str_len(token);

				/* No stars alone allowed in the first two class fields. */
				if (str_spn(token, "*"))
					return 2;

				else {

					memcpy(ptr, token, len);
					ptr += len;
				}

				*(ptr++) = c_DOT;
			}

			*(ptr++) = c_STAR;
			break;

		default:
			/* WTF? */
			return 2;
		}

		/* Terminate the string. */
		*(ptr++) = c_NULL;

		/* Mask is good now. Yatta. */
		wasChanged = str_not_equals_nocase(buffer, mask);
		str_copy_checked(buffer, mask, MASKMAX);
		return wasChanged;
	}
}

BOOL validate_channel(CSTR chan) {

	unsigned char c;

	if (IS_NULL(chan))
		return FALSE;

	while (*chan) {

		c = *chan++;

		if ((c < 33) || (c == ',') || (c == 160))
			return FALSE;
	}

	return TRUE;
}

BOOL validate_nick(CSTR nick, BOOL allowWild) {

	register unsigned char c;

	if (IS_NULL(nick) || (*nick == '-') || isdigit(*nick))
		return FALSE;

	while (*nick) {

		c = *(nick++);

		if (((c < '0') && (c != '-') && (allowWild ? (c != '*') : 1)) ||
			((c > '9') && (c < 'A') && (allowWild ? (c != '?') : 1)) ||
			(c >= '~'))
			return FALSE;
	}

	return TRUE;
}

BOOL validate_username(CSTR username, BOOL allowWild) {

	unsigned char c;


	if (IS_NULL(username) || strchr(username, '`'))
		return FALSE;

	while (*username) {

		c = *(username++);

		if (c > '~' || ((c < '0' || (c > '9' && c < 'A')) && !strchr((allowWild ? "-.*?" : "-."), c)))
			return FALSE;
	}

	return TRUE;
}

BOOL validate_host(CSTR host, BOOL allowWild, BOOL allowCIDR, BOOL allowCrypt) {

	unsigned char c;
	char *tld, *charset;


	if (IS_NULL(host))
		return FALSE;

	if (strchr(host, ':')) {

		int len = 0, colons = 0, special = 0;
		const char *ptr;

		/* This is an IPv6. */

		if (strchr(host, '.'))
			return FALSE;

		ptr = host;

		while (*ptr) {

			if (*ptr == ':') {

				++colons;
				len = 0;
			}
			else if (allowWild && strchr("*?", *ptr)) {

				++special;
				len = 0;
			}
			else if (isxdigit(*ptr)) {

				/* Look for fields larger than 4 bytes. */
				if (++len > 4)
					return FALSE;
			}
			else
				return FALSE;

			++ptr;
		}

		if ((!special && (colons < 2 || (colons < 7 && !strstr(host, "::")))) ||
			colons > 7 || strstr(host, ":::") || str_match_wild_nocase("*::*::*", host))
			return FALSE;

		return TRUE;
	}

	/* Hosts cannot begin with either '.' or '-'. */
	if ((host[0] == '.') || (host[0] == '-'))
		return FALSE;

	/* Hosts with no dots or colons are bad, unless it has a '*' or a '?'. */
	if (!strchr(host, '.') && (!allowWild || (!strchr(host, '*') && !strchr(host, '?'))))
		return FALSE;

	/* There can't be two dots in a row, or a hyphen as first character of a field. */
	if (strstr(host, "..") || strstr(host, ".-"))
		return FALSE;

	tld = strrchr(host, '.');

	if (tld) {

		++tld;

		if (IS_EMPTY_STR(tld))
			return FALSE;

		if (!strchr(tld, '*') && !strchr(tld, '?')) {

			char *err, buffer[HOSTSIZE];
			long int tldValue;


			if (allowCIDR && strchr(tld, '/')) {

				int idx = 0;

				while (*tld && (*tld != '/'))
					buffer[idx++] = *tld++;

				buffer[idx] = '\0';
				tld = buffer;
			}

			tldValue = strtol(tld, &err, 10);

			if (*err == '\0') {

				if (tldValue > 255)
					return FALSE;
			}
			else {

				if (!validate_tld(tld, TRUE))
					return FALSE;
			}
		}
	}

	/* Now check for invalid characters, according to bahamut standard. */

	charset = (allowWild ? (allowCrypt ? "-.*?=" : "-.*?") : (allowCrypt ? "-.=" : "-."));

	while (*host) {

		c = *(host++);

		if (allowCIDR && (c == '/')) {

			int cidr_size;

			if ((*host == '\0') || ((*(host + 1) != '\0') && (*(host + 2) != '\0')))
				return FALSE;

			cidr_size = ((*host - 48) * 10);

			if (*(host + 1) != '\0')
				cidr_size += (*(host + 1) - 48);

			if ((cidr_size < 1) || (cidr_size > 32))
				return FALSE;

			return TRUE;
		}

		if (!isalnum(c) && !strchr(charset, c))
			return FALSE;
	}

	return TRUE;
}

BOOL validate_mask(CSTR mask, BOOL allowWild, BOOL allowCIDR, BOOL allowCrypt) {

	char token[IRCBUFSIZE];
	char *ptr;

	if (strchr(mask, c_EXCLAM)) {

		ptr = str_tokenize(mask, token, sizeof(token), c_EXCLAM);

		if (IS_NULL(ptr) || IS_EMPTY_STR(token) || !validate_nick(token, allowWild))
			return FALSE;

		ptr = str_tokenize(ptr, token, sizeof(token), c_AT);

		if (IS_NULL(ptr) || IS_EMPTY_STR(token) || !validate_username(token, allowWild))
			return FALSE;
	}
	else {

		ptr = str_tokenize(mask, token, sizeof(token), c_AT);

		if (IS_NULL(ptr) || IS_EMPTY_STR(ptr))
			return validate_nick(mask, allowWild);

		if (IS_EMPTY_STR(token) || !validate_username(token, allowWild))
			return FALSE;
	}

	ptr = str_tokenize(ptr, token, sizeof(token), c_SPACE);

	if (IS_NULL(ptr) || IS_EMPTY_STR(token) || !validate_host(token, allowWild, allowCIDR, allowCrypt))
		return FALSE;

	return TRUE;
}


BOOL validate_date(const int dateYear, const int dateMonth, const int dateDay) {

	if ((dateYear < 1997) || (dateYear > time_today_year))
		return FALSE;

	if ((dateMonth <= 0) || (dateMonth > 12))
		return FALSE;

	if (dateDay <= 0)
		return FALSE;

	switch (dateMonth) {

		case 4:		/* April */
		case 6:		/* June */
		case 9:		/* September */
		case 11:	/* November */
			if (dateDay > 30)
				return FALSE;

			break;


		case 2:		/* February */
			if (dateDay > (year_is_leap(dateYear) ? 29 : 28))
				return FALSE;

			break;


		default:
			if (dateDay > 31)
				return FALSE;
	}

	if (dateYear == time_today_year) {

		/* Month is in the future? */
		if (dateMonth > time_today_month)
			return FALSE;

		/* Day is in the future? */
		if ((dateMonth == time_today_month) && (dateDay > time_today_day))
			return FALSE;
	}

	return TRUE;
}



HOST_TYPE host_type(CSTR host, short int *dotsCountPtr) {

	CSTR			ptr;
	char			ch;
	short int		numbersCount, alphaCount, dotsCount, columnsCount;
	BOOL			lastIsDot, slashFound;


	if (IS_NULL(host))
		return htInvalid;

	ptr = host;
	numbersCount = alphaCount = dotsCount = columnsCount = 0;
	lastIsDot = slashFound = FALSE;

	while ((ch = *ptr) != 0) {
		switch (ch) {

			case '0':
			case '1':
			case '2':
			case '3':
			case '4':
			case '5':
			case '6':
			case '7':
			case '8':
			case '9':
				++numbersCount;
				lastIsDot = FALSE;
				break;

			case '.':
				if (lastIsDot || // ".." ?
					columnsCount || // dotted IPv6 ??
					slashFound)  // "1.2.3.4/*.*"
					return htInvalid;

				++dotsCount;
				lastIsDot = TRUE;
				break;

			case ':':
				if (dotsCount ||	// dotted IPv6 ??
					slashFound) // IPv6 CIDR ??
					return htInvalid;

				++columnsCount;
				lastIsDot = FALSE;
				break;

			case '/':
				if (slashFound || // "*//*"
					lastIsDot || // "*./*"
					columnsCount) // IPv6 CIDR ??
					return htInvalid;

				slashFound = TRUE;
				lastIsDot = FALSE;
				break;

			default:
				++alphaCount;
				lastIsDot = FALSE;
				break;
		}

		++ptr;
	}

	if (IS_NOT_NULL(dotsCountPtr))
		*dotsCountPtr = dotsCount;

	if (lastIsDot) // *. ?
		return htInvalid;
	
	else if (columnsCount) // IPv6 ?
		return htIPv6;

	else if ((dotsCount == 3) && (numbersCount > 3) && (alphaCount == 0)) // IPv4 or IPv4 CIDR ?
		return slashFound ? htIPv4_CIDR : htIPv4;
	
	else if ((dotsCount >= 1) && (alphaCount >= 2)) // hostname ?
		return htHostname;

	else
		return htInvalid;
}


/*********************************************************
 * This function converts an IPv6 address from its       *
 * compact form to its complete form.                    *
 *********************************************************/

char *expand_ipv6(const char *input) {

	char output[40];
	char *ptr = output;
	int i = 0, colons, len;

	memcpy(ptr, "0000:0000:0000:0000:0000:0000:0000:0000", 40);

	colons = str_count(input, ':');

	if (colons > 7) {

		LOG_DEBUG_SNOOP("Warning: IPv6 %s is invalid!", input);
		return str_duplicate(input);
	}

	len = strlen(input);

	/* Point at the end of our buffer. We are going to loop through it backwards. */
	ptr = output + 38;

	/* Skip to the end of the string. */
	input += len - 1;

	while (len > 0) {

		switch (*input) {

			case ':':
				if (*(input + 1) == ':') {

					/* We hit a '::', move left for as many fields as were collapsed. */
					ptr -= (8 - colons) * 5;
					i = 0;
					break;
				}

				/* 4 + ':' = 5 */
				ptr -= (5 - i);
				i = 0;
				break;

			default:
				*(ptr--) = *input;
				i++;
		}

		input--;
		len--;
	}

	return str_duplicate(output);
}


/*********************************************************
 * This function converts a C-time time_t value into a   *
 * human-readable format.                                *
 *********************************************************/

char *convert_time(char *buffer, size_t bufferSize, time_t timeSpan, const LANG_ID langID) {

	int		weeks = 0, days = 0, hours = 0, minutes = 0;
	size_t	len = 0;
	char	langbuf[IRCBUFSIZE];


	if (timeSpan <= 0)
		timeSpan = 1;

	if (timeSpan >= ONE_WEEK) {

		weeks = timeSpan / ONE_WEEK;
		timeSpan -= weeks * ONE_WEEK;

		if (weeks == 1)
			len += str_copy_checked(lang_msg(langID, TIME_REPLY_WEEK), (buffer + len), (bufferSize - len));

		else {

			snprintf(langbuf, sizeof(langbuf), lang_msg(langID, TIME_REPLY_WEEKS), weeks);

			len += str_copy_checked(langbuf, (buffer + len), (bufferSize - len));
		}
	}

	if (timeSpan >= ONE_DAY) {

		days = timeSpan / ONE_DAY;
		timeSpan -= days * ONE_DAY;

		if (len > 0) {

			*(buffer + len++) = c_COMMA;
			*(buffer + len++) = c_SPACE;
		}

		if (days == 1)
			len += str_copy_checked(lang_msg(langID, TIME_REPLY_DAY), (buffer + len), (bufferSize - len));

		else {

			snprintf(langbuf, sizeof(langbuf), lang_msg(langID, TIME_REPLY_DAYS), days);

			len += str_copy_checked(langbuf, (buffer + len), (bufferSize - len));
		}
	}

	if (timeSpan >= ONE_HOUR) {

		hours = timeSpan / ONE_HOUR;
		timeSpan -= hours * ONE_HOUR;

		if (len > 0) {

			*(buffer + len++) = c_COMMA;
			*(buffer + len++) = c_SPACE;
		}

		if (hours == 1)
			len += str_copy_checked(lang_msg(langID, TIME_REPLY_HOUR), (buffer + len), (bufferSize - len));

		else {

			snprintf(langbuf, sizeof(langbuf), lang_msg(langID, TIME_REPLY_HOURS), hours);

			len += str_copy_checked(langbuf, (buffer + len), (bufferSize - len));
		}
	}

	if (timeSpan >= ONE_MINUTE) {

		minutes = timeSpan / ONE_MINUTE;
		timeSpan -= minutes * ONE_MINUTE;

		if (len > 0) {

			*(buffer + len++) = c_COMMA;
			*(buffer + len++) = c_SPACE;
		}

		if (minutes == 1)
			len += str_copy_checked(lang_msg(langID, TIME_REPLY_MINUTE), (buffer + len), (bufferSize - len));

		else {

			snprintf(langbuf, sizeof(langbuf), lang_msg(langID, TIME_REPLY_MINUTES), minutes);

			len += str_copy_checked(langbuf, (buffer + len), (bufferSize - len));
		}
	}

	if (timeSpan > 0) {

		if (len > 0) {

			*(buffer + len++) = c_COMMA;
			*(buffer + len++) = c_SPACE;
		}

		if (timeSpan == 1)
			len += str_copy_checked(lang_msg(langID, TIME_REPLY_SECOND), (buffer + len), (bufferSize - len));

		else {

			snprintf(langbuf, sizeof(langbuf), lang_msg(langID, TIME_REPLY_SECONDS), (int)timeSpan);

			len += str_copy_checked(langbuf, (buffer + len), (bufferSize - len));
		}
	}

	return buffer;
}


/*********************************************************
 * This function converts an expiration C-time time_t    *
 * value into a human-readable format.                   *
 *********************************************************/

char *expire_left(char *buffer, size_t len, time_t expiry) {

	if (expiry == 0)
		str_copy_checked("Does not expire.", buffer, len);

	else if (expiry <= NOW)
		str_copy_checked("Expires at next database update.", buffer, len);

	else
		snprintf(buffer, len, "Expires in %s.", convert_time(misc_buffer, MISC_BUFFER_SIZE, (expiry - NOW), LANG_DEFAULT));

	return buffer;
}


/*********************************************************
 * This function converts an amount of time into an      *
 * integer value.                                        *
 *********************************************************/

long int convert_amount(CSTR string) {

	char		*ptr;
	int			value;
	long int 	timeSpan = 0;
	BOOL		have_days = FALSE, have_hours = FALSE;
	BOOL		have_weeks = FALSE, have_minutes = FALSE, have_seconds = FALSE;


	if (string[0] == '+')
		++string;

	if ((string[0] == '0') && (string[1] == '\0'))
		return 0;

	value = strtol(string, &ptr, 10);

	while (value > 0) {

		switch (*ptr) {

			case 'w':
			case 'W':
				if (have_weeks)
					return -1;

				if (value > 12)
					return -1;

				timeSpan += (value * ONE_WEEK);
				have_weeks = TRUE;
				break;

			case 'd':
			case 'D':
				if (have_days)
					return -1;

				if (value > 100)
					return -1;

				timeSpan += (value * ONE_DAY);
				have_days = TRUE;
				break;

			case 'h':
			case 'H':
				if (have_hours)
					return -1;

				if (value > 3600)
					return -1;

				timeSpan += (value * ONE_HOUR);
				have_hours = TRUE;
				break;

			case 'm':
			case 'M':
				if (have_minutes)
					return -1;

				timeSpan += (value * ONE_MINUTE);
				have_minutes = TRUE;
				break;

			case 's':
			case 'S':
				if (have_seconds)
					return -1;

				timeSpan += value;
				have_seconds = TRUE;
				break;

			default:
				return -1;
		}

		if (*(ptr + 1) == '\0') {

			if (timeSpan <= 0)
				return -1;

			return timeSpan;
		}

		value = strtol(ptr + 1, &ptr, 10);
	}

	/* If we get here, something's wrong. Reject input. */
	return -1;
}


/*********************************************************
 * merge_args()                                          *
 *                                                       *
 * Take an argument count and argument vector and merge  *
 * them into a single string in which each argument is   *
 * separated by a space.                                 *
 *********************************************************/

STR	merge_args(const int ac, char * const av[]) {

	static char		buffer[4096];
	int				idx;
	size_t			len = 0;


	if ((ac == 0) || IS_NULL(av))
		return "Empty argument vector";

	len = str_copy_checked(av[0], buffer, sizeof(buffer));

	for (idx = 1; idx < ac; ++idx) {

		*(buffer + len++) = c_SPACE;
		len += str_copy_checked(av[idx], (buffer + len), (sizeof(buffer) - len));
	}

	return buffer;
}


/*********************************************************
 * get_ip()                                              *
 *                                                       *
 * Take an ip in host byte order and return a readable   *
 * output in standard internet format.                   *
 *********************************************************/

char *get_ip(unsigned long int ip) {

	static char buffer[16];

	unsigned char *bytes = (unsigned char *) &ip;
	snprintf(buffer, sizeof(buffer), "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);

	return buffer;
}


/*********************************************************
 * get_ip_r()                                            *
 *                                                       *
 * Same as above, but reentrant.                         *
 *********************************************************/

char *get_ip_r(char *buffer, size_t len, unsigned long int ip) {

	unsigned char *bytes = (unsigned char *) &ip;
	snprintf(buffer, len, "%u.%u.%u.%u", bytes[0], bytes[1], bytes[2], bytes[3]);

	return buffer;
}


/*********************************************************
 * get_ip6()                                             *
 *                                                       *
 * Take an ip6 in net byte order and return a readable   *
 * output in standard internet format.                   *
 *********************************************************/

char *get_ip6(const unsigned char *ip6) {

        static char buffer[INET6_ADDRSTRLEN];

        inet_ntop(AF_INET6, ip6, buffer, INET6_ADDRSTRLEN);
        return buffer;
}


/*********************************************************
 * get_ip6_r()                                           *
 *                                                       *
 * Same as above, but reentrant.                         *
  *********************************************************/

char *get_ip6_r(char *buffer, size_t len, const unsigned char *ip6) {

        inet_ntop(AF_INET6, ip6, buffer, len);
        return buffer;
}


/*********************************************************
 * aton()                                                *
 *                                                       *
 * Convert an ASCII IP to notation format.               *
 *********************************************************/

unsigned long int aton(CSTR ipaddr) {

	unsigned long int res;
	unsigned char *bytes = (unsigned char *) &res;
	long int quad;
	char *endptr;


	if (IS_NULL(ipaddr))
		return INADDR_NONE;

	/* Quad #1. */
	quad = strtol(ipaddr, &endptr, 10);

	if ((quad < 0) || (quad > 255) || (*endptr == '\0') || (*endptr != '.'))
		return INADDR_NONE;

	bytes[0] = (unsigned char) quad;

	/* Quad #2. */
	quad = strtol(++endptr, &endptr, 10);

	if ((quad < 0) || (quad > 255) || (*endptr == '\0') || (*endptr != '.'))
		return INADDR_NONE;

	bytes[1] = (unsigned char) quad;

	/* Quad #3. */
	quad = strtol(++endptr, &endptr, 10);

	if ((quad < 0) || (quad > 255) || (*endptr == '\0') || (*endptr != '.'))
		return INADDR_NONE;

	bytes[2] = (unsigned char) quad;

	/* Quad #4. */
	quad = strtol(++endptr, &endptr, 10);

	if ((quad < 0) || (quad > 255) || (*endptr != '\0'))
		return INADDR_NONE;

	bytes[3] = (unsigned char) quad;

	return res;
}


/*********************************************************
 * CRC                                                   *
 *********************************************************/

// Static CRC table
static unsigned long crc32_table[256] = {

	0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
	0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
	0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
	0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
	0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
	0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
	0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
	0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
	0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
	0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
	0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
	0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
	0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
	0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
	0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
	0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,

	0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
	0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
	0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
	0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
	0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
	0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
	0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
	0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
	0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
	0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
	0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
	0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
	0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
	0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
	0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
	0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,

	0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
	0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
	0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
	0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
	0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
	0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
	0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
	0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
	0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
	0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
	0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
	0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
	0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
	0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
	0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
	0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,

	0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
	0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
	0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
	0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
	0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
	0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
	0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
	0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
	0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
	0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
	0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
	0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
	0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
	0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
	0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
	0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
};


static void compute_crc32(const BYTE byte, unsigned long int *crc) {

	*crc = ((*crc) >> 8) ^ crc32_table[(byte) ^ ((*crc) & 0x000000FF)];
}


void crc32(PBYTE data, size_t size, unsigned long int *crc) {

	size_t		idx;

	for(idx = 0; idx < size; ++idx)
		compute_crc32(data[idx], crc);

	*crc = ~(*crc);
}
