/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* strings.c - Stringhe di testo comuni
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/memory.h"
#include "../inc/logging.h"
#include "../inc/signals.h"
#include "../inc/main.h"


/*********************************************************
 * Caratteri generici                                    *
 *********************************************************/

STDCHR	c_NULL		= '\0';
STDCHR	c_SPACE		= ' ';
STDCHR	c_DOT		= '.';
STDCHR	c_COMMA		= ',';
STDCHR	c_COLON		= ':';
STDCHR	c_QUESTION	= '?';
STDCHR	c_EXCLAM	= '!';
STDCHR	c_STAR		= '*';
STDCHR	c_SHARP		= '#';
STDCHR	c_AMP		= '&';
STDCHR	c_AT		= '@';
STDCHR	c_PLUS		= '+';
STDCHR	c_MINUS		= '-';
STDCHR	c_EQUAL		= '=';
STDCHR	c_SLASH		= '/';
STDCHR	c_BOLD		= '\2';
STDCHR	c_CR		= '\r';
STDCHR	c_LF		= '\n';


/*********************************************************
 * Stringhe generiche                                    *
 *********************************************************/

STDSTR	s_NULL		= "\0";
STDSTR	s_SPACE		= " ";
STDSTR	s_DOT		= ".";
STDSTR	s_COMMA		= ",";
STDSTR	s_COLON		= ":";
STDSTR	s_QUESTION	= "?";
STDSTR	s_EXCLAM	= "!";
STDSTR	s_STAR		= "*";
STDSTR	s_SHARP		= "#";
STDSTR	s_AMP		= "&";
STDSTR	s_AT		= "@";
STDSTR	s_PLUS		= "+";
STDSTR	s_MINUS		= "-";
STDSTR	s_EQUAL		= "=";
STDSTR	s_SLASH		= "/";
STDSTR	s_BOLD		= "\2";
STDSTR	s_CR		= "\r";
STDSTR	s_LF		= "\n";
STDSTR	s_YES		= "YES";
STDSTR	s_NO		= "NO";
STDSTR	s_ON		= "ON";
STDSTR	s_OFF		= "OFF";
STDSTR	s_ENABLE	= "ENABLE";
STDSTR	s_DISABLE	= "DISABLE";
STDSTR	s_ENABLED	= "ENABLED";
STDSTR	s_DISABLED	= "DISABLED";
STDSTR	s_BLOCK		= "BLOCK";
STDSTR	s_DONTBLOCK	= "DONTBLOCK";
STDSTR	s_TODAY		= "TODAY";

STDSTR	s_OPENMODE_READONLY	 = "r";
STDSTR	s_OPENMODE_WRITEONLY = "w";
STDSTR	s_OPENMODE_APPEND	 = "at";


/*********************************************************
 * Oper levels names                                     *
 *********************************************************/

STDSTR	s_OPER_MASTER	= "\2Services Master\2, IRC Operator";
STDSTR	s_OPER_CODER	= "\2Services Coder\2, IRC Operator";
STDSTR	s_OPER_SRA		= "\2Services Root Administrator\2, IRC Operator";
STDSTR	s_OPER_SA		= "\2Services Admin\2, IRC Operator";
STDSTR	s_OPER_SOP		= "\2Services Operator\2, IRC Operator";
STDSTR	s_OPER_HOP_OPER	= "\2Services Help Operator\2, IRC Operator";
STDSTR	s_OPER_HOP		= "\2Services Help Operator\2";
STDSTR	s_OPER_OPER		= "IRC Operator";


STDSTR	s_OPER_CMD_LEVEL_MASTER	= "Services Master";
STDSTR	s_OPER_CMD_LEVEL_CODER	= "Services Coders";
STDSTR	s_OPER_CMD_LEVEL_SRA	= "Services Roots";
STDSTR	s_OPER_CMD_LEVEL_SA		= "Services Administrators";
STDSTR	s_OPER_CMD_LEVEL_SOP	= "Services Operators";
STDSTR	s_OPER_CMD_LEVEL_HOP	= "Help Operators";
STDSTR	s_OPER_CMD_LEVEL_IRCOP	= "IRC Operators";


/*********************************************************
 * Logging                                               *
 *********************************************************/

STDSTR	s_LOG_NULL		= "NULL";
STDSTR	s_LOG_INVALID	= "invalid";
STDSTR	s_LOG_EMPTY		= "empty";

STDSTR	s_LOG_ERR_PARAMETER	= "%s called with %s parameter (%s)";


/*********************************************************
 * Errori                                                *
 *********************************************************/

STDSTR	s_ERR_OUT_OF_MEMORY	= "Out of memory";


/*********************************************************
 * Utility                                               *
 *********************************************************/

STDVAL str_parse_standard_value(CSTR value) {

	STDVAL	result = STDVAL_UNK;

	if (IS_NOT_NULL(value)) {

		if (str_equals_nocase(value, s_YES))
			result = STDVAL_YES;

		else if (str_equals_nocase(value, s_NO))
			result = STDVAL_NO;

		else if (str_equals_nocase(value, s_ON))
			result = STDVAL_ON;

		else if (str_equals_nocase(value, s_OFF))
			result = STDVAL_OFF;

		else if (str_equals_nocase(value, s_ENABLE))
			result = STDVAL_ENABLE;

		else if (str_equals_nocase(value, s_DISABLE))
			result = STDVAL_DISABLE;

		else if (str_equals_nocase(value, s_ENABLED))
			result = STDVAL_ENABLED;

		else if (str_equals_nocase(value, s_DISABLED))
			result = STDVAL_DISABLED;
	}

	return result;
}


__inline__ CSTR str_get_valid_display_value(CSTR string) {

	return IS_NULL(string) ? s_LOG_NULL : string;
}


/*********************************************************
 * str_replace()                                         *
 *                                                       *
 * Replace occurrences of 'find' with 'replace' in       *
 * string 'string'. Stop replacing if a replacement      *
 * would cause the string to exceed 'size' bytes         *
 * (including the null terminator). Return the string.   *
 *********************************************************/

STR str_replace(STR string, size_t size, CSTR find, CSTR replace) {

    STR		ptr = string;
    size_t	left, avail, find_len, replace_len, diff;

	if (IS_NOT_NULL(string) && IS_NOT_NULL(find) && IS_NOT_NULL(replace)) {

		left = str_len(string);
		find_len = str_len(find);
		replace_len = str_len(replace);

		avail = size - (left + 1);
		diff = replace_len - find_len;

		while (left >= find_len) {

			if (strncmp(ptr, find, find_len) != 0) {
				left--;
				ptr++;
				continue;
			}

			if (diff > avail)
				break;

			if (diff != 0)
				memmove(ptr + find_len + diff, ptr + find_len, left + 1);

			strncpy(ptr, replace, replace_len);
			ptr += replace_len;
			left -= find_len;
		}
	}

	return string;
}


/*********************************************************
 * str_tokenize()                                        *
 *                                                       *
 * string     : source string                            *
 * token      : target buffer                            *
 * token_len  : buffer size                              *
 * delimiters : delimiters set                           *
 *********************************************************/

STR str_tokenize(CSTR string, STR token, size_t token_len, char delimiter) {

	STR		lim;

	if (IS_NULL(string) || IS_EMPTY_STR(string))
		return NULL;

	lim = token + token_len - 1;

	while (*string && (token < lim)) {

		if (*string == delimiter) {

			*token = 0;
			return (STR) (string + 1);
		}

		*token++ = *string++;
	}

	*token = 0;

	return (STR)string;
}

/*
STR str_tokenize(CSTR string, STR token, size_t token_len, CSTR delimiters) {

	STR		lim;
	CSTR	delim;

	if (IS_NULL(string) || IS_EMPTY_STR(string))
		return NULL;

	lim = token + token_len - 1;
	
	while (*string && (token < lim)) {

		for (delim = delimiters; *delim; ++delim) {
			
			if (*string == *delim) {

				*token = 0;

				for (++string, delim = delimiters; *string && *delim; ++delim) {
					
					if (*string == *delim) {

						++string;
						delim = delimiters;
					}
				}

				return (STR)string;
			}
		}

		*token++ = *string++;
	}

	*token = 0;
	
	return (STR)string;
}
*/

STR str_compact(STR string) {

    char *ptr = string, *s, *t;

	if (IS_NULL(string))
		return string;

    for (; *ptr; ptr++) {

		if (*ptr == '*') {

			if (*(t = s = ptr + 1) == '*') {

				while (*t == '*')
					t++;
			}
			else if (*t == '?') {

				for (t++, s++; *t == '*' || *t == '?'; t++) {

					if (*t == '?')
						*s++ = *t;
				}
			}

			while ((*s++ = *t++));
		}
	}

	return string;
}


/*********************************************************
 * RTL strings functions                                 *
 *********************************************************/

/*
__inline__ int str_char_toupper(CCHAR ch) {
	return islower(ch) ? (int) (((unsigned char) ch) - ('a' - 'A')) : (int) ((unsigned char) ch);
}

__inline__ int str_char_tolower(CCHAR ch) {
	return isupper(ch) ? (int) (((unsigned char) ch) + ('a' - 'A')) : (int) ((unsigned char) ch);
}
*/

const unsigned char  _tolower_table[] = {

	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	' ', '!', '"', '#', '$', '%', '&', 0x27, '(', ')', '*', '+', ',', '-', '.', '/',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 
	'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '[', '\\', ']', '^', '_', '`',
	'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 
	'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', 
	0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 
	0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 
	0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 
	0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 
	0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 
	0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 
	0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 
	0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	0,0,0
};

const unsigned char _toupper_table[] = {

	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	' ', '!', '"', '#', '$', '%', '&', 0x27, '(', ')', '*', '+', ',', '-', '.', '/',
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 
	'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`',
	'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 
	'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '{', '|', '}', '~', 
	0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 
	0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 
	0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 
	0xaf, 0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 
	0xbf, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7, 0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 
	0xcf, 0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7, 0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 
	0xdf, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 
	0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff,
	0,0,0
};



STR	str_toupper(STR string) {

	CHAR	*ptr = string;

	if (IS_NOT_NULL(ptr))
		while (*ptr)
			*ptr++ = str_char_toupper(*ptr);
	return string;
}

STR	str_tolower(STR string) {

	CHAR	*ptr = string;

	if (IS_NOT_NULL(ptr))
		while (*ptr)
			*ptr++ = str_char_tolower(*ptr);

	return string;
}


size_t str_copy_checked(CSTR source, STR buffer, size_t bufferSize) {

	size_t len = 0;

	if ((bufferSize > 0) && IS_NOT_NULL(buffer) && IS_NOT_NULL(source)) {

		STR ptr = buffer;

		while ( (--bufferSize > 0) && ((*ptr++ = *source++) != c_NULL) )
			++len;

		*ptr = c_NULL;
	}

	return len;
}


size_t str_append_checked(CSTR append, STR buffer, size_t bufferFreeSpace) {
	
	size_t	appended = 0;

	if ((bufferFreeSpace > 1) && IS_NOT_NULL(buffer) && IS_NOT_NULL(append)) {

		STR		ptr = (STR)(buffer + str_len(buffer));

		while ( (--bufferFreeSpace > 0) && ((*ptr++ = *append++) != c_NULL) )
			++appended;

		*ptr = c_NULL;
	}

	return appended;
}


STR str_duplicate(CSTR string) {

	void	*buffer;

	if (IS_NULL(string)) {

		log_error(FACILITY_STRINGS, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_RESUMED,
			"str_duplicate(): NULL source string -> using an empty string as source");

		string = s_NULL;
	}

	buffer = strdup(string);

	if (IS_NULL(buffer)) {

		log_error(FACILITY_STRINGS, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_QUIT,
			"str_duplicate(): Out of memory");

		raise(SIG_OUT_OF_MEMORY);
	}

	return buffer;
}


int str_compare(CSTR string1, CSTR string2) {

	register const unsigned char	*str1 = (const unsigned char *) string1;
	register const unsigned char	*str2 = (const unsigned char *) string2;
	register unsigned char		ch1, ch2;

	if (IS_NULL(str1) || IS_NULL(str2))
		return (int)(str1 - str2);

	do {
		ch1 = (unsigned char) *str1++;
		ch2 = (unsigned char) *str2++;

	} while ((ch1 != c_NULL) && (ch1 == ch2));

	return ch1 - ch2;
}

int str_compare_nocase(CSTR string1, CSTR string2) {

	register const unsigned char	*str1 = (const unsigned char *) string1;
	register const unsigned char	*str2 = (const unsigned char *) string2;
	register unsigned char			ch1, ch2;

	if (IS_NULL(str1) || IS_NULL(str2))
		return (int)(str1 - str2);

	do {
		ch1 = (unsigned char) *str1++;
		ch2 = (unsigned char) *str2++;

		if ((ch1 >= 'A') && (ch1 <= 'Z'))
			ch1 -= ('A' - 'a');

		if ((ch2 >= 'A') && (ch2 <= 'Z'))
			ch2 -= ('A' - 'a');

	} while ((ch1 != c_NULL) && (ch1 == ch2));

	return ch1 - ch2;
}

int str_compare_partial(CSTR string1, CSTR string2, size_t len) {

	register const unsigned char	*str1 = (const unsigned char *) string1;
	register const unsigned char	*str2 = (const unsigned char *) string2;
	register unsigned int c;

	if (IS_NULL(str1) || IS_NULL(str2) || (len <= 0))
		return (int) (str1 - str2);

	while (((c = str_char_tolower(*str1)) == str_char_tolower(*str2)) && (len > 0)) {

		if ((c == 0) || (--len == 0))
			return 0;

		str1++;
		str2++;
	}

	if (c < str_char_tolower(*str2))
		return -1;

	return 1;
}

size_t str_len(CSTR string) {

	/*	Return the length of the null-terminated string "string".
		Scan for the null terminator quickly by testing four bytes at a time. */

	const char					*char_ptr;
	const unsigned long int		*longword_ptr;
	unsigned long int			longword, magic_bits, himagic, lomagic;

	if (IS_NULL(string))
		return 0;

	/*	Handle the first few characters by reading one character at a time.
		Do this until CHAR_PTR is aligned on a longword boundary. */

	for (char_ptr = string; ((unsigned long int) char_ptr & (sizeof(longword) - 1)) != 0; ++char_ptr) {
		if (*char_ptr == c_NULL)
			return char_ptr - string;
	}

	/*	All these elucidatory comments refer to 4-byte longwords,
		but the theory applies equally well to 8-byte longwords. */

	longword_ptr = (unsigned long int *) char_ptr;

	/*	Bits 31, 24, 16, and 8 of this number are zero. Call these bits
		the "holes." Note that there is a hole just to the left of
		each byte, with an extra at the end:
	
		bits:  01111110 11111110 11111110 11111111
		bytes: AAAAAAAA BBBBBBBB CCCCCCCC DDDDDDDD

		The 1-bits make sure that carries propagate to the next 0-bit.
		The 0-bits provide holes for carries to fall into. */

	magic_bits = 0x7efefeffL;
	himagic = 0x80808080L;
	lomagic = 0x01010101L;

	if (sizeof(longword) > 4) {

		/* 64-bit version of the magic. */
		/* Do the shift in two steps to avoid a warning if long has 32 bits. */
		magic_bits = ((0x7efefefeL << 16) << 16) | 0xfefefeffL;
		himagic = ((himagic << 16) << 16) | himagic;
		lomagic = ((lomagic << 16) << 16) | lomagic;
	}

	if (sizeof(longword) > 8)
		abort();

	/*	Instead of the traditional loop which tests each character,
		we will test a longword at a time. The tricky part is testing
		if *any of the four* bytes in the longword in question are zero. */

	for (;;) {

		/*	We tentatively exit the loop if adding MAGIC_BITS to
			LONGWORD fails to change any of the hole bits of LONGWORD.

			1) Is this safe? Will it catch all the zero bytes?
			Suppose there is a byte with all zeros. Any carry bits
			propagating from its left will fall into the hole at its
			least significant bit and stop. Since there will be no
			carry from its most significant bit, the LSB of the
			byte to the left will be unchanged, and the zero will be
			detected.

			2) Is this worthwhile? Will it ignore everything except
			zero bytes? Suppose every byte of LONGWORD has a bit set
			somewhere. There will be a carry into bit 8. If bit 8
			is set, this will carry into bit 16. If bit 8 is clear,
			one of bits 9-15 must be set, so there will be a carry
			into bit 16. Similarly, there will be a carry into bit
			24. If one of bits 24-30 is set, there will be a carry
			into bit 31, so all of the hole bits will be changed.

			The one misfire occurs when bits 24-30 are clear and bit
			31 is set; in this case, the hole at bit 31 is not
			changed. If we had access to the processor carry flag,
			we could close this loophole by putting the fourth hole
			at bit 32!

			So it ignores everything except 128's, when they're aligned
			properly. */

		longword = *longword_ptr++;

		if (
			#if 0

			/* Add MAGIC_BITS to LONGWORD. */

			(((longword + magic_bits)

			/* Set those bits that were unchanged by the addition. */

			^ ~longword)

			/* Look at only the hole bits. If any of the hole bits
			are unchanged, most likely one of the bytes was a zero. */

			& ~magic_bits)

			#else

			((longword - lomagic) & himagic)

			#endif

			!= 0) {

				/*	Which of the bytes was the zero? If none of them were, it was
					a misfire; continue the search. */

				const char *cp = (const char *) (longword_ptr - 1);

				if (cp[0] == 0)
					return cp - string;

				if (cp[1] == 0)
					return cp - string + 1;

				if (cp[2] == 0)
					return cp - string + 2;

				if (cp[3] == 0)
					return cp - string + 3;

				if (sizeof (longword) > 4) {

					if (cp[4] == 0)
						return cp - string + 4;

					if (cp[5] == 0)
						return cp - string + 5;

					if (cp[6] == 0)
						return cp - string + 6;

					if (cp[7] == 0)
						return cp - string + 7;
			}
		}
	}
}

size_t str_count(CSTR string, int c) {

	size_t i = 0;

	while (*string) {

		if (*string == c)
			++i;

		++string;
	}

	return i;
}

BOOL str_spn(CSTR string, CSTR charset) {

	while (*string && strchr(charset, *string))
		if (*(++string) == c_NULL)
			return TRUE;

	return FALSE;
}


/*********************************************************
 * String matching functions                             *
 *********************************************************/

static BOOL _str_perform_match(CSTR pattern, CSTR string, BOOL caseSensitive) {

	CHAR	ch;

	if (IS_NULL(pattern) || IS_NULL(string))
		return FALSE;

	for (;;) {
		switch (ch = *pattern++) {

			case '\0':
				return (*string == c_NULL);

			case '?':
				if (*string == c_NULL)
					return FALSE;

				++string;
				break;

			case '*': {

				CSTR	str;

				while (*pattern == '?') {

					/* Skip a character for each '?'. */

					if (*string == c_NULL)
						return FALSE;

					++string;
					++pattern;
				}


				if (*pattern == c_NULL) /* a trailing '*' matches everything else */
					return TRUE;

				str = string;
				while (*str != c_NULL) {

					if ( (caseSensitive ? *str == *pattern : str_char_tolower(*str) == str_char_tolower(*pattern)) &&
						 _str_perform_match(pattern, str, caseSensitive) )
						return TRUE;

					++str;
				}

				break;
			}

			default:
				if (caseSensitive ? *string++ != ch : str_char_tolower(*string++) != str_char_tolower(ch))
					return FALSE;

				break;
		}
	}
}

__inline__ BOOL str_match_wild(CSTR pattern, CSTR string) {
	return _str_perform_match(pattern, string, TRUE);
}

__inline__ BOOL str_match_wild_nocase(CSTR pattern, CSTR string) {
	return _str_perform_match(pattern, string, FALSE);
}

__inline__ BOOL str_match_everything(CSTR string) {
	return _str_perform_match(string, "akjhfkahfasfjd@ldksjfl.kss...kdjfd.jfklsjf", FALSE);
}


/*********************************************************
 * "Creator" support                                     *
 * Riempie i campi della struttura passata:              *
 * name: se NULL il campo relativo non viene modificato, *
 *       altrimenti viene impostato al valore indicato   *
 *       (via str_duplicate())                           *
 * time: se 0 il campo relativo viene impostato all'ora  *
 *       corrente, altrimenti a quanto indicato.         *
 *********************************************************/

void str_creator_init(Creator *creator) {

	if (IS_NOT_NULL(creator)) {

		creator->name = NULL;
		creator->time = 0;
	}
}

BOOL str_creator_set(Creator *creator, CSTR name, time_t time_set) {

	if (IS_NOT_NULL(creator)) {

		if (IS_NOT_NULL(name)) {

			if (IS_NOT_NULL(creator->name))
				mem_free(creator->name);

			creator->name = str_duplicate(name);
		}

		creator->time = time_set != 0 ? time_set : NOW;
		return TRUE;
	
	} else
		return FALSE;
}

__inline__ void str_creator_free(Creator *creator) {

	if (IS_NOT_NULL(creator))
		mem_free(creator->name);
}

void str_creationinfo_init(CreationInfo *info) {

	if (IS_NOT_NULL(info)) {

		info->reason = NULL;

		str_creator_init(&(info->creator));
	}
}

BOOL str_creationinfo_set(CreationInfo *info, CSTR creator, CSTR reason, time_t time_set) {

	if (IS_NULL(info) || IS_NULL(creator) || IS_NULL(reason))
		return FALSE;

	str_creator_set(&(info->creator), creator, time_set);

	if (IS_NOT_NULL(info->reason))
		mem_free(info->reason);

	info->reason = str_duplicate(reason);

	return TRUE;
}

__inline__ void str_creationinfo_free(CreationInfo *info) {

	if (IS_NOT_NULL(info)) {

		str_creator_free(&(info->creator));
		mem_free(info->reason);
	}
}

/*********************************************************/

BOOL str_settingsinfo_add(SettingsInfo **infoList, unsigned long int type, CSTR creator, CSTR reason) {

	SettingsInfo *info;

	info = *infoList;

	while (IS_NOT_NULL(info)) {

		if (info->type == type)
			return FALSE;

		info = info->next;
	}

	info = mem_malloc(sizeof(SettingsInfo));

	info->type = type;

	str_creationinfo_init(&(info->creation));
	str_creationinfo_set(&(info->creation), creator, reason, NOW);

	info->next = *infoList;
	*infoList = info;

	return TRUE;
}

/*********************************************************/

BOOL str_settingsinfo_remove(SettingsInfo **infoList, unsigned long int type) {

	SettingsInfo *info, *prevInfo = NULL;

	info = *infoList;

	while (IS_NOT_NULL(info)) {

		if (info->type == type) {

			if (IS_NOT_NULL(prevInfo->next))
				prevInfo->next = info->next;
			else
				*infoList = info->next;

			str_creationinfo_free(&(info->creation));

			mem_free(info);

			return TRUE;
		}

		prevInfo = info;
		info = info->next;
	}

	return FALSE;
}
