/*
*
* Azzurra IRC Services
* 
* cidr.c - CIDR Support
* 
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/cidr.h"


/*********************************************************
 * Public code                                           *
 *********************************************************/

unsigned int cidr_to_netmask(const unsigned int cidr) {

	return (cidr == 0) ? 0 : (0xFFFFFFFF - (1 << (32 - cidr)) + 1);
}


unsigned int cidr_from_netmask(const unsigned int mask)  {

	int tmp = 0;

	while (!(mask & (1 << tmp)) && (tmp < 32))
		++tmp;

	return (32 - tmp);
}


BOOL cidr_match(const CIDR_IP *cidr, const unsigned long ip) {

	return cidr ? ((ip & cidr->mask) == cidr->ip) : FALSE;
}

CIDR_RESULT cidr_ip_fill(CSTR source_ip, CIDR_IP *cidr, BOOL requireSlash) {

	char			ip[HOSTSIZE];
	char			*ptr, *slash_ptr;
	short int		numCount, dotCount;
	BOOL			lastIsDot, slashFound;

	int				cidr_size;
	unsigned long	net_address, host_address;


	if (!cidr || IS_NULL(source_ip) || IS_EMPTY_STR(source_ip))
		return cidrBadParam;

	str_copy_checked(source_ip, ip, sizeof(ip));
	dotCount = numCount = 0;
	lastIsDot = slashFound = FALSE;

	for (slash_ptr = NULL, ptr = ip; *ptr; ++ptr) {

		switch (*ptr) {

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
				++numCount;
				lastIsDot = FALSE;
				break;

			case '.':
				if (lastIsDot || // ".." ?
					slashFound)  // "1.2.3.4/*.*"
					return cidrInvalidIP;

				++dotCount;
				lastIsDot = TRUE;
				break;

			case '/':
				if (slashFound || // "*//*"
					lastIsDot) // "*./*"
					return cidrInvalidIP;

				slash_ptr = ptr;
				slashFound = TRUE;
				lastIsDot = FALSE;
				break;

			default:
				return cidrInvalidIP;
		}
	}

	if ((dotCount != 3) || !numCount)
		return cidrInvalidIP;

	if (slashFound && slash_ptr) {

		char *err;

		*slash_ptr = '\0';
		++slash_ptr;

		cidr_size = strtol(slash_ptr, &err, 10);

		if ((*err != '\0') || (cidr_size < 0) || (cidr_size > 32))
			return cidrInvalidMask;
	}
	else {

		if (requireSlash)
			return cidrInvalidMask;
		else
			cidr_size = 32;
	}

	if ((host_address = inet_addr(ip)) == INADDR_NONE)
		return cidrInvalidIP;

	net_address = htonl(cidr_to_netmask(cidr_size));
	host_address &= net_address;

	cidr->ip = host_address;
	cidr->mask = net_address;

	return cidrSuccess;
}

CIDR_RESULT cidr_ip_fill_direct(const unsigned long ip, const unsigned int mask, CIDR_IP *cidr) {

	cidr->mask = htonl(cidr_to_netmask(mask));
	cidr->ip = (ip & cidr->mask);

	return cidrSuccess;
}

const char *cidr_error_to_string(CIDR_RESULT error) {

	static char	buffer[24];

	switch (error) {

		case cidrSuccess:
			str_copy_checked("No errors", buffer, sizeof(buffer));
			break;

		case cidrBadParam:
			str_copy_checked("Invalid parameters", buffer, sizeof(buffer));
			break;

		case cidrInvalidIP:
			str_copy_checked("Invalid IP", buffer, sizeof(buffer));
			break;

		case cidrInvalidMask:
			str_copy_checked("Invalid mask", buffer, sizeof(buffer));
			break;

		default:
			str_copy_checked("Unknown error", buffer, sizeof(buffer));
			break;
	}

	return (CSTR) buffer;
}


/*********************************************************
 * Tries to convert a host to a CIDR address.            *
 * Returns -1 if it's not an IP, 1 if the IP address is  *
 * invalid, 0 if all went well.                          *
 *********************************************************/

CIDR_RESULT convert_host_to_cidr(CSTR host) {

	int		numcount = 0, wildcount = 0, dotcount = 0, slashcount = 0;
	char	buf[IRCBUFSIZE], *ptr;


	str_copy_checked(host, buf, sizeof(buf));

	for (ptr = buf; *ptr; ++ptr) {

		switch (*ptr) {

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
			++numcount;
			break;

		case '*':
		case '?':
			++wildcount;
			break;

		case '.':
			++dotcount;
			break;

		case '/':
			++slashcount;
			break;

		default:
			/* It's not an IP. */
			return cidrInvalidIP;
		}      
	}

	/* All wildcards, or wildcards and slashes?. Bad. */
	if (wildcount && (!numcount || slashcount))
		return cidrInvalidIP;

	/* Everything must have a dot. Never more than one slash. */
	if ((dotcount == 0) || (dotcount > 3) || (slashcount > 1))
		return cidrInvalidIP;

	if (!wildcount && !slashcount) {

		/* 1.2.3.4, convertible to 1.2.3.4/32 */
		return cidrSuccess;
	}
	else if (wildcount && numcount) {

		/* Wildcarded IP address. See if it can be converted to a CIDR. */
		char octet[4][4];
		int x = 0, y = 0;
		BOOL gotwild = FALSE;


		/* Separate this thing into dotcount octets. */
		for (ptr = buf; *ptr; ++ptr) {

			if (*ptr == c_DOT) {

				octet[x][y] = '\0';
				y = 0;
				++x;
				continue;
			}

			if (y > 2)
				return cidrFailure;

			octet[x][y++] = *ptr;
		}

		octet[x][y] = '\0';

		/* Verify that each octet is all numbers or just a '*' */
		/* Bans that match 123.123.123.1?? are still valid, just not convertable to a CIDR. */

		for (x = 0; x <= dotcount; ++x) {

			if (octet[x][0] == '*' && octet[x][1] == '\0') {

				/* First octet is a wildcard. Bad. */
				if (x == 0)
					return cidrFailure;

				gotwild = TRUE;
				continue;
			}

			/* IP in the format of 1.2.*.4 */
			if (gotwild)
				return cidrFailure;

			for (y = 0; octet[x][y]; ++y) {

				if (!isdigit(octet[x][y]))
					return cidrFailure;
			}
		}

		if (octet[1][0] == '*') {

			/* 1.*, convertible to 1.0.0.0/8 */
			return cidrSuccess;
		}
		else if (dotcount >= 2 && octet[2][0] == '*') {

			/* 1.2.*, convertible to 1.2.0.0/16 */
			return cidrSuccess;
		}
		else if (dotcount >= 3 && octet[3][0] == '*') {

			/* 1.2.3.*, convertible to 1.2.3.0/24 */
			return cidrSuccess;
		}
	}

	return cidrFailure;
}
