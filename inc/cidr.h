/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* cidr.h - CIDR
* 
*/

#ifndef SRV_CIDR_H
#define SRV_CIDR_H

#include <arpa/inet.h>

/*********************************************************
 * Data types                                            *
 *********************************************************/

struct _CIDR_IP {

	unsigned int ip;
	unsigned int mask;
};

typedef struct _CIDR_IP	CIDR_IP;


enum _CIDR_RESULT { cidrSuccess = 0, cidrBadParam, cidrInvalidIP, cidrInvalidMask, cidrFailure };
typedef enum _CIDR_RESULT	CIDR_RESULT;


#ifndef	INADDR_NONE
#define	INADDR_NONE	((unsigned long )0xFFFFFFFF)
#endif


/*********************************************************
 * Public code                                           *
 *********************************************************/

unsigned int cidr_to_netmask(unsigned int cidr);
unsigned int cidr_from_netmask(unsigned int mask);

BOOL cidr_match(const CIDR_IP *cidr, unsigned long int ip);

CIDR_RESULT cidr_ip_fill(CSTR source_ip, CIDR_IP *cidr, BOOL requireSlash);
CIDR_RESULT cidr_ip_fill_direct(const unsigned long ip, const unsigned int mask, CIDR_IP *cidr);
CIDR_RESULT convert_host_to_cidr(CSTR host);

CSTR cidr_error_to_string(CIDR_RESULT error);


#endif /* SRV_CIDR_H */
