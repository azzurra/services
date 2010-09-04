/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* misc.h - Misc stuff
* 
*/


#ifndef SRV_MISC_H
#define SRV_MISC_H


/*********************************************************
 * Data types                                            *
 *********************************************************/

enum _HOST_TYPE { htInvalid = 0, htHostname, htIPv4, htIPv4_CIDR, htIPv6};
typedef enum _HOST_TYPE		HOST_TYPE;


/*********************************************************
 * Constants                                             *
 *********************************************************/

/* Invalid password levels. */
#define	INVALID_PW_LEVEL_0	0	/* Starting level. */
#define	INVALID_PW_LEVEL_1	1	/* Warn user, ignore for 30 minutes. */
#define	INVALID_PW_LEVEL_2	2	/* Warn user, ignore for 3 hours. */

/* CRC32 */
#define CRC32_INITIAL_VALUE		0xFFFFFFFF


/*********************************************************
 * Public code                                           *
 *********************************************************/

#ifdef USE_SERVICES
extern void update_invalid_password_count(User *user, CSTR service, CSTR target);
extern BOOL validate_email(CSTR email, BOOL allowWild);
#endif

extern int randomseed();
extern int mask_contains_crypt(CSTR mask);
extern int validate_access(char *mask);
extern BOOL validate_channel(CSTR chan);
extern BOOL validate_nick(CSTR nick, BOOL allowWild);
extern BOOL validate_username(CSTR nick, BOOL allowWild);
extern BOOL validate_host(CSTR nick, BOOL allowWild, BOOL allowCIDR, BOOL allowCrypt);
extern BOOL validate_mask(CSTR nick, BOOL allowWild, BOOL allowCIDR, BOOL allowCrypt);
extern BOOL validate_tld(CSTR tld, BOOL allowFW);

extern char *terminate_string_ccodes(char *string);
extern BOOL string_has_ccodes(CSTR string);
extern BOOL validate_string(CSTR string);

extern HOST_TYPE host_type(CSTR host, short int *dotsCountPtr);

extern BOOL year_is_leap(const int year);
extern BOOL validate_date(const int dateYear, const int dateMonth, const int dateDay);

extern char *expand_ipv6(CSTR input);

extern char *convert_time(char *buffer, size_t len, time_t timeSpan, const LANG_ID langID);
extern char *expire_left(char *buffer, size_t len, time_t expiry);
extern long int convert_amount(CSTR string);

extern char *merge_args(const int ac, char * const av[]);

extern char *get_ip(unsigned long ip);
extern char *get_ip_r(char *buffer, size_t len, unsigned long int ip);
extern char *get_ip6(const unsigned char *ip6);
extern char *get_ip6_r(char *buffer, size_t len, const unsigned char *ip6);

extern unsigned long int aton(CSTR ipaddr);


// CRC
void crc32(PBYTE data, size_t size, unsigned long int *crc);

#endif /* SRV_MISC_H */
