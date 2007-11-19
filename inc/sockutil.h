/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* sockutil.h - Socket utility routines
* 
* Originally based on SirvNET Services (c) 1998-2002 Trevor Klingbeil (priority1@dal.net)
*
*/


#ifndef SRV_SOCKUTIL_H
#define SRV_SOCKUTIL_H


/*********************************************************
 * Data types                                            *
 *********************************************************/

enum _SOCKET_RESULT { socketSuccess = 0, socketTimeout, socketError };
typedef enum _SOCKET_RESULT		SOCKET_RESULT;


/*********************************************************
 * Global variables                                      *
 *********************************************************/

extern unsigned long long int total_read;
extern unsigned long long int total_written;


/*********************************************************
 * Public code                                           *
 *********************************************************/

extern SOCKET_RESULT socket_read(char *buf, long int len);
extern __inline__ void socket_write(char *text, size_t len);
extern BOOL socket_connect(CSTR host, const unsigned short int port);
extern void socket_disconnect(void);


#endif /* SRV_SOCKUTIL_H */
