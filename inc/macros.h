/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* macros.h - helpful macros
* 
*/

#ifndef SRV_MACROS_H
#define SRV_MACROS_H


/*********************************************************
 * Data types                                            *
 *********************************************************/

typedef	int					BOOL;

typedef	unsigned char		BYTE;
typedef unsigned char*		PBYTE;

#ifndef HAVE_ULONG
#define HAVE_ULONG
typedef unsigned long int  ULONG;
#endif

typedef unsigned long int		flags_t;
typedef unsigned short int		short_flags_t;
typedef unsigned char			tiny_flags_t;

typedef	unsigned int			result_t;


/*********************************************************
 * Constants                                             *
 *********************************************************/

#define TRUE				(BOOL) 1
#define FALSE				(BOOL) 0

#define GRANTED				(BOOL) 1
#define DENIED				(BOOL) 0


#define RESULT_FAILURE			(result_t) 0
#define RESULT_SUCCESS			(result_t) 1
#define RESULT_DENIED			(result_t) 2
#define RESULT_ALREADY			(result_t) 3
#define RESULT_NOTIMP			(result_t) 4

#define RESULT_BADPARAMETER		(result_t) 5
#define RESULT_VALUEERROR		(result_t) 6
#define RESULT_NOTFOUND			(result_t) 7

#define ONE_MINUTE		60
#define ONE_HOUR		3600
#define ONE_DAY			86400
#define ONE_WEEK		604800


/*********************************************************
 * Macro                                                 *
 *********************************************************/

#define IS_NULL(v)			((v) == NULL)
#define IS_NOT_NULL(v)		((v) != NULL)

#define IS_EMPTY_STR(v)		((*(v) == c_NULL))
#define IS_NOT_EMPTY_STR(v)	((*(v) != c_NULL))

 
#define AddFlag(v, f)       ((v) |= (f))
#define RemoveFlag(v, f)    ((v) &= ~(f))
#define FlagSet(v, f)       (((v) & (f)) != 0)
#define FlagUnset(v, f)     (((v) & (f)) == 0)


#define getrandom(min, max) ((rand() % (unsigned long int)(((max)+1) - (min))) + (min))


#ifndef min
#define	min(a, b)	((a) < (b) ? (a) : (b))
#endif

#ifndef max
#define	max(a, b)	((a) > (b) ? (a) : (b))
#endif

#define RANGE_INC(num, inc, range)      ( ((num) + (inc)) % (range) )

#define APPEND_BUFFER(var, string) \
	if ((var)) { \
		\
		if (len > 0) { \
		\
			*(buffer + len++) = c_COMMA; \
			*(buffer + len++) = c_SPACE; \
		} \
		\
		len += str_copy_checked((string), (buffer + len), (sizeof(buffer) - len)); \
	}

#define APPEND_FLAG(var, flag, string) \
	if (FlagSet((var), (flag))) { \
		\
		if (len > 0) { \
		\
			*(buffer + len++) = c_COMMA; \
			*(buffer + len++) = c_SPACE; \
		} \
		\
		len += str_copy_checked((string), (buffer + len), (sizeof(buffer) - len)); \
	}


#endif /* SRV_MACROS_H */
