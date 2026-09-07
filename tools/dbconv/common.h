/* SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-URL: https://spdx.org/licenses/GPL-2.0-or-later.html
 *
 * Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)
 *
 * common.h - stuff that doesn't fit anywhere else
 */

#ifndef DBCONV_COMMON_H
#define DBCONV_COMMON_H 1

typedef unsigned long int   flags_t;
typedef unsigned short int  short_flags_t;
typedef unsigned char       tiny_flags_t;

typedef	unsigned int        result_t;

#define CRC32_INITIAL_VALUE 0xFFFFFFFF

extern void strcasecanon(char *str);

extern time_t NOW;

#endif /* DBCONV_COMMON_H */
