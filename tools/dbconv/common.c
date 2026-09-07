/* SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-URL: https://spdx.org/licenses/GPL-2.0-or-later.html
 *
 * Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)
 *
 * common.c - just about anything
 */

#include "dbconv.h"

time_t NOW;

void strcasecanon(char *str) {
    while (*str) {
        *str = tolower((unsigned char)*str);
        str++;
    }
}
