/*
 * SPDX-License-Identifier: ISC
 * SPDX-URL: https://spdx.org/licenses/ISC.html
 *
 * Copyright (C) 2005 William Pitcock, et al.
 *
 * A hook system.
 */

#ifndef AZSVC_HOOK_H
#define AZSVC_HOOK_H 1

#include <services/common.h>
#include <services/strings.h>

typedef void (*hook_fn)(void *data);

struct hook
{
	stringref       name;
	mowgli_list_t   hooks;
};

extern void hooks_init(void);

extern void hook_del_hook(const char *, hook_fn);
extern void hook_add_hook(const char *, hook_fn, unsigned int);
extern void hook_call_event(const char *, void *);

extern void hook_stop(void);
extern void hook_continue(void *newptr);

#endif /* !AZSVC_HOOK_H */
