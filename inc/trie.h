/*
 * Azzurra IRC Services (C) 2001-2011 Azzurra IRC Network
 *
 * This program is free but copyrighted software; see COPYING for details.
 *
 * trie.h - Prefix tree data type
 * Copyright (C) 2001 Matteo Panella <morpheus@azzurra.org>
 *
 * Based on trie.h from cprops library
 * cprops - c prototyping tools (C) 2005-2011 Ilan Aelion, Philip Prindeville
 * Licensed under the terms of LGPLv2.
 */

#ifndef SRV_TRIE_H
#define SRV_TRIE_H

#include "mtab.h"

/* Forward declaration of trie struct */
struct _trie;

/* trie nodes can have any number of subnodes mapped by an mtab */
typedef struct _trie_node
{
    mtab *others;
    void *leaf;
} trie_node;


/* The trie struct itself */
typedef struct _trie
{
    trie_node *root;
    int path_count;
} trie;

/* Public API */
extern trie *trie_create(void);
extern void trie_destroy(trie *grp);
extern int trie_add(trie *grp, char *key, void *leaf);
extern int trie_remove(trie *grp, char *key, void **leaf);
/* We only perform exact matches */
extern void *trie_find(trie *grp, char *key);

extern int trie_count(trie *grp);

/* Just in case... */
extern void trie_set_root(trie *grp, void *leaf);

#endif /* SRV_TRIE_H */
