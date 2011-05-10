/*
 * Azzurra IRC Services (C) 2001-2011 Azzurra IRC Network
 *
 * This program is free but copyrighted software; see COPYING for details.
 *
 * mtab.h - Specialized hashtable for trie edge storage
 * Copyright (C) 2001 Matteo Panella <morpheus@azzurra.org>
 *
 * Based on mtab.h from cprops library
 * cprops - c prototyping tools (C) 2005-2011 Ilan Aelion, Philip Prindeville
 * Licensed under the terms of LGPLv2.
 */

#ifndef SRV_MTAB_H
#define SRV_MTAB_H

/* Table entry descriptor. mtab entries map a character to a value
 * and in addition allow specifying an attribute for the mapping.
 * This is used by tries to collapse multiple single child trie edges
 * into a single node.
 */
typedef struct _mtab_node
{
    unsigned char key;
    void *value;
    void *attr;
    struct _mtab_node *next;
} mtab_node;

mtab_node *mtab_node_new(unsigned char key, void *value, void *attr);

/* Node destructor function.
 * The owner parameter is used by trie to recursively delete a sub-tree.
 */
typedef void *(*mtab_dtr)(void *owner, mtab_node *node);

/* The mtab data type itself */
typedef struct _mtab
{
    int size;
    int items;
    mtab_node **table;
} mtab;

/* Public API */

extern mtab *mtab_new(int size);
extern void mtab_delete(mtab *t);
extern void mtab_delete_custom(mtab *t, void *owner, mtab_dtr dtr);
extern mtab_node *mtab_put(mtab *t, unsigned char key, void *value, void *attr);
extern mtab_node *mtab_get(mtab *t, unsigned char key);
extern void *mtab_remove(mtab *t, unsigned char key);

extern int mtab_count(mtab *t);

#endif /* SRV_MTAB_H */
