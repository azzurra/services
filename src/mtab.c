/*
 * Azzurra IRC Services (C) 2001-2011 Azzurra IRC Network
 *
 * This program is free but copyrighted software; see COPYING for details.
 *
 * mtab.c - Specialized hashtable for trie edge storage
 * Copyright (C) 2001 Matteo Panella <morpheus@azzurra.org>
 *
 * Based on mtab.c from cprops library
 * cprops - c prototyping tools (C) 2005-2011 Ilan Aelion, Philip Prindeville
 * Licensed under the terms of LGPLv2.
 */

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/memory.h"
#include "../inc/mtab.h"

/* Prime numbers for hash table sizes */
static int sizes[] = {   1,   3,   5,   7,  11,  19,  29,  37,  47,  59,
                        71,  89, 107, 127, 151, 181, 211, 239, 257, 281 };

static const int sizes_len = sizeof(sizes) / sizeof(int);

#define MIN_FILL_FACTOR 30
#define MAX_FILL_FACTOR 100
#define DOWNSIZE_RATIO  2

/* Perform a binary search on the sizes array to choose the first entry
 * larger than the requested size.
 */
static int choose_size(int size)
{
    int new_size;

    if (sizes[sizes_len - 1] < size)
    {
        /* The original for() was quite unreadable */
        new_size = sizes[sizes_len - 1];
        while (new_size < size)
            new_size = new_size * 2 + 1;
    }
    else
    {
        int min = -1;
        int max = sizes_len - 1;
        int pos;

        while (max > min + 1)
        {
            pos = (max + min + 1) / 2;
            if (sizes[pos] < size)
                min = pos;
            else
                max = pos;
        }

        new_size = sizes[max];
    }

    return new_size;
}

static void resize_table(mtab *t, int size)
{
    mtab_node **table = (mtab_node **) mem_calloc(size, sizeof(mtab_node *));

    if (table)
    {
        int i;
        mtab_node *ni;
        mtab_node **nf;
        for (i = 0; i < t->size; i++)
        {
            ni = t->table[i];
            while (ni)
            {
                nf = &table[ni->key % size];
                while (*nf)
                    nf = &(*nf)->next;
                *nf = ni;
                ni = ni->next;
                (*nf)->next = NULL;
            }
        }

        mem_free(t->table);
        t->table = table;
        t->size = size;
    }
}

mtab_node *mtab_node_new(unsigned char key, void *value, void *attr)
{
    mtab_node *node = mem_calloc(1, sizeof(mtab_node));
    if (node)
    {
        node->key = key;
        node->value = value;
        node->attr = attr;
    }

    return node;
}

mtab *mtab_new(int size)
{
    mtab *t = mem_calloc(1, sizeof(mtab));
    if (t)
    {
        t->size = choose_size(size);
        t->table = mem_calloc(t->size, sizeof(mtab_node *));
        if (t->table == NULL)
        {
            mem_free(t);
            t = NULL;
        }
    }

    return t;
}

/* The 'owner' pointer is used by trie delegation code to pass a pointer to
 * the trie being deleted
 */
void mtab_delete_custom(mtab *t, void *owner, mtab_dtr dtr)
{
    while (t->size--)
    {
        mtab_node *curr = t->table[t->size];
        mtab_node *tmp;
        while (curr)
        {
            tmp = curr;
            curr = curr->next;
            (*dtr)(owner, tmp);
            mem_free(tmp);
        }
    }

    mem_free(t->table);
    mem_free(t);
}

void mtab_delete(mtab *t)
{
    while (t->size--)
    {
        mtab_node *curr = t->table[t->size];
        mtab_node *tmp;
        while (curr)
        {
            tmp = curr;
            curr = curr->next;
            mem_free(tmp);
        }
    }

    mem_free(t->table);
    mem_free(t);
}

/* Inserting a new value for an already present key silently replaces the
 * existing value
 */
mtab_node *mtab_put(mtab *t, unsigned char key, void *value, void *attr)
{
    mtab_node **loc;

    if ((t->items + 1) * 100 > t->size * MAX_FILL_FACTOR)
        resize_table(t, choose_size(t->size + 1));

    loc = &t->table[key % t->size];
    while (*loc && (*loc)->key != key)
        loc = &(*loc)->next;

    if (*loc == NULL)
    {
        t->items++;
        *loc = mtab_node_new(key, value, attr);
    }
    else
    {
        (*loc)->value = value; /* replace */
        if ((*loc)->attr)
            mem_free((*loc)->attr);
        (*loc)->attr = attr;
    }

    return *loc;
}

mtab_node *mtab_get(mtab *t, unsigned char key)
{
    mtab_node *node = t->table[key % t->size];

    while (node && key != node->key)
        node = node->next;

    return node;
}

/* Perform a table resize if table density drops below the fill ratio. This is
 * not an issue for tries used in command and protocol parsers since they're
 * mostly static, but if we want to use tries in other contexts (eg. IPv6
 * clone detection) we need to keep memory pressure to the bare minimum.
 */
void *mtab_remove(mtab *t, unsigned char key)
{
    mtab_node **node;
    void *res = NULL;

    node = &t->table[key % t->size];

    while ((*node) && key != (*node)->key)
        node = &(*node)->next;

    if (*node)
    {
        mtab_node *rm = *node;
        *node = rm->next;
        res = rm->value;
        if (rm->attr)
            mem_free(rm->attr);
        mem_free(rm);

        t->items--;
    }

    if (t->items > 0 && t->items * 100 < t->size * MIN_FILL_FACTOR)
        resize_table(t, choose_size(t->size / DOWNSIZE_RATIO));

    return res;
}

int mtab_count(mtab *t)
{
    return t->items;
}
