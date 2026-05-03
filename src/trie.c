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

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/memory.h"
#include "../inc/trie.h"

#define NODE_MATCH(n,i)     ((n)->others ? mtab_get((n)->others, *i) : NULL)
#define BRANCH_COUNT(node)  mtab_count((node)->others)

/* Node manipulation functions */
static trie_node *trie_node_new(void *leaf);
static void *trie_node_delete(struct _trie *grp, trie_node *node);
static void trie_delete_mapping(struct _trie *grp, mtab_node *map_node);
static void trie_node_unmap(struct _trie *grp, trie_node **node);

/* Allocate a new node */
static trie_node *trie_node_new(void *leaf)
{
    trie_node *node;

    node = (trie_node *) mem_calloc(1, sizeof(trie_node));
    if (node)
    {
        node->others = mtab_new(0);
        node->leaf = leaf;
    }

    return node;
}

/* Recursively delete the subtree rooted at node */
static void *trie_node_delete(trie *grp, trie_node *node)
{
    void *leaf = NULL;

    if (node)
    {
        mtab_delete_custom(node->others, grp, (mtab_dtr)trie_delete_mapping);
        leaf = node->leaf;
        mem_free(node);
    }

    return leaf;
}

/* mtab destructor callback ('grp' here is mapped to 'owner') */
static void trie_delete_mapping(trie *grp, mtab_node *map_node)
{
    if (map_node)
    {
        if (map_node->attr)
            mem_free(map_node->attr);
        if (map_node->value)
            trie_node_delete(grp, map_node->value);
    }
}

static void trie_node_unmap(trie *grp, trie_node **node)
{
    trie_node_delete(grp, *node);
    *node = NULL;
}

trie *trie_create(void)
{
    trie *grp = mem_calloc(1, sizeof(trie));

    if (grp == NULL)
        return NULL;

    grp->root = trie_node_new(NULL);
    if (grp->root == NULL)
    {
        mem_free(grp);
        return NULL;
    }

    return grp;
}

/* Recursively delete trie structure */
void trie_destroy(trie *grp)
{
    if (grp)
    {
        trie_node_delete(grp, grp->root);
        mem_free(grp);
    }
}

static void *NODE_STORE(trie_node *node, char *key, trie_node *sub)
{
    char *k = str_duplicate(key);
    void *rv;
    if (k == NULL)
        return NULL;
    rv = mtab_put(node->others, *k, sub, k);
    if (rv == NULL)
        mem_free(k);
    return rv;
}

/* Recursive insertion function */
static int trie_node_store(trie *grp, trie_node *node, char *key, void *leaf)
{
    char *next;
    mtab_node *map_node;
    trie_node *sub;

    map_node = NODE_MATCH(node, key);

    if (map_node == NULL)
    {
        /* Not mapped, add it */
        sub = trie_node_new(leaf);
        if (NODE_STORE(node, key, sub) == NULL)
            return FALSE;
    }
    else
    {
        next = map_node->attr;
        while (*key && *key == *next)
        {
            key++;
            next++;
        }

        if (*next)
        {
            /* branch abc, key abx or ab */
            trie_node *old = map_node->value;
            if ((sub = trie_node_new(NULL)) == NULL)
                return FALSE;
            if (NODE_STORE(sub, next, old) == NULL)
            {
                trie_node_delete(grp, sub);
                return FALSE;
            }
            *next = '\0';
            map_node->value = sub;
            if (*key)
            {
                /* key abx */
                trie_node *nptr = trie_node_new(leaf);
                if (NODE_STORE(sub, key, nptr) == NULL)
                {
                    trie_node_delete(grp, nptr);
                    return FALSE;
                }
            }
            else
                sub->leaf = leaf; /* key ab */
        }
        else if (*key) /* branch abc, key abcde */
            return trie_node_store(grp, map_node->value, key, leaf);
        else
        {
            /* branch abc, key abc */
            trie_node *nptr = map_node->value;
            nptr->leaf = leaf;
        }
    }
    return TRUE;
}

/* Wrapper for recursive insertion */
int trie_add(trie *grp, char *key, void *leaf)
{
    int rc = TRUE;

    if (key == NULL)
        /* map NULL key to root node */
        grp->root->leaf = leaf;
    else
        rc = trie_node_store(grp, grp->root, key, leaf);

    if (rc)
        grp->path_count++;

    return rc;
}

/* helper functions for trie_remove */
static char *mergestr(char *s1, char *s2)
{
    char *s;
    size_t len = str_len(s1) + str_len(s2);

    s = mem_malloc((len + 1) * sizeof(char));
    if (s == NULL)
        return NULL;

    len -= str_copy_checked(s1, s, len + 1);
    str_append_checked(s2, s, len + 1);

    return s;
}

static mtab_node *get_single_entry(mtab *t)
{
    int i;

    for (i = 0; i < t->size; i++)
        if (t->table[i])
            return t->table[i];

    return NULL;
}

/* Remove mappings */
int trie_remove(trie *grp, char *key, void **leaf)
{
    int rc = TRUE;
    trie_node *nlink = grp->root;
    trie_node *prev = NULL;
    char ccurr, cprev = 0;
    mtab_node *map_node;
    char *branch;

    if (nlink == NULL)
        return 0;       /* tree is empty */

    if (key == NULL)
    {
        /* NULL keys are stored on the root */
        if (leaf)
            *leaf = nlink->leaf;
        if (nlink->leaf)
        {
            grp->path_count--;
            nlink->leaf = NULL;
        }
        return rc;
    }

    /* Keep pointers one and two nodes up for merging in more complex cases */
    ccurr = *key;
    while ((map_node = NODE_MATCH(nlink, key)) != NULL)
    {
        branch = map_node->attr;

        while (*key && *key == *branch)
        {
            key++;
            branch++;
        }
        if (*branch)
            break;      /* mismatch */
        if (*key == '\0')
        {
            /* found! */
            char *attr;
            trie_node *node = map_node->value;
            if (leaf)
                *leaf = node->leaf;
            if (node->leaf)
            {
                grp->path_count--;
                node->leaf = NULL;

                /* Remove node if empty */
                if (mtab_count(node->others) == 0)
                {
                    mtab_remove(nlink->others, ccurr);
                    trie_node_unmap(grp, &node);

                    /* Check if we can compress the parent node */
                    if (prev && mtab_count(nlink->others) == 1 && nlink->leaf == NULL)
                    {
                        mtab_node *sub2 = mtab_get(prev->others, cprev);
                        mtab_node *sub = get_single_entry(nlink->others);
                        attr = mergestr(sub2->attr, sub->attr);
                        if (attr)
                        {
                            if (NODE_STORE(prev, attr, sub->value))
                            {
                                mtab_remove(nlink->others, sub->key);
                                trie_node_delete(grp, nlink);
                            }
                            mem_free(attr);
                        }
                    }
                }
                else if (mtab_count(node->others) == 1)
                {
                    /* mid-branch removal: prefix was a valid string, but has
                     * been unmapped
                     */
                    mtab_node *sub = get_single_entry(node->others);
                    attr = mergestr(map_node->attr, sub->attr);
                    if (attr)
                    {
                        if (NODE_STORE(nlink, attr, sub->value))
                        {
                            mtab_remove(node->others, sub->key);
                            trie_node_delete(grp, node);
                        }
                        mem_free(attr);
                    }
                }
            }
            break;
        }

        prev = nlink;
        cprev = ccurr;
        ccurr = *key;
        nlink = map_node->value;
    }

    return rc;
}

void *trie_find(trie *grp, char *key)
{
    void *last = NULL;
    trie_node *nlink = grp->root;
    mtab_node *map_node;
    char *branch = NULL;

    while ((map_node = NODE_MATCH(nlink, key)) != NULL)
    {
        branch = map_node->attr;

        while (*key && *key == *branch)
        {
            key++;
            branch++;
        }
        if (*branch)
            break;      /* mismatch */

        nlink = map_node->value;
    }

    if (nlink)
        last = nlink->leaf;

    if (*key == '\0' && branch && *branch == '\0')
        return last;
    return NULL;
}

int trie_count(trie *grp)
{
    return grp->path_count;
}

void trie_set_root(trie *grp, void *leaf)
{
    grp->root->leaf = leaf;
}
