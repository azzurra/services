/* SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-URL: https://spdx.org/licenses/GPL-2.0-or-later.html
 *
 * Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)
 *
 * memoserv.c - memoserv data loading and conversion
 */

#include "dbconv.h"

static mowgli_heap_t *memodb_heap;
mowgli_patricia_t *memotree;

static void memolist_destroy_cb(const char *key, void *data, void *privdata);

void memoserv_init(void) {
    memodb_heap = mowgli_heap_create(sizeof(MemoList), 2, BH_NOW);
    memotree = mowgli_patricia_create_named("memotree", &strcasecanon);
}

void memoserv_terminate(void) {
    mowgli_patricia_destroy(memotree, &memolist_destroy_cb, NULL);
    mowgli_heap_destroy(memodb_heap);
}

void load_ms_dbase(void) {
    FILE *f;
    int ver, idx, memoIdx;
    MemoList *ml;
    Memo *memo;

    if ((f = open_db_read("MemoServ", MEMOSERV_DB)) == NULL)
        mowgli_log_fatal("Could not open %s", MEMOSERV_DB);

    uint8_t flags;
    switch (ver = get_file_version(f, MEMOSERV_DB, &flags)) {
        case MEMOSERV_DB_CURRENT_VERSION:
            for (idx = 65; idx < 126; ++idx) {
                MemoIgnore *ignore;

                while (fgetc(f) == 1) {
                    ml = mowgli_heap_alloc(memodb_heap);

                    if (flags & DATAFILE64) {
                        if (fread(ml, sizeof(MemoList), 1, f) != 1)
                            mowgli_log_fatal("Read error (1) on %s", MEMOSERV_DB);
                    } else {
                        MemoList32 memoList32;
                        if (fread(&memoList32, sizeof(MemoList32), 1, f) != 1)
                            mowgli_log_fatal("Read error (1) on %s", MEMOSERV_DB);
                        memcpy(ml->nick, memoList32.nick, NICKMAX);
                        ml->ignores = (void *)(uintptr_t)memoList32.ignores;
                        ml->n_ignores = memoList32.n_ignores;
                        ml->n_memos = memoList32.n_memos;
                        ml->memos = (void *)(uintptr_t)memoList32.memos;
                        ml->next = (void *)(uintptr_t)memoList32.next;
                        ml->prev = (void *)(uintptr_t)memoList32.prev;
                        memset(ml->reserved, 0, sizeof(ml->reserved));
                    }

                    mowgli_patricia_add(memotree, ml->nick, ml);

                    if (ml->n_memos > 0) {
                        ml->memos = mowgli_alloc_array(sizeof(Memo), ml->n_memos);

                        if (flags & DATAFILE64) {
                            if (fread(ml->memos, sizeof(Memo), ml->n_memos, f) != (size_t) ml->n_memos)
                                mowgli_log_fatal("Read error (2) on %s", MEMOSERV_DB);
                        } else {
                            Memo32 *memos32 = mowgli_alloc_array(sizeof(Memo32), ml->n_memos);

                            if (fread(memos32, sizeof(Memo32), ml->n_memos, f) != (size_t) ml->n_memos)
                                mowgli_log_fatal("Read error (2) on %s", MEMOSERV_DB);
                            for (memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx) {
                                memcpy(ml->memos[memoIdx].sender, memos32[memoIdx].sender, NICKMAX);
                                ml->memos[memoIdx].unused = memos32[memoIdx].unused;
                                ml->memos[memoIdx].time = memos32[memoIdx].time;
                                ml->memos[memoIdx].text = (void *)(uintptr_t)memos32[memoIdx].text;
                                ml->memos[memoIdx].chan = (void *)(uintptr_t)memos32[memoIdx].chan;
                                ml->memos[memoIdx].flags = memos32[memoIdx].flags;
                                ml->memos[memoIdx].level = memos32[memoIdx].level;
                                memset(ml->memos[memoIdx].reserved, 0, sizeof(ml->memos[memoIdx].reserved));
                            }
                            mowgli_free(memos32);
                        }

                        for (memo = ml->memos, memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx, ++memo) {

                            memo->text = read_string(f, MEMOSERV_DB);

                            if (memo->chan != NULL)
                                memo->chan = read_string(f, MEMOSERV_DB);
                        }
                    }
                    else
                        ml->memos = NULL;

                    ml->ignores = NULL;

                    if (ml->n_ignores > 0) {
                        for (memoIdx = 0; memoIdx < ml->n_ignores; ++memoIdx) {
                            ignore = mowgli_alloc(sizeof(MemoIgnore));

                            if (flags & DATAFILE64) {
                                if (fread(ignore, sizeof(MemoIgnore), 1, f) != 1)
                                    mowgli_log_fatal("Read error (3) on %s", MEMOSERV_DB);
                            } else {
                                MemoIgnore32 ignore32;
                                if (fread(&ignore32, sizeof(MemoIgnore32), 1, f) != 1)
                                    mowgli_log_fatal("Read error (3) on %s", MEMOSERV_DB);
                                ignore->creationTime = ignore32.creationTime;
                                ignore->ignoredNick = (void *)(uintptr_t)ignore32.ignoredNick;
                            }

                            if (ignore->ignoredNick != NULL)
                                ignore->ignoredNick = read_string(f, MEMOSERV_DB);

                            ignore->prev = NULL;
                            ignore->next = ml->ignores;

                            if (ml->ignores != NULL)
                                ml->ignores->prev = ignore;

                            ml->ignores = ignore;
                        }
                    }
                }
            }
            break;

        default:
            mowgli_log_fatal("Unsupported version number (%d) on %s", ver, MEMOSERV_DB);
    }

    close_db(f, MEMOSERV_DB);
}

static void memolist_destroy_cb(const char *key, void *data, void *privdata) {
    MemoList *ml = (MemoList *)data;
    int memoIdx;
    MemoIgnore *ignore, *next;

    /* Clear all remaining memos. */
    for (memoIdx = 0; memoIdx < ml->n_memos; ++memoIdx) {

        mowgli_free(ml->memos[memoIdx].text);

        if (ml->memos[memoIdx].chan)
            mowgli_free(ml->memos[memoIdx].chan);
    }

    if (ml->memos)
        mowgli_free(ml->memos);

    /* Clear all ignores, if any. */
    for (ignore = ml->ignores; ignore != NULL; ) {
        next = ignore->next;

        mowgli_free(ignore->ignoredNick);
        mowgli_free(ignore);

        ignore = next;
    }

    mowgli_heap_free(memodb_heap, ml);
}
