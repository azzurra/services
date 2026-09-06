/* SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-URL: https://spdx.org/licenses/GPL-2.0-or-later.html
 *
 * Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)
 *
 * nickserv.c - nickserv data loading and conversion
 */

#include "dbconv.h"

static mowgli_heap_t *nickdb_heap;
static mowgli_patricia_t *nicktree;

static void nickinfo32_to64(NickInfo32 *ni32, NickInfo *ni);

void nickserv_init(void) {
    nickdb_heap = mowgli_heap_create(sizeof(NickInfo), 2, BH_NOW);
    nicktree = mowgli_patricia_create_named("nicktree", &strcasecanon);
}

static void nickinfo_destroy_cb(const char *key, void *data, void *privdata) {
    NickInfo *ni = (NickInfo *)data;

    if (ni == NULL)
        return;

    if (ni->url)
        mowgli_free(ni->url);
    if (ni->email)
        mowgli_free(ni->email);
    if (ni->forward)
        mowgli_free(ni->forward);
    if (ni->hold)
        mowgli_free(ni->hold);
    if (ni->mark)
        mowgli_free(ni->mark);
    if (ni->forbid)
        mowgli_free(ni->forbid);
    if (ni->freeze)
        mowgli_free(ni->freeze);
    if (ni->regemail)
        mowgli_free(ni->regemail);

    mowgli_free(ni->last_usermask);
    mowgli_free(ni->last_realname);

    if (ni->accesscount) {
        int i;

        for (i = 0; i < ni->accesscount; i++)
            mowgli_free(ni->access[i]);

        mowgli_free(ni->access);
    }

    mowgli_heap_free(nickdb_heap, ni);
}

void nickserv_terminate(void) {
    mowgli_patricia_destroy(nicktree, &nickinfo_destroy_cb, NULL);
    mowgli_heap_destroy(nickdb_heap);
}

void load_ns_dbase(void) {
    FILE *f;
    int ver, i = 0, j;
    uint8_t flags;
    NickInfo *ni;

    if ((f = open_db_read("NickServ", NICKSERV_DB)) == NULL)
        mowgli_log_fatal("Could not open NickServ main db, aborting");

    switch (ver = get_file_version(f, NICKSERV_DB, &flags)) {
        case NICKSERV_DB_CURRENT_VERSION:
            for (i = 65; i < 126; ++i) {
                while (fgetc(f) == 1) {
                    ni = mowgli_heap_alloc(nickdb_heap);

                    if (flags & DATAFILE64) {
                        if (fread(ni, sizeof(NickInfo), 1, f) != 1)
                            mowgli_log_fatal("Read error on %s", NICKSERV_DB);
                    } else {
                        NickInfo32 *ni32 = mowgli_alloc(sizeof(NickInfo32));
                        if (fread(ni32, sizeof(NickInfo32), 1, f) != 1)
                            mowgli_log_fatal("Read error on %s", NICKSERV_DB);
                        nickinfo32_to64(ni32, ni);
                        mowgli_free(ni32);
                    }

                    if (ni->langID == LANG_DE || ni->langID == LANG_JP)
                        ni->langID = LANG_DEFAULT;

                    ni->flags &= ~(NI_TIMEOUT | NI_ENFORCE | NI_ENFORCED);

                    mowgli_patricia_add(nicktree, ni->nick, ni);

                    if (ni->url)
                        ni->url = read_string(f, NICKSERV_DB);
                    if (ni->email)
                        ni->email = read_string(f, NICKSERV_DB);
                    if (ni->forward)
                        ni->forward = read_string(f, NICKSERV_DB);
                    if (ni->hold)
                        ni->hold = read_string(f, NICKSERV_DB);
                    if (ni->mark)
                        ni->mark = read_string(f, NICKSERV_DB);
                    if (ni->forbid)
                        ni->forbid = read_string(f, NICKSERV_DB);
                    if (ni->freeze)
                        ni->freeze = read_string(f, NICKSERV_DB);
                    if (ni->regemail)
                        ni->regemail = read_string(f, NICKSERV_DB);

                    ni->last_usermask = read_string(f, NICKSERV_DB);
                    ni->last_realname = read_string(f, NICKSERV_DB);

                    if (ni->accesscount) {
                        char **anAccess;

                        anAccess = mowgli_alloc(sizeof(char *) * ni->accesscount);
                        ni->access = anAccess;

                        for (j = 0; j < ni->accesscount; ++j, ++anAccess)
                            *anAccess = read_string(f, NICKSERV_DB);
                    }

                }
            }
            break;

        default:
            mowgli_log_fatal("Unsupported version number (%d) on %s", ver, NICKSERV_DB);
    }

    close_db(f, NICKSERV_DB);
}

void dump_ns_dbase(void) {
    mowgli_patricia_iteration_state_t state;
    void *elem;
    unsigned int i = 0;

    mowgli_log("******* DUMPING NickServ Database *******");

    MOWGLI_PATRICIA_FOREACH(elem, &state, nicktree) {
        NickInfo *ni = (NickInfo *)elem;
        mowgli_log(" %d) %s", ++i, ni->nick);
        if (ni->flags & NI_HOLD)
            mowgli_log("   * HELD by %s", ni->hold ? ni->hold : "<NULL>");
    }
}

static void nickinfo32_to64(NickInfo32 * ni32, NickInfo *ni) {
    //we don't care about valid pointer, we just make sure NULL stays NULL and not NULL stays NOT NULL
    //eventually they will get overwritten with a valid pointer later

    ni->next = NULL;
    ni->prev = NULL;
    memcpy(ni->nick, ni32->nick, NICKMAX);
    memcpy(ni->pass, ni32->pass, PASSMAX);
    ni->last_usermask = (char *)(uintptr_t)ni32->last_usermask;
    ni->last_realname = (char *)(uintptr_t)ni32->last_realname;
    ni->time_registered = ni32->time_registered;
    ni->last_seen = ni32->last_seen;
    ni->accesscount = ni32->accesscount;
    ni->access = (char **)(uintptr_t)ni32->access;
    ni->flags = ni32->flags;
    ni->last_drop_request = ni32->last_drop_request;
    ni->channelcount = ni32->channelcount;
    ni->url = (char *)(uintptr_t)ni32->url;
    ni->email = (char *)(uintptr_t)ni32->email;
    ni->forward = (char *)(uintptr_t)ni32->forward;
    ni->hold = (char *)(uintptr_t)ni32->hold;
    ni->mark = (char *)(uintptr_t)ni32->mark;
    ni->forbid = (char *)(uintptr_t)ni32->forbid;
    ni->news = ni32->news;
    ni->regemail = (char *)(uintptr_t)ni32->regemail;
    ni->last_email_request = ni32->last_email_request;
    ni->auth = ni32->auth;
    ni->freeze = (char *)(uintptr_t)ni32->freeze;
    ni->langID = ni32->langID;
    memset(ni->reserved, 0, sizeof(ni->reserved));
}
