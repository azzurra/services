/* SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-URL: https://spdx.org/licenses/GPL-2.0-or-later.html
 *
 * Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)
 *
 * chanserv.c - chanserv data loading and conversion
 */

#include "dbconv.h"

static mowgli_heap_t *chandb_heap;
mowgli_patricia_t *chantree;
mowgli_list_t *cs_suspend_list;


static void channelinfo32_to64(ChannelInfo32 *ci32, ChannelInfo *ci);
static void compact_chan_access_list(ChannelInfo *ci, const int removed);
static void chaninfo_destroy_cb(const char *key, void *data, void *privdata);

void chanserv_init(void) {
    chandb_heap = mowgli_heap_create(sizeof(ChannelInfo), 2, BH_NOW);
    cs_suspend_list = mowgli_list_create();
    chantree = mowgli_patricia_create_named("chantree", &strcasecanon);
}

void chanserv_terminate(void) {
    mowgli_node_t *n, *tn;

    mowgli_patricia_destroy(chantree, &chaninfo_destroy_cb, NULL);

    MOWGLI_LIST_FOREACH_SAFE(n, tn, cs_suspend_list->head) {
        mowgli_node_delete(n, cs_suspend_list);
        mowgli_free(n->data);
        mowgli_node_free(n);
    }
    mowgli_list_free(cs_suspend_list);

    mowgli_heap_destroy(chandb_heap);
}

void load_cs_dbase(void) {
    FILE *f;
    int ver, i;
    uint8_t flags;
    ChannelInfo *ci = NULL;
    NickInfo *ni;

    if ((f = open_db_read("ChanServ", CHANSERV_DB)) == NULL)
        mowgli_log_fatal("Cannot open %s", CHANSERV_DB);

    switch (ver = get_file_version(f, CHANSERV_DB, &flags)) {
        case CHANSERV_DB_CURRENT_VERSION:
            for (i = 0; i < 256; ++i) {
                while (fgetc(f) == 1) {
                    ci = mowgli_heap_alloc(chandb_heap);

                    if (flags & DATAFILE64) {
                        if (fread(ci, sizeof(ChannelInfo), 1, f) != 1)
                            mowgli_log_fatal("Read error on %s", CHANSERV_DB);
                    } else {
                        ChannelInfo32 ci32;
                        if (fread(&ci32, sizeof(ChannelInfo32), 1, f) != 1)
                            mowgli_log_fatal("Read error on %s", CHANSERV_DB);
                        channelinfo32_to64(&ci32, ci);
                    }

                    /* Strip runtime flags and settings */
                    ci->flags &= ~(CI_NOENTRY | CI_TIMEOUT);
                    ci->settings &= ~CI_ACCCESS_CFOUNDER_LOCK;

                    /* Reset invalid language id */
                    if (ci->langID == LANG_DE || ci->langID == LANG_JP)
                        ci->langID = LANG_DEFAULT;

                    memset(ci->reserved, 0, sizeof(ci->reserved));

                    if (ci->accesscount == 0)
                        ci->access = NULL;

                    mowgli_patricia_add(chantree, ci->name, ci);

                    ci->desc = read_string(f, CHANSERV_DB);

                    if (ci->successor)
                        ci->successor = read_string(f, CHANSERV_DB);
                    if (ci->url)
                        ci->url = read_string(f, CHANSERV_DB);
                    if (ci->email)
                        ci->email = read_string(f, CHANSERV_DB);
                    if (ci->mlock_key)
                        ci->mlock_key = read_string(f, CHANSERV_DB);
                    if (ci->last_topic)
                        ci->last_topic = read_string(f, CHANSERV_DB);
                    if (ci->welcome)
                        ci->welcome = read_string(f, CHANSERV_DB);
                    if (ci->hold)
                        ci->hold = read_string(f, CHANSERV_DB);
                    if (ci->mark)
                        ci->mark = read_string(f, CHANSERV_DB);
                    if (ci->freeze)
                        ci->freeze = read_string(f, CHANSERV_DB);
                    if (ci->forbid)
                        ci->forbid = read_string(f, CHANSERV_DB);
                    if (ci->real_founder)
                        ci->real_founder = read_string(f, CHANSERV_DB);

                    if (ci->accesscount) {
                        ChanAccess *anAccess;
                        ChanAccess32 *access32 = NULL;
                        int unused_access, accessIdx;

                        anAccess = mowgli_alloc_array(sizeof(ChanAccess), ci->accesscount);
                        ci->access = anAccess;
                        if (flags & DATAFILE64) {
                            if ((signed)fread(anAccess, sizeof(ChanAccess), ci->accesscount, f) != ci->accesscount)
                                mowgli_log_fatal("Read error on %s", CHANSERV_DB);
                        } else {
                            access32  = mowgli_alloc_array(sizeof(ChanAccess32), ci->accesscount);
                            if ((signed)fread(access32, sizeof(ChanAccess32), ci->accesscount, f) != ci->accesscount)
                                mowgli_log_fatal("Read error on %s", CHANSERV_DB);
                            for (accessIdx = 0; accessIdx < ci->accesscount; ++accessIdx) {
                                anAccess[accessIdx].name = NULL; /* Don't care */
                                anAccess[accessIdx].level = access32[accessIdx].level;
                                anAccess[accessIdx].status = access32[accessIdx].status;
                                anAccess[accessIdx].creator = NULL; /* Don't care */
                                anAccess[accessIdx].creationTime = access32[accessIdx].creationTime;
                            }
                            mowgli_free(access32);
                        }

                        for (accessIdx = 0; accessIdx < ci->accesscount; ++accessIdx, ++anAccess) {
                            anAccess->name = read_string(f, CHANSERV_DB);
                            anAccess->creator = read_string(f, CHANSERV_DB);
                        }

                        accessIdx = 0;
                        anAccess = ci->access;
                        unused_access = 0;

                        while (accessIdx < ci->accesscount) {
                            switch (anAccess->status) {
                                case ACCESS_ENTRY_FREE:
                                case ACCESS_ENTRY_EXPIRED:
                                    if (anAccess->name != NULL) {
                                        mowgli_free(anAccess->name);
                                        anAccess->name = NULL;
                                    }

                                    if (anAccess->creator != NULL) {
                                        mowgli_free(anAccess->creator);
                                        anAccess->creator = NULL;
                                    }

                                    anAccess->status = ACCESS_ENTRY_FREE;
                                    anAccess->flags = 0;
                                    ++unused_access;
                                    break;

                                case ACCESS_ENTRY_NICK:
                                    if (anAccess->name != NULL) {
                                        ni = (NickInfo *)mowgli_patricia_retrieve(nicktree, anAccess->name);

                                        if (ni == NULL || strncasecmp(ni->nick, ci->founder, sizeof(ni->nick))) {
                                            mowgli_free(anAccess->name);
                                            anAccess->name = NULL;

                                            if (anAccess->creator != NULL) {
                                                anAccess->status = ACCESS_ENTRY_FREE;
                                                anAccess->flags = 0;
                                                ++unused_access;
                                            }
                                        }
                                    }
                                    break;
                            }

                            ++accessIdx;
                            ++anAccess;
                        }

                        if (unused_access > 0)
                            compact_chan_access_list(ci, unused_access);
                    } /* ci->accesscount */

                    if (ci->akickcount) {
                        AutoKick *anAkick;
                        AutoKick32 *anAkick32 = NULL;
                        int akickIdx;

                        anAkick = mowgli_alloc_array(sizeof(AutoKick), ci->akickcount);
                        ci->akick = anAkick;

                        if (flags & DATAFILE64) {
                            if ((signed)fread(anAkick, sizeof(AutoKick), ci->akickcount, f) != ci->akickcount)
                                mowgli_log_fatal("Read error on %s", CHANSERV_DB);
                        } else {
                            anAkick32 = mowgli_alloc_array(sizeof(AutoKick32), ci->akickcount);
                            if ((signed)fread(anAkick32, sizeof(AutoKick32), ci->akickcount, f) != ci->akickcount)
                                mowgli_log_fatal("Read error on %s", CHANSERV_DB);
                            for (akickIdx = 0; akickIdx < ci->akickcount; ++akickIdx) {
                                anAkick[akickIdx].isNick = anAkick32[akickIdx].isNick;
                                anAkick[akickIdx].flags = anAkick32[akickIdx].flags;
                                anAkick[akickIdx].name = (char *)(uintptr_t) anAkick32[akickIdx].name;
                                anAkick[akickIdx].reason = (char *)(uintptr_t) anAkick32[akickIdx].reason;
                                anAkick[akickIdx].creator = (char *)(uintptr_t) anAkick32[akickIdx].creator;
                                anAkick[akickIdx].banType = anAkick32[akickIdx].banType;
                                anAkick[akickIdx].creationTime = anAkick32[akickIdx].creationTime;
                            }
                            mowgli_free(anAkick32);
                        }

                        for (akickIdx = 0; akickIdx < ci->akickcount; ++akickIdx, ++anAkick) {
                            anAkick->name = read_string(f, CHANSERV_DB);

                            if (anAkick->reason)
                                anAkick->reason = read_string(f, CHANSERV_DB);

                            if (anAkick->creator)
                                anAkick->creator = read_string(f, CHANSERV_DB);
                        }
                    } /* ci->akickcount */
                }
            }
            break;

        default:
            mowgli_log_fatal("Unsupported version number (%d) on %s", i, CHANSERV_DB);
    }

    close_db(f, CHANSERV_DB);
}

void load_suspend_db(void) {
    FILE *f;
    ChannelSuspendData *csd;
    int i;
    uint8_t flags;

    if ((f = open_db_read("OperServ", SUSPEND_DB)) == NULL)
        mowgli_log_fatal("Cannot open %s", SUSPEND_DB);

    if ((i = get_file_version(f, SUSPEND_DB, &flags)) > FILE_VERSION_MAX)
        mowgli_log_fatal("Unsupported version number (%d) on %s", i, SUSPEND_DB);

    i = 0;
    while (fgetc(f) == 1) {
        ++i;

        csd = mowgli_alloc(sizeof(ChannelSuspendData));

        if (flags & DATAFILE64) {
            if (fread(csd, sizeof(ChannelSuspendData), 1, f) != 1)
                mowgli_log_fatal("Read error on %s at entry %d", SUSPEND_DB, i);
        } else {
            ChannelSuspendData32 csd32;
            if (fread(&csd32, sizeof(ChannelSuspendData32), 1, f) != 1)
                mowgli_log_fatal("Read error on %s at entry %d", SUSPEND_DB, i);

            csd->expires = csd32.expires;
            mowgli_strlcpy(csd->name, csd32.name, sizeof(csd->name));
            mowgli_strlcpy(csd->who, csd32.who, sizeof(csd->who));
        }

        mowgli_node_add(csd, mowgli_node_create(), cs_suspend_list);
    }

    close_db(f, SUSPEND_DB);
}

static void compact_chan_access_list(ChannelInfo *ci, const int removed) {

    if (removed == 0) {
        mowgli_log_error("ChanServ in compact_chan_access_list(): Call with removed == 0 for %s!", ci->name);
        return;
    }

    if (removed == ci->accesscount) {
        /* The entire list is empty, release it */
        mowgli_free(ci->access);
        ci->access = NULL;
        ci->accesscount = 0;
    }
    else {
        /* Some elements are empty, compact it */
        ChanAccess *anAccess, *nextUsed;

        int check = ci->accesscount;
        int checkIndex, nextCheckIndex;

        for (anAccess = ci->access, checkIndex = 0; checkIndex < check; ++anAccess, ++checkIndex) {
            if (anAccess->status == ACCESS_ENTRY_FREE) {
                /* Entry "vuota". */
                for (nextUsed = (anAccess + 1), nextCheckIndex = (checkIndex + 1); nextCheckIndex < check; ++nextUsed, ++nextCheckIndex) {
                    if (nextUsed->status != ACCESS_ENTRY_FREE) {
                        /* Trovata entry utilizzata. */
                        anAccess->level = nextUsed->level;
                        anAccess->name = nextUsed->name;
                        anAccess->status = nextUsed->status;
                        anAccess->creator = nextUsed->creator;
                        anAccess->creationTime = nextUsed->creationTime;
                        anAccess->flags = nextUsed->flags;

                        nextUsed->level = 0;
                        nextUsed->name = NULL;
                        nextUsed->status = ACCESS_ENTRY_FREE;
                        nextUsed->creator = NULL;
                        nextUsed->creationTime = 0;
                        nextUsed->flags = 0;
                        break;
                    }
                }

                /* Se l'ultima ricerca di entry utilizzate non ne ha trovate, inutile continuare. */
                if (nextCheckIndex >= check)
                    break;
            }
        }

        ci->accesscount -= removed;

        if (ci->accesscount > 0) {
            /* ci->access = mem_realloc(ci->access, sizeof(ChanAccess) * ci->accesscount); */
            anAccess = ci->access;
            ci->access = mowgli_alloc_array(sizeof(ChanAccess), ci->accesscount);
            memcpy(ci->access, anAccess, sizeof(ChanAccess)*ci->accesscount);
            mowgli_free(anAccess);
        } else {
            mowgli_free(ci->access);
            ci->access = NULL;
        }
    }
}

static void channelinfo32_to64(ChannelInfo32 *ci32, ChannelInfo *ci) {
    ci->next = (ChannelInfo *)(uintptr_t)ci32->next;
    ci->prev = (ChannelInfo *)(uintptr_t)ci32->prev;
    memcpy(ci->name, ci32->name, CHANMAX);
    memcpy(ci->founder, ci32->founder, NICKMAX);
    memcpy(ci->founderpass, ci32->founderpass, PASSMAX);
    ci->desc = (char *)(uintptr_t) ci32->desc;
    ci->time_registered = ci32->time_registered;
    ci->last_used = ci32->last_used;
    ci->accesscount = ci32->accesscount;
    ci->access = (ChanAccess_V7 *)(uintptr_t) ci32->access;
    ci->akickcount = ci32->akickcount;
    ci->akick = (AutoKick_V7 *)(uintptr_t) ci32->akick;
    ci->mlock_on = ci32->mlock_on;
    ci->mlock_off = ci32->mlock_off;
    ci->mlock_limit = ci32->mlock_limit;
    ci->mlock_key = (char *)(uintptr_t) ci32->mlock_key;
    ci->last_topic = (char *)(uintptr_t) ci32->last_topic;
    memcpy(ci->last_topic_setter, ci32->last_topic_setter, NICKMAX);
    ci->last_topic_time = ci32->last_topic_time;
    ci->flags = ci32->flags;
    ci->successor = (char *)(uintptr_t) ci32->successor;
    ci->url = (char *)(uintptr_t) ci32->url;
    ci->email = (char *)(uintptr_t) ci32->email;
    ci->welcome = (char *)(uintptr_t) ci32->welcome;
    ci->hold = (char *)(uintptr_t) ci32->hold;
    ci->mark = (char *)(uintptr_t) ci32->mark;
    ci->freeze = (char *)(uintptr_t) ci32->freeze;
    ci->forbid = (char *)(uintptr_t) ci32->forbid;
    ci->topic_allow = ci32->topic_allow;
    ci->auth = ci32->auth;
    ci->settings = ci32->settings;
    ci->real_founder = (char *)(uintptr_t) ci32->real_founder;
    ci->last_drop_request = ci32->last_drop_request;
    ci->langID = ci32->langID;
    ci->banType = ci32->banType;
    memset(ci->reserved, 0, sizeof(ci->reserved));
}

static void chaninfo_destroy_cb(const char *key, void *data, void *privdata) {
    ChannelInfo *ci = (ChannelInfo *)data;
    int i;

    if (ci->desc)
        mowgli_free(ci->desc);
    if (ci->successor)
        mowgli_free(ci->successor);
    if (ci->url)
        mowgli_free(ci->url);
    if (ci->email)
        mowgli_free(ci->email);
    if (ci->real_founder)
        mowgli_free(ci->real_founder);
    if (ci->mlock_key)
        mowgli_free(ci->mlock_key);
    if (ci->last_topic)
        mowgli_free(ci->last_topic);

    if (ci->access) {
        ChanAccess *anAccess;

        for (anAccess = ci->access, i = 0; (i < ci->accesscount) && anAccess != NULL; ++anAccess, ++i) {
            if (anAccess->name)
                mowgli_free(anAccess->name);

            if (anAccess->creator)
                mowgli_free(anAccess->creator);
        }
        mowgli_free(ci->access);
    }

    for (i = 0; i < ci->akickcount; ++i) {
        mowgli_free(ci->akick[i].name);

        if (ci->akick[i].reason)
            mowgli_free(ci->akick[i].reason);
        if (ci->akick[i].creator)
            mowgli_free(ci->akick[i].creator);
    }

    if (ci->akick)
        mowgli_free(ci->akick);
    if (ci->welcome)
        mowgli_free(ci->welcome);
    if (ci->hold)
        mowgli_free(ci->hold);
    if (ci->mark)
        mowgli_free(ci->mark);
    if (ci->freeze)
        mowgli_free(ci->freeze);
    if (ci->forbid)
        mowgli_free(ci->forbid);

    mowgli_heap_free(chandb_heap, ci);
}
