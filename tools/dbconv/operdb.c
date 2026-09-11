/* SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-URL: https://spdx.org/licenses/GPL-2.0-or-later.html
 *
 * Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)
 *
 * operdb.c - combined OperServ/RootServ database loading routines
 */

#include "dbconv.h"

mowgli_list_t *serverBotList = NULL;
mowgli_list_t *spam_list = NULL;
mowgli_list_t *trigger_list = NULL;

dynConfig dynConf = {
    .cs_regLimit = 0,
    .ns_regLimit = 0,
    .welcomeNotice = NULL,
};

static void access_destroy(Access *anAccess);
static void rootserv_db_load(void);
static bool access_db_load(mowgli_list_t *accessList, const char *database);
static bool dynconf_db_load(void);
static bool spam_db_load(void);
static bool trigger_db_load(void);

static void str_creator_init(Creator *creator);
static bool str_creator_set(Creator *creator, const char *name, time_t time_set);
static inline void str_creator_free(Creator *creator);

static void str_creationinfo_init(CreationInfo *info);
static bool str_creationinfo_set(CreationInfo *info, const char *creator, const char *reason, time_t time_set);
static inline void str_creationinfo_free(CreationInfo *info);

static bool str_settingsinfo_add(SettingsInfo **infoList, unsigned long int type, const char *creator, const char *reason);
static bool str_settingsinfo_remove(SettingsInfo **infoList, unsigned long int type);

void operdb_init(void) {
    /* RootServ */
    serverBotList = mowgli_list_create();
    /* Spam */
    spam_list = mowgli_list_create();
    /* Trigger */
    trigger_list = mowgli_list_create();
}

void operdb_terminate(void) {
    mowgli_node_t *n, *tn;

    /* Trigger */
    MOWGLI_LIST_FOREACH_SAFE(n, tn, trigger_list->head) {
        Trigger *trigger = (Trigger *)n->data;
        mowgli_node_delete(n, trigger_list);
        if (trigger->username != NULL)
            mowgli_free(trigger->username);
        mowgli_free(trigger->host);
        str_creationinfo_free(&(trigger->info));
        mowgli_free(trigger);
        mowgli_node_free(n);
    }
    mowgli_list_free(trigger_list);

    /* Spam */
    MOWGLI_LIST_FOREACH_SAFE(n, tn, spam_list->head) {
        SpamItem *spam = (SpamItem *)n->data;
        mowgli_node_delete(n, spam_list);
        mowgli_free(spam->text);
        mowgli_free(spam->reason);
        str_creator_free(&(spam->creator));
        mowgli_free(spam);
        mowgli_node_free(n);
    }
    mowgli_list_free(spam_list);

    /* RootServ */
    MOWGLI_LIST_FOREACH_SAFE(n, tn, serverBotList->head) {
        mowgli_node_delete(n, serverBotList);
        access_destroy((Access *)n->data);
        mowgli_node_free(n);
    }
    mowgli_list_free(serverBotList);
    if (dynConf.welcomeNotice) {
        mowgli_free(dynConf.welcomeNotice);
        dynConf.welcomeNotice = NULL;
    }
}

void operdb_load(void) {
    rootserv_db_load();
    spam_db_load();
    trigger_db_load();
}

static void rootserv_db_load(void) {
    access_db_load(serverBotList, SERVERBOT_DB);
    dynconf_db_load();
}

static bool access_db_load(mowgli_list_t *accessList, const char *database) {
    STGHANDLE stg = 0;
    STG_RESULT result;

    result = stg_open(database, &stg);

    switch (result) {
        case stgSuccess: {
            STGVERSION version;
            bool in_section, read_done, is64Bit;
            int recordIdx = 0;

            version = stg_data_version(stg);
            is64Bit = stg_is64bit(stg);
            switch (version) {
                case ACCESS_DB_CURRENT_VERSION: {
                    Access *anAccess;
                    Access32 acc32;
                    /* Start of section marker */
                    result = stg_read_record(stg, NULL, 0);
                    if (result == stgBeginOfSection) {
                        in_section = true;
                        while (in_section) {
                            anAccess = mowgli_alloc(sizeof(Access));
                            ++recordIdx;

                            if (is64Bit) {
                                result = stg_read_record(stg, (unsigned char *)anAccess, sizeof(Access));
                            } else {
                                result = stg_read_record(stg, (unsigned char *)&acc32, sizeof(Access32));
                            }

                            switch (result) {
                                case stgEndOfSection:
                                    in_section = false;
                                    mowgli_free(anAccess);
                                    break;
                                case stgSuccess:
                                    read_done = true;
                                    if (!is64Bit) {
                                        /* CRAP! */
                                        anAccess->flags = acc32.flags;
                                        anAccess->lastUpdate = acc32.lastUpdate;
                                        anAccess->creator.name = (char *)(uintptr_t)acc32.creator.name;
                                        anAccess->creator.time = acc32.creator.time;
                                        anAccess->host = (char *)(uintptr_t)acc32.host;
                                        anAccess->host2 = (char *)(uintptr_t)acc32.host2;
                                        anAccess->host3 = (char *)(uintptr_t)acc32.host3;
                                        anAccess->server = (char *)(uintptr_t)acc32.server;
                                        anAccess->server2 = (char *)(uintptr_t)acc32.server2;
                                        anAccess->server3 = (char *)(uintptr_t)acc32.server3;
                                        anAccess->user = (char *)(uintptr_t)acc32.user;
                                        anAccess->user2 = (char *)(uintptr_t)acc32.user2;
                                        anAccess->user3 = (char *)(uintptr_t)acc32.user3;
                                        anAccess->nick = (char *)(uintptr_t)acc32.nick;
                                        anAccess->modes_off = acc32.modes_off;
                                        anAccess->modes_on = acc32.modes_on;
                                    }

                                    read_done &= (result = stg_read_string(stg, &(anAccess->nick), NULL)) == stgSuccess;

                                    if (read_done && anAccess->user != NULL)
                                        read_done &= (result = stg_read_string(stg, &(anAccess->user), NULL)) == stgSuccess;

                                    if (read_done && anAccess->user2 != NULL)
                                        read_done &= (result = stg_read_string(stg, &(anAccess->user2), NULL)) == stgSuccess;

                                    if (read_done && anAccess->user3 != NULL)
                                        read_done &= (result = stg_read_string(stg, &(anAccess->user3), NULL)) == stgSuccess;

                                    if (read_done && anAccess->host != NULL)
                                        read_done &= (result = stg_read_string(stg, &(anAccess->host), NULL)) == stgSuccess;

                                    if (read_done && anAccess->host2 != NULL)
                                        read_done &= (result = stg_read_string(stg, &(anAccess->host2), NULL)) == stgSuccess;

                                    if (read_done && anAccess->host3 != NULL)
                                        read_done &= (result = stg_read_string(stg, &(anAccess->host3), NULL)) == stgSuccess;

                                    if (read_done && anAccess->server != NULL)
                                        read_done &= (result = stg_read_string(stg, &(anAccess->server), NULL)) == stgSuccess;

                                    if (read_done && anAccess->server2 != NULL)
                                        read_done &= (result = stg_read_string(stg, &(anAccess->server2), NULL)) == stgSuccess;

                                    if (read_done && anAccess->server3 != NULL)
                                        read_done &= (result = stg_read_string(stg, &(anAccess->server3), NULL)) == stgSuccess;

                                    if (read_done && anAccess->creator.name != NULL)
                                        read_done &= (result = stg_read_string(stg, &(anAccess->creator.name), NULL)) == stgSuccess;

                                    if (!read_done)
                                        mowgli_log_fatal("Read error on %s (2) - %s", database, stg_result_to_string(result));

                                    /* Link it. */
                                    mowgli_node_add(anAccess, mowgli_node_create(), accessList);
                                    break;

                                default:
                                    mowgli_log_fatal("Read error on %s [Record #%d] - %s", database, recordIdx, stg_result_to_string(result));
                            }
                        }
                    }
                    else
                        mowgli_log_fatal("Read error on %s : invalid format", database);

                    stg_close(stg, database);
                    return true;
                }

                default:
                    mowgli_log_fatal("Unsupported version number (%d) on %s", version, database);
            }
        }

        case stgNotFound:
            return true;

        default:
            stg_close(stg, database);
            mowgli_log_fatal("Error opening %s - %s", database, stg_result_to_string(result));
    }
}

static bool dynconf_db_load(void) {
    STGHANDLE   stg = 0;
    STG_RESULT  result;

    result = stg_open(DYNCONF_DB, &stg);
    switch (result) {
        case stgSuccess: { // OK -> loading data
            STGVERSION version;

            version = stg_data_version(stg);
            bool is64Bit = stg_is64bit(stg);

            switch (version) {
                case DYNCONF_DB_CURRENT_VERSION: {
                    // start-of-section marker
                    result = stg_read_record(stg, NULL, 0);

                    if (result == stgBeginOfSection) {
                        dynConfig32 cfg32;

                        if (is64Bit)
                            result = stg_read_record(stg, (unsigned char *)&dynConf, sizeof(dynConfig));
                        else {
                            result = stg_read_record(stg, (unsigned char *)&cfg32, sizeof(dynConfig32));
                            dynConf.welcomeNotice = (char *)(uintptr_t)cfg32.welcomeNotice;
                            dynConf.cs_regLimit = cfg32.cs_regLimit;
                            dynConf.ns_regLimit = cfg32.ns_regLimit;
                        }

                        if (result != stgSuccess)
                            mowgli_log_fatal("Read error on %s - %s", DYNCONF_DB, stg_result_to_string(result));

                        if (dynConf.welcomeNotice != NULL) {
                            result = stg_read_string(stg, &(dynConf.welcomeNotice), NULL);

                            if (result != stgSuccess)
                                mowgli_log_fatal("Read error (2) on %s - %s", DYNCONF_DB, stg_result_to_string(result));
                        }

                        result = stg_read_record(stg, NULL, 0);

                        if (result != stgEndOfSection)
                            mowgli_log_fatal("Read error (3) on %s - %s", DYNCONF_DB, stg_result_to_string(result));
                    }
                    else
                        mowgli_log_fatal("Read error on %s : invalid format", DYNCONF_DB);

                    stg_close(stg, DYNCONF_DB);
                    return true;
                }

                default:
                    mowgli_log_fatal("Unsupported version number (%d) on %s", version, DYNCONF_DB);
            }
        }

        case stgNotFound: // no data to load
            return true;

        default: // error!
            stg_close(stg, DYNCONF_DB);

            mowgli_log_fatal("Error opening %s - %s", DYNCONF_DB, stg_result_to_string(result));
            return false;
    }
}

static bool spam_db_load(void) {
    STGHANDLE   stg = STG_INVALID_HANDLE;
    STG_RESULT  result;
    SpamItem    *spam;

    result = stg_open(SPAM_DB, &stg);
    switch (result) {
        case stgSuccess: { // OK -> loading data
            STGVERSION  version;

            version = stg_data_version(stg);
            bool is64bit = stg_is64bit(stg);
            switch (version) {
                case SPAM_DB_CURRENT_VERSION: {
                    bool    read_done, data_available = true;

                    do {
                        spam = mowgli_alloc(sizeof(SpamItem));

                        if (is64bit)
                            result = stg_read_record(stg, (unsigned char *)spam, sizeof(SpamItem));
                        else {
                            SpamItem32 si32;
                            result = stg_read_record(stg, (unsigned char *)&si32, sizeof(SpamItem32));
                            spam->text = (char *)(uintptr_t)si32.text;
                            spam->flags = si32.flags;
                            spam->type = si32.type;
                            spam->creator.name = (char *)(uintptr_t)si32.creator.name;
                            spam->creator.time = si32.creator.time;
                            spam->reason = (char *)(uintptr_t)si32.reason;
                            spam->pad = si32.pad;
                        }

                        switch (result) {
                            case stgSuccess: // a valid item
                                read_done = true;
                                if (spam->text)
                                    read_done &= (result = stg_read_string(stg, &(spam->text), NULL)) == stgSuccess;

                                if (read_done && spam->creator.name != NULL)
                                    read_done &= (result = stg_read_string(stg, &(spam->creator.name), NULL)) == stgSuccess;

                                if (read_done && spam->reason != NULL)
                                    read_done &= (result = stg_read_string(stg, &(spam->reason), NULL)) == stgSuccess;

                                if (!read_done)
                                    mowgli_log_fatal("Read error on %s (2) - %s", SPAM_DB, stg_result_to_string(result));

                                mowgli_node_add(spam, mowgli_node_create(), spam_list);
                                break;

                            case stgEndOfData:
                                data_available = false;
                                mowgli_free(spam);
                                break;

                            default: // some error
                                mowgli_log_fatal("Read error on %s - %s", SPAM_DB, stg_result_to_string(result));
                                return false;
                        }
                    } while (data_available);

                    stg_close(stg, SPAM_DB);
                    return true;
                }

                default:
                    mowgli_log_fatal("Unsupported version number (%d) on %s", version, SPAM_DB);
                    return false;
            }
        }

        case stgNotFound: // no data to load
            return true;

        default: // error!
            stg_close(stg, SPAM_DB);

            mowgli_log_fatal("Error opening %s - %s", SPAM_DB, stg_result_to_string(result));
            return false;
    }
}

static bool trigger_db_load(void) {
    STGHANDLE   stg = 0;
    STG_RESULT  result;

    result = stg_open(TRIGGER_DB, &stg);

    switch (result) {
        case stgSuccess: { // OK -> loading data
            STGVERSION  version;
            bool        in_section;
            bool        read_done;


            version = stg_data_version(stg);
            bool is64Bit = stg_is64bit(stg);

            switch (version) {
                case TRIGGER_DB_CURRENT_VERSION: {
                    Trigger_V10     *aTrigger;

                    // start-of-section marker
                    result = stg_read_record(stg, NULL, 0);

                    if (result == stgBeginOfSection) {
                        in_section = true;

                        while (in_section) {
                            aTrigger = mowgli_alloc(sizeof(Trigger_V10));
                            if (is64Bit)
                                result = stg_read_record(stg, (unsigned char *)aTrigger, sizeof(Trigger_V10));
                            else {
                                Trigger32 tr;
                                result = stg_read_record(stg, (unsigned char *)&tr, sizeof(Trigger32));
                                aTrigger->value = tr.value;
                                aTrigger->cidr = tr.cidr;
                                aTrigger->flags = tr.flags;
                                aTrigger->lastUsed = tr.lastUsed;
                                aTrigger->username = (char *)(uintptr_t)tr.username;
                                aTrigger->host = (char *)(uintptr_t)tr.host;
                                aTrigger->info.creator.name = (char *)(uintptr_t)tr.info.creator.name;
                                aTrigger->info.creator.time = tr.info.creator.time;
                                aTrigger->info.reason = (char *)(uintptr_t)tr.info.reason;
                                aTrigger->pad = tr.pad;
                            }

                            switch (result) {
                                case stgEndOfSection: // end-of-section
                                    in_section = false;
                                    mowgli_free(aTrigger);
                                    break;

                                case stgSuccess: // a valid record
                                    read_done = true;

                                    if (aTrigger->username != NULL)
                                        read_done &= (result = stg_read_string(stg, &(aTrigger->username), NULL)) == stgSuccess;

                                    if (read_done && aTrigger->host != NULL)
                                        read_done &= (result = stg_read_string(stg, &(aTrigger->host), NULL)) == stgSuccess;

                                    if (read_done && aTrigger->info.creator.name != NULL)
                                        read_done &= (result = stg_read_string(stg, &(aTrigger->info.creator.name), NULL)) == stgSuccess;

                                    if (read_done && aTrigger->info.reason != NULL)
                                        read_done &= (result = stg_read_string(stg, &(aTrigger->info.reason), NULL)) == stgSuccess;

                                    if (!read_done)
                                        mowgli_log_fatal("Read error on %s (2) - %s", TRIGGER_DB, stg_result_to_string(result));

                                    mowgli_node_add(aTrigger, mowgli_node_create(), trigger_list);
                                    break;

                                default: // some error
                                    mowgli_log_fatal("Read error on %s - %s", TRIGGER_DB, stg_result_to_string(result));
                            }
                        }
                    }
                    else
                        mowgli_log_fatal("Read error on %s : invalid format", TRIGGER_DB);

                    stg_close(stg, TRIGGER_DB);
                    return true;
                }

                default:
                    mowgli_log_fatal("Unsupported version number (%d) on %s", version, TRIGGER_DB);
            }
        }

        case stgNotFound: // no data to load
            return true;

        default: // error!
            stg_close(stg, TRIGGER_DB);
            mowgli_log_fatal("Error opening %s - %s", TRIGGER_DB, stg_result_to_string(result));
            return false;
    }
}

static void access_destroy(Access *anAccess) {
        if (anAccess->nick)
            mowgli_free(anAccess->nick);
        if (anAccess->user)
            mowgli_free(anAccess->user);
        if (anAccess->user2)
            mowgli_free(anAccess->user2);
        if (anAccess->user3)
            mowgli_free(anAccess->user3);
        if (anAccess->host)
            mowgli_free(anAccess->host);
        if (anAccess->host2)
            mowgli_free(anAccess->host2);
        if (anAccess->host3)
            mowgli_free(anAccess->host3);
        if (anAccess->server)
            mowgli_free(anAccess->server);
        if (anAccess->server2)
            mowgli_free(anAccess->server2);
        if (anAccess->server3)
            mowgli_free(anAccess->server3);

        str_creator_free(&(anAccess->creator));

        mowgli_free(anAccess);
}

static void str_creator_init(Creator *creator) {
    if (creator != NULL) {
        creator->name = NULL;
        creator->time = 0;
    }
}

static bool str_creator_set(Creator *creator, const char *name, time_t time_set) {
    if (creator != NULL) {

        if (name != NULL) {
            if (creator->name != NULL)
                mowgli_free(creator->name);

            creator->name = mowgli_strdup(name);
        }

        creator->time = time_set != 0 ? time_set : NOW;
        return true;

    } else
        return false;
}

static inline void str_creator_free(Creator *creator) {
    if (creator != NULL)
        mowgli_free(creator->name);
}

void str_creationinfo_init(CreationInfo *info) {
    if (info != NULL) {
        info->reason = NULL;
        str_creator_init(&(info->creator));
    }
}

static bool str_creationinfo_set(CreationInfo *info, const char *creator, const char *reason, time_t time_set) {
    if (info == NULL || creator == NULL || reason == NULL)
        return false;

    str_creator_set(&(info->creator), creator, time_set);

    if (info->reason != NULL)
        mowgli_free(info->reason);

    info->reason = mowgli_strdup(reason);

    return true;
}

static inline void str_creationinfo_free(CreationInfo *info) {
    if (info != NULL) {
        str_creator_free(&(info->creator));
        mowgli_free(info->reason);
    }
}

/*********************************************************/

static bool str_settingsinfo_add(SettingsInfo **infoList, unsigned long int type, const char *creator, const char *reason) {
    SettingsInfo *info;

    info = *infoList;

    while (info != NULL) {
        if (info->type == type)
            return false;

        info = info->next;
    }

    info = mowgli_alloc(sizeof(SettingsInfo));

    info->type = type;

    str_creationinfo_init(&(info->creation));
    str_creationinfo_set(&(info->creation), creator, reason, NOW);

    info->next = *infoList;
    *infoList = info;

    return true;
}

/*********************************************************/

static bool str_settingsinfo_remove(SettingsInfo **infoList, unsigned long int type) {
    SettingsInfo *info, *prevInfo = NULL;

    info = *infoList;

    while (info != NULL) {
        if (info->type == type) {

            if (prevInfo->next != NULL)
                prevInfo->next = info->next;
            else
                *infoList = info->next;

            str_creationinfo_free(&(info->creation));
            mowgli_free(info);
            return true;
        }

        prevInfo = info;
        info = info->next;
    }

    return false;
}
