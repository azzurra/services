/* SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-URL: https://spdx.org/licenses/GPL-2.0-or-later.html
 *
 * Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)
 *
 * Based on Atheme IRC Services
 * Copyright (C) 2005-2015 Atheme Project (http://atheme.org/)
 * Copyright (C) 2015-2019 Atheme Development Group (https://atheme.github.io/)
 *
 * database.h - New database routines for Azzurra IRC Services
 */

#ifndef AZSVC_DATABASE_H
#define AZSVC_DATABASE_H 1

#define IDLEN 9U

/****************************************************
 * Data types                                       *
 ****************************************************/

/* Database transaction type */
enum database_transaction {
    /* Read transaction */
    DB_READ,
    /* Write transaction */
    DB_WRITE
};

/* Database handle */
struct database_handle {
    enum database_transaction   txn;
    char *                      file;
    unsigned int                line;
    unsigned int                token;

    /* Lexer state fields */
    char *          buf;
    unsigned int    bufsize;
    char *          rtoken;
    FILE *          f;

    /* Grammar version */
    unsigned int grver;

    /* Database version identifier */
    unsigned int dbv;

    /* Database time */
    time_t db_time;
};

/****************************************************
 * Constants                                        *
 ****************************************************/
enum database_hook_priority {
    DB_HOOK_PRIO_NS,
    DB_HOOK_PRIO_CS,
    DB_HOOK_PRIO_OTHER,
    DB_HOOK_PRIO_BOTTOM
};

/****************************************************
 * Functions                                        *
 ****************************************************/

extern void init_entities(void);
void entity_set_last_uid(const char *last_uid);
const char *entity_get_last_uid(void);
const char *entity_alloc_uid(void);

extern void db_save(const char *filename);

extern struct database_handle *db_open(const char *filename, enum database_transaction txn);
extern void db_close(struct database_handle *db);

extern bool db_start_row(struct database_handle *db, const char *type);
extern bool db_write_word(struct database_handle *db, const char *word);
extern bool db_write_str(struct database_handle *db, const char *str);
extern bool db_write_int(struct database_handle *db, int num);
extern bool db_write_uint(struct database_handle *db, unsigned int num);
extern bool db_write_time(struct database_handle *db, time_t time);
extern bool db_write_format(struct database_handle *db, const char *str, ...) AZSVC_FATTR_PRINTF(2, 3);
extern bool db_commit_row(struct database_handle *db);

#endif /* AZSVC_DATABASE_H */
