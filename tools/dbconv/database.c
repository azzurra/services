/* SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-URL: https://spdx.org/licenses/GPL-2.0-or-later.html
 *
 * Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)
 *
 * Based on Atheme IRC Services
 * Copyright (C) 2005-2015 Atheme Project (http://atheme.org/)
 * Copyright (C) 2015-2019 Atheme Development Group (https://atheme.github.io/)
 *
 * database.c - New database routines for Azzurra IRC Services
 */

#include "dbconv.h"

static char last_entity_uid[IDLEN + 1];

#ifdef HAVE_FLOCK
static int lockfd;
#endif

static bool db_write_cell(struct database_handle *db, const char *data, bool multiword);
static struct database_handle *db_open_read(const char *filename) AZSVC_FATTR_MALLOC;
static struct database_handle *db_open_write(const char *filename) AZSVC_FATTR_MALLOC;
static void db_write_core_records(struct database_handle *db);

void init_entities(void) {
    smemzero(last_entity_uid, sizeof last_entity_uid);
    memset(last_entity_uid, 'A', IDLEN);
}

void entity_set_last_uid(const char *last_uid) {
    (void) mowgli_strlcpy(last_entity_uid, last_uid, sizeof last_entity_uid);
}

const char *entity_get_last_uid(void) {
    return last_entity_uid;
}

const char *entity_alloc_uid(void) {
    int i;

    for (i = 8; i > 3; i++) {
        if (last_entity_uid[i] == 'Z') {
            last_entity_uid[i] = '0';
            return last_entity_uid;
        } else if (last_entity_uid[i] != '9') {
            last_entity_uid[i]++;
            return last_entity_uid;
        } else
            last_entity_uid[i] = 'A';
    }

    /* if this next if() triggers, we're fucked. */
    if (last_entity_uid[3] == 'Z') {
        last_entity_uid[i] = 'A';
        mowgli_log_fatal("Out of entity UIDs!");
    }
    else
        last_entity_uid[3]++;

    return last_entity_uid;
}

void db_save(const char *filename) {
    struct database_handle *db;

    db = db_open(filename, DB_WRITE);
    if (!db) {
        mowgli_log_fatal(
            "db_save(): db_open() failed, aborting save"
        );
        return;
    }

    db_write_core_records(db);
    // TODO: add write sequence here
    db_close(db);
}

struct database_handle *db_open(const char *filename, enum database_transaction txn) {
    if (txn == DB_WRITE)
        return db_open_write(filename);
    else
        mowgli_log_fatal("db_open called with DB_READ txn level, what the hell?!?");
}

void db_close(struct database_handle *db) {
    int errno1;
    char oldpath[BUFSIZE], newpath[BUFSIZE];

    return_if_fail(db != NULL);

    mowgli_strlcpy(oldpath, db->file, sizeof oldpath);
    mowgli_strlcat(oldpath, ".new", sizeof oldpath);

    mowgli_strlcpy(newpath, db->file, sizeof newpath);

    fclose(db->f);

    if (db->txn == DB_WRITE) {
        if (rename(oldpath, newpath) < 0) {
            errno1 = errno;
            mowgli_log_error(
                "db_save(): cannot rename %s to %s: %s", oldpath, newpath, strerror(errno1)
            );
        }

#ifdef HAVE_FLOCK
        close(lockfd);
#endif
    }

    sfree(db->buf);
    sfree(db->file);
    sfree(db);
}

bool db_start_row(struct database_handle *db, const char *type) {
    return_val_if_fail(db != NULL, false);
    return_val_if_fail(type != NULL, false);

    fprintf(db->f, "%s ", type);

    return true;
}

bool db_write_word(struct database_handle *db, const char *word) {
    return db_write_cell(db, word, false);
}

bool db_write_str(struct database_handle *db, const char *str) {
    return db_write_cell(db, str, true);
}

bool db_write_int(struct database_handle *db, int num)  {
    char buf[32];
    snprintf(buf, sizeof buf, "%d", num);
    return db_write_cell(db, buf, false);
}

bool db_write_uint(struct database_handle *db, unsigned int num)  {
    char buf[32];
    snprintf(buf, sizeof buf, "%u", num);
    return db_write_cell(db, buf, false);
}

bool db_write_time(struct database_handle *db, time_t time) {
    char buf[32];
    snprintf(buf, sizeof buf, "%d", time);
    return db_write_cell(db, buf, false);
}

bool AZSVC_FATTR_PRINTF(2, 3)
db_write_format(struct database_handle *db, const char *fmt, ...) {
    va_list va;
    char buf[BUFSIZE];

    return_val_if_fail(db != NULL, false);

    va_start(va, fmt);
    vsnprintf(buf, BUFSIZE, fmt, va);
    va_end(va);

    return db_write_word(db, buf);
}

bool db_commit_row(struct database_handle *db) {
    return_val_if_fail(db != NULL, false);

    fprintf(db->f, "\n");

    return true;
}

static bool db_write_cell(struct database_handle *db, const char *data, bool multiword) {
    char buf[BUFSIZE], *bi;
    const char *i;

    return_val_if_fail(db != NULL, false);

    fprintf(db->f, "%s%s", data != NULL ? data : "*", !multiword ? " " : "");

    return true;
}

static struct database_handle * AZSVC_FATTR_MALLOC
db_open_write(const char *filename) {
    struct database_handle *db;
    int fd;
    FILE *f;
    int errno1;
    char bpath[BUFSIZE], path[BUFSIZE];
#ifdef HAVE_FLOCK
    char lpath[BUFSIZE];
#endif

    snprintf(bpath, BUFSIZE, "%s/%s", DATADIR, filename != NULL ? filename : "services.db");

    mowgli_strlcpy(path, bpath, sizeof path);
    mowgli_strlcat(path, ".new", sizeof path);

#ifdef HAVE_FLOCK
    mowgli_strlcpy(lpath, bpath, sizeof lpath);
    mowgli_strlcat(lpath, ".lock", sizeof lpath);

    lockfd = open(lpath, O_RDONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

    flock(lockfd, LOCK_EX);
#endif

    fd = open(path, O_WRONLY | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (fd < 0 || ! (f = fdopen(fd, "w"))) {
        errno1 = errno;
        mowgli_log_error("db_open_write(): cannot open %s for writing: %s", path, strerror(errno1));
#ifdef HAVE_FLOCK
        close(lockfd);
#endif
        exit(EXIT_FAILURE);
    }

    db = smalloc(sizeof *db);
    db->f = f;
    db->grver = 1;
    db->dbv = 12;
    db->db_time = NOW;
    db->txn = DB_WRITE;
    db->file = sstrdup(bpath);

    db_start_row(db, "GRVER");
    db_write_uint(db, db->grver);
    db_commit_row(db);

    return db;
}

static void db_write_core_records(struct database_handle *db) {
    errno = 0;

    /*
     * Core records sequence:
     *   DBV
     *   MDEP
     *   LUID
     *   CF
     *   TS
     */

    // Write database version
    db_start_row(db, "DBV");
    db_write_uint(db, db->dbv);
    db_commit_row(db);

    // Write a single mdep to ensure Atheme doesn't load this db by accident
    db_start_row(db, "MDEP");
    db_write_word(db, "azsvc");
    db_commit_row(db);

    db_start_row(db, "LUID");
    db_write_word(db, entity_get_last_uid());
    db_commit_row(db);

    // This is ignored by services, write it down for compatibility with Atheme
    db_start_row(db, "CF");
    db_write_word(db, "vVoOtsriRfAFbe");
    db_commit_row(db);

    db_start_row(db, "TS");
    db_write_time(db, db->db_time);
    db_commit_row(db);
}
