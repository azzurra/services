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

#include <services/common.h>
#include <services/strings.h>
#include <services/messages.h>
#include <services/logging.h>
#include <services/send.h>
#include <services/memory.h>
#include <services/database.h>
#include <services/main.h>

/* Tree of database row type handlers */
static mowgli_patricia_t *db_types = NULL;

static unsigned int dbv;
static time_t db_time;

static char last_entity_uid[IDLEN + 1];

#ifdef HAVE_FLOCK
static int lockfd;
#endif

static bool db_write_cell(struct database_handle *db, const char *data, bool multiword);
static struct database_handle *db_open_read(const char *filename) AZSVC_FATTR_MALLOC;
static struct database_handle *db_open_write(const char *filename) AZSVC_FATTR_MALLOC;
static void db_write_core_records(struct database_handle *db);

static void db_h_grver(struct database_handle *db, const char *type);
static void db_h_unknown(struct database_handle *db, const char *type) AZSVC_FATTR_NORETURN;
static void db_h_dbv(struct database_handle *db, const char *type);
static void db_h_mdep(struct database_handle *db, const char *type);
static void db_h_luid(struct database_handle *db, const char *type);
static void db_h_ts(struct database_handle *db, const char *type);
static void db_ignore_row(struct database_handle *db, const char *type);

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
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_HALTED, "Out of entity UIDs!");
        send_globops(NULL, "Out of entity UIDs. This is a Bad Thing. You should probably do something about this.");
    }
    else
        last_entity_uid[3]++;

    return last_entity_uid;
}

void db_load(const char *filename) {
    struct database_handle *db;

    db = db_open(filename, DB_READ);
    if (db == NULL)
        return;

    db_time = 0;

    LOG_DEBUG("db_load(): %s open with DB_READ transaction level, parsing will begin shortly", db->file);
    db_parse(db);
    LOG_DEBUG("db_load(): finished parsing %s, check debug and main log for errors.", db->file);

    db_close(db);
}

void db_save(const char *filename) {
    struct database_handle *db;

    db = db_open(filename, DB_WRITE);
    if (!db) {
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_EXCEPTION, LOG_SEVERITY_ERROR_HALTED,
            "db_save(): db_open() failed, aborting save"
        );
        return;
    }

    db_write_core_records(db);
    // TODO: fire db_write event hooks
    db_close(db);
}

struct database_handle *db_open(const char *filename, enum database_transaction txn) {
    if (txn == DB_WRITE)
        return db_open_write(filename);
    return db_open_read(filename);
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
            log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_EXCEPTION, LOG_SEVERITY_ERROR_PROPAGATED,
                "db_save(): cannot rename %s to %s: %s", oldpath, newpath, strerror(errno1)
            );
            send_globops(NULL, "\2DATABASE ERROR\2: db_save(): cannot rename services.db.new to services.db: %s", strerror(errno1));
        }

#ifdef HAVE_FLOCK
        close(lockfd);
#endif
    }

    sfree(db->buf);
    sfree(db->file);
    sfree(db);
}

void db_parse(struct database_handle *db) {
    const char *cmd;
    return_if_fail(db != NULL);

    while (db_read_next_row(db)) {
        cmd = db_read_word(db);
        if (!cmd || !*cmd || strchr("#\n\t \r", *cmd)) continue;
        db_process(db, cmd);
    }
}

bool db_read_next_row(struct database_handle *db) {
    int c = 0;
    unsigned int n = 0;
    return_val_if_fail(db != NULL, false);

    while ((c = getc(db->f)) != EOF && c != '\n') {
        db->buf[n++] = c;
        if (n == db->bufsize) {
            db->bufsize *= 2;
            db->buf = srealloc(db->buf, db->bufsize);
        }
    }
    db->buf[n] = '\0';
    db->rtoken = db->buf;

    if (c == EOF && ferror(db->f)) {
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_QUIT,
            "db_read_next_row(): error at %s line %u: %s", db->file, db->line, strerror(errno)
        );
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_QUIT,
            "db_read_next_row(): shutting down to avoid data loss"
        );
        exit(EXIT_FAILURE);
    }

    if (c == EOF && n == 0)
        return false;

    db->line++;
    db->token = 0;
    return true;
}

const char *db_read_word(struct database_handle *db) {
    char *ptr, *res;
    static char buf[BUFSIZE];

    return_null_if_fail(db != NULL);

    res = db->rtoken;
    if (res == NULL)
        return NULL;

    ptr = strchr(res, ' ');
    if (ptr != NULL) {
        *ptr++ = '\0';
        db->rtoken = ptr;
    } else {
        db->rtoken = NULL;
    }

    db->token++;

    return res;
}

const char *db_read_str(struct database_handle *db) {
    char *res;

    return_null_if_fail(db != NULL);

    res = db->rtoken;

    db->token++;
    return res;
}

bool db_read_int(struct database_handle *db, int *r) {
    const char *s = db_read_word(db);
    char *rp;

    return_val_if_fail(db != NULL, false);

    s = db_read_word(db);
    if (!s)
        return false;

    *r = strtol(s, &rp, 0);
    return *s && !*rp;
}

bool db_read_uint(struct database_handle *db, unsigned int *r)  {
    return_val_if_fail(db != NULL, false);

    const char *s = db_read_word(db);
    char *rp;

    if (!s)
        return false;

    *r = strtoul(s, &rp, 0);
    return *s && !*rp;
}

bool db_read_time(struct database_handle *db, time_t *t)  {
    return_val_if_fail(db != NULL, false);

    const char *s = db_read_word(db);
    char *rp;

    if (!s)
        return false;

    *t = strtol(s, &rp, 0);
    return *s && !*rp;
}

const char *db_sread_word(struct database_handle *db) {
    const char *w = db_read_word(db);

    if (!w) {
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_FATAL, LOG_SEVERITY_ERROR_QUIT,
            "db_sread_word(): needed word at file %s line %u token %u", db->file, db->line, db->token
        );
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_FATAL, LOG_SEVERITY_ERROR_QUIT,
            "db_sread_word(): shutting down to avoid data loss"
        );
        exit(EXIT_FAILURE);
    }

    return w;
}

const char *db_sread_str(struct database_handle *db)  {
    const char *w = db_read_str(db);

    if (!w) {
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_FATAL, LOG_SEVERITY_ERROR_QUIT,
            "db_sread_str(): needed multiword at file %s line %u token %u", db->file, db->line, db->token
        );
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_FATAL, LOG_SEVERITY_ERROR_QUIT,
            "db_sread_str(): shutting down to avoid data loss"
        );
        exit(EXIT_FAILURE);
    }

    return w;
}

int db_sread_int(struct database_handle *db) {
    int r;
    bool ok = db_read_int(db, &r);

    if (!ok) {
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_FATAL, LOG_SEVERITY_ERROR_QUIT,
            "db_sread_int(): needed int at file %s line %u token %u", db->file, db->line, db->token
        );
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_FATAL, LOG_SEVERITY_ERROR_QUIT,
            "db_sread_int(): shutting down to avoid data loss"
        );
        exit(EXIT_FAILURE);
    }

    return r;
}

unsigned int db_sread_uint(struct database_handle *db) {
    unsigned int r;
    bool ok = db_read_uint(db, &r);

    if (!ok) {
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_FATAL, LOG_SEVERITY_ERROR_QUIT,
            "db_sread_uint(): needed int at file %s line %u token %u", db->file, db->line, db->token
        );
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_FATAL, LOG_SEVERITY_ERROR_QUIT,
            "db_sread_uint(): shutting down to avoid data loss"
        );
        exit(EXIT_FAILURE);
    }

    return r;
}

time_t db_sread_time(struct database_handle *db) {
    time_t r;
    bool ok = db_read_time(db, &r);

    if (!ok) {
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_FATAL, LOG_SEVERITY_ERROR_QUIT,
            "db_sread_uint64(): needed int at file %s line %u token %u", db->file, db->line, db->token
        );
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_FATAL, LOG_SEVERITY_ERROR_QUIT,
            "db_sread_uint64(): shutting down to avoid data loss"
        );
        exit(EXIT_FAILURE);
    }

    return r;
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

void db_register_type_handler(const char *type, database_handler_fn fun) {
    return_if_fail(db_types != NULL);
    return_if_fail(type != NULL);
    return_if_fail(fun != NULL);

    mowgli_patricia_add(db_types, type, fun);
}

void db_unregister_type_handler(const char *type) {
    return_if_fail(db_types != NULL);
    return_if_fail(type != NULL);

    mowgli_patricia_delete(db_types, type);
}

void db_process(struct database_handle *db, const char *type) {
    database_handler_fn fun;

    return_if_fail(db_types != NULL);
    return_if_fail(db != NULL);
    return_if_fail(type != NULL);

    fun = mowgli_patricia_retrieve(db_types, type);

    if (!fun)
        fun = mowgli_patricia_retrieve(db_types, "???");

    fun(db, type);
}

void db_init(void) {
    db_types = mowgli_patricia_create(&strcasecanon);

    if (!db_types) {
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_ASSERTION, LOG_SEVERITY_ERROR_QUIT,
            "db_init(): object allocator failure"
        );
        exit(EXIT_FAILURE);
    }

    db_register_type_handler("GRVER", db_h_grver);
    db_register_type_handler("DBV", db_h_dbv);
    db_register_type_handler("MDEP", db_h_mdep);
    db_register_type_handler("LUID", db_h_luid);
    db_register_type_handler("CF", db_ignore_row); // CF is silently ignored
    db_register_type_handler("TS", db_h_ts);

    db_register_type_handler("NAM", db_ignore_row); // NAM is silently ignored
    db_register_type_handler("MDN", db_ignore_row); // ... and so is MDN

    db_register_type_handler("???", db_h_unknown);
}

void db_terminate(void) {
    mowgli_patricia_destroy(db_types, NULL, NULL);
}

static bool db_write_cell(struct database_handle *db, const char *data, bool multiword) {
    char buf[BUFSIZE], *bi;
    const char *i;

    return_val_if_fail(db != NULL, false);

    fprintf(db->f, "%s%s", data != NULL ? data : "*", !multiword ? " " : "");

    return true;
}

static struct database_handle * AZSVC_FATTR_MALLOC
db_open_read(const char *filename) {
    struct database_handle *db;
    FILE *f;
    int errno1;
    char path[BUFSIZE];

    snprintf(path, BUFSIZE, "%s/%s", DATADIR, filename != NULL ? filename : "services.db");
    f = fopen(path, "r");
    if (!f) {
        errno1 = errno;

        if (errno = ENOENT)
            return NULL;

        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_FATAL, LOG_SEVERITY_ERROR_QUIT,
            "db_open_read(): cannot open %s for reading: %s", path, strerror(errno1)
        );
        send_globops(NULL, "db_open_read(): cannot open %s for reading: %s", path, strerror(errno1));
        exit(EXIT_FAILURE);
    }

    db = smalloc(sizeof *db);
    db->grver = 1;
    db->bufsize = 512;
    db->buf = smalloc(db->bufsize);
    db->f = f;
    db->txn = DB_READ;
    db->file = sstrdup(path);

    return db;
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
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_EXCEPTION, LOG_SEVERITY_ERROR_HALTED,
            "db_open_write(): cannot open %s for writing: %s", path, strerror(errno1)
        );
        send_globops(NULL, "\2DATABASE ERROR\2: db_open_write(): cannot open %s for writing: %s", path, strerror(errno1));
#ifdef HAVE_FLOCK
        close(lockfd);
#endif
        return NULL;
    }

    db = smalloc(sizeof *db);
    db->f = f;
    db->grver = 1;
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
    db_write_uint(db, 12);
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
    db_write_time(db, NOW);
    db_commit_row(db);
}

static void db_h_grver(struct database_handle *db, const char *type) {
    db->grver = db_sread_uint(db);

    if (db->grver != 1)
        log_error(FACILITY_DATABASE, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_WARNING,
            "db_h_grver(): grammar version %lu is unsupported, trying to continue anyway...", db->grver
        );
}

static void AZSVC_FATTR_NORETURN db_h_unknown(struct database_handle *db, const char *type) {
    fatal_error(FACILITY_DATABASE, __LINE__,
        "db %s:%u: unknown directive '%s', shutting down to avoid data loss", db->file, db->line, type
    );
}

static void db_h_dbv(struct database_handle *db, const char *type) {
    dbv = db_sread_uint(db);
}

static void db_h_mdep(struct database_handle *db, const char *type) {
    const char *const modname = db_sread_word(db);

    if (!modname || !*modname) {
        // Weird, but acceptable
        return;
    }

    if (strncmp(modname, "azsvc", 5) != 0) {
        // YIKES! services.db comes from Atheme!!!!
        fatal_error(FACILITY_DATABASE, __LINE__,
            "db %s:%u: trying to load unknown module '%s', shutting down to avoid catastrophic errors (are you using an atheme db?)",
            db->file, db->line, modname
        );
    }
}

static void db_h_luid(struct database_handle *db, const char *type) {
    entity_set_last_uid(db_sread_word(db));
}

static void db_h_ts(struct database_handle *db, const char *type) {
    db_time = db_sread_time(db);
}

static void db_ignore_row(struct database_handle *db, const char *type) {
    return;
}
