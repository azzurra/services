/* SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-URL: https://spdx.org/licenses/GPL-2.0-or-later.html
 *
 * Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)
 *
 * main.c - dbconv main entry point
 */

#include "dbconv.h"

static void print_help(void) {
    printf("usage: dbconv\n\n");
}

int main(int argc, char *argv[]) {
    int r;
    mowgli_getopt_option_t long_opts[] = {
        { NULL, 0, NULL, 0, 0 }
    };

    mowgli_allocation_policy_t *const policy = mowgli_allocation_policy_create("azsvc", &smalloc, &sfree);

    if (!policy) {
        (void) fprintf(stderr, "Error: mowgli_allocation_policy_create() failed!\n");
        return false;
    }

    (void) mowgli_allocator_set_policy(policy);


    /* Disable mowgli thread support */
    mowgli_thread_set_policy(MOWGLI_THREAD_POLICY_DISABLED);

    /* Parse command line arguments */
    while ((r = mowgli_getopt_long(argc, argv, "h", long_opts, NULL)) != -1) {
        switch(r) {
            case 'h':
                print_help();
                exit(EXIT_SUCCESS);
            default:
                fprintf(stderr, "usage: dbconv\n");
                exit(EXIT_FAILURE);
        }
    }

    if (chdir(DATADIR) < 0) {
        mowgli_log_fatal("Could not change directory to %s: %s", DATADIR, strerror(errno));
    }

    NOW = time(NULL);

    init_entities();
    nickserv_init();
    chanserv_init();
    memoserv_init();
    operdb_init();

    mowgli_log("Loading legacy services databases");
    load_ns_dbase();
    load_cs_dbase();
    load_suspend_db();
    load_ms_dbase();
    operdb_load();
    /* We don't really care about StatServ and SeenServ at the moment... */
    mowgli_log("Database load complete");

    mowgli_log("Creating new services.db");
    db_save("services.db");
    mowgli_log("Done creating new services.db");

    operdb_terminate();
    memoserv_terminate();
    chanserv_terminate();
    nickserv_terminate();

    return EXIT_SUCCESS;
}
