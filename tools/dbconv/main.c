/* SPDX-License-Identifier: GPL-2.0-or-later
 * SPDX-URL: https://spdx.org/licenses/GPL-2.0-or-later.html
 *
 * Copyright (C) 2026 Azzurra IRC Network (https://www.azzurra.chat/)
 *
 * main.c - dbconv main entry point
 */

#include "dbconv.h"

static void print_help(void) {
    printf("usage: dbconv [-m master]\n\n"
           "-m <master>    Nickname of the static Services Master\n"
    );
}

int main(int argc, char *argv[]) {
    bool have_svc_master;
    char *svc_master = NULL;
    int r;
    mowgli_getopt_option_t long_opts[] = {
        { NULL, 0, NULL, 0, 0 }
    };

    /* Disable mowgli thread support */
    mowgli_thread_set_policy(MOWGLI_THREAD_POLICY_DISABLED);

    /* Parse command line arguments */
    while ((r = mowgli_getopt_long(argc, argv, "m:h", long_opts, NULL)) != -1) {
        switch(r) {
            case 'm':
                svc_master = mowgli_strdup(mowgli_optarg);
                have_svc_master = true;
                break;
            case 'h':
                print_help();
                exit(EXIT_SUCCESS);
            default:
                fprintf(stderr, "usage: dbconv [-m master]\n");
                exit(EXIT_FAILURE);
        }
    }

    if (chdir(DATADIR) < 0) {
        mowgli_log_fatal("Could not change directory to %s: %s", DATADIR, strerror(errno));
    }

    nickserv_init();
    chanserv_init();

    load_ns_dbase();
    load_cs_dbase();
    load_suspend_db();

    chanserv_terminate();
    nickserv_terminate();

    if (svc_master != NULL)
        mowgli_free(svc_master);

    return EXIT_SUCCESS;
}
