// Convert legacy memory management function calls to their new counterparts
//
// Confidence: High
// Copyright: (C) Matteo Panella, Azzurra IRC Network. GPLv2.
// URL: https://github.com/azzurra/services
// Options: -I include -all_includes --preprocess

@smemzero@
expression E1, E2;
@@

- memset(E1, 0, E2)
+ smemzero(E1, E2)

@smalloc@
expression E;
@@

- mem_malloc(E)
+ smalloc(E)

@calloc1_to_smalloc@
expression E;
@@

- mem_calloc(1, E)
+ smalloc(E)

@scalloc@
expression E1, E2;
@@

- mem_calloc(E1, E2)
+ scalloc(E1, E2)

@srealloc@
expression E1, E2;
@@

- mem_realloc(E1, E2)
+ srealloc(E1, E2)

@sfree@
expression E;
@@

- mem_free(E)
+ sfree(E)
