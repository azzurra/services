/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* memory.h - Memory management routines
*
*/

#ifndef SRV_MEMORY_H
#define SRV_MEMORY_H

/*********************************************************
 * Memory allocation functions                           *
 *********************************************************/

#if !defined(HAVE_MEMSET_S) && !defined(HAVE_EXPLICIT_BZERO) && !defined(HAVE_LIBSODIUM_MEMZERO)
// This symbol is located in src/main.c
extern void *(* volatile volatile_memset)(void *, int, size_t);
#endif /* !HAVE_MEMSET_S && !HAVE_EXPLICIT_BZERO && !HAVE_LIBSODIUM_MEMZERO */

int smemcmp(const void *ptr1, const void *ptr2, size_t len)
    AZSVC_FATTR_WUR
    AZSVC_FATTR_DIAGNOSE_IF(!ptr1, "calling smemcmp() with !ptr1", "error")
    AZSVC_FATTR_DIAGNOSE_IF(!ptr2, "calling smemcmp() with !ptr2", "error")
    AZSVC_FATTR_DIAGNOSE_IF(!len, "calling smemcmp() with !len", "error");

void smemzerofree(void *ptr, size_t len)
    AZSVC_FATTR_OWNERSHIP_TAKES(malloc, 1)
    AZSVC_FATTR_DIAGNOSE_IF(!ptr, "calling smemzerofree() with !ptr", "warning")
    AZSVC_FATTR_DIAGNOSE_IF(!len, "calling smemzerofree() with !len", "warning");

void smemzero(void *ptr, size_t len)
    AZSVC_FATTR_DIAGNOSE_IF(!ptr, "calling smemzero() with !ptr", "warning")
    AZSVC_FATTR_DIAGNOSE_IF(!len, "calling smemzero() with !len", "error");

void sfree(void *ptr)
    AZSVC_FATTR_OWNERSHIP_TAKES(malloc, 1);

void *scalloc(size_t num, size_t len)
    AZSVC_FATTR_ALLOC_SIZE_PRODUCT(1, 2)
    AZSVC_FATTR_MALLOC
    AZSVC_FATTR_RETURNS_NONNULL
    AZSVC_FATTR_OWNERSHIP_RETURNS(malloc)
    AZSVC_FATTR_DIAGNOSE_IF(!num, "calling scalloc() with !num", "error")
    AZSVC_FATTR_DIAGNOSE_IF(!len, "calling scalloc() with !len", "error");

void *smalloc(size_t len)
    AZSVC_FATTR_ALLOC_SIZE(1)
    AZSVC_FATTR_MALLOC
    AZSVC_FATTR_RETURNS_NONNULL
    AZSVC_FATTR_OWNERSHIP_RETURNS(malloc)
    AZSVC_FATTR_DIAGNOSE_IF(!len, "calling smalloc() with !len", "error");

void *srealloc(void *ptr, size_t len)
    AZSVC_FATTR_ALLOC_SIZE(2)
    AZSVC_FATTR_WUR
    AZSVC_FATTR_OWNERSHIP_TAKES(malloc, 1)
    AZSVC_FATTR_OWNERSHIP_RETURNS(malloc)
    AZSVC_FATTR_DIAGNOSE_IF((!ptr && !len), "calling srealloc() with (!ptr && !len)", "warning");

void *sreallocarray(void *ptr, size_t num, size_t len)
    AZSVC_FATTR_ALLOC_SIZE_PRODUCT(2, 3)
    AZSVC_FATTR_WUR
    AZSVC_FATTR_OWNERSHIP_TAKES(malloc, 1)
    AZSVC_FATTR_OWNERSHIP_RETURNS(malloc)
    AZSVC_FATTR_DIAGNOSE_IF((!ptr && !num), "calling sreallocarray() with (!ptr && !num)", "warning")
    AZSVC_FATTR_DIAGNOSE_IF((!ptr && !len), "calling sreallocarray() with (!ptr && !len)", "warning");

char *sstrdup(const char *ptr)
    AZSVC_FATTR_MALLOC
    AZSVC_FATTR_OWNERSHIP_RETURNS(malloc)
    AZSVC_FATTR_DIAGNOSE_IF(!ptr, "calling sstrdup() with !ptr", "warning");

char *sstrndup(const char *ptr, size_t maxlen)
    AZSVC_FATTR_MALLOC
    AZSVC_FATTR_OWNERSHIP_RETURNS(malloc)
    AZSVC_FATTR_DIAGNOSE_IF(!ptr, "calling sstrndup() with !ptr", "warning")
    AZSVC_FATTR_DIAGNOSE_IF(!maxlen, "calling sstrndup() with !maxlen", "error");

void *smemdup(const void *ptr, size_t len)
    AZSVC_FATTR_MALLOC
    AZSVC_FATTR_OWNERSHIP_RETURNS(malloc)
    AZSVC_FATTR_DIAGNOSE_IF(!ptr, "calling smemdup() with !ptr", "warning")
    AZSVC_FATTR_DIAGNOSE_IF(!len, "calling smemdup() with !len", "error");

/*********************************************************
 * Heap management                                       *
 *********************************************************/

mowgli_heap_t *heap_get(const size_t size);
void heap_destroy(mowgli_heap_t *const restrict heap);

#endif /* SRV_MEMORY_H */
