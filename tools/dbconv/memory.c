/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* memory.c - Memory management routines
*
*/


/*********************************************************
 * Headers                                               *
 *********************************************************/

#include "dbconv.h"

#if !defined(HAVE_TIMINGSAFE_BCMP) && !defined(HAVE_TIMINGSAFE_MEMCMP) && !defined(HAVE_CONSTTIME_MEMEQUAL)
#  if defined(HAVE_LIBSODIUM_MEMCMP)
#    include <sodium/utils.h>
#  elif defined(HAVE_LIBCRYPTO_MEMCMP)
#    include <openssl/crypto.h>
#  elif defined(HAVE_LIBNETTLE_MEMEQL)
#    include <nettle/memops.h>
#  endif
#endif /* !HAVE_TIMINGSAFE_BCMP && !HAVE_TIMINGSAFE_MEMCMP && !HAVE_CONSTTIME_MEMEQUAL */

#if !defined(HAVE_MEMSET_S) && !defined(HAVE_EXPLICIT_BZERO) && !defined(HAVE_EXPLICIT_MEMSET)
#  if defined(HAVE_LIBSODIUM_MEMZERO)
#    include <sodium/utils.h>
#  elif defined(HAVE_LIBCRYPTO_CLEANSE)
#    include <openssl/crypto.h>
#  endif
#endif /* !HAVE_MEMSET_S && !HAVE_EXPLICIT_BZERO && !HAVE_EXPLICIT_MEMSET */


/*********************************************************
 * Memory allocation functions                           *
 *                                                       *
 * Versions of the memory allocation functions which     *
 * will cause the program to terminate with an "Out of   *
 * memory" error if the memory cannot be allocated.      *
 * The return value from these functions is never NULL.  *
 *********************************************************/

void sfree(void *const restrict ptr) {
    (void) free(ptr);
}

void smemzerofree(void *const restrict ptr, const size_t len) {
    (void) smemzero(ptr, len);
    (void) sfree(ptr);
}

void * AZSVC_FATTR_ALLOC_SIZE_PRODUCT(1, 2) AZSVC_FATTR_MALLOC AZSVC_FATTR_RETURNS_NONNULL
scalloc(const size_t num, const size_t len) {
    void *const buf = calloc(num, len);

    if (!buf) {
        mowgli_log_fatal("scalloc(): Out of memory on a %zu byte request.", num * len);
    }

    return buf;
}

void * AZSVC_FATTR_ALLOC_SIZE(2) AZSVC_FATTR_WUR
srealloc(void *const restrict ptr, const size_t len) {
    void *const buf = realloc(ptr, len);

    if (len && !buf) {
        mowgli_log_fatal("srealloc(): Out of memory on a %zu byte request.", len);
    }

    return buf;
}

void * AZSVC_FATTR_ALLOC_SIZE(1) AZSVC_FATTR_MALLOC AZSVC_FATTR_RETURNS_NONNULL
smalloc(const size_t len) {
    return scalloc(1, len);
}

void * AZSVC_FATTR_ALLOC_SIZE_PRODUCT(2, 3) AZSVC_FATTR_WUR
sreallocarray(void *const restrict ptr, const size_t num, const size_t len) {
    const size_t product = (num * len);

    // Check for overflow
    if (product < num || product < len || num > (SIZE_MAX / len)) {
        mowgli_log_fatal("sreallocarray(): Overflow on a request of num %zu with len %zu.", num, len);
    }

    return srealloc(ptr, product);
}

int AZSVC_FATTR_WUR
smemcmp(const void *const ptr1, const void *const ptr2, const size_t len) {
#if defined(HAVE_TIMINGSAFE_BCMP)
    return timingsafe_bcmp(ptr1, ptr2, len);
#elif defined(HAVE_TIMINGSAFE_MEMCMP)
    return timingsafe_memcmp(ptr1, ptr2, len);
#elif defined(HAVE_CONSTTIME_MEMEQUAL)
    return !consttime_memequal(ptr1, ptr2, len);
#elif defined(HAVE_LIBSODIUM_MEMCMP)
    return sodium_memcmp(ptr1, ptr2, len);
#elif defined(HAVE_LIBCRYPTO_MEMCMP)
    return CRYPTO_memcmp(ptr1, ptr2, len);
#elif defined(HAVE_LIBNETTLE_MEMEQL)
    return !nettle_memeql_sec(ptr1, ptr2, len);
#else
#warning "No secure library constant-time memory comparison function is available"
    /* WARNING:
     *   This is highly liable to be optimised out with
     *   LTO builds, but it's still better than nothing.
     */
    volatile const unsigned char *val1 = (volatile const unsigned char *) ptr1;
    volatile const unsigned char *val2 = (volatile const unsigned char *) ptr2;
    volatile int result = 0;

    for (size_t i = 0; i < len; i++)
        result |= (int) ((*val1++) ^ (*val2++));

    return result;
#endif
}

void
smemzero(void *const restrict ptr, const size_t len)
{
    if (! (ptr && len))
        return;

#if defined(HAVE_MEMSET_S)
    if (memset_s(ptr, len, 0x00, len) != 0)
        RAISE_EXCEPTION;
#elif defined(HAVE_EXPLICIT_BZERO)
    (void) explicit_bzero(ptr, len);
#elif defined(HAVE_EXPLICIT_MEMSET)
    (void) explicit_memset(ptr, 0x00, len);
#elif defined(HAVE_LIBSODIUM_MEMZERO)
    (void) sodium_memzero(ptr, len);
#elif defined(HAVE_LIBCRYPTO_CLEANSE)
    (void) OPENSSL_cleanse(ptr, len);
#else
#warning "No secure library memory erasing function is available"

    /* Indirect memset(3) through a volatile function pointer should hopefully prevent dead-store elimination
     * removing the call. This may not work if Azzurra IRC Services is built with Link Time Optimisation, because
     * the compiler may be able to prove (for a given definition of proof) that the pointer always points to
     * memset(3); LTO lets the compiler analyse every compilation unit, not just this one. Alas, the C standard
     * only requires the compiler to read the value of the pointer, not make the function call through it; so if
     * it reads it and determines that it still points to memset(3), it can still decide not to call it. To
     * hopefully prevent the compiler making assumptions about what it points to, it is not located in this
     * compilation unit. Still, the C standar does not guarantee that this will work, and a sufficiently clever
     * compiler may still remove the smemzero function calls if Full LTO is used, because nothing in this program
     * or any of its modules sets the function pointer to any other value.
     *
     * Clang <= 7.0 with/without Thin LTO does not remove any calls; other compilers & situations are untested.
     */

    (void) volatile_memset(ptr, 0x00, len);
#endif
}

void * AZSVC_FATTR_MALLOC
smemdup(const void *const restrict ptr, const size_t len)
{
    if (! ptr || ! len)
        return NULL;

    void *const buf = smalloc(len);

    return memcpy(buf, ptr, len);
}

char * AZSVC_FATTR_MALLOC
sstrdup(const char *const restrict ptr)
{
    if (! ptr)
        return NULL;

    const size_t len = strlen(ptr);
    char *const buf = smalloc(len + 1);

    if (len)
        (void) memcpy(buf, ptr, len);

    return buf;
}

char * AZSVC_FATTR_MALLOC
sstrndup(const char *const restrict ptr, const size_t maxlen)
{
    if (! ptr)
        return NULL;

    const size_t len = strnlen(ptr, maxlen);
    char *const buf = smalloc(len + 1);

    if (len)
        (void) memcpy(buf, ptr, len);

    return buf;
}

/*********************************************************
 * Heap management                                       *
 *********************************************************/

static inline size_t heap_prealloc_size(const size_t size) {
    const size_t page_size = sysconf(_SC_PAGESIZE);

#ifdef AZSVC_ENABLE_LARGENET
    const size_t prealloc_size = (page_size / size) * 4U;
#else
    const size_t prealloc_size = (page_size / size);
#endif

    return prealloc_size;
}

static inline size_t heap_normalize_size(const size_t size) {
    const size_t normalized = ((size / sizeof(void *)) + ((size / sizeof(void *)) % 2U)) * sizeof(void *);

    return normalized;
}

mowgli_heap_t *heap_get(const size_t size) {
    const size_t normalized = heap_normalize_size(size);
    mowgli_heap_t *const heap = mowgli_heap_create(normalized, heap_prealloc_size(normalized), BH_NOW);

    if (!heap)
        return NULL;

    return heap;
}

void heap_destroy(mowgli_heap_t *const restrict heap) {
    return_if_fail(heap != NULL);

    (void) mowgli_heap_destroy(heap);
}
