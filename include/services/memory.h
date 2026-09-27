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

#include <services/attributes.h>
#include <services/sysconf.h>

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

/*********************************************************
 * Memory pools (DEPRECATED!)                            *
 *********************************************************/

typedef struct _mem_block	MemoryBlock;

typedef struct _mem_pool {

	unsigned int	id;
	size_t			item_size;
	int				items_per_block;
	int				map_item_count;
	int				block_count;
	int				free_items;
	MemoryBlock		*blocks;

} MemoryPool;


typedef unsigned long int	MEMORYBLOCK_ID;



typedef struct _mp_stats {

	unsigned int	id;
    unsigned long	memory_allocated;
    unsigned long	memory_free;
    unsigned long	items_allocated;
    unsigned long	items_free;
	unsigned long	items_per_block;
	unsigned long	block_count;
    float			block_avg_usage;

} MemoryPoolStats;


MemoryPool		*mempool_create(unsigned int id, size_t item_size, int items_per_block_count, int initial_blocks_count);
void			mempool_destroy(MemoryPool *mp);

void			*_mempool_alloc(MemoryPool *mp, BOOL wipe);

void			*_mempool_alloc2(MemoryPool *mp, BOOL wipe, MEMORYBLOCK_ID *mblock_id);

void			mempool_free(MemoryPool *mp, void *mem);
void			mempool_free2(MemoryPool *mp, void *mem, MEMORYBLOCK_ID mblock_id);

unsigned int	mempool_garbage_collect(MemoryPool *mp);
void			mempool_stats(MemoryPool *mp, MemoryPoolStats *pstats);

#define			mempool_alloc(ptrtype, pool, wipe)	(ptrtype)(_mempool_alloc( (pool) , (wipe) ))
#define			mempool_alloc2(ptrtype, pool, wipe, mbd)	(ptrtype)(_mempool_alloc2( (pool) , (wipe) , (mbd) ))



/*********************************************************
 * Memory pools IDs                                      *
 *********************************************************/

#define		MEMPOOL_ID_USER					10

#define		MEMPOOL_ID_CHANS				11
#define		MEMPOOL_ID_CHANS_CHAN_ENTRY		12
#define		MEMPOOL_ID_CHANS_USER_ENTRY		13

#define		MEMPOOL_ID_NICKDB				20

#define		MEMPOOL_ID_CHANDB				30
#define		MEMPOOL_ID_CHANDB_ACCESS		31
#define		MEMPOOL_ID_CHANDB_AKICK			32

#define		MEMPOOL_ID_MEMODB				40

#define		MEMPOOL_ID_STATS_CHANDB			100
#define		MEMPOOL_ID_SEEN_SEENDB			110



/*********************************************************
 * Memory pools startup settings                         *
 *********************************************************/

// - Elementi per blocco allocato

#define MP_IPB_USERS					500
#define MP_IPB_CHANS					250
#define MP_IPB_CHANS_CHAN_ENTRY			(MP_IPB_USERS * 2)
#define MP_IPB_CHANS_USER_ENTRY			(MP_IPB_USERS * 2)
#define MP_IPB_NICKDB					1000
#define MP_IPB_CHANDB					500
#define MP_IPB_CHANDB_ACCESS			(MP_IPB_CHANS * 6)
#define MP_IPB_CHANDB_AKICK				(MP_IPB_CHANS * 2)
#define MP_IPB_MEMODB					0

#define MP_IPB_STATS_CHANDB				0
#define MP_IPB_SEEN_SEENDB				5000


// - Blocchi allocati inizialmente

#define MB_IBC_USERS					4
#define MB_IBC_CHANS					6
#define MB_IBC_CHANS_CHAN_ENTRY			MB_IBC_USERS
#define MB_IBC_CHANS_USER_ENTRY			MB_IBC_USERS
#define MB_IBC_NICKDB					25
#define MB_IBC_CHANDB					18
#define MB_IBC_CHANDB_ACCESS			36
#define MB_IBC_CHANDB_AKICK				18
#define MB_IBC_MEMODB					0

#define MB_IBC_STATS_CHANDB				0
#define MP_IBC_SEEN_SEENDB				39



#endif /* SRV_MEMORY_H */
