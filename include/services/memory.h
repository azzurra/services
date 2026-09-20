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

void *mem_malloc(size_t size);
void *mem_calloc(size_t count, size_t size);
void *mem_realloc(void *ptr, size_t size);

#define mem_free(ptr)	free((ptr))


/*********************************************************
 * Memory pools                                          *
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
