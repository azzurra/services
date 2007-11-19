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

#include "../inc/common.h"
#include "../inc/strings.h"
#include "../inc/messages.h"
#include "../inc/logging.h"
#include "../inc/signals.h"
#include "../inc/memory.h"




/*********************************************************
 * Memory allocation functions                           *
 *                                                       *
 * Versions of the memory allocation functions which     *
 * will cause the program to terminate with an "Out of   *
 * memory" error if the memory cannot be allocated.      *
 * The return value from these functions is never NULL.  *
 *********************************************************/

void *mem_malloc(size_t size) {

	void	*buffer;

	if (size == 0) {

		log_error(FACILITY_MEMORY, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_RESUMED,
			"mem_malloc(): Illegal attempt to allocate 0 bytes (%s)", log_get_trace_string(trace_main_facility, trace_main_line, trace_current_facility, trace_current_line));

		size = 1;
	}

	buffer = malloc(size);

	if (IS_NULL(buffer)) {

		log_error(FACILITY_MEMORY, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_QUIT,
			"mem_malloc(): Out of memory on a %d byte request.", size);

		raise(SIG_OUT_OF_MEMORY);
	}

	return buffer;
}

void *mem_calloc(size_t count, size_t size) {

	void	*buffer;

	if ((size == 0) || (count == 0)) {

		log_error(FACILITY_MEMORY, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_RESUMED,
			"mem_calloc(): Illegal attempt to allocate 0 bytes");

		if (size == 0)
			size = 1;

		if (count == 0)
			count = 1;
	}

	buffer = calloc(count, size);

	if (IS_NULL(buffer)) {

		log_error(FACILITY_MEMORY, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_QUIT,
			"mem_calloc(): Out of memory on a %d byte request.", size * count);

		raise(SIG_OUT_OF_MEMORY);
	}

	return buffer;
}

void *mem_realloc(void *ptr, size_t size) {

	void	*buffer;

	if (size == 0)
		log_error(FACILITY_MEMORY, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_WARNING,
			"mem_realloc(): 0 bytes reallocation request -> freeing memory");

	buffer = realloc(ptr, size);

	if (IS_NULL(buffer) && (size != 0)) {

		log_error(FACILITY_MEMORY, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_QUIT,
			"mem_realloc(): Out of memory on a %d byte request.", size);

		raise(SIG_OUT_OF_MEMORY);
	}

	return buffer;
}


/*********************************************************
 * Memory pools                                          *
 *********************************************************/


struct _mem_block {

	void			*buffer_start;
	void			*buffer_end;
	unsigned long	*allocation_map;
	int				free_items;
	MemoryBlock		*next_block;
};


#define MP_MAP_REGION_SIZE    (sizeof(long) * 8)


static void _mempool_allocate_block(MemoryPool *mp) {

	MemoryBlock        *new_block;


	new_block = mem_malloc(sizeof(MemoryBlock));

	new_block->free_items = mp->items_per_block;
	new_block->next_block = mp->blocks;

	new_block->allocation_map = (unsigned long*) mem_calloc(sizeof(unsigned long), mp->map_item_count + 1);
	new_block->buffer_start = mem_calloc(mp->item_size, mp->items_per_block + 1);

	new_block->buffer_end = (void*)((unsigned long)new_block->buffer_start + (unsigned long)((mp->items_per_block - 1) * mp->item_size));

	++mp->block_count;
	mp->free_items += mp->items_per_block;
	mp->blocks = new_block;
}


MemoryPool *mempool_create(unsigned int id, size_t item_size, int items_per_block_count, int initial_blocks_count) {

	MemoryPool	*mp;
	int			i;


    if (items_per_block_count <= 0)
        items_per_block_count = 1;

	mp = mem_malloc(sizeof(MemoryPool));

	mp->id = id;
    mp->item_size = item_size + (item_size & (sizeof(void*) - 1));
    mp->items_per_block = items_per_block_count;
    mp->block_count = mp->free_items = 0;
    mp->blocks = NULL;

    mp->map_item_count = (items_per_block_count / MP_MAP_REGION_SIZE) + 1;
    if ((items_per_block_count % MP_MAP_REGION_SIZE) == 0)
        --mp->map_item_count;

    for (i = 0; i < initial_blocks_count; ++i)
        _mempool_allocate_block(mp);

	return mp;
}

void mempool_destroy(MemoryPool *mp) {

	if (mp) {

		MemoryBlock		*ptr, *next;

		for (ptr = mp->blocks; IS_NOT_NULL(ptr); ptr = next) {

			next = ptr->next_block;

			mem_free(ptr->allocation_map);
			mem_free(ptr->buffer_start);
			mem_free(ptr);
		}
	}
}

void *_mempool_alloc(MemoryPool *mp, BOOL wipe) {

    MemoryBlock		*ptr;
    void			*mem;
    int				map_region_index;
    unsigned long	map_region_offset;
    unsigned long	map_region_mask;


	if (!mp)
		return NULL;
	
	if (mp->free_items == 0) {

        _mempool_allocate_block(mp);

		ptr = mp->blocks;

        ptr->allocation_map[0] = 0x01L;
        --ptr->free_items;
        --mp->free_items;
        /*
        if (IS_NULL(mp->blocks->buffer_start)) // FIX : inutile ?
            return NULL;
        */

        mem = mp->blocks->buffer_start;
        if (wipe)
            memset(mem, 0, mp->item_size);

		return mem;
    }

    for (ptr = mp->blocks; IS_NOT_NULL(ptr); ptr = ptr->next_block) {

        if (ptr->free_items > 0) {

            map_region_mask = 0x01L;
            map_region_offset = map_region_index = 0;

            while (map_region_index < mp->map_item_count) {

                if ((map_region_mask == (unsigned long)0x01L) && (ptr->allocation_map[map_region_index] == (unsigned long)(~0))) {

                    // la regione corrente della mappa e' completamente utilizzata. Passare alla prossima
                    ++map_region_index;
                    map_region_offset = 0;
                    continue;
                }

                // Controllare l'elemento correte, se e' libero allocarlo
                if (!(map_region_mask & ptr->allocation_map[map_region_index])) {

                    ptr->allocation_map[map_region_index] |= map_region_mask; // marcato come "in uso"
                    --ptr->free_items;
                    --mp->free_items;

                    mem = (void*) ( (unsigned long)ptr->buffer_start + ((map_region_index * MP_MAP_REGION_SIZE + map_region_offset) * (unsigned long)mp->item_size));
                    if (wipe)
                       memset(mem, 0, mp->item_size);

					return mem;
                }

                // Passare al prossimo elemento della regione corrente
                ++map_region_offset;
                map_region_mask <<= 1;

                if (!map_region_mask) {

                    // Passare alla prossima regione della mappa
                    map_region_mask = 0x01L;
                    ++map_region_index;
                    map_region_offset = 0;
                }
            }
        }
    }

    return NULL;
}


void *_mempool_alloc2(MemoryPool *mp, BOOL wipe, MEMORYBLOCK_ID *mblock_id) {

    MemoryBlock		*ptr;
    void			*mem;
    int				map_region_index;
    unsigned long	map_region_offset;
    unsigned long	map_region_mask;


	if (!mp)
		return NULL;
	
	if (mp->free_items == 0) {

        _mempool_allocate_block(mp);

		ptr = mp->blocks;

        ptr->allocation_map[0] = 0x01L;
        --ptr->free_items;
        --mp->free_items;
        /*
        if (IS_NULL(mp->blocks->buffer_start)) // FIX : inutile ?
            return NULL;
        */

        mem = mp->blocks->buffer_start;
        if (wipe)
            memset(mem, 0, mp->item_size);

		if (IS_NOT_NULL(mblock_id))
			*mblock_id = (unsigned long) mp->blocks;

		return mem;
    }

    for (ptr = mp->blocks; IS_NOT_NULL(ptr); ptr = ptr->next_block) {

        if (ptr->free_items > 0) {

            map_region_mask = 0x01L;
            map_region_offset = map_region_index = 0;

            while (map_region_index < mp->map_item_count) {

                if ((map_region_mask == (unsigned long)0x01L) && (ptr->allocation_map[map_region_index] == (unsigned long)(~0))) {

                    // la regione corrente della mappa e' completamente utilizzata. Passare alla prossima
                    ++map_region_index;
                    map_region_offset = 0;
                    continue;
                }

                // Controllare l'elemento correte, se e' libero allocarlo
                if (!(map_region_mask & ptr->allocation_map[map_region_index])) {

                    ptr->allocation_map[map_region_index] |= map_region_mask; // marcato come "in uso"
                    --ptr->free_items;
                    --mp->free_items;

                    mem = (void*) ( (unsigned long)ptr->buffer_start + ((map_region_index * MP_MAP_REGION_SIZE + map_region_offset) * (unsigned long)mp->item_size));
                    if (wipe)
                       memset(mem, 0, mp->item_size);

					if (IS_NOT_NULL(mblock_id))
						*mblock_id = (unsigned long) ptr;

					return mem;
                }

                // Passare al prossimo elemento della regione corrente
                ++map_region_offset;
                map_region_mask <<= 1;

                if (!map_region_mask) {

                    // Passare alla prossima regione della mappa
                    map_region_mask = 0x01L;
                    ++map_region_index;
                    map_region_offset = 0;
                }
            }
        }
    }

    return NULL;
}


void mempool_free(MemoryPool *mp, void *mem) {

    MemoryBlock		*ptr;
    unsigned long	map_region_offset;
    unsigned long	map_region_mask;


	if (mp)
		for (ptr = mp->blocks; IS_NOT_NULL(ptr); ptr = ptr->next_block) {

			if ((mem >= ptr->buffer_start) && (mem <= ptr->buffer_end)) {

				map_region_offset = ((unsigned long)mem - (unsigned long)(ptr->buffer_start)) / (unsigned long)mp->item_size;
				map_region_mask = 0x01L << (map_region_offset % MP_MAP_REGION_SIZE);
				map_region_offset = map_region_offset / MP_MAP_REGION_SIZE;

				if ((ptr->allocation_map[map_region_offset] & map_region_mask) == 0) {
					log_error(FACILITY_MEMORY, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_WARNING, "mempool_free(): block already free! [PoolID: %d | ptr: 0x%X]", mp->id, mem);

				} else {

					ptr->allocation_map[map_region_offset] &= ~map_region_mask;
					++ptr->free_items;
					++mp->free_items;
				}

				break;
			}
		}
}


void mempool_free2(MemoryPool *mp, void *mem, MEMORYBLOCK_ID mblock_id) {

    MemoryBlock		*ptr;
    unsigned long	map_region_offset;
    unsigned long	map_region_mask;


	if (mp && (mblock_id != 0)) {
		
		ptr = (MemoryBlock*) mblock_id;

		/*for (ptr = mp->blocks; IS_NOT_NULL(ptr); ptr = ptr->next_block)*/ {

			if ((mem >= ptr->buffer_start) && (mem <= ptr->buffer_end)) {
				/**/
				map_region_offset = ((unsigned long)mem - (unsigned long)(ptr->buffer_start)) / (unsigned long)mp->item_size;
				map_region_mask = 0x01L << (map_region_offset % MP_MAP_REGION_SIZE);
				map_region_offset = map_region_offset / MP_MAP_REGION_SIZE;

				/*
				if (bd->mask != map_region_mask)
					LOG_DEBUG_SNOOP("mempool_free2() - given mask != computed mask : 0x%08X / 0x%08X", bd->mask, map_region_mask);
				else
					LOG_DEBUG_SNOOP("mask ok");
				if (bd->offset != map_region_offset)
					LOG_DEBUG_SNOOP("mempool_free2() - given offset != computed offset : 0x%08X / 0x%08X", bd->offset, map_region_offset);
				else
					LOG_DEBUG_SNOOP("offset ok");
				*/
/*
				map_region_mask = bd->mask;
				map_region_offset = bd->offset;
*/
				if ((ptr->allocation_map[map_region_offset] & map_region_mask) == 0) {
					log_error(FACILITY_MEMORY, __LINE__, LOG_TYPE_ERROR_SANITY, LOG_SEVERITY_ERROR_WARNING, "mempool_free(): block already free! [PoolID: %d | ptr: 0x%X]", mp->id, mem);

				} else {

					ptr->allocation_map[map_region_offset] &= ~map_region_mask;
					++ptr->free_items;
					++mp->free_items;
				}

				/*break*/;
			}
		}
	}
}

unsigned int mempool_garbage_collect(MemoryPool *mp) {

    MemoryBlock    *ptr, *last_block;
    int            map_region_index, count = 0;


    if (mp->free_items < mp->items_per_block)
        return 0; // Non e' possibile che esista almeno un blocco completamente libero

    ptr = last_block = mp->blocks;
    while (ptr) {

        for (map_region_index = 0; map_region_index < mp->map_item_count; ++map_region_index)
            if (ptr->allocation_map[map_region_index])
                break;

        if (map_region_index == mp->map_item_count) {

            // Il blocco e' completamente libero. Deallocarlo.

			mem_free(ptr->allocation_map);
			mem_free(ptr->buffer_start);

            if (last_block) {

                last_block->next_block = ptr->next_block;
				mem_free(ptr);
				ptr = last_block->next_block;

            } else {

                mp->blocks = ptr->next_block;
				mem_free(ptr);
				ptr = mp->blocks;
            }

            --mp->block_count;
            mp->free_items -= mp->items_per_block;

			++count;

        } else {

            // Il blocco non e' libero. Passare al prossimo.
            last_block = ptr;
            ptr = ptr->next_block;
        }
    }

	return count;
}

void mempool_stats(MemoryPool *mp, MemoryPoolStats *pstats) {

	if (mp && pstats) {

		pstats->id = mp->id;
        pstats->items_allocated = mp->items_per_block * mp->block_count;
        pstats->items_free = mp->free_items;
		pstats->items_per_block = mp->items_per_block;

        pstats->memory_allocated = mp->item_size * pstats->items_allocated;
        pstats->memory_free = mp->item_size * mp->free_items;
		pstats->block_count = mp->block_count;

        pstats->block_avg_usage = mp->block_count > 0 ? (pstats->items_allocated - pstats->items_free) / mp->block_count : 0.0f;
    }
}
