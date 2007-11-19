/*
*
* Azzurra IRC Services (c) 2001-2005 Azzurra IRC Network
* Original code by Shaka (shaka@azzurra.org) and Gastaman (gastaman@azzurra.org)
*
* This program is free but copyrighted software; see the file COPYING for
* details.
*
* list.h
* 
* Basato su:
*  IRC Services is copyright (c) 1996-2002 Andrew Church.
*      E-mail: <achurch@achurch.org>
*  Parts written by Andrew Kempe and others.
* 
*/


#ifndef SRV_LIST_H
#define SRV_LIST_H


/*********************************************************
 * List handling                                         *
 *********************************************************/


// Add / remove

/*	Insert `node' into the beginning of `list'. `node' and `list' must be simple 
	variables (or indirections or array references).
*/
#undef  LIST_INSERT
#define LIST_INSERT(node, list) \
    do { \
		node->next = list; \
		node->prev = NULL; \
		if (list) \
			(list)->prev = node; \
		list = node; \
    } while (0)


/*	Insert `node' into `list' so that `list' maintains its order as determined by the 
	function `compare_function' called on `compare_field' of each node.
	`node' and `list' must be simple variables; `compare_field' must be a field of `node'; 
	and `compare_function' must be a function that takes two `compare_field's and returns -1, 0, 
	or 1 indicating whether the first argument is ordered before, equal to, or after the second (strcmp, for example).
	If an equal node is found, `node' is inserted after it.
*/
#undef  LIST_INSERT_ORDERED
#define LIST_INSERT_ORDERED(node, list, compare_function, compare_field) \
    do { \
		typeof(node) ptr, prev; \
		for (ptr = list, prev = NULL; ptr; prev = ptr, ptr = ptr->next) { \
			if (compare_function(node->compare_field, ptr->compare_field) < 0) \
				break; \
		} \
		node->next = ptr; \
		node->prev = prev; \
		if (ptr) \
			ptr->prev = node; \
		if (prev) \
			prev->next = node; \
		else \
			list = node; \
	} while (0)

#undef  LIST_INSERT_ORDERED_SCALAR
#define LIST_INSERT_ORDERED_SCALAR(node, list, compare_field) \
    do { \
		typeof(node) ptr, prev; \
		for (ptr = list, prev = NULL; ptr; prev = ptr, ptr = ptr->next) { \
			if (node->compare_field < ptr->compare_field) \
				break; \
		} \
		node->next = ptr; \
		node->prev = prev; \
		if (ptr) \
			ptr->prev = node; \
		if (prev) \
			prev->next = node; \
		else \
			list = node; \
	} while (0)


/*	Remove `node' from `list'.  `node' and `list' must be simple variables. */
#undef  LIST_REMOVE
#define LIST_REMOVE(node, list) \
    do { \
		if (node->next) \
			node->next->prev = node->prev; \
		if (node->prev) \
			node->prev->next = node->next; \
		else \
			list = node->next; \
    } while (0)



// Enumerators

/*	Loop over every element in `list', using `iter' as the iterator.
	The macro has the same properties as a for() loop.  `iter' must be a simple variable.
*/
#undef  LIST_FOREACH
#define LIST_FOREACH(iterator, list) \
	for (iterator = (list); iterator; iterator = iterator->next)

/*	Iterate over `list' using an extra variable (`temp') to hold the next element, 
	ensuring proper operation even when the current element is deleted.
*/
#undef  LIST_FOREACH_SAFE
#define LIST_FOREACH_SAFE(iterator, list, temp) \
    for (iterator = (list); iterator && (temp = iterator->next, 1); iterator = temp)



// Search

/* Search `list' as LIST_SEARCH does, but for a list known to be ordered. */
#undef  LIST_SEARCH_ORDERED
#define LIST_SEARCH_ORDERED(list, field, target, compare_function, result) \
    do { \
		LIST_FOREACH (result, list) { \
			\
			int i = compare_function(result->field, target); \
			\
			if (i > 0) \
				result = NULL; \
			\
			if (i >= 0) \
				break; \
		} \
    } while (0)

#undef  LIST_SEARCH_ORDERED_SCALAR
#define LIST_SEARCH_ORDERED_SCALAR(list, field, target, result) \
    do { \
		LIST_FOREACH (result, list) { \
			\
			if (result->field > target) { \
				result = NULL; \
				break; \
			\
			} else if (result->field == target) \
				break; \
		} \
    } while (0)




/*********************************************************
 * Hash tables                                           *
 *********************************************************/


#ifndef HASH_DATA_MODIFIER
#define HASH_DATA_MODIFIER
#endif

#ifndef HASH_FUNCTIONS_MODIFIER
#define HASH_FUNCTIONS_MODIFIER
#endif


// Hash function

#ifndef LIST_USE_MY_HASH


static const BYTE hash_hashlookup[256] = {

     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
     0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,

     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
    16,17,18,19,20,21,22,23,24,25,26,27,28,29, 0, 0,
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
    16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,30,

    31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,
    31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,
    31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,
    31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,

    31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,
    31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,
    31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,
    31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,31,
};


#ifndef HASH_KEY_OFFSET
#define HASH_KEY_OFFSET		0
#endif


#define HASH_HASHFUNC(key) (hash_hashlookup[(BYTE)(*((key) + HASH_KEY_OFFSET))] << 5 | (*((key) + HASH_KEY_OFFSET) ? hash_hashlookup[(BYTE)((key)[1 + HASH_KEY_OFFSET])] : 0))


//#define HASH_HASHSIZE	1024


#endif /* LIST_USE_MY_HASH */



// Hash table

#undef  CREATE_HASHTABLE
#define CREATE_HASHTABLE(basename, datatype, hashsize) \
	HASH_DATA_MODIFIER datatype *hashtable_##basename[hashsize]; \
	HASH_DATA_MODIFIER datatype *hashtable_##basename##_tails[hashsize];

#undef  CREATE_HASHTABLE_NOTAIL
#define CREATE_HASHTABLE_NOTAIL(basename, datatype, hashsize) \
	HASH_DATA_MODIFIER datatype *hashtable_##basename[hashsize];



// Add / remove


#undef  CREATE_HASH_ADD
#define CREATE_HASH_ADD(basename, datatype, key) \
	HASH_FUNCTIONS_MODIFIER void hash_##basename##_add(datatype *node) { \
		\
		datatype **branch = &hashtable_##basename[HASH_HASHFUNC(node->key)]; \
		LIST_INSERT_ORDERED(node, *branch, str_compare_nocase, key); \
	}

#undef  CREATE_HASH_ADD_SCALAR
#define CREATE_HASH_ADD_SCALAR(basename, datatype, key) \
	HASH_FUNCTIONS_MODIFIER void hash_##basename##_add(datatype *node) { \
		\
		datatype **branch = &hashtable_##basename[HASH_HASHFUNC(node->key)]; \
		LIST_INSERT_ORDERED_SCALAR(node, *branch, key); \
	}



#undef  CREATE_HASH_ADD_TAIL
#define CREATE_HASH_ADD_TAIL(basename, datatype, key) \
	HASH_FUNCTIONS_MODIFIER void hash_##basename##_add_tail(datatype *node) { \
		\
		int			idx = HASH_HASHFUNC(node->key); \
		datatype	*tail; \
		\
		tail = hashtable_##basename##_tails[idx]; \
		if (tail != NULL) { \
			node->next = NULL; \
			node->prev = tail; \
			tail->next = node; \
		} else { \
			node->prev = node->next = NULL; \
			hashtable_##basename[idx] = node; \
		} \
		hashtable_##basename##_tails[idx] = node; \
	}


#undef  CREATE_HASH_REMOVE
#define CREATE_HASH_REMOVE(basename, datatype, key) \
	HASH_FUNCTIONS_MODIFIER void hash_##basename##_remove(datatype *node) { \
		\
		int	idx = HASH_HASHFUNC(node->key); \
		\
		LIST_REMOVE(node, hashtable_##basename[idx]); \
		if (node == hashtable_##basename##_tails[idx]) \
			hashtable_##basename##_tails[idx] = node->prev; \
    }

#undef  CREATE_HASH_REMOVE_NOTAIL
#define CREATE_HASH_REMOVE_NOTAIL(basename, datatype, key) \
	HASH_FUNCTIONS_MODIFIER void hash_##basename##_remove(datatype *node) { \
		\
		int	idx = HASH_HASHFUNC(node->key); \
		\
		LIST_REMOVE(node, hashtable_##basename[idx]); \
    }



// Search

#undef  CREATE_HASH_FIND
#define CREATE_HASH_FIND(basename, datatype, key) \
	HASH_FUNCTIONS_MODIFIER datatype *hash_##basename##_find(const char *value) { \
		\
		datatype	*result; \
		\
		LIST_SEARCH_ORDERED(hashtable_##basename[HASH_HASHFUNC(value)], key, value, str_compare_nocase, result); \
		\
		return result; \
    }

#undef  CREATE_HASH_FIND_SCALAR
#define CREATE_HASH_FIND_SCALAR(basename, datatype, key) \
	HASH_FUNCTIONS_MODIFIER datatype *hash_##basename##_find(unsigned long int value) { \
		\
		datatype	*result; \
		\
		LIST_SEARCH_ORDERED_SCALAR(hashtable_##basename[HASH_HASHFUNC(value)], key, value, result); \
		\
		return result; \
    }



// Enumerators

#undef  HASH_FOREACH_BRANCH
#define HASH_FOREACH_BRANCH(idx, hashsize) \
	for ((idx) = 0; (idx) < (hashsize); ++(idx))


#undef  HASH_FOREACH_BRANCH_ITEM
#define HASH_FOREACH_BRANCH_ITEM(basename, idx, iterator) \
	for (iterator = hashtable_##basename[idx]; iterator; iterator = iterator->next)


#undef  HASH_FOREACH_BRANCH_ITEM_SAFE
#define HASH_FOREACH_BRANCH_ITEM_SAFE(basename, idx, iterator, temp) \
    for (iterator = hashtable_##basename[idx]; iterator && (temp = iterator->next, 1); iterator = temp)


#endif /* SRV_LIST_H */
