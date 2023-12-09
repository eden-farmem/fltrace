/*
 * map.h - simple <int,int> hash map with quadratic probing
 * (https://en.wikipedia.org/wiki/Quadratic_probing)
 * 
 * Properties:
 * - Keys and values are unsigned long ints
 * - Uses quadratic probing 
 * - Automatically resizes when reaches 2/3 capacity
 * - No remove operation
 */

#include <stdlib.h>
#include "base/map.h"

/**
 * Initializes a map
 */
void map_init(struct hashmap *m, unsigned long capacity)
{
	m->capacity = capacity;
	m->size = 0;
	m->buckets = calloc(m->capacity, sizeof(struct hashbucket));
}

/**
 * Destroys a map
 */
void map_destroy(struct hashmap *m)
{
	if (m->buckets != NULL) {
		free(m->buckets);
		m->buckets = NULL;
	}
}

/**
 * Adds or updates a key value pair into a map.
 */
void map_put(struct hashmap *m, unsigned long key, unsigned long value)
{
	if (m->size > m->capacity * 2 / 3) {
		map_grow(m);
	}

	const unsigned long n = m->capacity;

	for (unsigned long i = 0; i < n; i++) {
		const unsigned long index = (key + i * i) % n;
		struct hashbucket *bucket = &m->buckets[index];
		if (!bucket->used || bucket->key == key) {
			bucket->key = key;
			bucket->value = value;
			bucket->used = true;
			m->size++;
			return;
		}
	}
}

/**
 * Grows the map capacity
 */
void map_grow(struct hashmap *m)
{
	struct hashbucket *old_buckets = m->buckets;
	unsigned long old_capacity = m->capacity;

	m->capacity = m->capacity * 2;
	m->buckets = calloc(m->capacity, sizeof(struct hashbucket));

	for (unsigned long i = 0; i < old_capacity; i++) {
		if (old_buckets[i].used) {
			map_put(m, old_buckets[i].key, old_buckets[i].value);
		}
	}

	free(old_buckets);
}

/**
 * Returns the value associated with the specified key.
 *
 * Returns -1 if the key is not found.
 */
long int map_get(struct hashmap *m, unsigned long key)
{
	const unsigned long n = m->capacity;

	for (unsigned long i = 0; i < n; i++) {
		const unsigned long index = (key + i * i) % n;
		const struct hashbucket *bucket = &m->buckets[index];
		if (bucket->used && bucket->key == key) {
			return bucket->value;
		}
	}

	return -1;
}