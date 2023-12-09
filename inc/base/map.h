/*
 * map.h - a simple <int,int> hash map
 */

#include "base/types.h"

struct hashbucket {
	unsigned long key;
	unsigned long value;
	bool used;
};

struct hashmap {
	unsigned long capacity;
	unsigned long size;
	struct hashbucket* buckets;
};
typedef struct hashmap hashmap_t;

/* API */
void map_init(struct hashmap *m, unsigned long capacity);
void map_destroy(struct hashmap *m);
void map_put(struct hashmap *m, unsigned long key, unsigned long value);
void map_grow(struct hashmap *m);
long int map_get(struct hashmap *m, unsigned long key);