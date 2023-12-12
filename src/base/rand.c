/**
 * rand.c - A fast xorshift pseudo-random generator
 * from https://prng.di.unimi.it/xoshiro256plusplus.c 
 */

#include "base/log.h"
#include "base/rand.h"

uint64_t __splitmix64(uint64_t* state)
{
    assert(state);
    uint64_t result = ((*state) += 0x9E3779B97f4A7C15);
    result = (result ^ (result >> 30)) * 0xBF58476D1CE4E5B9;
    result = (result ^ (result >> 27)) * 0x94D049BB133111EB;
    return result ^ (result >> 31);
}

/* from wikipedia: https://en.wikipedia.org/wiki/Xorshift */ 
int rand_seed(struct rand_state* result, uint64_t seed)
{
    assert(result);
    uint64_t smx_state = seed;
    uint64_t tmp = __splitmix64(&smx_state);
    result->s[0] = (uint32_t)tmp;
    result->s[1] = (uint32_t)(tmp >> 32);

    tmp = __splitmix64(&smx_state);
    result->s[2] = (uint32_t)tmp;
    result->s[3] = (uint32_t)(tmp >> 32);
    if (result->s[0] == 0 && result->s[1] == 0 && 
        result->s[2] == 0 && result->s[3] == 0)
            return 1;	/*bad seed*/
    return 0;
}