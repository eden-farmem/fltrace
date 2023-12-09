/**
 * rand.h - A fast xorshift pseudo-random generator
 * from https://prng.di.unimi.it/xoshiro256plusplus.c 
 */

#pragma once

#include <stdint.h>

struct rand_state {
    unsigned long s[4];
};

/**
 * Fast Random Number Generator API
 */
int rand_seed(struct rand_state* result, uint64_t seed);

static inline uint64_t __rotl(const uint64_t x, int k) 
{
    return (x << k) | (x >> (64 - k));
}

static inline uint64_t rand_next(struct rand_state* state)
{
    uint64_t* s = state->s;
    const uint64_t result = __rotl(s[0] + s[3], 23) + s[0];
    const uint64_t t = s[1] << 17;

    s[2] ^= s[0];
    s[3] ^= s[1];
    s[1] ^= s[2];
    s[0] ^= s[3];

    s[2] ^= t;

    s[3] = __rotl(s[3], 45);
    return result;
}