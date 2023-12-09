/*
 * qestimator.h - fast moving quantile estimator
 * From https://aakinshin.net/posts/mp2-quantile-estimator/
 */

#pragma once

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"

/**
 * P2 quantile estimator for a series of values.
 */
struct p2estimator
{
    double p;
    int n[5];
    double ns[5];
    double dns[5];
    double q[5];
    int count;
};

/* compare fn for sort */
static inline int p2estimator_sort_cmpfunc (const void * a, const void * b)
{
    if (*(double*)a > *(double*)b) return 1;
    else if (*(double*)a < *(double*)b) return -1;
    else return 0;
}

/**
 * p2estimator_init - initialize a quantile estimator
 */
static inline void p2estimator_init(struct p2estimator *e, double prob)
{
    e->p = prob;
    memset(e->n, 0, sizeof(e->n));
    memset(e->ns, 0, sizeof(e->ns));
    memset(e->dns, 0, sizeof(e->dns));
    memset(e->q, 0, sizeof(e->q));
    e->count = 0;
}

static inline double p2estimator_parabolic(struct p2estimator *e, int i, double d)
{
    return e->q[i] + d / (e->n[i + 1] - e->n[i - 1]) * (
        (e->n[i] - e->n[i - 1] + d) * (e->q[i + 1] - e->q[i]) 
            / (e->n[i + 1] - e->n[i]) +
        (e->n[i + 1] - e->n[i] - d) * (e->q[i] - e->q[i - 1]) 
            / (e->n[i] - e->n[i - 1])
    );
}

static inline double p2estimator_linear(struct p2estimator *e, int i, int d)
{
    return e->q[i] + d * (e->q[i + d] - e->q[i]) / (e->n[i + d] - e->n[i]);
}

/**
 * p2estimator_add - add a value to the estimator
 */
static inline void p2estimator_add(struct p2estimator *e, double value)
{
    int i, k, dint;
    double d, qs;

    if (e->count < 5)
    {
        e->q[e->count++] = value;
        if (e->count == 5)
        {
            qsort(e->q, 5, sizeof(double), p2estimator_sort_cmpfunc);

            for (int i = 0; i < 5; i++)
                e->n[i] = i;

            e->ns[0] = 0;
            e->ns[1] = 2 * e->p;
            e->ns[2] = 4 * e->p;
            e->ns[3] = 2 + 2 * e->p;
            e->ns[4] = 4;

            e->dns[0] = 0;
            e->dns[1] = e->p / 2;
            e->dns[2] = e->p;
            e->dns[3] = (1 + e->p) / 2;
            e->dns[4] = 1;
        }

        return;
    }

    if (value < e->q[0])
    {
        e->q[0] = value;
        k = 0;
    }
    else if (value < e->q[1])
        k = 0;
    else if (value < e->q[2])
        k = 1;
    else if (value < e->q[3])
        k = 2;
    else if (value < e->q[4])
        k = 3;
    else
    {
        e->q[4] = value;
        k = 3;
    }

    for (i = k + 1; i < 5; i++)
        e->n[i]++;
    for (i = 0; i < 5; i++)
        e->ns[i] += e->dns[i];

    for (i = 1; i <= 3; i++)
    {
        d = e->ns[i] - e->n[i];
        if ((d >= 1 && (e->n[i + 1] - e->n[i]) > 1)
            || (d <= -1 && (e->n[i - 1] - e->n[i]) < -1))
        {
            dint = d >= 0 ? 1 : -1;
            qs = p2estimator_parabolic(e, i, dint);
            if (e->q[i - 1] < qs && qs < e->q[i + 1])
                e->q[i] = qs;
            else
                e->q[i] = p2estimator_linear(e, i, dint);
            e->n[i] += dint;
        }
    }

    e->count++;
}

/**
 * p2estimator_get - get the current quantile estimate
 */
static inline double p2estimator_get_quantile(struct p2estimator *e)
{
    int index;

    BUG_ON(e->count == 0);
    if (e->count <= 5)
    {
        qsort(e->q, e->count, sizeof(double), p2estimator_sort_cmpfunc);
        index = (int) round((e->count - 1) * e->p);
        assert(index >= 0 && index < e->count);
        return e->q[index];
    }

    return e->q[2];
}

/**
 * p2estimator_clear - reset the estimator
 */
static inline void p2estimator_clear(struct p2estimator *e)
{
    e->count = 0;
}

/**
 * Moving P2 quantile estimator for a sliding window 
 */
struct mov_p2estimator
{
    struct p2estimator p2;
    int window_size;
    int n;
    double previous_window_estimation;
};

/**
 * mov_p2estimator_init - initialize a moving quantile estimator
 */
static inline void mov_p2estimator_init(struct mov_p2estimator *e,
    double prob, int window_size)
{
    p2estimator_init(&e->p2, prob);
    e->window_size = window_size;
    e->n = 0;
    e->previous_window_estimation = 0;
}

/**
 * mov_p2estimator_add - add a new value to the estimator
 */
static inline void mov_p2estimator_add(struct mov_p2estimator *e, double value)
{
    e->n++;
    if (e->n % e->window_size == 0)
    {
        e->previous_window_estimation = p2estimator_get_quantile(&e->p2);
        p2estimator_clear(&e->p2);
    }
    p2estimator_add(&e->p2, value);
}

/**
 * mov_p2estimator_get_quantile - get the current quantile estimation
 */
static inline double mov_p2estimator_get_quantile(struct mov_p2estimator *e)
{
    double estimation1, estimation2;
    double w1, w2;

    BUG_ON(e->n == 0);

    if (e->n < e->window_size)
        return p2estimator_get_quantile(&e->p2);
    
    estimation1 = e->previous_window_estimation;
    estimation2 = p2estimator_get_quantile(&e->p2);
    w2 = (e->n % e->window_size + 1) * 1.0 / e->window_size;
    w1 = 1.0 - w2;
    return w1 * estimation1 + w2 * estimation2;
}