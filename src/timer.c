/*
 * NetDefender Timer System - Adapted from DPVS
 *
 * Original DPVS Copyright (C) 2021 iQIYI (www.iqiyi.com).
 * Modified for NetDefender project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */
/*
 * timer.c: High-performance timer system for NetDefender.
 *
 * Features:
 * - Multi-level timing wheel algorithm (O(1) complexity)
 * - Global and per-lcore timer support
 * - One-shot and periodic timers
 * - Lockless per-lcore implementation
 * - Driven by DPDK rte_timer
 */
#include <unistd.h>
#include <sys/time.h>
#include <stdbool.h>
#include <assert.h>
#include "list.h"
#include "common.h"
#include "timer.h"
#include "dpdk.h"
#include "rte_timer.h"
#include "rte_spinlock.h"
#include "parser.h"
#include "global_data.h"

#define NDTIMER
#define RTE_LOGTYPE_NDTIMER      RTE_LOGTYPE_USER1

/*
 * The NetDefender timer is designed for scenarios with huge numbers of
 * connections that have concentrated timeouts (e.g., 120s/60s for flows),
 * while other timeout values are less common.
 *
 * To prevent performance issues from migrating too many timers from higher
 * levels to lower levels, we use a large "first" level wheel (hash) to
 * "cover" most (millions of) connections.
 *
 * We use the same hash size for all levels to simplify implementation,
 * assuming sufficient memory is available.
 */

#define NDF_TIMER_HZ           1000

/*
 * With 1000Hz, if LEVEL_SIZE is 2<<18 (524288) and LEVEL_DEPTH is 2:
 * - First wheel covers: ~524 seconds
 * - All wheels cover: ~8.7 years
 */
/* __NOTE__: Ensure (LEVEL_SIZE ** LEVEL_DEPTH) > TIMER_MAX_TICKS. */
#define LEVEL_SIZE              (2<<18)
#define LEVEL_DEPTH             2

/* About 49 days with 1000Hz, see ndf_tick_t */
#define TIMER_MAX_TICKS         0xffffffff
#define TIMER_MAX_SECS          (TIMER_MAX_TICKS / NDF_TIMER_HZ)

struct timer_scheduler {
    /* Timing wheels and cursors */
    rte_spinlock_t      lock;
    uint32_t            cursors[LEVEL_DEPTH];
    struct list_head    *hashs[LEVEL_DEPTH];

    /* Leverage DPDK rte_timer to drive the scheduler */
    struct rte_timer    rte_tim;
};

/* Per-lcore timer scheduler */
static RTE_DEFINE_PER_LCORE(struct timer_scheduler, timer_sched);
/* Global timer scheduler */
static struct timer_scheduler g_timer_sched;


static inline void timer_sched_lock(struct timer_scheduler *sched)
{
    if (unlikely(sched == &g_timer_sched))
        rte_spinlock_lock(&sched->lock);
    return;
}

static inline void timer_sched_unlock(struct timer_scheduler *sched)
{
    if (unlikely(sched == &g_timer_sched))
        rte_spinlock_unlock(&sched->lock);
    return;
}

ndf_tick_t ndf_timeval_to_ticks(const struct timeval *tv)
{
    uint64_t ticks;

    ticks = tv->tv_sec * NDF_TIMER_HZ + \
            tv->tv_usec * NDF_TIMER_HZ / 1000000;

    if (unlikely(ticks >= TIMER_MAX_TICKS))
        return TIMER_MAX_TICKS;

    return (ndf_tick_t)ticks;
}

void ndf_ticks_to_timeval(const ndf_tick_t ticks, struct timeval *tv)
{
    tv->tv_sec = ticks / NDF_TIMER_HZ;
    tv->tv_usec = ticks % NDF_TIMER_HZ * 1000000 / NDF_TIMER_HZ;
}

/* Ticks for each level's step */
static inline ndf_tick_t get_level_ticks(int level)
{
    ndf_tick_t ticks = 1;
    assert(level >= 0 && level < LEVEL_DEPTH);

    while (--level >= 0)
        ticks *= LEVEL_SIZE;

    return ticks;
}

static inline bool timer_pending(const struct ndf_timer *timer)
{
    return (timer->list.prev != LIST_POISON2
            && timer->list.prev != NULL
            && timer->list.prev != &timer->list);
}

/* Call me with lock held */
static int __ndf_timer_sched(struct timer_scheduler *sched,
                              struct ndf_timer *timer, struct timeval *delay,
                              ndf_timer_cb_t handler, void *arg, bool period)
{
    uint32_t off, hash;
    int level;

    assert(timer);
    assert(delay && handler);

    if (timer_pending(timer))
        RTE_LOG(WARNING, NDTIMER, "schedule a pending timer?\n");

    timer->handler = handler;
    timer->priv = arg;
    timer->is_period = period;
    timer->delay = ndf_timeval_to_ticks(delay);

    if (unlikely(timer->delay >= TIMER_MAX_TICKS)) {
        RTE_LOG(WARNING, NDTIMER, "exceed timer range\n");
        return ENDF_INVAL;
    }

    /*
     * Scheduling a 0 delay timer makes no sense.
     * It will never stop (periodic) or never trigger (one-shot).
     */
    if (unlikely(!timer->delay)) {
        RTE_LOG(INFO, NDTIMER, "trigger 0 delay timer at next tick.\n");
        timer->delay = 1;
    }

    timer->left = timer->delay;
    /* Add to corresponding wheel, from higher level to lower. */
    for (level = LEVEL_DEPTH - 1; level >= 0; level--) {
        off = timer->delay / get_level_ticks(level);
        if (off > 0) {
            hash = (sched->cursors[level] + off) % LEVEL_SIZE;
            list_add_tail(&timer->list, &sched->hashs[level][hash]);
            /* Store the remainder */
            timer->left = timer->left % get_level_ticks(level);
            for (level = level - 1; level >= 0; level--)
                timer->left += sched->cursors[level] * get_level_ticks(level);
            return ENDF_OK;
        }
    }

    /* Not adopted by any wheel (should never happen) */
    RTE_LOG(WARNING, NDTIMER, "unexpected error\n");
    return ENDF_INVAL;
}

/* Call me with lock held */
static void __time_now(struct timer_scheduler *sched, struct timeval *now)
{
    ndf_tick_t ticks = 0;
    int l;

    for (l = LEVEL_DEPTH - 1; l >= 0; l--)
        ticks += sched->cursors[l] * get_level_ticks(l);
    ndf_ticks_to_timeval(ticks, now);
}

static void timer_expire(struct timer_scheduler *sched, struct ndf_timer *timer)
{
    ndf_timer_cb_t handler;
    void *priv;
    int err;
    struct timeval delay;
    assert(timer && timer->handler);

    /* Remove from hash table first, since timer may be
     * rescheduled by handler, so we can't remove it after. */
    handler = timer->handler;
    priv    = timer->priv;
    if (timer_pending(timer))
        list_del(&timer->list);

    err = handler(priv);

    if (err != NDTIMER_OK || !timer->is_period)
        return;

    /* Re-schedule for periodic timer */
    ndf_ticks_to_timeval(timer->delay, &delay);
    err = __ndf_timer_sched(sched, timer, &delay, timer->handler,
                             timer->priv, timer->is_period);
    if (err != ENDF_OK)
        RTE_LOG(ERR, NDTIMER, "%s: fail to re-schedule\n", __func__);
}

/*
 * Takes exactly one tick between invocations,
 * except when the system (including timer handlers) takes more than
 * one tick to call rte_timer_manage().
 * We don't need to calculate ticks elapsed by ourselves.
 */
static void rte_timer_tick_cb(struct rte_timer *tim, void *arg)
{
    struct timer_scheduler *sched = arg;
    struct ndf_timer *timer;
    struct list_head *head;
    uint64_t hash, off;
    int level, lower;
    uint32_t *cursor;
    bool carry;

    assert(tim && sched);

    /* Drive timer to move and handle expired timers. */
    timer_sched_lock(sched);
    for (level = 0; level < LEVEL_DEPTH; level++) {
        cursor = &sched->cursors[level];
        (*cursor)++;

        if (likely(*cursor < LEVEL_SIZE)) {
            carry = false;
        } else {
            /* Reset the cursor and handle next level later. */
            *cursor = 0;
            carry = true;
        }

        head = &sched->hashs[level][*cursor];
        while (!list_empty(head)) {
            timer = list_first_entry(head, struct ndf_timer, list);
            /* Are all lower level ticks empty? */
            if (!timer->left) {
                timer_expire(sched, timer);
            } else {
                /* Drop to lower level wheel, note it may not drop to
                 * the "next" lower level wheel. */
                list_del(&timer->list);

                for (lower = level; lower >= 0; lower--) {
                    off = timer->left / get_level_ticks(lower);
                    if (off > 0) {
                        hash = (sched->cursors[lower] + off) % LEVEL_SIZE;
                        list_add_tail(&timer->list, &sched->hashs[lower][hash]);
                        /*
                         * Store the remainder.
                         * All lower cursors must be 0, so it's not necessary
                         * to calculate the offset. See __ndf_timer_sched for details.
                         */
                        timer->left = timer->left % get_level_ticks(lower);
                        break;
                    }
                }
            }
        }
        if (!carry)
            break;
    }
    timer_sched_unlock(sched);
}

static int timer_init_scheduler(struct timer_scheduler *sched, lcoreid_t cid)
{
    int i, l;

    rte_spinlock_init(&sched->lock);

    timer_sched_lock(sched);
    for (l = 0; l < LEVEL_DEPTH; l++) {
        sched->cursors[l] = 0;

        sched->hashs[l] = rte_malloc(NULL,
                                     sizeof(struct list_head) * LEVEL_SIZE, 0);
        if (!sched->hashs[l]) {
            RTE_LOG(ERR, NDTIMER, "[%02d] no memory.\n", cid);
            timer_sched_unlock(sched);
            return ENDF_NOMEM;
        }

        for (i = 0; i < LEVEL_SIZE; i++)
            INIT_LIST_HEAD(&sched->hashs[l][i]);
    }
    timer_sched_unlock(sched);

    rte_timer_init(&sched->rte_tim);
    /* Ticks should be exactly same as precision */
    if (rte_timer_reset(&sched->rte_tim, g_cycles_per_sec / NDF_TIMER_HZ,
                        PERIODICAL, cid, rte_timer_tick_cb, sched) != 0) {
        RTE_LOG(ERR, NDTIMER, "[%02d] fail to reset rte timer.\n", cid);
        return ENDF_INVAL;
    }

    RTE_LOG(DEBUG, NDTIMER, "[%02d] timer initialized %p.\n", cid, sched);
    return ENDF_OK;
}

static int timer_term_scheduler(struct timer_scheduler *sched)
{
    struct ndf_timer *timer, *next;
    int i, l;

    rte_timer_stop_sync(&sched->rte_tim);

    /* Delete all pending timers */
    timer_sched_lock(sched);

    for (l = 0; l < LEVEL_DEPTH; l++) {
        for (i = 0; i < LEVEL_SIZE; i++) {
            list_for_each_entry_safe(timer, next, &sched->hashs[l][i], list)
                list_del(&timer->list);
        }

        rte_free(sched->hashs[l]);
        sched->cursors[l] = 0;
    }

    timer_sched_unlock(sched);

    return ENDF_OK;
}

static int timer_lcore_init(void *arg)
{
    lcoreid_t cid = rte_lcore_id();

    if (cid >= NDF_MAX_LCORE)
        return ENDF_OK;

    if (!rte_lcore_is_enabled(cid))
        return ENDF_DISABLED;

    return timer_init_scheduler(&RTE_PER_LCORE(timer_sched), rte_lcore_id());
}

static int timer_lcore_term(void *arg)
{
    lcoreid_t cid = rte_lcore_id();

    if (cid >= NDF_MAX_LCORE)
        return ENDF_OK;

    if (!rte_lcore_is_enabled(cid))
        return ENDF_DISABLED;

    return timer_term_scheduler(&RTE_PER_LCORE(timer_sched));
}

int ndf_timer_init(void)
{
    lcoreid_t cid;
    int err;

    /* Per-lcore timer */
    rte_eal_mp_remote_launch(timer_lcore_init, NULL, SKIP_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        err = rte_eal_wait_lcore(cid);
        if (err < 0) {
            RTE_LOG(ERR, NDTIMER, "%s: lcore %d: %s.\n",
                    __func__, cid, ndf_strerror(err));
            return err;
        }
    }

    /* Global timer */
    return timer_init_scheduler(&g_timer_sched, rte_get_main_lcore());
}

int ndf_timer_term(void)
{
    lcoreid_t cid;
    int err;

    /* Per-lcore timer */
    rte_eal_mp_remote_launch(timer_lcore_term, NULL, SKIP_MAIN);
    RTE_LCORE_FOREACH_WORKER(cid) {
        err = rte_eal_wait_lcore(cid);
        if (err < 0) {
            RTE_LOG(WARNING, NDTIMER, "%s: lcore %d: %s.\n",
                    __func__, cid, ndf_strerror(err));
        }
    }

    /* Global timer */
    return timer_term_scheduler(&g_timer_sched);
}

static inline struct timer_scheduler *this_lcore_sched(bool global)
{
    /* Any lcore (including master and slaves) can use global timer,
     * but only slave lcores can use per-lcore timer. */
    if (!global && rte_lcore_id() == rte_get_main_lcore()) {
        RTE_LOG(ERR, NDTIMER, "try get per-lcore timer from master\n");
        return NULL;
    }
    return global ? &g_timer_sched : &RTE_PER_LCORE(timer_sched);
}

int ndf_timer_sched_nolock(struct ndf_timer *timer, struct timeval *delay,
                     ndf_timer_cb_t handler, void *arg, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    int err;

    if (!sched || !timer || !delay || !handler
            || delay->tv_sec >= TIMER_MAX_SECS)
        return ENDF_INVAL;

    err = __ndf_timer_sched(sched, timer, delay, handler, arg, false);

    return err;
}

int ndf_timer_sched(struct ndf_timer *timer, struct timeval *delay,
                     ndf_timer_cb_t handler, void *arg, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    int err;

    if (!sched || !timer || !delay || !handler
            || delay->tv_sec >= TIMER_MAX_SECS)
        return ENDF_INVAL;

    timer_sched_lock(sched);
    err = __ndf_timer_sched(sched, timer, delay, handler, arg, false);
    timer_sched_unlock(sched);

    return err;
}

int ndf_timer_sched_abs_nolock(struct ndf_timer *timer, struct timeval *expire,
                         ndf_timer_cb_t handler, void *arg, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    int err;
    struct timeval now, delta;

    if (!sched || !timer || !expire || !handler)
        return ENDF_INVAL;

    __time_now(sched, &now);
    if (!timercmp(expire, &now, >)) {
        /* Consider the diff between user call ndf_time_now() and NOW,
         * it's possible timer already expired although rarely.
         * To schedule a 1-tick timer? No, let's trigger it now.
         * Note we cannot call timer_expire() directly. */
        handler(arg);
        return ENDF_OK;
    } else {
        timersub(expire, &now, &delta);
        if (delta.tv_sec >= TIMER_MAX_SECS) {
            return ENDF_INVAL;
        }
    }

    err = __ndf_timer_sched(sched, timer, &delta, handler, arg, false);

    return err;
}

int ndf_timer_sched_abs(struct ndf_timer *timer, struct timeval *expire,
                         ndf_timer_cb_t handler, void *arg, bool global)
{
    int err;
    struct timer_scheduler *sched = this_lcore_sched(global);

    timer_sched_lock(sched);
    err = ndf_timer_sched_abs_nolock(timer, expire, handler, arg, global);
    timer_sched_unlock(sched);

    return err;
}

int ndf_timer_sched_period_nolock(struct ndf_timer *timer,
        struct timeval *intv, ndf_timer_cb_t handler, void *arg, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    int err;

    if (!sched || !timer || !intv || !handler || intv->tv_sec >= TIMER_MAX_SECS)
        return ENDF_INVAL;

    err = __ndf_timer_sched(sched, timer, intv, handler, arg, true);

    return err;
}

int ndf_timer_sched_period(struct ndf_timer *timer, struct timeval *intv,
                            ndf_timer_cb_t handler, void *arg, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    int err;

    if (!sched || !timer || !intv || !handler || intv->tv_sec >= TIMER_MAX_SECS)
        return ENDF_INVAL;

    timer_sched_lock(sched);
    err = __ndf_timer_sched(sched, timer, intv, handler, arg, true);
    timer_sched_unlock(sched);

    return err;
}

int ndf_timer_cancel_nolock(struct ndf_timer *timer, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);

    if (!sched || !timer)
        return ENDF_INVAL;

    if (timer_pending(timer))
        list_del(&timer->list);

    return ENDF_OK;
}

int ndf_timer_cancel(struct ndf_timer *timer, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);

    if (!sched || !timer)
        return ENDF_INVAL;

    timer_sched_lock(sched);
    if (timer_pending(timer))
        list_del(&timer->list);
    timer_sched_unlock(sched);

    return ENDF_OK;
}

int ndf_timer_reset_nolock(struct ndf_timer *timer, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    struct timeval delay;
    int err;

    if (!sched || !timer)
        return ENDF_INVAL;

    if (timer_pending(timer))
        list_del(&timer->list);

    ndf_ticks_to_timeval(timer->delay, &delay);
    err = __ndf_timer_sched(sched, timer, &delay, timer->handler,
                             timer->priv, timer->is_period);
    return err;
}

int ndf_timer_reset(struct ndf_timer *timer, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    struct timeval delay;
    int err;

    if (!sched || !timer)
        return ENDF_INVAL;

    timer_sched_lock(sched);
    if (timer_pending(timer))
        list_del(&timer->list);

    ndf_ticks_to_timeval(timer->delay, &delay);
    err = __ndf_timer_sched(sched, timer, &delay, timer->handler,
                             timer->priv, timer->is_period);
    timer_sched_unlock(sched);

    return err;
}

int ndf_timer_update_nolock(struct ndf_timer *timer, struct timeval *delay, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    int err;

    if (!sched || !timer || !delay)
        return ENDF_INVAL;

    if (timer_pending(timer))
        list_del(&timer->list);
    err = __ndf_timer_sched(sched, timer, delay,
            timer->handler, timer->priv, timer->is_period);

    return err;
}

int ndf_timer_update(struct ndf_timer *timer, struct timeval *delay, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    int err;

    if (!sched || !timer || !delay)
        return ENDF_INVAL;

    timer_sched_lock(sched);
    if (timer_pending(timer))
        list_del(&timer->list);
    err = __ndf_timer_sched(sched, timer, delay,
            timer->handler, timer->priv, timer->is_period);
    timer_sched_unlock(sched);

    return err;
}

int ndf_time_now_nolock(struct timeval *now, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    if (!sched || !now)
        return ENDF_INVAL;

    __time_now(sched, now);

    return ENDF_OK;
}

int ndf_time_now(struct timeval *now, bool global)
{
    struct timer_scheduler *sched = this_lcore_sched(global);
    if (!sched || !now)
        return ENDF_INVAL;

    timer_sched_lock(sched);
    __time_now(sched, now);
    timer_sched_unlock(sched);

    return ENDF_OK;
}

void ndf_time_rand_delay(struct timeval *tv, long delay_us)
{
    assert(delay_us > 0);

    long rand;
    uint64_t t_us;

    /* We use lrand48 instead of random for performance consideration.
     * lrand48 is not thread-safe, but it does not matter here. */
    rand = lrand48() % delay_us;
    t_us = tv->tv_sec * 1000000 + tv->tv_usec + rand;

    tv->tv_sec = t_us / 1000000;
    tv->tv_usec = t_us % 1000000;
}

/*
 * Configuration file support
 */
#define TIMER_SCHED_INTERVAL_DEF    10
#define TIMER_SCHED_INTERVAL_MIN    1
#define TIMER_SCHED_INTERVAL_MAX    10000000

static rte_atomic32_t g_sched_interval;

int ndf_timer_sched_interval_get(void)
{
    return rte_atomic32_read(&g_sched_interval);
}

static void timer_sched_interval_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    int sched_interval = 0;

    if (!str)
        return;

    sched_interval = atoi(str);
    FREE_PTR(str);

    if (sched_interval < TIMER_SCHED_INTERVAL_MIN ||
            sched_interval > TIMER_SCHED_INTERVAL_MAX) {
        RTE_LOG(WARNING, NDTIMER, "invalid sched_interval config %d, "
                "using default %d\n", sched_interval,
                TIMER_SCHED_INTERVAL_DEF);
        sched_interval = TIMER_SCHED_INTERVAL_DEF;
    }
    RTE_LOG(INFO, NDTIMER, "sched_interval = %d\n", sched_interval);
    rte_atomic32_set(&g_sched_interval, sched_interval);
}

void ndf_timer_keyword_value_init(void)
{
    rte_atomic32_set(&g_sched_interval, TIMER_SCHED_INTERVAL_DEF);
}

void ndf_install_timer_keywords(void)
{
    install_keyword_root("timer_defs", NULL);
    install_keyword("schedule_interval", timer_sched_interval_handler,
                    KW_TYPE_NORMAL);
}
