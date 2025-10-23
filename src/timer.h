/*
 * NetDefender Timer System Header - Adapted from DPVS
 *
 * Original DPVS Copyright (C) 2021 iQIYI (www.iqiyi.com).
 * Modified for NetDefender project.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 */
#ifndef __NDF_TIMER_H__
#define __NDF_TIMER_H__

#include <stdint.h>
#include <sys/time.h>
#include "list.h"

/*
 * __NOTE__
 * Timer handler should be as quick as possible
 * and must not block.
 */
enum {
    NDTIMER_OK = 0,
    NDTIMER_STOP,
};

typedef int (*ndf_timer_cb_t)(void *arg);

typedef uint32_t ndf_tick_t;

/* Internal struct - user should never modify it directly. */
struct ndf_timer {
    struct list_head    list;

    ndf_timer_cb_t      handler;
    void                *priv;
    bool                is_period;

    /*
     * 'delay' for one-shot timer
     * 'interval' for periodic timer.
     */
    ndf_tick_t          delay;
    ndf_tick_t          left;
};

/* Time conversion utilities */
ndf_tick_t ndf_timeval_to_ticks(const struct timeval *tv);
void ndf_ticks_to_timeval(const ndf_tick_t ticks, struct timeval *tv);

/* Timer lifecycle */
int ndf_timer_init(void);
int ndf_timer_term(void);

/**
 * if @global is 'true' it's system wide timer, or it's per-lcore.
 * for per-lcore module pls set global to 'false'otherwise
 * set @global to 'true'. a timer is global or not must be consistent
 * all the time, DO NOT mix up.
 *
 * the 'nolock' api is used in timer handlers to avoid deadlock.
 *
 * NOTE: any lcore (including master and slaves) can use global timer,
 * but only slaves can use per-lcore timer.
 */

/* Get current timer time */
int ndf_time_now(struct timeval *now, bool global);
int ndf_time_now_nolock(struct timeval *now, bool global);

/* Schedule one-shot timer expire at "time_now" + @delay */
int ndf_timer_sched(struct ndf_timer *timer, struct timeval *delay,
                     ndf_timer_cb_t handler, void *arg, bool global);
int ndf_timer_sched_nolock(struct ndf_timer *timer, struct timeval *delay,
                     ndf_timer_cb_t handler, void *arg, bool global);

/* Schedule one-shot timer expire at @expire (abstract time not delta value) */
int ndf_timer_sched_abs(struct ndf_timer *timer, struct timeval *expire,
                         ndf_timer_cb_t handler, void *arg, bool global);
int ndf_timer_sched_abs_nolock(struct ndf_timer *timer, struct timeval *expire,
                         ndf_timer_cb_t handler, void *arg, bool global);

/* Schedule periodic timer with interval @intv */
int ndf_timer_sched_period(struct ndf_timer *timer, struct timeval *intv,
                            ndf_timer_cb_t handler, void *arg, bool global);
int ndf_timer_sched_period_nolock(struct ndf_timer *timer, struct timeval *intv,
                            ndf_timer_cb_t handler, void *arg, bool global);

/* Timer control operations */
int ndf_timer_cancel(struct ndf_timer *timer, bool global);
int ndf_timer_cancel_nolock(struct ndf_timer *timer, bool global);

/* Restart the timer, for both one-shot and periodic */
int ndf_timer_reset(struct ndf_timer *timer, bool global);
int ndf_timer_reset_nolock(struct ndf_timer *timer, bool global);

/* Set timer with new delay (one-shot) or interval (periodic) */
int ndf_timer_update(struct ndf_timer *timer,
                      struct timeval *delay, bool global);
int ndf_timer_update_nolock(struct ndf_timer *timer,
                      struct timeval *delay, bool global);

/* Add random delay to timeval (for timer jitter) */
void ndf_time_rand_delay(struct timeval *tv, long delay_us);

/* Configuration file support */
int ndf_timer_sched_interval_get(void);
void ndf_timer_keyword_value_init(void);
void ndf_install_timer_keywords(void);

#endif /* __NDF_TIMER_H__ */
