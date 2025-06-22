
#include "timer.h"
#include <rte_timer.h>

/*
 * config file
 */
#define TIMER_SCHED_INTERVAL_DEF    10
#define TIMER_SCHED_INTERVAL_MIN    1
#define TIMER_SCHED_INTERVAL_MAX    10000000

static rte_atomic32_t g_sched_interval;

int dpvs_timer_sched_interval_get(void)
{
    return rte_atomic32_read(&g_sched_interval);
}