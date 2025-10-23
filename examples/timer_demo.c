/*
 * NetDefender Timer Usage Example
 *
 * This example demonstrates how to use the NetDefender timer system
 * for various scenarios in the NIDS application.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include "dpdk.h"
#include "timer.h"
#include "common.h"

#define RTE_LOGTYPE_TIMER_DEMO RTE_LOGTYPE_USER1

/*
 * Example 1: One-shot timer (e.g., for flow timeout)
 * This simulates a TCP flow that times out after 60 seconds
 */
struct flow_entry {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    struct ndf_timer timeout_timer;
};

static int flow_timeout_handler(void *arg)
{
    struct flow_entry *flow = (struct flow_entry *)arg;

    RTE_LOG(INFO, TIMER_DEMO, "Flow timeout: %u.%u.%u.%u:%u -> %u.%u.%u.%u:%u\n",
            (flow->src_ip >> 24) & 0xFF,
            (flow->src_ip >> 16) & 0xFF,
            (flow->src_ip >> 8) & 0xFF,
            flow->src_ip & 0xFF,
            flow->src_port,
            (flow->dst_ip >> 24) & 0xFF,
            (flow->dst_ip >> 16) & 0xFF,
            (flow->dst_ip >> 8) & 0xFF,
            flow->dst_ip & 0xFF,
            flow->dst_port);

    // Clean up flow entry (in real code, would remove from hash table)
    // free(flow);

    return NDTIMER_STOP; // One-shot timer
}

static void example_flow_timeout(void)
{
    struct flow_entry *flow = calloc(1, sizeof(struct flow_entry));
    struct timeval timeout = {60, 0}; // 60 seconds

    // Simulate a flow entry
    flow->src_ip = 0xC0A80001; // 192.168.0.1
    flow->dst_ip = 0x08080808; // 8.8.8.8
    flow->src_port = 12345;
    flow->dst_port = 80;

    // Schedule timeout timer (per-lcore timer for best performance)
    int ret = ndf_timer_sched(&flow->timeout_timer, &timeout,
                               flow_timeout_handler, flow, false);

    if (ret != ENDF_OK) {
        RTE_LOG(ERR, TIMER_DEMO, "Failed to schedule flow timeout timer\n");
        free(flow);
    } else {
        RTE_LOG(INFO, TIMER_DEMO, "Flow timeout timer scheduled for 60s\n");
    }
}

/*
 * Example 2: Periodic timer (e.g., for statistics reporting)
 * This simulates periodic stats output every 5 seconds
 */
struct stats_context {
    uint64_t packets_processed;
    uint64_t bytes_processed;
    uint64_t alerts_generated;
    struct ndf_timer stats_timer;
};

static int stats_report_handler(void *arg)
{
    struct stats_context *ctx = (struct stats_context *)arg;

    RTE_LOG(INFO, TIMER_DEMO, "=== Statistics Report ===\n");
    RTE_LOG(INFO, TIMER_DEMO, "  Packets: %lu\n", ctx->packets_processed);
    RTE_LOG(INFO, TIMER_DEMO, "  Bytes:   %lu\n", ctx->bytes_processed);
    RTE_LOG(INFO, TIMER_DEMO, "  Alerts:  %lu\n", ctx->alerts_generated);

    // Simulate incrementing stats
    ctx->packets_processed += 1000;
    ctx->bytes_processed += 1500000;
    ctx->alerts_generated += 5;

    return NDTIMER_OK; // Continue periodic timer
}

static void example_periodic_stats(void)
{
    static struct stats_context stats_ctx = {0};
    struct timeval interval = {5, 0}; // 5 seconds

    // Schedule periodic stats timer (global timer so all lcores can see it)
    int ret = ndf_timer_sched_period(&stats_ctx.stats_timer, &interval,
                                      stats_report_handler, &stats_ctx, true);

    if (ret != ENDF_OK) {
        RTE_LOG(ERR, TIMER_DEMO, "Failed to schedule stats timer\n");
    } else {
        RTE_LOG(INFO, TIMER_DEMO, "Periodic stats timer scheduled (every 5s)\n");
    }
}

/*
 * Example 3: Rule reload timer (e.g., for hot reloading detection rules)
 * This simulates periodic rule file checking every 60 seconds
 */
struct rule_reload_context {
    char *rule_file_path;
    time_t last_mtime;
    struct ndf_timer reload_timer;
};

static int rule_reload_handler(void *arg)
{
    struct rule_reload_context *ctx = (struct rule_reload_context *)arg;

    RTE_LOG(INFO, TIMER_DEMO, "Checking rule file: %s\n", ctx->rule_file_path);

    // In real code, would check file mtime and reload if changed
    // For demo, just print a message
    RTE_LOG(INFO, TIMER_DEMO, "Rule file check complete (no changes)\n");

    return NDTIMER_OK; // Continue periodic checking
}

static void example_rule_reload(void)
{
    static struct rule_reload_context reload_ctx = {
        .rule_file_path = "/etc/netdefender/rules/custom.rules",
        .last_mtime = 0,
    };
    struct timeval interval = {60, 0}; // 60 seconds

    // Schedule rule reload check timer (global timer)
    int ret = ndf_timer_sched_period(&reload_ctx.reload_timer, &interval,
                                      rule_reload_handler, &reload_ctx, true);

    if (ret != ENDF_OK) {
        RTE_LOG(ERR, TIMER_DEMO, "Failed to schedule rule reload timer\n");
    } else {
        RTE_LOG(INFO, TIMER_DEMO, "Rule reload timer scheduled (every 60s)\n");
    }
}

/*
 * Example 4: Timer cancellation and reset
 */
static struct ndf_timer demo_timer;
static int demo_counter = 0;

static int demo_timer_handler(void *arg)
{
    int *counter = (int *)arg;
    (*counter)++;

    RTE_LOG(INFO, TIMER_DEMO, "Demo timer fired, count = %d\n", *counter);

    if (*counter >= 5) {
        RTE_LOG(INFO, TIMER_DEMO, "Stopping demo timer after 5 triggers\n");
        return NDTIMER_STOP;
    }

    return NDTIMER_OK;
}

static void example_timer_control(void)
{
    struct timeval interval = {2, 0}; // 2 seconds
    int ret;

    // Schedule periodic timer
    ret = ndf_timer_sched_period(&demo_timer, &interval,
                                  demo_timer_handler, &demo_counter, false);

    if (ret != ENDF_OK) {
        RTE_LOG(ERR, TIMER_DEMO, "Failed to schedule demo timer\n");
        return;
    }

    RTE_LOG(INFO, TIMER_DEMO, "Demo timer scheduled (every 2s)\n");

    // Simulate canceling and resetting timer
    sleep(5);

    RTE_LOG(INFO, TIMER_DEMO, "Canceling demo timer...\n");
    ndf_timer_cancel(&demo_timer, false);

    sleep(2);

    RTE_LOG(INFO, TIMER_DEMO, "Resetting demo timer...\n");
    demo_counter = 0;
    ndf_timer_reset(&demo_timer, false);
}

/*
 * Example 5: Getting current timer time
 */
static void example_time_now(void)
{
    struct timeval now;
    int ret;

    // Get global timer time
    ret = ndf_time_now(&now, true);
    if (ret == ENDF_OK) {
        RTE_LOG(INFO, TIMER_DEMO, "Global timer time: %ld.%06ld\n",
                now.tv_sec, now.tv_usec);
    }

    // Get per-lcore timer time
    ret = ndf_time_now(&now, false);
    if (ret == ENDF_OK) {
        RTE_LOG(INFO, TIMER_DEMO, "Per-lcore timer time: %ld.%06ld\n",
                now.tv_sec, now.tv_usec);
    }
}

/*
 * Main demo function (would be called from worker thread)
 */
void timer_demo_main(void)
{
    RTE_LOG(INFO, TIMER_DEMO, "\n========================================\n");
    RTE_LOG(INFO, TIMER_DEMO, "NetDefender Timer System Demo\n");
    RTE_LOG(INFO, TIMER_DEMO, "========================================\n\n");

    // Example 1: Flow timeout timer
    RTE_LOG(INFO, TIMER_DEMO, "Example 1: Flow Timeout Timer\n");
    example_flow_timeout();

    // Example 2: Periodic statistics timer
    RTE_LOG(INFO, TIMER_DEMO, "\nExample 2: Periodic Statistics Timer\n");
    example_periodic_stats();

    // Example 3: Rule reload timer
    RTE_LOG(INFO, TIMER_DEMO, "\nExample 3: Rule Reload Timer\n");
    example_rule_reload();

    // Example 4: Timer control (cancel/reset)
    RTE_LOG(INFO, TIMER_DEMO, "\nExample 4: Timer Control\n");
    example_timer_control();

    // Example 5: Getting current time
    RTE_LOG(INFO, TIMER_DEMO, "\nExample 5: Getting Current Timer Time\n");
    example_time_now();

    RTE_LOG(INFO, TIMER_DEMO, "\n========================================\n");
    RTE_LOG(INFO, TIMER_DEMO, "Timer Demo Complete\n");
    RTE_LOG(INFO, TIMER_DEMO, "========================================\n\n");
}

/*
 * Usage Notes:
 *
 * 1. **Per-lcore vs Global Timers**:
 *    - Per-lcore timers (global=false): Lockless, high performance,
 *      can only be accessed from the lcore that created them.
 *      Use for flow timeouts, per-lcore statistics, etc.
 *    - Global timers (global=true): Can be accessed from any lcore,
 *      but uses spinlocks. Use for system-wide events like rule reloads.
 *
 * 2. **Timer Precision**:
 *    - Timers run at 1000Hz (1ms precision).
 *    - Actual trigger time may vary by ±1ms depending on system load.
 *
 * 3. **Handler Requirements**:
 *    - Timer handlers MUST be quick and non-blocking.
 *    - Do not call blocking I/O, sleep, or long computations.
 *    - For heavy work, schedule it as a job instead.
 *
 * 4. **Memory Management**:
 *    - Timer struct (struct ndf_timer) must remain valid until
 *      timer expires or is canceled.
 *    - For dynamic timers, use rte_malloc/rte_free, not malloc/free.
 *
 * 5. **Thread Safety**:
 *    - Per-lcore timers: Thread-safe within the same lcore only.
 *    - Global timers: Thread-safe across all lcores.
 *    - Use *_nolock variants only inside timer handlers to avoid deadlock.
 */
