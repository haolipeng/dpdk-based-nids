/*
 * NetDefender - Protocol Detection Framework Implementation
 *
 * This module implements the core protocol detection engine.
 */

#include "proto_detect.h"
#include "app_proto.h"
#include "flow.h"
#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>

#define RTE_LOGTYPE_PROTO_DETECT RTE_LOGTYPE_USER1

/* Global configuration */
static proto_detect_config_t global_config = {
    .max_inspect_depth = 4096,      /* 4KB default */
    .enable_port_detection = true,
    .enable_pattern_matching = true,
    .enable_probing_parsers = true,
};

/* Global pattern lists (shared across all lcores) */
static proto_pattern_t *global_patterns_ts = NULL;
static proto_pattern_t *global_patterns_tc = NULL;
static proto_prober_t *global_probers = NULL;

/* Statistics */
static struct {
    uint64_t patterns_registered;
    uint64_t probers_registered;
} global_stats = {0};

int proto_detect_init(const proto_detect_config_t *config)
{
    if (config) {
        global_config = *config;
    }

    RTE_LOG(INFO, PROTO_DETECT, "Protocol detection initialized:\n");
    RTE_LOG(INFO, PROTO_DETECT, "  Max inspect depth: %u bytes\n",
            global_config.max_inspect_depth);
    RTE_LOG(INFO, PROTO_DETECT, "  Port detection: %s\n",
            global_config.enable_port_detection ? "enabled" : "disabled");
    RTE_LOG(INFO, PROTO_DETECT, "  Pattern matching: %s\n",
            global_config.enable_pattern_matching ? "enabled" : "disabled");
    RTE_LOG(INFO, PROTO_DETECT, "  Probing parsers: %s\n",
            global_config.enable_probing_parsers ? "enabled" : "disabled");

    /* Register built-in protocol detectors */
    proto_detect_register_http();
    proto_detect_register_tls();
    proto_detect_register_dns();

    return 0;
}

void proto_detect_cleanup(void)
{
    /* Free global pattern lists */
    proto_pattern_t *pattern = global_patterns_ts;
    while (pattern) {
        proto_pattern_t *next = pattern->next;
        rte_free((void *)pattern->pattern);
        rte_free(pattern);
        pattern = next;
    }

    pattern = global_patterns_tc;
    while (pattern) {
        proto_pattern_t *next = pattern->next;
        rte_free((void *)pattern->pattern);
        rte_free(pattern);
        pattern = next;
    }

    /* Free global prober list */
    proto_prober_t *prober = global_probers;
    while (prober) {
        proto_prober_t *next = prober->next;
        rte_free(prober);
        prober = next;
    }

    global_patterns_ts = NULL;
    global_patterns_tc = NULL;
    global_probers = NULL;

    RTE_LOG(INFO, PROTO_DETECT, "Protocol detection cleaned up\n");
}

proto_detect_ctx_t *proto_detect_ctx_create(void)
{
    proto_detect_ctx_t *ctx = rte_zmalloc("proto_detect_ctx",
                                           sizeof(proto_detect_ctx_t), 0);
    if (!ctx) {
        RTE_LOG(ERR, PROTO_DETECT, "Failed to allocate detection context\n");
        return NULL;
    }

    /* Each lcore gets pointers to the shared global lists */
    ctx->patterns_ts = global_patterns_ts;
    ctx->patterns_tc = global_patterns_tc;
    ctx->probers = global_probers;

    return ctx;
}

void proto_detect_ctx_free(proto_detect_ctx_t *ctx)
{
    if (ctx) {
        rte_free(ctx);
    }
}

int proto_detect_register_pattern(app_proto_t protocol,
                                   const char *pattern, uint16_t pattern_len,
                                   uint16_t depth, uint16_t offset,
                                   uint8_t direction, bool case_sensitive)
{
    if (!pattern || pattern_len == 0) {
        return -1;
    }

    /* Allocate pattern entry */
    proto_pattern_t *entry = rte_zmalloc("proto_pattern",
                                          sizeof(proto_pattern_t), 0);
    if (!entry) {
        RTE_LOG(ERR, PROTO_DETECT, "Failed to allocate pattern entry\n");
        return -1;
    }

    /* Copy pattern data */
    char *pattern_copy = rte_malloc("pattern_data", pattern_len, 0);
    if (!pattern_copy) {
        rte_free(entry);
        return -1;
    }
    rte_memcpy(pattern_copy, pattern, pattern_len);

    /* Fill entry */
    entry->protocol = protocol;
    entry->pattern = pattern_copy;
    entry->pattern_len = pattern_len;
    entry->depth = depth;
    entry->offset = offset;
    entry->direction = direction;
    entry->case_sensitive = case_sensitive;

    /* Add to appropriate list(s) */
    if (direction & PROTO_DETECT_DIR_TOSERVER) {
        entry->next = global_patterns_ts;
        global_patterns_ts = entry;
    }
    if (direction & PROTO_DETECT_DIR_TOCLIENT) {
        /* If both directions, duplicate the entry */
        if (direction & PROTO_DETECT_DIR_TOSERVER) {
            proto_pattern_t *entry2 = rte_zmalloc("proto_pattern",
                                                   sizeof(proto_pattern_t), 0);
            if (entry2) {
                *entry2 = *entry;  /* Shallow copy - shares pattern string */
                entry2->next = global_patterns_tc;
                global_patterns_tc = entry2;
            }
        } else {
            entry->next = global_patterns_tc;
            global_patterns_tc = entry;
        }
    }

    global_stats.patterns_registered++;

    RTE_LOG(DEBUG, PROTO_DETECT, "Registered pattern for %s: \"%.*s\" (len=%u, depth=%u)\n",
            app_proto_to_string(protocol), pattern_len, pattern, pattern_len, depth);

    return 0;
}

int proto_detect_register_prober(app_proto_t protocol, uint16_t port,
                                  uint16_t min_depth, uint16_t max_depth,
                                  uint8_t direction, probing_parser_fn parser_fn)
{
    if (!parser_fn) {
        return -1;
    }

    proto_prober_t *entry = rte_zmalloc("proto_prober",
                                         sizeof(proto_prober_t), 0);
    if (!entry) {
        RTE_LOG(ERR, PROTO_DETECT, "Failed to allocate prober entry\n");
        return -1;
    }

    entry->protocol = protocol;
    entry->port = port;
    entry->min_depth = min_depth;
    entry->max_depth = max_depth;
    entry->direction = direction;
    entry->parser_fn = parser_fn;

    /* Add to global list */
    entry->next = global_probers;
    global_probers = entry;

    global_stats.probers_registered++;

    RTE_LOG(DEBUG, PROTO_DETECT, "Registered prober for %s: port=%u, min_depth=%u\n",
            app_proto_to_string(protocol), port, min_depth);

    return 0;
}

/**
 * @brief Pattern matching helper (case-insensitive Boyer-Moore-like search)
 */
static bool pattern_match(const uint8_t *data, uint32_t data_len,
                          const char *pattern, uint16_t pattern_len,
                          bool case_sensitive)
{
    if (data_len < pattern_len) {
        return false;
    }

    /* Simple naive search - can be optimized later with Boyer-Moore or KMP */
    for (uint32_t i = 0; i <= data_len - pattern_len; i++) {
        bool match = true;
        for (uint16_t j = 0; j < pattern_len; j++) {
            if (case_sensitive) {
                if (data[i + j] != (uint8_t)pattern[j]) {
                    match = false;
                    break;
                }
            } else {
                if (tolower(data[i + j]) != tolower((uint8_t)pattern[j])) {
                    match = false;
                    break;
                }
            }
        }
        if (match) {
            return true;
        }
    }

    return false;
}

/**
 * @brief Try pattern matching detection
 */
static app_proto_t try_pattern_detection(proto_detect_ctx_t *ctx,
                                          const uint8_t *data, uint32_t len,
                                          uint8_t direction)
{
    proto_pattern_t *pattern_list = (direction == PROTO_DETECT_DIR_TOSERVER) ?
                                     ctx->patterns_ts : ctx->patterns_tc;

    for (proto_pattern_t *p = pattern_list; p != NULL; p = p->next) {
        /* Check offset constraints */
        if (p->offset > 0 && len < p->offset) {
            continue;
        }

        /* Check depth constraints */
        uint32_t search_len = len;
        if (p->depth > 0 && search_len > p->depth) {
            search_len = p->depth;
        }

        const uint8_t *search_data = data + p->offset;
        search_len -= p->offset;

        /* Try pattern match */
        if (pattern_match(search_data, search_len, p->pattern,
                          p->pattern_len, p->case_sensitive)) {
            ctx->detections_by_pattern++;
            return p->protocol;
        }
    }

    return APP_PROTO_UNKNOWN;
}

/**
 * @brief Try probing parser detection
 */
static app_proto_t try_prober_detection(proto_detect_ctx_t *ctx,
                                         struct flow *flow,
                                         const uint8_t *data, uint32_t len,
                                         uint8_t direction, bool *reverse_flow)
{
    uint16_t dport = flow->dst_port;
    uint16_t sport = flow->src_port;
    uint16_t port = (direction == PROTO_DETECT_DIR_TOSERVER) ? dport : sport;

    for (proto_prober_t *p = ctx->probers; p != NULL; p = p->next) {
        /* Check direction */
        if (!(p->direction & direction)) {
            continue;
        }

        /* Check port (0 = any port) */
        if (p->port != 0 && p->port != port) {
            continue;
        }

        /* Check minimum depth */
        if (len < p->min_depth) {
            continue;
        }

        /* Limit to max depth */
        uint32_t probe_len = len;
        if (p->max_depth > 0 && probe_len > p->max_depth) {
            probe_len = p->max_depth;
        }

        /* Call probing function */
        app_proto_t result = p->parser_fn(flow, direction, data, probe_len, reverse_flow);
        if (result != APP_PROTO_UNKNOWN) {
            if (result != APP_PROTO_FAILED) {
                ctx->detections_by_prober++;
            }
            return result;
        }
    }

    return APP_PROTO_UNKNOWN;
}

/**
 * @brief Try port-based hint detection
 */
static app_proto_t try_port_detection(proto_detect_ctx_t *ctx,
                                       struct flow *flow,
                                       uint8_t direction)
{
    uint16_t port = (direction == PROTO_DETECT_DIR_TOSERVER) ?
                    flow->dst_port : flow->src_port;

    /* Common port mappings */
    switch (port) {
        case 80:
        case 8080:
            return APP_PROTO_HTTP;
        case 443:
        case 8443:
            return APP_PROTO_TLS;
        case 53:
            return APP_PROTO_DNS;
        case 22:
            return APP_PROTO_SSH;
        case 21:
            return APP_PROTO_FTP;
        case 25:
            return APP_PROTO_SMTP;
        case 3306:
            return APP_PROTO_MYSQL;
        case 5432:
            return APP_PROTO_PGSQL;
        default:
            return APP_PROTO_UNKNOWN;
    }
}

int proto_detect_get_proto(proto_detect_ctx_t *ctx, struct flow *flow,
                            const uint8_t *data, uint32_t len, uint8_t direction,
                            proto_detect_result_t *result)
{
    if (!ctx || !flow || !data || !result) {
        return -2;
    }

    /* Initialize result */
    result->protocol = APP_PROTO_UNKNOWN;
    result->confidence = PROTO_CONFIDENCE_LOW;
    result->reverse_flow = false;

    /* Limit inspection depth */
    if (len > global_config.max_inspect_depth) {
        len = global_config.max_inspect_depth;
    }

    /* Need at least a few bytes for meaningful detection */
    if (len < 4) {
        return -1;  /* Not enough data */
    }

    /* Try detection methods in order of reliability */

    /* 1. Pattern matching (highest confidence) */
    if (global_config.enable_pattern_matching) {
        app_proto_t proto = try_pattern_detection(ctx, data, len, direction);
        if (proto != APP_PROTO_UNKNOWN) {
            result->protocol = proto;
            result->confidence = PROTO_CONFIDENCE_HIGH;
            return 0;
        }
    }

    /* 2. Probing parsers (medium-high confidence) */
    if (global_config.enable_probing_parsers) {
        bool reverse = false;
        app_proto_t proto = try_prober_detection(ctx, flow, data, len,
                                                   direction, &reverse);
        if (proto == APP_PROTO_FAILED) {
            result->protocol = APP_PROTO_FAILED;
            ctx->detection_failures++;
            return 0;
        }
        if (proto != APP_PROTO_UNKNOWN) {
            result->protocol = proto;
            result->confidence = PROTO_CONFIDENCE_MEDIUM;
            result->reverse_flow = reverse;
            return 0;
        }
    }

    /* 3. Port-based hint (lowest confidence, last resort) */
    if (global_config.enable_port_detection) {
        app_proto_t proto = try_port_detection(ctx, flow, direction);
        if (proto != APP_PROTO_UNKNOWN) {
            result->protocol = proto;
            result->confidence = PROTO_CONFIDENCE_LOW;
            ctx->detections_by_port++;
            return 0;
        }
    }

    /* No detection */
    return -1;
}

void proto_detect_stats(const proto_detect_ctx_t *ctx, char *buf, size_t buf_size)
{
    if (!ctx || !buf || buf_size == 0) {
        return;
    }

    snprintf(buf, buf_size,
             "Protocol Detection Stats:\n"
             "  By pattern: %lu\n"
             "  By prober:  %lu\n"
             "  By port:    %lu\n"
             "  Failures:   %lu\n"
             "Global:\n"
             "  Patterns:   %lu\n"
             "  Probers:    %lu\n",
             ctx->detections_by_pattern,
             ctx->detections_by_prober,
             ctx->detections_by_port,
             ctx->detection_failures,
             global_stats.patterns_registered,
             global_stats.probers_registered);
}
