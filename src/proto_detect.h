/*
 * NetDefender - Protocol Detection Framework
 *
 * This module provides the protocol detection engine that identifies
 * application layer protocols using pattern matching and probing parsers.
 */

#ifndef __PROTO_DETECT_H__
#define __PROTO_DETECT_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "app_proto.h"

/* Forward declarations */
struct flow;

/**
 * @brief Traffic direction flags
 */
#define PROTO_DETECT_DIR_TOSERVER   0x01    /* Client to server */
#define PROTO_DETECT_DIR_TOCLIENT   0x02    /* Server to client */
#define PROTO_DETECT_DIR_BOTH       0x03    /* Both directions */

/**
 * @brief Protocol detection method
 */
typedef enum {
    PROTO_DETECT_METHOD_PATTERN = 0,    /* Pattern matching */
    PROTO_DETECT_METHOD_PROBING,        /* Probing parser */
    PROTO_DETECT_METHOD_PORT,           /* Port-based hint */
} proto_detect_method_t;

/**
 * @brief Probing parser function type
 *
 * Examines packet data to determine if it matches a protocol.
 *
 * @param flow Flow entry being examined
 * @param direction Direction of traffic (TOSERVER/TOCLIENT)
 * @param data Packet payload data
 * @param len Payload length
 * @param reverse_flow Output: set to true if detection is for reverse direction
 * @return Detected protocol, or APP_PROTO_UNKNOWN if no match, APP_PROTO_FAILED if definitely not this protocol
 */
typedef app_proto_t (*probing_parser_fn)(struct flow *flow, uint8_t direction,
                                          const uint8_t *data, uint32_t len,
                                          bool *reverse_flow);

/**
 * @brief Pattern matching entry
 */
typedef struct proto_pattern {
    app_proto_t protocol;           /* Protocol this pattern detects */
    const char *pattern;            /* Pattern string to match */
    uint16_t pattern_len;           /* Pattern length */
    uint16_t depth;                 /* Maximum offset to search (0 = unlimited) */
    uint16_t offset;                /* Minimum offset to start searching */
    uint8_t direction;              /* Direction flags */
    bool case_sensitive;            /* Case-sensitive matching */
    struct proto_pattern *next;     /* Next pattern in list */
} proto_pattern_t;

/**
 * @brief Probing parser entry
 */
typedef struct proto_prober {
    app_proto_t protocol;           /* Protocol this prober detects */
    uint16_t port;                  /* Port number (0 = any port) */
    uint16_t min_depth;             /* Minimum data required */
    uint16_t max_depth;             /* Maximum data to examine */
    uint8_t direction;              /* Direction flags */
    probing_parser_fn parser_fn;    /* Probing function */
    struct proto_prober *next;      /* Next prober in list */
} proto_prober_t;

/**
 * @brief Protocol detection context (per-lcore)
 */
typedef struct proto_detect_ctx {
    proto_pattern_t *patterns_ts;   /* Patterns for toserver direction */
    proto_pattern_t *patterns_tc;   /* Patterns for toclient direction */
    proto_prober_t *probers;        /* Probing parsers */

    /* Statistics */
    uint64_t detections_by_pattern; /* Detections via pattern matching */
    uint64_t detections_by_prober;  /* Detections via probing */
    uint64_t detections_by_port;    /* Detections via port hint */
    uint64_t detection_failures;    /* Failed detections */
} proto_detect_ctx_t;

/**
 * @brief Protocol detection configuration
 */
typedef struct proto_detect_config {
    uint32_t max_inspect_depth;     /* Maximum bytes to inspect per flow (default: 4KB) */
    bool enable_port_detection;     /* Enable port-based hints (default: true) */
    bool enable_pattern_matching;   /* Enable pattern matching (default: true) */
    bool enable_probing_parsers;    /* Enable probing parsers (default: true) */
} proto_detect_config_t;

/**
 * @brief Initialize protocol detection system (global)
 *
 * @param config Detection configuration
 * @return 0 on success, -1 on error
 */
int proto_detect_init(const proto_detect_config_t *config);

/**
 * @brief Cleanup protocol detection system (global)
 */
void proto_detect_cleanup(void);

/**
 * @brief Create per-lcore detection context
 *
 * @return Detection context, or NULL on error
 */
proto_detect_ctx_t *proto_detect_ctx_create(void);

/**
 * @brief Free per-lcore detection context
 *
 * @param ctx Detection context to free
 */
void proto_detect_ctx_free(proto_detect_ctx_t *ctx);

/**
 * @brief Register a pattern for protocol detection
 *
 * @param protocol Protocol to detect
 * @param pattern Pattern string to match
 * @param pattern_len Pattern length
 * @param depth Maximum search depth (0 = unlimited)
 * @param offset Minimum search offset
 * @param direction Direction flags
 * @param case_sensitive Case-sensitive matching
 * @return 0 on success, -1 on error
 */
int proto_detect_register_pattern(app_proto_t protocol,
                                   const char *pattern, uint16_t pattern_len,
                                   uint16_t depth, uint16_t offset,
                                   uint8_t direction, bool case_sensitive);

/**
 * @brief Register a probing parser for protocol detection
 *
 * @param protocol Protocol to detect
 * @param port Port number (0 = any port)
 * @param min_depth Minimum data required
 * @param max_depth Maximum data to examine
 * @param direction Direction flags
 * @param parser_fn Probing parser function
 * @return 0 on success, -1 on error
 */
int proto_detect_register_prober(app_proto_t protocol, uint16_t port,
                                  uint16_t min_depth, uint16_t max_depth,
                                  uint8_t direction, probing_parser_fn parser_fn);

/**
 * @brief Detect application protocol for a flow
 *
 * This is the main detection function called from the packet processing path.
 * It tries detection methods in order: pattern matching → probing → port hint.
 *
 * @param ctx Detection context (per-lcore)
 * @param flow Flow entry to detect protocol for
 * @param data Packet payload data
 * @param len Payload length
 * @param direction Traffic direction
 * @param result Output: detection result
 * @return 0 on success (result filled), -1 if not enough data, -2 on error
 */
int proto_detect_get_proto(proto_detect_ctx_t *ctx, struct flow *flow,
                            const uint8_t *data, uint32_t len, uint8_t direction,
                            proto_detect_result_t *result);

/**
 * @brief Get detection statistics
 *
 * @param ctx Detection context
 * @param buf Output buffer for statistics string
 * @param buf_size Size of output buffer
 */
void proto_detect_stats(const proto_detect_ctx_t *ctx, char *buf, size_t buf_size);

/* Protocol-specific detection functions (implemented in separate files) */

/**
 * @brief Register HTTP protocol detection
 * @return 0 on success, -1 on error
 */
int proto_detect_register_http(void);

/**
 * @brief Register TLS protocol detection
 * @return 0 on success, -1 on error
 */
int proto_detect_register_tls(void);

/**
 * @brief Register DNS protocol detection
 * @return 0 on success, -1 on error
 */
int proto_detect_register_dns(void);

#endif /* __PROTO_DETECT_H__ */
