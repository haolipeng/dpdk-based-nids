/*
 * NetDefender - JSON Output Module
 *
 * This module outputs events in EVE JSON format (compatible with Suricata).
 * EVE (Extensible Event Format) is a JSON-based logging format that can be
 * consumed by Elasticsearch, Logstash, Filebeat, and other SIEM tools.
 */

#ifndef __OUTPUT_JSON_H__
#define __OUTPUT_JSON_H__

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <time.h>

/* Forward declarations */
struct flow;
struct alert;
struct http_transaction;
struct dns_transaction;
struct tls_conn;

/* JSON output event types */
typedef enum {
    JSON_EVENT_ALERT = 0,
    JSON_EVENT_HTTP,
    JSON_EVENT_DNS,
    JSON_EVENT_TLS,
    JSON_EVENT_FLOW,
    JSON_EVENT_STATS,
} json_event_type_t;

/* JSON output configuration */
typedef struct json_output_ctx {
    /* Output file */
    FILE *fp;
    char *filename;

    /* File rotation */
    bool rotate_enabled;
    uint64_t rotate_size;      /* Max file size before rotation (bytes) */
    uint64_t rotate_interval;  /* Rotation interval (seconds) */
    uint32_t rotate_count;     /* Number of rotated files to keep */
    uint64_t current_size;     /* Current file size */
    time_t last_rotate;        /* Last rotation time */

    /* Output options */
    bool indent;               /* Pretty-print JSON */
    bool log_flow_info;        /* Include flow 5-tuple in all events */
    bool log_timestamp;        /* Include timestamp in all events */

    /* Statistics */
    uint64_t events_written;
    uint64_t bytes_written;
    uint64_t rotations;
    uint64_t write_errors;
} json_output_ctx_t;

/* JSON buffer for building output */
typedef struct json_builder {
    char *buf;
    size_t size;
    size_t offset;
    int indent_level;
} json_builder_t;

/* Function prototypes */

/**
 * @brief Initialize JSON output system
 * @param filename Output filename (NULL for stdout)
 * @param indent Enable pretty-printing
 * @return JSON output context or NULL on error
 */
json_output_ctx_t *json_output_init(const char *filename, bool indent);

/**
 * @brief Free JSON output system
 * @param ctx JSON output context
 */
void json_output_free(json_output_ctx_t *ctx);

/**
 * @brief Enable file rotation
 * @param ctx JSON output context
 * @param max_size Maximum file size in bytes
 * @param interval Rotation interval in seconds
 * @param count Number of files to keep
 */
void json_output_enable_rotation(json_output_ctx_t *ctx, uint64_t max_size,
                                   uint64_t interval, uint32_t count);

/**
 * @brief Rotate log file if needed
 * @param ctx JSON output context
 * @return 0 on success, -1 on error
 */
int json_output_rotate(json_output_ctx_t *ctx);

/**
 * @brief Output alert event in EVE JSON format
 * @param ctx JSON output context
 * @param alert Alert structure
 * @param flow Flow structure
 * @return 0 on success, -1 on error
 */
int json_output_alert(json_output_ctx_t *ctx, struct alert *alert,
                      struct flow *flow);

/**
 * @brief Output HTTP transaction in EVE JSON format
 * @param ctx JSON output context
 * @param tx HTTP transaction
 * @param flow Flow structure
 * @return 0 on success, -1 on error
 */
int json_output_http(json_output_ctx_t *ctx, struct http_transaction *tx,
                     struct flow *flow);

/**
 * @brief Output DNS transaction in EVE JSON format
 * @param ctx JSON output context
 * @param tx DNS transaction
 * @param flow Flow structure
 * @return 0 on success, -1 on error
 */
int json_output_dns(json_output_ctx_t *ctx, struct dns_transaction *tx,
                    struct flow *flow);

/**
 * @brief Output TLS handshake in EVE JSON format
 * @param ctx JSON output context
 * @param tls_conn TLS connection
 * @param flow Flow structure
 * @return 0 on success, -1 on error
 */
int json_output_tls(json_output_ctx_t *ctx, struct tls_conn *tls_conn,
                    struct flow *flow);

/**
 * @brief Output flow event in EVE JSON format
 * @param ctx JSON output context
 * @param flow Flow structure
 * @return 0 on success, -1 on error
 */
int json_output_flow(json_output_ctx_t *ctx, struct flow *flow);

/**
 * @brief Output statistics in EVE JSON format
 * @param ctx JSON output context
 * @return 0 on success, -1 on error
 */
int json_output_stats(json_output_ctx_t *ctx);

/**
 * @brief Get output statistics
 * @param ctx JSON output context
 * @param buf Output buffer
 * @param buflen Buffer length
 */
void json_output_get_stats(json_output_ctx_t *ctx, char *buf, size_t buflen);

/* JSON builder helper functions */

/**
 * @brief Create a new JSON builder
 * @param initial_size Initial buffer size
 * @return JSON builder or NULL on error
 */
json_builder_t *json_builder_create(size_t initial_size);

/**
 * @brief Free JSON builder
 * @param jb JSON builder
 */
void json_builder_free(json_builder_t *jb);

/**
 * @brief Start a JSON object
 * @param jb JSON builder
 */
void json_builder_start_object(json_builder_t *jb);

/**
 * @brief End a JSON object
 * @param jb JSON builder
 */
void json_builder_end_object(json_builder_t *jb);

/**
 * @brief Start a JSON array
 * @param jb JSON builder
 */
void json_builder_start_array(json_builder_t *jb);

/**
 * @brief End a JSON array
 * @param jb JSON builder
 */
void json_builder_end_array(json_builder_t *jb);

/**
 * @brief Add a string field
 * @param jb JSON builder
 * @param key Field key
 * @param value String value
 */
void json_builder_add_string(json_builder_t *jb, const char *key, const char *value);

/**
 * @brief Add an integer field
 * @param jb JSON builder
 * @param key Field key
 * @param value Integer value
 */
void json_builder_add_int(json_builder_t *jb, const char *key, int64_t value);

/**
 * @brief Add an unsigned integer field
 * @param jb JSON builder
 * @param key Field key
 * @param value Unsigned integer value
 */
void json_builder_add_uint(json_builder_t *jb, const char *key, uint64_t value);

/**
 * @brief Add a boolean field
 * @param jb JSON builder
 * @param key Field key
 * @param value Boolean value
 */
void json_builder_add_bool(json_builder_t *jb, const char *key, bool value);

/**
 * @brief Add a null field
 * @param jb JSON builder
 * @param key Field key
 */
void json_builder_add_null(json_builder_t *jb, const char *key);

/**
 * @brief Get the built JSON string
 * @param jb JSON builder
 * @return JSON string (do not free)
 */
const char *json_builder_get_string(json_builder_t *jb);

/**
 * @brief Reset JSON builder for reuse
 * @param jb JSON builder
 */
void json_builder_reset(json_builder_t *jb);

/* Helper functions for common fields */

/**
 * @brief Add timestamp to JSON
 * @param jb JSON builder
 * @param key Field key
 * @param timestamp Timestamp (NULL for current time)
 */
void json_add_timestamp(json_builder_t *jb, const char *key, const struct timeval *timestamp);

/**
 * @brief Add flow 5-tuple to JSON
 * @param jb JSON builder
 * @param flow Flow structure
 */
void json_add_flow_info(json_builder_t *jb, struct flow *flow);

#endif /* __OUTPUT_JSON_H__ */
