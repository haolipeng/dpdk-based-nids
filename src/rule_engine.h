/*
 * NetDefender - Rule Engine
 *
 * This module provides a lightweight rule-based detection engine
 * for HTTP, DNS, and other protocols.
 */

#ifndef __RULE_ENGINE_H__
#define __RULE_ENGINE_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/time.h>
#include "app_proto.h"

/* Forward declarations */
struct flow;
struct http_transaction;
struct dns_transaction;
struct tls_conn;

/* Alert severity levels */
typedef enum {
    ALERT_SEVERITY_INFO = 0,
    ALERT_SEVERITY_LOW,
    ALERT_SEVERITY_MEDIUM,
    ALERT_SEVERITY_HIGH,
    ALERT_SEVERITY_CRITICAL,
} alert_severity_t;

/* Alert categories */
typedef enum {
    ALERT_CATEGORY_UNKNOWN = 0,
    ALERT_CATEGORY_WEB_ATTACK,          /* SQL injection, XSS, etc. */
    ALERT_CATEGORY_MALWARE,             /* Malware download, C2 */
    ALERT_CATEGORY_POLICY_VIOLATION,    /* Policy violations */
    ALERT_CATEGORY_RECON,               /* Reconnaissance */
    ALERT_CATEGORY_DOS,                 /* Denial of Service */
    ALERT_CATEGORY_DATA_LEAK,           /* Data exfiltration */
    ALERT_CATEGORY_ANOMALY,             /* Anomalous behavior */
    ALERT_CATEGORY_SCAN,                /* Port scanning */
    ALERT_CATEGORY_BRUTE_FORCE,         /* Brute force attacks */
    ALERT_CATEGORY_EXFILTRATION,        /* Data exfiltration */
    ALERT_CATEGORY_CRYPTO,              /* Cryptographic issues */
} alert_category_t;

/* Alert structure */
typedef struct alert {
    uint32_t alert_id;              /* Unique alert ID */
    uint32_t rule_id;               /* Rule that triggered */
    alert_severity_t severity;      /* Alert severity */
    alert_category_t category;      /* Alert category */
    app_proto_t protocol;           /* Protocol (HTTP, DNS, etc.) */

    char *message;                  /* Alert message */
    char *detail;                   /* Additional details */

    /* Flow information */
    uint32_t src_ip;                /* Source IP (IPv4) */
    uint32_t dst_ip;                /* Destination IP */
    uint16_t src_port;              /* Source port */
    uint16_t dst_port;              /* Destination port */

    struct timeval timestamp;       /* Alert timestamp */

    struct alert *next;             /* Next alert in list */
} alert_t;

/* Rule match condition types */
typedef enum {
    RULE_MATCH_CONTENT = 0,         /* Content/string match */
    RULE_MATCH_PCRE,                /* Regex match (simplified) */
    RULE_MATCH_LENGTH,              /* Length check */
    RULE_MATCH_ENTROPY,             /* Entropy check */
    RULE_MATCH_FREQUENCY,           /* Frequency check */
} rule_match_type_t;

/* Rule condition */
typedef struct rule_condition {
    rule_match_type_t type;
    char *pattern;                  /* Pattern to match */
    bool case_sensitive;            /* Case-sensitive match */
    bool negated;                   /* Negate the match */

    /* For LENGTH type */
    uint32_t min_length;
    uint32_t max_length;

    /* For ENTROPY type */
    double min_entropy;
    double max_entropy;

    struct rule_condition *next;    /* Next condition (AND logic) */
} rule_condition_t;

/* Detection rule */
typedef struct detection_rule {
    uint32_t rule_id;               /* Unique rule ID */
    bool enabled;                   /* Rule enabled/disabled */

    char *name;                     /* Rule name */
    char *description;              /* Rule description */
    alert_severity_t severity;      /* Alert severity */
    alert_category_t category;      /* Alert category */

    /* Target protocol */
    app_proto_t protocol;           /* APP_PROTO_HTTP, APP_PROTO_DNS, etc. */

    /* Conditions (all must match - AND logic) */
    rule_condition_t *conditions;

    /* For HTTP rules */
    struct {
        bool check_uri;             /* Check URI */
        bool check_headers;         /* Check headers */
        bool check_body;            /* Check body */
        bool check_method;          /* Check method */
        char *target_header;        /* Specific header to check */
    } http;

    /* For DNS rules */
    struct {
        bool check_query;           /* Check query name */
        bool check_response;        /* Check response */
        uint16_t qtype;             /* Query type filter (0 = any) */
    } dns;

    /* For TLS rules */
    struct {
        bool check_sni;             /* Check Server Name Indication */
        bool check_ja3;             /* Check JA3 fingerprint */
        bool check_cipher;          /* Check cipher suite */
        bool check_version;         /* Check TLS version */
        bool check_cert;            /* Check certificate */
        char *ja3_hash;             /* Specific JA3 hash to match */
    } tls;

    struct detection_rule *next;    /* Next rule */
} detection_rule_t;

/* Rule engine statistics */
typedef struct rule_stats {
    uint64_t rules_loaded;          /* Total rules loaded */
    uint64_t rules_enabled;         /* Enabled rules */
    uint64_t packets_inspected;     /* Packets inspected */
    uint64_t alerts_generated;      /* Total alerts */
    uint64_t alerts_by_severity[5]; /* Alerts by severity */
} rule_stats_t;

/* Forward declaration for JSON output */
struct json_output_ctx;

/* Rule engine context */
typedef struct rule_engine {
    detection_rule_t *rules;        /* Rule list */
    alert_t *alerts;                /* Alert list */
    uint32_t alert_id_counter;      /* Alert ID counter */

    rule_stats_t stats;             /* Statistics */

    /* Alert limits */
    uint32_t max_alerts;            /* Max alerts to keep */
    uint32_t alert_count;           /* Current alert count */

    /* JSON output context */
    struct json_output_ctx *json_output;  /* JSON output (if enabled) */
} rule_engine_t;

/**
 * @brief Initialize rule engine
 *
 * @return Rule engine context, or NULL on error
 */
rule_engine_t *rule_engine_init(void);

/**
 * @brief Free rule engine
 *
 * @param engine Rule engine to free
 */
void rule_engine_free(rule_engine_t *engine);

/**
 * @brief Add detection rule
 *
 * @param engine Rule engine
 * @param rule Rule to add
 * @return 0 on success, -1 on error
 */
int rule_engine_add_rule(rule_engine_t *engine, detection_rule_t *rule);

/**
 * @brief Load built-in rules
 *
 * Loads a set of built-in detection rules for:
 * - SQL injection
 * - XSS attacks
 * - Path traversal
 * - DGA domains
 * - Malicious TLDs
 * - DNS tunneling
 *
 * @param engine Rule engine
 * @return Number of rules loaded
 */
int rule_engine_load_builtin_rules(rule_engine_t *engine);

/**
 * @brief Inspect HTTP transaction
 *
 * @param engine Rule engine
 * @param flow Flow context
 * @param tx HTTP transaction
 * @return Number of alerts generated
 */
int rule_engine_inspect_http(rule_engine_t *engine, struct flow *flow,
                              struct http_transaction *tx);

/**
 * @brief Inspect DNS transaction
 *
 * @param engine Rule engine
 * @param flow Flow context
 * @param tx DNS transaction
 * @return Number of alerts generated
 */
int rule_engine_inspect_dns(rule_engine_t *engine, struct flow *flow,
                             struct dns_transaction *tx);

/**
 * @brief Inspect TLS connection
 *
 * @param engine Rule engine
 * @param flow Flow context
 * @param tls_conn TLS connection
 * @return Number of alerts generated
 */
int rule_engine_inspect_tls(rule_engine_t *engine, struct flow *flow,
                             struct tls_conn *tls_conn);

/**
 * @brief Create custom alert (for behavioral detector)
 *
 * @param engine Rule engine
 * @param rule Rule structure
 * @param flow Flow context
 * @param detail Alert detail message
 * @return 0 on success, -1 on error
 */
int rule_engine_create_custom_alert(rule_engine_t *engine,
                                     detection_rule_t *rule,
                                     struct flow *flow,
                                     const char *detail);

/**
 * @brief Get latest alerts
 *
 * @param engine Rule engine
 * @param max_alerts Maximum number of alerts to return
 * @return Alert list
 */
alert_t *rule_engine_get_alerts(rule_engine_t *engine, uint32_t max_alerts);

/**
 * @brief Clear alerts
 *
 * @param engine Rule engine
 */
void rule_engine_clear_alerts(rule_engine_t *engine);

/**
 * @brief Set JSON output context for alerts
 *
 * @param engine Rule engine
 * @param json_ctx JSON output context
 */
void rule_engine_set_json_output(rule_engine_t *engine, struct json_output_ctx *json_ctx);

/**
 * @brief Get statistics
 *
 * @param engine Rule engine
 * @param buf Output buffer
 * @param buf_size Buffer size
 */
void rule_engine_get_stats(const rule_engine_t *engine, char *buf, size_t buf_size);

/**
 * @brief Convert severity to string
 *
 * @param severity Severity level
 * @return Severity string
 */
const char *alert_severity_to_string(alert_severity_t severity);

/**
 * @brief Convert category to string
 *
 * @param category Alert category
 * @return Category string
 */
const char *alert_category_to_string(alert_category_t category);

/* Helper functions for rule creation */

/**
 * @brief Create content match condition
 *
 * @param pattern Pattern to match
 * @param case_sensitive Case-sensitive match
 * @return Condition, or NULL on error
 */
rule_condition_t *rule_condition_content(const char *pattern, bool case_sensitive);

/**
 * @brief Create length check condition
 *
 * @param min_length Minimum length
 * @param max_length Maximum length (0 = no max)
 * @return Condition, or NULL on error
 */
rule_condition_t *rule_condition_length(uint32_t min_length, uint32_t max_length);

/**
 * @brief Create entropy check condition
 *
 * @param min_entropy Minimum entropy
 * @param max_entropy Maximum entropy
 * @return Condition, or NULL on error
 */
rule_condition_t *rule_condition_entropy(double min_entropy, double max_entropy);

#endif /* __RULE_ENGINE_H__ */
