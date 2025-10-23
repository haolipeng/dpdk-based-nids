/*
 * NetDefender - Rule Engine Implementation
 *
 * This module implements a lightweight rule-based detection engine.
 */

#define _GNU_SOURCE  /* For strcasestr */

#include "rule_engine.h"
#include "flow.h"
#include "http_parser.h"
#include "dns_parser.h"
#include "output_json.h"
#include <rte_malloc.h>
#include <rte_log.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <stdlib.h>
#include <math.h>
#include <arpa/inet.h>
#include <sys/time.h>

#define RTE_LOGTYPE_RULE_ENGINE RTE_LOGTYPE_USER7

/* Maximum alerts to keep in memory */
#define MAX_ALERTS_DEFAULT 1000

const char *alert_severity_to_string(alert_severity_t severity)
{
    switch (severity) {
        case ALERT_SEVERITY_INFO:     return "INFO";
        case ALERT_SEVERITY_LOW:      return "LOW";
        case ALERT_SEVERITY_MEDIUM:   return "MEDIUM";
        case ALERT_SEVERITY_HIGH:     return "HIGH";
        case ALERT_SEVERITY_CRITICAL: return "CRITICAL";
        default:                      return "UNKNOWN";
    }
}

const char *alert_category_to_string(alert_category_t category)
{
    switch (category) {
        case ALERT_CATEGORY_WEB_ATTACK:       return "WEB_ATTACK";
        case ALERT_CATEGORY_MALWARE:          return "MALWARE";
        case ALERT_CATEGORY_POLICY_VIOLATION: return "POLICY_VIOLATION";
        case ALERT_CATEGORY_RECON:            return "RECONNAISSANCE";
        case ALERT_CATEGORY_DOS:              return "DOS";
        case ALERT_CATEGORY_DATA_LEAK:        return "DATA_LEAK";
        case ALERT_CATEGORY_ANOMALY:          return "ANOMALY";
        case ALERT_CATEGORY_SCAN:             return "SCAN";
        case ALERT_CATEGORY_BRUTE_FORCE:      return "BRUTE_FORCE";
        case ALERT_CATEGORY_EXFILTRATION:     return "EXFILTRATION";
        case ALERT_CATEGORY_CRYPTO:           return "CRYPTO";
        default:                              return "UNKNOWN";
    }
}

rule_engine_t *rule_engine_init(void)
{
    rule_engine_t *engine = rte_zmalloc("rule_engine", sizeof(rule_engine_t), 0);
    if (!engine) {
        return NULL;
    }

    engine->max_alerts = MAX_ALERTS_DEFAULT;
    return engine;
}

static void free_conditions(rule_condition_t *cond)
{
    while (cond) {
        rule_condition_t *next = cond->next;
        if (cond->pattern) rte_free(cond->pattern);
        rte_free(cond);
        cond = next;
    }
}

static void free_rule(detection_rule_t *rule)
{
    if (!rule) return;
    if (rule->name) rte_free(rule->name);
    if (rule->description) rte_free(rule->description);
    if (rule->http.target_header) rte_free(rule->http.target_header);
    free_conditions(rule->conditions);
    rte_free(rule);
}

static void free_alert(alert_t *alert)
{
    if (!alert) return;
    if (alert->message) rte_free(alert->message);
    if (alert->detail) rte_free(alert->detail);
    rte_free(alert);
}

void rule_engine_free(rule_engine_t *engine)
{
    if (!engine) return;

    /* Free rules */
    detection_rule_t *rule = engine->rules;
    while (rule) {
        detection_rule_t *next = rule->next;
        free_rule(rule);
        rule = next;
    }

    /* Free alerts */
    alert_t *alert = engine->alerts;
    while (alert) {
        alert_t *next = alert->next;
        free_alert(alert);
        alert = next;
    }

    rte_free(engine);
}

int rule_engine_add_rule(rule_engine_t *engine, detection_rule_t *rule)
{
    if (!engine || !rule) {
        return -1;
    }

    /* Add to front of list */
    rule->next = engine->rules;
    engine->rules = rule;

    engine->stats.rules_loaded++;
    if (rule->enabled) {
        engine->stats.rules_enabled++;
    }

    return 0;
}

/**
 * @brief Create alert
 */
static alert_t *create_alert(rule_engine_t *engine, detection_rule_t *rule,
                              struct flow *flow, const char *detail)
{
    alert_t *alert = rte_zmalloc("alert", sizeof(alert_t), 0);
    if (!alert) {
        return NULL;
    }

    alert->alert_id = ++engine->alert_id_counter;
    alert->rule_id = rule->rule_id;
    alert->severity = rule->severity;
    alert->category = rule->category;
    alert->protocol = rule->protocol;
    gettimeofday(&alert->timestamp, NULL);

    /* Copy flow info */
    if (flow->flags & FLOW_IPV4) {
        alert->src_ip = flow->src_addr.addr_data32[0];
        alert->dst_ip = flow->dst_addr.addr_data32[0];
    }
    alert->src_port = flow->src_port;
    alert->dst_port = flow->dst_port;

    /* Copy message */
    if (rule->name) {
        alert->message = rte_malloc("alert_msg", strlen(rule->name) + 1, 0);
        if (alert->message) {
            strcpy(alert->message, rule->name);
        }
    }

    /* Copy detail */
    if (detail) {
        alert->detail = rte_malloc("alert_detail", strlen(detail) + 1, 0);
        if (alert->detail) {
            strcpy(alert->detail, detail);
        }
    }

    /* Add to alert list */
    alert->next = engine->alerts;
    engine->alerts = alert;
    engine->alert_count++;

    /* Log alert creation with key details */
    char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
    if (flow->flags & FLOW_IPV4) {
        inet_ntop(AF_INET, &alert->src_ip, src_ip_str, sizeof(src_ip_str));
        inet_ntop(AF_INET, &alert->dst_ip, dst_ip_str, sizeof(dst_ip_str));
        RTE_LOG(NOTICE, RULE_ENGINE,
                "ALERT #%u: [%s] %s | %s:%u -> %s:%u | Rule ID: %u | %s\n",
                alert->alert_id,
                alert_severity_to_string(alert->severity),
                alert->message ? alert->message : "Unknown",
                src_ip_str, alert->src_port,
                dst_ip_str, alert->dst_port,
                alert->rule_id,
                alert->detail ? alert->detail : "");
    }

    /* Limit alert count */
    if (engine->alert_count > engine->max_alerts) {
        /* Remove oldest alert */
        alert_t *prev = NULL;
        alert_t *curr = engine->alerts;
        while (curr && curr->next) {
            prev = curr;
            curr = curr->next;
        }
        if (prev) {
            prev->next = NULL;
            free_alert(curr);
            engine->alert_count--;
        }
    }

    /* Update statistics */
    engine->stats.alerts_generated++;
    if (alert->severity < 5) {
        engine->stats.alerts_by_severity[alert->severity]++;
    }

    RTE_LOG(INFO, RULE_ENGINE,
            "ALERT [%s/%s] rule_id=%u: %s - %s\n",
            alert_severity_to_string(alert->severity),
            alert_category_to_string(alert->category),
            alert->rule_id,
            alert->message ? alert->message : "unknown",
            alert->detail ? alert->detail : "");

    /* Output to JSON if enabled */
    if (engine->json_output) {
        json_output_alert(engine->json_output, alert, flow);
    }

    return alert;
}

/**
 * @brief Check if string contains pattern (case-insensitive optional)
 */
static bool string_contains(const char *haystack, const char *needle,
                            bool case_sensitive)
{
    if (!haystack || !needle) return false;

    if (case_sensitive) {
        return strstr(haystack, needle) != NULL;
    } else {
        return strcasestr(haystack, needle) != NULL;
    }
}

/**
 * @brief Calculate string entropy
 */
static double calculate_entropy(const char *str)
{
    if (!str) return 0.0;

    int freq[256] = {0};
    int len = 0;

    for (const char *p = str; *p; p++) {
        freq[(unsigned char)*p]++;
        len++;
    }

    if (len == 0) return 0.0;

    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }

    return entropy;
}

/**
 * @brief Check if condition matches
 */
static bool check_condition(rule_condition_t *cond, const char *data)
{
    if (!cond || !data) return false;

    bool match = false;

    switch (cond->type) {
        case RULE_MATCH_CONTENT:
            match = string_contains(data, cond->pattern, cond->case_sensitive);
            break;

        case RULE_MATCH_LENGTH: {
            size_t len = strlen(data);
            match = (len >= cond->min_length);
            if (cond->max_length > 0) {
                match = match && (len <= cond->max_length);
            }
            break;
        }

        case RULE_MATCH_ENTROPY: {
            double entropy = calculate_entropy(data);
            match = (entropy >= cond->min_entropy && entropy <= cond->max_entropy);
            break;
        }

        default:
            match = false;
    }

    return cond->negated ? !match : match;
}

/**
 * @brief Check HTTP transaction against rule
 */
static bool check_http_rule(detection_rule_t *rule, http_transaction_t *tx,
                            char *detail_out, size_t detail_size)
{
    if (!tx || !rule->enabled) return false;

    bool all_conditions_match = true;

    /* Check each field the rule specifies */
    if (rule->http.check_uri && tx->request && tx->request->uri) {
        for (rule_condition_t *cond = rule->conditions; cond; cond = cond->next) {
            if (!check_condition(cond, tx->request->uri)) {
                all_conditions_match = false;
                break;
            }
        }
        if (all_conditions_match && detail_out) {
            snprintf(detail_out, detail_size, "URI: %s", tx->request->uri);
        }
    }

    if (rule->http.check_headers && tx->request) {
        /* Check specific header or all headers */
        if (rule->http.target_header) {
            http_header_t *h = http_find_header(tx->request->headers,
                                               rule->http.target_header);
            if (h && h->value) {
                for (rule_condition_t *cond = rule->conditions; cond; cond = cond->next) {
                    if (!check_condition(cond, h->value)) {
                        all_conditions_match = false;
                        break;
                    }
                }
                if (all_conditions_match && detail_out) {
                    snprintf(detail_out, detail_size, "%s: %s",
                            rule->http.target_header, h->value);
                }
            }
        }
    }

    return all_conditions_match;
}

/**
 * @brief Check DNS transaction against rule
 */
static bool check_dns_rule(detection_rule_t *rule, dns_transaction_t *tx,
                           char *detail_out, size_t detail_size)
{
    if (!tx || !rule->enabled) return false;

    bool all_conditions_match = true;

    if (rule->dns.check_query && tx->questions) {
        dns_question_t *q = tx->questions;
        if (q->qname) {
            /* Check query type filter */
            if (rule->dns.qtype != 0 && q->qtype != rule->dns.qtype) {
                return false;
            }

            for (rule_condition_t *cond = rule->conditions; cond; cond = cond->next) {
                if (!check_condition(cond, q->qname)) {
                    all_conditions_match = false;
                    break;
                }
            }
            if (all_conditions_match && detail_out) {
                snprintf(detail_out, detail_size, "Query: %s", q->qname);
            }
        }
    }

    return all_conditions_match;
}

int rule_engine_inspect_http(rule_engine_t *engine, struct flow *flow,
                              http_transaction_t *tx)
{
    if (!engine || !flow || !tx) {
        return 0;
    }

    engine->stats.packets_inspected++;

    /* 周期性输出规则评估统计 */
    static __thread uint64_t http_inspections = 0;
    if (unlikely(++http_inspections % 10000 == 0)) {
        RTE_LOG(INFO, RULE_ENGINE,
                "HTTP rule evaluation: %lu inspections, %lu total packets, %lu alerts\n",
                http_inspections, engine->stats.packets_inspected,
                engine->stats.alerts_generated);
    }

    int alerts = 0;
    char detail[256];

    for (detection_rule_t *rule = engine->rules; rule; rule = rule->next) {
        if (rule->protocol != APP_PROTO_HTTP) continue;

        if (check_http_rule(rule, tx, detail, sizeof(detail))) {
            create_alert(engine, rule, flow, detail);
            alerts++;
        }
    }

    return alerts;
}

int rule_engine_inspect_dns(rule_engine_t *engine, struct flow *flow,
                             dns_transaction_t *tx)
{
    if (!engine || !flow || !tx) {
        return 0;
    }

    engine->stats.packets_inspected++;

    int alerts = 0;
    char detail[256];

    for (detection_rule_t *rule = engine->rules; rule; rule = rule->next) {
        if (rule->protocol != APP_PROTO_DNS) continue;

        if (check_dns_rule(rule, tx, detail, sizeof(detail))) {
            create_alert(engine, rule, flow, detail);
            alerts++;
        }
    }

    return alerts;
}

/* Helper functions for creating conditions */

rule_condition_t *rule_condition_content(const char *pattern, bool case_sensitive)
{
    if (!pattern) return NULL;

    rule_condition_t *cond = rte_zmalloc("rule_condition", sizeof(rule_condition_t), 0);
    if (!cond) return NULL;

    cond->type = RULE_MATCH_CONTENT;
    cond->pattern = rte_malloc("pattern", strlen(pattern) + 1, 0);
    if (!cond->pattern) {
        rte_free(cond);
        return NULL;
    }
    strcpy(cond->pattern, pattern);
    cond->case_sensitive = case_sensitive;

    return cond;
}

rule_condition_t *rule_condition_length(uint32_t min_length, uint32_t max_length)
{
    rule_condition_t *cond = rte_zmalloc("rule_condition", sizeof(rule_condition_t), 0);
    if (!cond) return NULL;

    cond->type = RULE_MATCH_LENGTH;
    cond->min_length = min_length;
    cond->max_length = max_length;

    return cond;
}

rule_condition_t *rule_condition_entropy(double min_entropy, double max_entropy)
{
    rule_condition_t *cond = rte_zmalloc("rule_condition", sizeof(rule_condition_t), 0);
    if (!cond) return NULL;

    cond->type = RULE_MATCH_ENTROPY;
    cond->min_entropy = min_entropy;
    cond->max_entropy = max_entropy;

    return cond;
}

/**
 * @brief Load built-in HTTP attack detection rules
 */
static int load_http_rules(rule_engine_t *engine)
{
    int count = 0;

    /* SQL Injection - UNION attack */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 1001;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "SQL Injection - UNION");
            rule->description = rte_malloc("desc", 128, 0);
            strcpy(rule->description, "Detects SQL UNION-based injection attempts");
            rule->severity = ALERT_SEVERITY_HIGH;
            rule->category = ALERT_CATEGORY_WEB_ATTACK;
            rule->protocol = APP_PROTO_HTTP;
            rule->http.check_uri = true;
            rule->conditions = rule_condition_content("union", false);
            if (rule->conditions) {
                rule->conditions->next = rule_condition_content("select", false);
            }
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    /* SQL Injection - Comment-based */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 1002;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "SQL Injection - Comment");
            rule->severity = ALERT_SEVERITY_HIGH;
            rule->category = ALERT_CATEGORY_WEB_ATTACK;
            rule->protocol = APP_PROTO_HTTP;
            rule->http.check_uri = true;
            rule->conditions = rule_condition_content("--", true);
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    /* XSS - Script tag */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 1003;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "XSS - Script Tag");
            rule->severity = ALERT_SEVERITY_MEDIUM;
            rule->category = ALERT_CATEGORY_WEB_ATTACK;
            rule->protocol = APP_PROTO_HTTP;
            rule->http.check_uri = true;
            rule->conditions = rule_condition_content("<script", false);
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    /* Path Traversal */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 1004;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "Path Traversal");
            rule->severity = ALERT_SEVERITY_HIGH;
            rule->category = ALERT_CATEGORY_WEB_ATTACK;
            rule->protocol = APP_PROTO_HTTP;
            rule->http.check_uri = true;
            rule->conditions = rule_condition_content("../", true);
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    /* Command Injection */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 1005;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "Command Injection");
            rule->severity = ALERT_SEVERITY_CRITICAL;
            rule->category = ALERT_CATEGORY_WEB_ATTACK;
            rule->protocol = APP_PROTO_HTTP;
            rule->http.check_uri = true;
            rule->conditions = rule_condition_content(";", true);
            if (rule->conditions) {
                rule->conditions->next = rule_condition_content("bash", false);
            }
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    return count;
}

/**
 * @brief Load built-in DNS attack detection rules
 */
static int load_dns_rules(rule_engine_t *engine)
{
    int count = 0;

    /* DGA Domain - High Entropy */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 2001;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "DGA Domain - High Entropy");
            rule->severity = ALERT_SEVERITY_MEDIUM;
            rule->category = ALERT_CATEGORY_MALWARE;
            rule->protocol = APP_PROTO_DNS;
            rule->dns.check_query = true;
            rule->conditions = rule_condition_entropy(4.0, 8.0);
            if (rule->conditions) {
                rule->conditions->next = rule_condition_length(20, 0);
            }
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    /* Suspicious TLD - .tk */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 2002;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "Suspicious TLD - .tk");
            rule->severity = ALERT_SEVERITY_LOW;
            rule->category = ALERT_CATEGORY_MALWARE;
            rule->protocol = APP_PROTO_DNS;
            rule->dns.check_query = true;
            rule->conditions = rule_condition_content(".tk", false);
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    /* DNS Tunneling - TXT Query */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 2003;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "DNS Tunneling - Long TXT");
            rule->severity = ALERT_SEVERITY_MEDIUM;
            rule->category = ALERT_CATEGORY_DATA_LEAK;
            rule->protocol = APP_PROTO_DNS;
            rule->dns.check_query = true;
            rule->dns.qtype = DNS_TYPE_TXT;
            rule->conditions = rule_condition_length(50, 0);
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    /* Excessive Subdomains */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 2004;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "Excessive Subdomains");
            rule->severity = ALERT_SEVERITY_LOW;
            rule->category = ALERT_CATEGORY_ANOMALY;
            rule->protocol = APP_PROTO_DNS;
            rule->dns.check_query = true;
            rule->conditions = rule_condition_length(80, 0);
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    return count;
}

/**
 * @brief Load built-in TLS detection rules
 */
static int load_tls_rules(rule_engine_t *engine)
{
    int count = 0;

    /* TLS Weak Cipher Detection */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 3001;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "TLS Weak Cipher");
            rule->description = rte_malloc("desc", 128, 0);
            strcpy(rule->description, "Detects use of weak TLS cipher suites");
            rule->severity = ALERT_SEVERITY_MEDIUM;
            rule->category = ALERT_CATEGORY_CRYPTO;
            rule->protocol = APP_PROTO_TLS;
            rule->tls.check_cipher = true;
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    /* TLS Version Downgrade */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 3002;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "TLS Version Downgrade");
            rule->description = rte_malloc("desc", 128, 0);
            strcpy(rule->description, "Detects TLS version downgrade attacks");
            rule->severity = ALERT_SEVERITY_HIGH;
            rule->category = ALERT_CATEGORY_CRYPTO;
            rule->protocol = APP_PROTO_TLS;
            rule->tls.check_version = true;
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    /* TLS Certificate Error */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 3003;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "TLS Certificate Error");
            rule->description = rte_malloc("desc", 128, 0);
            strcpy(rule->description, "Detects expired or self-signed certificates");
            rule->severity = ALERT_SEVERITY_MEDIUM;
            rule->category = ALERT_CATEGORY_CRYPTO;
            rule->protocol = APP_PROTO_TLS;
            rule->tls.check_cert = true;
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    /* Malicious SNI - Suspicious TLD */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 3004;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "Suspicious TLS SNI");
            rule->description = rte_malloc("desc", 128, 0);
            strcpy(rule->description, "Detects suspicious TLS SNI patterns");
            rule->severity = ALERT_SEVERITY_MEDIUM;
            rule->category = ALERT_CATEGORY_MALWARE;
            rule->protocol = APP_PROTO_TLS;
            rule->tls.check_sni = true;
            rule->conditions = rule_condition_content(".tk", false);
            if (rule->conditions) {
                /* Add .cc TLD */
                rule_condition_t *cond2 = rule_condition_content(".cc", false);
                if (cond2) {
                    rule->conditions->next = cond2;
                }
            }
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    /* JA3 - Metasploit */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 3005;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "Metasploit JA3");
            rule->description = rte_malloc("desc", 128, 0);
            strcpy(rule->description, "Detects Metasploit framework JA3 fingerprint");
            rule->severity = ALERT_SEVERITY_CRITICAL;
            rule->category = ALERT_CATEGORY_MALWARE;
            rule->protocol = APP_PROTO_TLS;
            rule->tls.check_ja3 = true;
            /* Metasploit JA3 hash: a0e9f5d64349fb13191bc781f81f42e1 */
            rule->tls.ja3_hash = rte_malloc("ja3", 64, 0);
            strcpy(rule->tls.ja3_hash, "a0e9f5d64349fb13191bc781f81f42e1");
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    /* JA3 - Cobalt Strike */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 3006;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "Cobalt Strike JA3");
            rule->description = rte_malloc("desc", 128, 0);
            strcpy(rule->description, "Detects Cobalt Strike JA3 fingerprint");
            rule->severity = ALERT_SEVERITY_CRITICAL;
            rule->category = ALERT_CATEGORY_MALWARE;
            rule->protocol = APP_PROTO_TLS;
            rule->tls.check_ja3 = true;
            /* Cobalt Strike JA3 hash: a0e9f5d64349fb13191bc781f81f42e1 */
            rule->tls.ja3_hash = rte_malloc("ja3", 64, 0);
            strcpy(rule->tls.ja3_hash, "72a589da586844d7f0818ce684948eea");
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    /* JA3 - Trickbot */
    {
        detection_rule_t *rule = rte_zmalloc("rule", sizeof(detection_rule_t), 0);
        if (rule) {
            rule->rule_id = 3007;
            rule->enabled = true;
            rule->name = rte_malloc("name", 64, 0);
            strcpy(rule->name, "Trickbot JA3");
            rule->description = rte_malloc("desc", 128, 0);
            strcpy(rule->description, "Detects Trickbot malware JA3 fingerprint");
            rule->severity = ALERT_SEVERITY_CRITICAL;
            rule->category = ALERT_CATEGORY_MALWARE;
            rule->protocol = APP_PROTO_TLS;
            rule->tls.check_ja3 = true;
            /* Trickbot JA3 hash */
            rule->tls.ja3_hash = rte_malloc("ja3", 64, 0);
            strcpy(rule->tls.ja3_hash, "6734f37431670b3ab4292b8f60f29984");
            rule_engine_add_rule(engine, rule);
            count++;
        }
    }

    RTE_LOG(INFO, USER1, "Loaded %d TLS detection rules\n", count);

    return count;
}

int rule_engine_load_builtin_rules(rule_engine_t *engine)
{
    if (!engine) return 0;

    int total = 0;
    total += load_http_rules(engine);
    total += load_dns_rules(engine);
    total += load_tls_rules(engine);

    RTE_LOG(INFO, RULE_ENGINE, "Loaded %d built-in detection rules\n", total);

    return total;
}

alert_t *rule_engine_get_alerts(rule_engine_t *engine, uint32_t max_alerts)
{
    if (!engine) return NULL;
    return engine->alerts;  /* Returns linked list */
}

void rule_engine_clear_alerts(rule_engine_t *engine)
{
    if (!engine) return;

    alert_t *alert = engine->alerts;
    while (alert) {
        alert_t *next = alert->next;
        free_alert(alert);
        alert = next;
    }

    engine->alerts = NULL;
    engine->alert_count = 0;
}

void rule_engine_set_json_output(rule_engine_t *engine, struct json_output_ctx *json_ctx)
{
    if (!engine) return;
    engine->json_output = json_ctx;
}

void rule_engine_get_stats(const rule_engine_t *engine, char *buf, size_t buf_size)
{
    if (!engine || !buf || buf_size == 0) return;

    snprintf(buf, buf_size,
             "Rules: loaded=%lu enabled=%lu | "
             "Inspected: %lu | "
             "Alerts: total=%lu INFO=%lu LOW=%lu MED=%lu HIGH=%lu CRIT=%lu",
             engine->stats.rules_loaded,
             engine->stats.rules_enabled,
             engine->stats.packets_inspected,
             engine->stats.alerts_generated,
             engine->stats.alerts_by_severity[ALERT_SEVERITY_INFO],
             engine->stats.alerts_by_severity[ALERT_SEVERITY_LOW],
             engine->stats.alerts_by_severity[ALERT_SEVERITY_MEDIUM],
             engine->stats.alerts_by_severity[ALERT_SEVERITY_HIGH],
             engine->stats.alerts_by_severity[ALERT_SEVERITY_CRITICAL]);
}

/* ==========================================================================
 * TLS Inspection
 * ========================================================================== */

#include "tls_parser.h"

/**
 * @brief Check if TLS rule matches connection
 */
static bool check_tls_rule(detection_rule_t *rule, tls_conn_t *tls_conn,
                           char *detail, size_t detail_len)
{
    if (!rule->enabled) return false;

    /* Check SNI (Server Name Indication) */
    if (rule->tls.check_sni && tls_conn->client_hello != NULL &&
        tls_conn->client_hello->sni != NULL) {

        for (rule_condition_t *cond = rule->conditions; cond; cond = cond->next) {
            if (cond->type == RULE_MATCH_CONTENT) {
                if (string_contains(tls_conn->client_hello->sni, cond->pattern,
                                   cond->case_sensitive) != cond->negated) {
                    snprintf(detail, detail_len, "SNI: %s",
                             tls_conn->client_hello->sni);
                    return true;
                }
            }
        }
    }

    /* Check JA3 fingerprint */
    if (rule->tls.check_ja3 && rule->tls.ja3_hash != NULL &&
        tls_conn->client_hello != NULL) {

        char ja3_hex[TLS_JA3_HASH_LEN * 2 + 1];
        for (int i = 0; i < TLS_JA3_HASH_LEN; i++) {
            snprintf(ja3_hex + i * 2, 3, "%02x",
                     tls_conn->client_hello->ja3_hash[i]);
        }

        if (strcasestr(ja3_hex, rule->tls.ja3_hash) != NULL) {
            snprintf(detail, detail_len,
                     "JA3: %s, SNI: %s",
                     ja3_hex,
                     tls_conn->client_hello->sni ? tls_conn->client_hello->sni : "N/A");
            return true;
        }
    }

    /* Check weak cipher */
    if (rule->tls.check_cipher && tls_conn->weak_cipher) {
        snprintf(detail, detail_len, "Weak cipher detected");
        return true;
    }

    /* Check TLS version */
    if (rule->tls.check_version && tls_conn->version_downgrade) {
        snprintf(detail, detail_len, "TLS version downgrade detected");
        return true;
    }

    /* Check certificate issues */
    if (rule->tls.check_cert &&
        (tls_conn->expired_cert || tls_conn->self_signed_cert)) {

        snprintf(detail, detail_len, "Certificate error: %s%s",
                 tls_conn->expired_cert ? "expired " : "",
                 tls_conn->self_signed_cert ? "self-signed" : "");
        return true;
    }

    return false;
}

/**
 * @brief Inspect TLS connection
 */
int rule_engine_inspect_tls(rule_engine_t *engine, struct flow *flow,
                             tls_conn_t *tls_conn)
{
    if (!engine || !flow || !tls_conn) {
        return 0;
    }

    engine->stats.packets_inspected++;

    int alerts = 0;
    char detail[512];

    for (detection_rule_t *rule = engine->rules; rule; rule = rule->next) {
        if (rule->protocol != APP_PROTO_TLS) continue;

        if (check_tls_rule(rule, tls_conn, detail, sizeof(detail))) {
            create_alert(engine, rule, flow, detail);
            alerts++;
        }
    }

    return alerts;
}

/**
 * @brief Create custom alert (for behavioral detector)
 */
int rule_engine_create_custom_alert(rule_engine_t *engine,
                                     detection_rule_t *rule,
                                     struct flow *flow,
                                     const char *detail)
{
    if (!engine || !rule || !flow) {
        return -1;
    }

    create_alert(engine, rule, flow, detail);

    return 0;
}
