/*
 * NetDefender - Behavioral Detection Module
 *
 * This module implements behavioral analysis to detect:
 * - Port scanning attacks
 * - Brute force attacks
 * - Data exfiltration
 * - Traffic anomalies
 */

#define _GNU_SOURCE
#include "behavioral_detector.h"
#include "rule_engine.h"
#include "flow.h"
#include "http_parser.h"
#include "dns_parser.h"
#include "tls_parser.h"

#include <rte_malloc.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_jhash.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#define RTE_LOGTYPE_BEHAVIORAL RTE_LOGTYPE_USER2

/* Helper macros */
#define HASH_KEY(key, size) (rte_jhash(&(key), sizeof(key), 0) % (size))
#define IS_EXTERNAL_IP(ip) (((ip) & 0xFF) != 10 && ((ip) & 0xFFF0) != 0xAC10 && ((ip) & 0xFFFF) != 0xC0A8)
#define IS_OFF_HOURS(hour) ((hour) >= 22 || (hour) < 6)

/* ==========================================================================
 * Helper Functions
 * ========================================================================== */

/**
 * @brief Calculate hash for source IP
 */
static inline uint32_t hash_src_ip(uint32_t src_ip)
{
    return HASH_KEY(src_ip, TRACKER_HASH_SIZE);
}

/**
 * @brief Calculate hash for target (IP + port)
 */
static inline uint32_t hash_target(uint32_t target_ip, uint16_t target_port)
{
    uint64_t key = ((uint64_t)target_ip << 16) | target_port;
    return rte_jhash(&key, sizeof(key), 0) % TRACKER_HASH_SIZE;
}

/**
 * @brief Calculate hash for flow pair (src_ip + dst_ip)
 */
static inline uint32_t hash_flow_pair(uint32_t src_ip, uint32_t dst_ip)
{
    uint64_t key = ((uint64_t)src_ip << 32) | dst_ip;
    return rte_jhash(&key, sizeof(key), 0) % TRACKER_HASH_SIZE;
}

/**
 * @brief Check if time is within window
 */
static inline bool is_within_window(time_t current, time_t first, time_t window_sec)
{
    return (current - first) <= window_sec;
}

/**
 * @brief Get current time
 */
static inline time_t get_current_time(void)
{
    return time(NULL);
}

/**
 * @brief Get current hour (0-23)
 */
static inline int get_current_hour(void)
{
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    return tm_info->tm_hour;
}

/**
 * @brief Get IPv4 address from flow address (assumes IPv4)
 */
static inline uint32_t get_ipv4_addr(const flow_address_t *addr)
{
    return addr->addr_data32[0];
}

/**
 * @brief Convert IP address to string
 */
static void ip_to_str(uint32_t ip, char *buf, size_t buflen)
{
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &addr, buf, buflen);
}

/**
 * @brief Age out expired port scan trackers
 */
static void age_port_scan_trackers(behavioral_detector_t *detector)
{
    time_t now = get_current_time();

    for (uint32_t i = 0; i < TRACKER_HASH_SIZE; i++) {
        port_scan_tracker_t **prev = &detector->scan_trackers[i];
        port_scan_tracker_t *tracker = detector->scan_trackers[i];

        while (tracker != NULL) {
            /* Age out trackers older than 5 minutes */
            if ((now - tracker->last_seen) > 300) {
                port_scan_tracker_t *old = tracker;
                *prev = tracker->next;
                tracker = tracker->next;
                rte_free(old);
            } else {
                prev = &tracker->next;
                tracker = tracker->next;
            }
        }
    }
}

/**
 * @brief Age out expired brute force trackers
 */
static void age_brute_force_trackers(behavioral_detector_t *detector)
{
    time_t now = get_current_time();

    for (uint32_t i = 0; i < TRACKER_HASH_SIZE; i++) {
        brute_force_tracker_t **prev = &detector->brute_trackers[i];
        brute_force_tracker_t *tracker = detector->brute_trackers[i];

        while (tracker != NULL) {
            /* Age out trackers older than 10 minutes */
            if ((now - tracker->window_start) > 600) {
                brute_force_tracker_t *old = tracker;
                *prev = tracker->next;
                tracker = tracker->next;
                rte_free(old);
            } else {
                prev = &tracker->next;
                tracker = tracker->next;
            }
        }
    }
}

/**
 * @brief Age out expired data exfiltration trackers
 */
static void age_exfil_trackers(behavioral_detector_t *detector)
{
    time_t now = get_current_time();

    for (uint32_t i = 0; i < TRACKER_HASH_SIZE; i++) {
        data_exfil_tracker_t **prev = &detector->exfil_trackers[i];
        data_exfil_tracker_t *tracker = detector->exfil_trackers[i];

        while (tracker != NULL) {
            /* Age out trackers older than 30 minutes */
            if ((now - tracker->window_start) > 1800) {
                data_exfil_tracker_t *old = tracker;
                *prev = tracker->next;
                tracker = tracker->next;
                rte_free(old);
            } else {
                prev = &tracker->next;
                tracker = tracker->next;
            }
        }
    }
}

/**
 * @brief Age out expired traffic anomaly trackers
 */
static void age_anomaly_trackers(behavioral_detector_t *detector)
{
    time_t now = get_current_time();

    for (uint32_t i = 0; i < TRACKER_HASH_SIZE; i++) {
        traffic_anomaly_tracker_t **prev = &detector->anomaly_trackers[i];
        traffic_anomaly_tracker_t *tracker = detector->anomaly_trackers[i];

        while (tracker != NULL) {
            /* Age out trackers older than 5 minutes */
            if ((now - tracker->window_start) > 300) {
                traffic_anomaly_tracker_t *old = tracker;
                *prev = tracker->next;
                tracker = tracker->next;
                rte_free(old);
            } else {
                prev = &tracker->next;
                tracker = tracker->next;
            }
        }
    }
}

/* ==========================================================================
 * Port Scan Detection
 * ========================================================================== */

/**
 * @brief Find or create port scan tracker for source IP
 */
static port_scan_tracker_t *get_port_scan_tracker(behavioral_detector_t *detector,
                                                    uint32_t src_ip, bool create)
{
    uint32_t hash = hash_src_ip(src_ip);
    port_scan_tracker_t *tracker = detector->scan_trackers[hash];

    /* Search for existing tracker */
    while (tracker != NULL) {
        if (tracker->src_ip == src_ip) {
            return tracker;
        }
        tracker = tracker->next;
    }

    /* Create new tracker if requested */
    if (create) {
        tracker = rte_zmalloc("port_scan_tracker", sizeof(port_scan_tracker_t), 0);
        if (tracker == NULL) {
            RTE_LOG(ERR, BEHAVIORAL, "Failed to allocate port scan tracker\n");
            return NULL;
        }

        tracker->src_ip = src_ip;
        tracker->first_seen = get_current_time();
        tracker->last_seen = tracker->first_seen;
        tracker->port_count = 0;
        tracker->syn_count = 0;
        tracker->syn_ack_count = 0;
        tracker->is_syn_scan = false;
        tracker->alerted = false;

        /* Insert at head of hash chain */
        tracker->next = detector->scan_trackers[hash];
        detector->scan_trackers[hash] = tracker;
    }

    return tracker;
}

/**
 * @brief Add port to tracker's port list
 */
static bool add_port_to_tracker(port_scan_tracker_t *tracker, uint16_t port)
{
    /* Check if port already tracked */
    for (uint16_t i = 0; i < tracker->port_count; i++) {
        if (tracker->ports_contacted[i] == port) {
            return false;  /* Already tracked */
        }
    }

    /* Add new port if space available */
    if (tracker->port_count < MAX_TRACKED_PORTS) {
        tracker->ports_contacted[tracker->port_count++] = port;
        return true;
    }

    return false;
}

/**
 * @brief Detect port scanning activity
 */
static void detect_port_scan(behavioral_detector_t *detector, flow_t *flow,
                               const uint8_t *tcp_flags)
{
    if (flow->proto != IPPROTO_TCP || tcp_flags == NULL) {
        return;
    }

    time_t now = get_current_time();
    uint32_t src_ip = get_ipv4_addr(&flow->src_addr);
    port_scan_tracker_t *tracker = get_port_scan_tracker(detector, src_ip, true);

    if (tracker == NULL) {
        return;
    }

    /* Reset tracker if outside time window */
    if (!is_within_window(now, tracker->first_seen, PORT_SCAN_WINDOW)) {
        tracker->first_seen = now;
        tracker->port_count = 0;
        tracker->syn_count = 0;
        tracker->syn_ack_count = 0;
        tracker->is_syn_scan = false;
        tracker->alerted = false;
    }

    tracker->last_seen = now;

    /* Track SYN packets (potential scan probe) */
    if (*tcp_flags & 0x02) {  /* SYN flag */
        tracker->syn_count++;

        /* Add destination port to tracked ports */
        bool new_port = add_port_to_tracker(tracker, flow->dst_port);

        /* Detect SYN scan pattern */
        if ((*tcp_flags & 0x10) == 0) {  /* No ACK flag = SYN-only */
            tracker->is_syn_scan = true;
        }

        /* Check if port scan threshold reached */
        if (new_port && tracker->port_count >= PORT_SCAN_THRESHOLD && !tracker->alerted) {
            /* Generate alert */
            char detail[256];
            char src_ip_str[INET_ADDRSTRLEN];
            ip_to_str(src_ip, src_ip_str, sizeof(src_ip_str));

            snprintf(detail, sizeof(detail),
                     "Port scan detected from %s: %u ports in %ld seconds (SYN scan: %s)",
                     src_ip_str, tracker->port_count,
                     (long)(now - tracker->first_seen),
                     tracker->is_syn_scan ? "yes" : "no");

            /* Create detection rule for alert */
            detection_rule_t scan_rule = {
                .rule_id = 9000,
                .enabled = true,
                .severity = ALERT_SEVERITY_HIGH,
                .category = ALERT_CATEGORY_SCAN,
            };
            scan_rule.name = rte_malloc("name", 32, 0);
            if (scan_rule.name) {
                strcpy(scan_rule.name, "Port Scan Detected");
            }

            rule_engine_create_custom_alert(detector->rule_engine, &scan_rule,
                                           flow, detail);

            tracker->alerted = true;
            detector->scans_detected++;

            RTE_LOG(WARNING, BEHAVIORAL,
                    "Port scan: %s contacted %u ports in %ld seconds\n",
                    src_ip_str, tracker->port_count, (long)(now - tracker->first_seen));
        }
    }

    /* Track SYN-ACK packets (scan response) */
    if ((*tcp_flags & 0x12) == 0x12) {  /* SYN+ACK */
        tracker->syn_ack_count++;
    }
}

/* ==========================================================================
 * Brute Force Detection
 * ========================================================================== */

/**
 * @brief Find or create brute force tracker
 */
static brute_force_tracker_t *get_brute_force_tracker(behavioral_detector_t *detector,
                                                       uint32_t target_ip,
                                                       uint16_t target_port,
                                                       bool create)
{
    uint32_t hash = hash_target(target_ip, target_port);
    brute_force_tracker_t *tracker = detector->brute_trackers[hash];

    /* Search for existing tracker */
    while (tracker != NULL) {
        if (tracker->target_ip == target_ip && tracker->target_port == target_port) {
            return tracker;
        }
        tracker = tracker->next;
    }

    /* Create new tracker if requested */
    if (create) {
        tracker = rte_zmalloc("brute_force_tracker", sizeof(brute_force_tracker_t), 0);
        if (tracker == NULL) {
            RTE_LOG(ERR, BEHAVIORAL, "Failed to allocate brute force tracker\n");
            return NULL;
        }

        tracker->target_ip = target_ip;
        tracker->target_port = target_port;
        tracker->window_start = get_current_time();
        tracker->last_attempt = tracker->window_start;
        tracker->failed_attempts = 0;
        tracker->alerted = false;
        memset(&tracker->proto, 0, sizeof(tracker->proto));

        /* Insert at head of hash chain */
        tracker->next = detector->brute_trackers[hash];
        detector->brute_trackers[hash] = tracker;
    }

    return tracker;
}

/**
 * @brief Detect brute force attacks on HTTP
 */
static void detect_brute_force_http(behavioral_detector_t *detector, flow_t *flow,
                                     http_transaction_t *tx)
{
    /* Check if response exists and is auth failure */
    if (!tx->response || (tx->response->status_code != 401 && tx->response->status_code != 403)) {
        return;  /* Only track auth failures */
    }

    time_t now = get_current_time();
    uint32_t dst_ip = get_ipv4_addr(&flow->dst_addr);
    brute_force_tracker_t *tracker = get_brute_force_tracker(detector,
                                                              dst_ip,
                                                              flow->dst_port,
                                                              true);

    if (tracker == NULL) {
        return;
    }

    /* Reset tracker if outside time window */
    if (!is_within_window(now, tracker->window_start, BRUTE_FORCE_WINDOW)) {
        tracker->window_start = now;
        tracker->failed_attempts = 0;
        tracker->proto.http.http_401_count = 0;
        tracker->proto.http.http_403_count = 0;
        tracker->alerted = false;
    }

    tracker->last_attempt = now;
    tracker->failed_attempts++;

    if (tx->response->status_code == 401) {
        tracker->proto.http.http_401_count++;
    } else if (tx->response->status_code == 403) {
        tracker->proto.http.http_403_count++;
    }

    /* Check if brute force threshold reached */
    if (tracker->failed_attempts >= BRUTE_FORCE_THRESHOLD && !tracker->alerted) {
        char detail[256];
        char target_ip_str[INET_ADDRSTRLEN];
        ip_to_str(dst_ip, target_ip_str, sizeof(target_ip_str));

        snprintf(detail, sizeof(detail),
                 "HTTP brute force attack against %s:%u - %u failed attempts "
                 "(401: %u, 403: %u) in %ld seconds",
                 target_ip_str, flow->dst_port, tracker->failed_attempts,
                 tracker->proto.http.http_401_count,
                 tracker->proto.http.http_403_count,
                 (long)(now - tracker->window_start));

        detection_rule_t brute_rule = {
            .rule_id = 9001,
            .enabled = true,
            .severity = ALERT_SEVERITY_HIGH,
            .category = ALERT_CATEGORY_BRUTE_FORCE,
        };
        brute_rule.name = rte_malloc("name", 32, 0);
        if (brute_rule.name) {
            strcpy(brute_rule.name, "HTTP Brute Force Attack");
        }

        rule_engine_create_custom_alert(detector->rule_engine, &brute_rule,
                                       flow, detail);

        tracker->alerted = true;
        detector->brute_forces_detected++;

        RTE_LOG(WARNING, BEHAVIORAL,
                "Brute force: %s:%u received %u auth failures in %ld seconds\n",
                target_ip_str, flow->dst_port, tracker->failed_attempts,
                (long)(now - tracker->window_start));
    }
}

/**
 * @brief Detect brute force attacks
 */
static void detect_brute_force(behavioral_detector_t *detector, flow_t *flow)
{
    /* HTTP brute force detection */
    if (flow->alproto == APP_PROTO_HTTP && flow->protoctx.tcp != NULL &&
        flow->protoctx.tcp->app_parser != NULL) {

        http_conn_t *http_conn = (http_conn_t *)flow->protoctx.tcp->app_parser;
        http_transaction_t *tx = http_conn->transactions;

        while (tx != NULL) {
            detect_brute_force_http(detector, flow, tx);
            tx = tx->next;
        }
    }

    /* TODO: Add SSH, FTP, RDP brute force detection */
}

/* ==========================================================================
 * Data Exfiltration Detection
 * ========================================================================== */

/**
 * @brief Find or create data exfiltration tracker
 */
static data_exfil_tracker_t *get_exfil_tracker(behavioral_detector_t *detector,
                                                uint32_t src_ip, uint32_t dst_ip,
                                                bool create)
{
    uint32_t hash = hash_flow_pair(src_ip, dst_ip);
    data_exfil_tracker_t *tracker = detector->exfil_trackers[hash];

    /* Search for existing tracker */
    while (tracker != NULL) {
        if (tracker->src_ip == src_ip && tracker->dst_ip == dst_ip) {
            return tracker;
        }
        tracker = tracker->next;
    }

    /* Create new tracker if requested */
    if (create) {
        tracker = rte_zmalloc("data_exfil_tracker", sizeof(data_exfil_tracker_t), 0);
        if (tracker == NULL) {
            RTE_LOG(ERR, BEHAVIORAL, "Failed to allocate exfil tracker\n");
            return NULL;
        }

        tracker->src_ip = src_ip;
        tracker->dst_ip = dst_ip;
        tracker->window_start = get_current_time();
        tracker->last_transfer = tracker->window_start;
        tracker->bytes_transferred = 0;
        tracker->packet_count = 0;
        tracker->off_hours = IS_OFF_HOURS(get_current_hour());
        tracker->alerted = false;

        /* Insert at head of hash chain */
        tracker->next = detector->exfil_trackers[hash];
        detector->exfil_trackers[hash] = tracker;
    }

    return tracker;
}

/**
 * @brief Detect data exfiltration
 */
static void detect_data_exfiltration(behavioral_detector_t *detector, flow_t *flow,
                                      uint32_t bytes_transferred)
{
    time_t now = get_current_time();
    int current_hour = get_current_hour();

    uint32_t src_ip = get_ipv4_addr(&flow->src_addr);
    uint32_t dst_ip = get_ipv4_addr(&flow->dst_addr);

    data_exfil_tracker_t *tracker = get_exfil_tracker(detector, src_ip, dst_ip, true);

    if (tracker == NULL) {
        return;
    }

    /* Reset tracker if outside time window */
    if (!is_within_window(now, tracker->window_start, DATA_EXFIL_WINDOW)) {
        tracker->window_start = now;
        tracker->bytes_transferred = 0;
        tracker->packet_count = 0;
        tracker->off_hours = IS_OFF_HOURS(current_hour);
        tracker->alerted = false;
    }

    tracker->last_transfer = now;
    tracker->bytes_transferred += bytes_transferred;
    tracker->packet_count++;

    /* Update off-hours flag */
    if (IS_OFF_HOURS(current_hour)) {
        tracker->off_hours = true;
    }

    /* Check if exfiltration threshold reached */
    bool suspicious = false;
    char reason[128] = {0};
    bool is_external = IS_EXTERNAL_IP(dst_ip);

    /* Large data transfer to external IP */
    if (tracker->bytes_transferred >= DATA_EXFIL_THRESHOLD &&
        is_external && !tracker->alerted) {
        suspicious = true;
        snprintf(reason, sizeof(reason),
                 "large transfer to external IP (%lu MB)",
                 tracker->bytes_transferred / (1024 * 1024));
    }

    /* Off-hours transfer (even smaller amounts are suspicious) */
    if (tracker->off_hours && tracker->bytes_transferred >= (DATA_EXFIL_THRESHOLD / 10) &&
        !tracker->alerted) {
        suspicious = true;
        snprintf(reason, sizeof(reason),
                 "off-hours transfer (%lu MB during 22:00-06:00)",
                 tracker->bytes_transferred / (1024 * 1024));
    }

    if (suspicious) {
        char detail[512];
        char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
        ip_to_str(src_ip, src_ip_str, sizeof(src_ip_str));
        ip_to_str(dst_ip, dst_ip_str, sizeof(dst_ip_str));

        snprintf(detail, sizeof(detail),
                 "Potential data exfiltration: %s -> %s, %s, "
                 "%u packets in %ld seconds",
                 src_ip_str, dst_ip_str, reason,
                 tracker->packet_count, (long)(now - tracker->window_start));

        detection_rule_t exfil_rule = {
            .rule_id = 9002,
            .enabled = true,
            .severity = ALERT_SEVERITY_CRITICAL,
            .category = ALERT_CATEGORY_EXFILTRATION,
        };
        exfil_rule.name = rte_malloc("name", 32, 0);
        if (exfil_rule.name) {
            strcpy(exfil_rule.name, "Potential Data Exfiltration");
        }

        rule_engine_create_custom_alert(detector->rule_engine, &exfil_rule,
                                       flow, detail);

        tracker->alerted = true;
        detector->exfiltrations_detected++;

        RTE_LOG(WARNING, BEHAVIORAL,
                "Data exfiltration: %s -> %s, %s\n",
                src_ip_str, dst_ip_str, reason);
    }
}

/* ==========================================================================
 * Traffic Anomaly Detection
 * ========================================================================== */

/**
 * @brief Find or create traffic anomaly tracker
 */
static traffic_anomaly_tracker_t *get_anomaly_tracker(behavioral_detector_t *detector,
                                                       uint32_t src_ip,
                                                       bool create)
{
    uint32_t hash = hash_src_ip(src_ip);
    traffic_anomaly_tracker_t *tracker = detector->anomaly_trackers[hash];

    /* Search for existing tracker */
    while (tracker != NULL) {
        if (tracker->src_ip == src_ip) {
            return tracker;
        }
        tracker = tracker->next;
    }

    /* Create new tracker if requested */
    if (create) {
        tracker = rte_zmalloc("anomaly_tracker", sizeof(traffic_anomaly_tracker_t), 0);
        if (tracker == NULL) {
            RTE_LOG(ERR, BEHAVIORAL, "Failed to allocate anomaly tracker\n");
            return NULL;
        }

        tracker->src_ip = src_ip;
        tracker->window_start = get_current_time();
        tracker->large_requests = 0;
        tracker->large_responses = 0;
        tracker->high_freq_queries = 0;
        tracker->weak_ciphers = 0;
        tracker->cert_errors = 0;
        tracker->alerted = false;

        /* Insert at head of hash chain */
        tracker->next = detector->anomaly_trackers[hash];
        detector->anomaly_trackers[hash] = tracker;
    }

    return tracker;
}

/**
 * @brief Detect HTTP anomalies
 */
static void detect_http_anomalies(behavioral_detector_t *detector, flow_t *flow,
                                   http_transaction_t *tx)
{
    uint32_t src_ip = get_ipv4_addr(&flow->src_addr);
    traffic_anomaly_tracker_t *tracker = get_anomaly_tracker(detector, src_ip, true);

    if (tracker == NULL || tx == NULL) {
        return;
    }

    /* Note: HTTP body length tracking would require parsing HTTP headers
     * or tracking stream_buffer sizes. For now, we just track transaction count
     * as a placeholder for future enhancement */
    tracker->large_requests++;

    /* TODO: Implement HTTP body size tracking when content-length parsing is available */
}

/**
 * @brief Detect DNS anomalies
 */
static void detect_dns_anomalies(behavioral_detector_t *detector, flow_t *flow)
{
    if (flow->alproto != APP_PROTO_DNS || flow->protoctx.udp == NULL) {
        return;
    }

    /* UDP app_parser is void*, cast to dns_conn_t */
    void *parser = flow->protoctx.udp;
    if (parser == NULL) {
        return;
    }

    uint32_t src_ip = get_ipv4_addr(&flow->src_addr);
    dns_conn_t *dns_conn = (dns_conn_t *)parser;
    traffic_anomaly_tracker_t *tracker = get_anomaly_tracker(detector, src_ip, true);

    if (tracker == NULL) {
        return;
    }

    time_t now = get_current_time();

    /* Reset window if needed */
    if (!is_within_window(now, tracker->window_start, ANOMALY_WINDOW)) {
        tracker->window_start = now;
        tracker->high_freq_queries = 0;
        tracker->alerted = false;
    }

    /* Count DNS queries */
    dns_transaction_t *tx = dns_conn->transactions;
    while (tx != NULL) {
        tracker->high_freq_queries++;
        tx = tx->next;
    }

    /* Detect high-frequency DNS queries */
    if (tracker->high_freq_queries > DNS_HIGH_FREQ_THRESHOLD && !tracker->alerted) {
        char detail[256];
        char src_ip_str[INET_ADDRSTRLEN];
        ip_to_str(src_ip, src_ip_str, sizeof(src_ip_str));

        snprintf(detail, sizeof(detail),
                 "High-frequency DNS queries from %s: %u queries in %ld seconds",
                 src_ip_str, tracker->high_freq_queries,
                 (long)(now - tracker->window_start));

        detection_rule_t dns_rule = {
            .rule_id = 9004,
            .enabled = true,
            .severity = ALERT_SEVERITY_MEDIUM,
            .category = ALERT_CATEGORY_ANOMALY,
        };
        dns_rule.name = rte_malloc("name", 32, 0);
        if (dns_rule.name) {
            strcpy(dns_rule.name, "DNS High Frequency Anomaly");
        }

        rule_engine_create_custom_alert(detector->rule_engine, &dns_rule,
                                       flow, detail);

        tracker->alerted = true;
        detector->anomalies_detected++;
    }
}

/**
 * @brief Detect TLS anomalies
 */
static void detect_tls_anomalies(behavioral_detector_t *detector, flow_t *flow)
{
    if (flow->alproto != APP_PROTO_TLS || flow->protoctx.tcp == NULL ||
        flow->protoctx.tcp->app_parser == NULL) {
        return;
    }

    uint32_t src_ip = get_ipv4_addr(&flow->src_addr);
    tls_conn_t *tls_conn = (tls_conn_t *)flow->protoctx.tcp->app_parser;
    traffic_anomaly_tracker_t *tracker = get_anomaly_tracker(detector, src_ip, true);

    if (tracker == NULL) {
        return;
    }

    /* Track weak ciphers */
    if (tls_conn->weak_cipher) {
        tracker->weak_ciphers++;
    }

    /* Track certificate errors */
    if (tls_conn->expired_cert || tls_conn->self_signed_cert) {
        tracker->cert_errors++;

        if (!tracker->alerted) {
            char detail[256];
            char src_ip_str[INET_ADDRSTRLEN];
            ip_to_str(src_ip, src_ip_str, sizeof(src_ip_str));

            snprintf(detail, sizeof(detail),
                     "TLS certificate anomaly from %s: %s%s",
                     src_ip_str,
                     tls_conn->expired_cert ? "expired" : "",
                     tls_conn->self_signed_cert ? "self-signed" : "");

            detection_rule_t tls_rule = {
                .rule_id = 9005,
                .enabled = true,
                .severity = ALERT_SEVERITY_MEDIUM,
                .category = ALERT_CATEGORY_ANOMALY,
            };
            tls_rule.name = rte_malloc("name", 32, 0);
            if (tls_rule.name) {
                strcpy(tls_rule.name, "TLS Certificate Anomaly");
            }

            rule_engine_create_custom_alert(detector->rule_engine, &tls_rule,
                                           flow, detail);

            tracker->alerted = true;
            detector->anomalies_detected++;
        }
    }
}

/**
 * @brief Detect traffic anomalies
 */
static void detect_traffic_anomaly(behavioral_detector_t *detector, flow_t *flow)
{
    /* HTTP anomalies */
    if (flow->alproto == APP_PROTO_HTTP && flow->protoctx.tcp != NULL &&
        flow->protoctx.tcp->app_parser != NULL) {

        http_conn_t *http_conn = (http_conn_t *)flow->protoctx.tcp->app_parser;
        http_transaction_t *tx = http_conn->transactions;

        while (tx != NULL) {
            detect_http_anomalies(detector, flow, tx);
            tx = tx->next;
        }
    }

    /* DNS anomalies */
    detect_dns_anomalies(detector, flow);

    /* TLS anomalies */
    detect_tls_anomalies(detector, flow);
}

/* ==========================================================================
 * Main API Functions
 * ========================================================================== */

/**
 * @brief Initialize behavioral detector
 */
behavioral_detector_t *behavioral_detector_init(struct rule_engine *rule_engine)
{
    if (rule_engine == NULL) {
        RTE_LOG(ERR, BEHAVIORAL, "Rule engine is NULL\n");
        return NULL;
    }

    behavioral_detector_t *detector = rte_zmalloc("behavioral_detector",
                                                   sizeof(behavioral_detector_t),
                                                   0);
    if (detector == NULL) {
        RTE_LOG(ERR, BEHAVIORAL, "Failed to allocate behavioral detector\n");
        return NULL;
    }

    /* Initialize hash tables */
    memset(detector->scan_trackers, 0, sizeof(detector->scan_trackers));
    memset(detector->brute_trackers, 0, sizeof(detector->brute_trackers));
    memset(detector->exfil_trackers, 0, sizeof(detector->exfil_trackers));
    memset(detector->anomaly_trackers, 0, sizeof(detector->anomaly_trackers));

    detector->rule_engine = rule_engine;

    /* Initialize statistics */
    detector->scans_detected = 0;
    detector->brute_forces_detected = 0;
    detector->exfiltrations_detected = 0;
    detector->anomalies_detected = 0;

    RTE_LOG(INFO, BEHAVIORAL, "Behavioral detector initialized\n");

    return detector;
}

/**
 * @brief Free behavioral detector
 */
void behavioral_detector_free(behavioral_detector_t *detector)
{
    if (detector == NULL) {
        return;
    }

    /* Free all port scan trackers */
    for (uint32_t i = 0; i < TRACKER_HASH_SIZE; i++) {
        port_scan_tracker_t *tracker = detector->scan_trackers[i];
        while (tracker != NULL) {
            port_scan_tracker_t *next = tracker->next;
            rte_free(tracker);
            tracker = next;
        }
    }

    /* Free all brute force trackers */
    for (uint32_t i = 0; i < TRACKER_HASH_SIZE; i++) {
        brute_force_tracker_t *tracker = detector->brute_trackers[i];
        while (tracker != NULL) {
            brute_force_tracker_t *next = tracker->next;
            rte_free(tracker);
            tracker = next;
        }
    }

    /* Free all data exfiltration trackers */
    for (uint32_t i = 0; i < TRACKER_HASH_SIZE; i++) {
        data_exfil_tracker_t *tracker = detector->exfil_trackers[i];
        while (tracker != NULL) {
            data_exfil_tracker_t *next = tracker->next;
            rte_free(tracker);
            tracker = next;
        }
    }

    /* Free all traffic anomaly trackers */
    for (uint32_t i = 0; i < TRACKER_HASH_SIZE; i++) {
        traffic_anomaly_tracker_t *tracker = detector->anomaly_trackers[i];
        while (tracker != NULL) {
            traffic_anomaly_tracker_t *next = tracker->next;
            rte_free(tracker);
            tracker = next;
        }
    }

    rte_free(detector);

    RTE_LOG(INFO, BEHAVIORAL, "Behavioral detector freed\n");
}

/**
 * @brief Inspect packet for behavioral anomalies
 */
void behavioral_detector_inspect_packet(behavioral_detector_t *detector,
                                         flow_t *flow,
                                         const uint8_t *packet,
                                         uint32_t packet_len,
                                         const uint8_t *tcp_flags)
{
    if (detector == NULL || flow == NULL) {
        return;
    }

    static uint64_t packet_count = 0;

    /* Age out old trackers periodically (every 10000 packets) */
    if ((++packet_count % 10000) == 0) {
        age_port_scan_trackers(detector);
        age_brute_force_trackers(detector);
        age_exfil_trackers(detector);
        age_anomaly_trackers(detector);
    }

    /* Port scan detection (TCP only) */
    detect_port_scan(detector, flow, tcp_flags);

    /* Brute force detection */
    detect_brute_force(detector, flow);

    /* Data exfiltration detection (track all bytes) */
    if (packet_len > 0) {
        detect_data_exfiltration(detector, flow, packet_len);
    }

    /* Traffic anomaly detection */
    detect_traffic_anomaly(detector, flow);
}

/**
 * @brief Get behavioral detector statistics
 */
void behavioral_detector_get_stats(behavioral_detector_t *detector, char *buf,
                                    size_t buflen)
{
    if (detector == NULL || buf == NULL || buflen == 0) {
        return;
    }

    /* Count active trackers */
    uint32_t scan_tracker_count = 0;
    for (uint32_t i = 0; i < TRACKER_HASH_SIZE; i++) {
        port_scan_tracker_t *tracker = detector->scan_trackers[i];
        while (tracker != NULL) {
            scan_tracker_count++;
            tracker = tracker->next;
        }
    }

    uint32_t brute_tracker_count = 0;
    for (uint32_t i = 0; i < TRACKER_HASH_SIZE; i++) {
        brute_force_tracker_t *tracker = detector->brute_trackers[i];
        while (tracker != NULL) {
            brute_tracker_count++;
            tracker = tracker->next;
        }
    }

    uint32_t exfil_tracker_count = 0;
    for (uint32_t i = 0; i < TRACKER_HASH_SIZE; i++) {
        data_exfil_tracker_t *tracker = detector->exfil_trackers[i];
        while (tracker != NULL) {
            exfil_tracker_count++;
            tracker = tracker->next;
        }
    }

    uint32_t anomaly_tracker_count = 0;
    for (uint32_t i = 0; i < TRACKER_HASH_SIZE; i++) {
        traffic_anomaly_tracker_t *tracker = detector->anomaly_trackers[i];
        while (tracker != NULL) {
            anomaly_tracker_count++;
            tracker = tracker->next;
        }
    }

    snprintf(buf, buflen,
             "Behavioral Detector Statistics:\n"
             "  Port Scans Detected:      %lu\n"
             "  Brute Forces Detected:    %lu\n"
             "  Exfiltrations Detected:   %lu\n"
             "  Anomalies Detected:       %lu\n"
             "  Active Scan Trackers:     %u\n"
             "  Active Brute Trackers:    %u\n"
             "  Active Exfil Trackers:    %u\n"
             "  Active Anomaly Trackers:  %u\n",
             detector->scans_detected,
             detector->brute_forces_detected,
             detector->exfiltrations_detected,
             detector->anomalies_detected,
             scan_tracker_count,
             brute_tracker_count,
             exfil_tracker_count,
             anomaly_tracker_count);
}
