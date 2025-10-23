/*
 * NetDefender - Behavioral Anomaly Detector
 *
 * This module provides behavioral analysis for detecting:
 * - Port scanning
 * - Brute force attacks
 * - Data exfiltration
 * - Traffic anomalies
 */

#ifndef __BEHAVIORAL_DETECTOR_H__
#define __BEHAVIORAL_DETECTOR_H__

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Forward declarations */
struct flow;
struct packet_info;
struct http_transaction;
struct rule_engine;

/* Configuration constants */
#define PORT_SCAN_WINDOW        60      /* Time window in seconds */
#define PORT_SCAN_THRESHOLD     10      /* Ports to trigger alert */
#define BRUTE_FORCE_WINDOW      600     /* 10 minutes */
#define BRUTE_FORCE_THRESHOLD   5       /* Failed attempts */
#define DATA_EXFIL_WINDOW       600     /* 10 minutes */
#define DATA_EXFIL_THRESHOLD    (100 * 1024 * 1024)  /* 100MB */
#define TRACKER_HASH_SIZE       1024    /* Hash table size */
#define MAX_TRACKED_PORTS       1024    /* Max ports per scanner */

/* Traffic anomaly thresholds */
#define HTTP_LARGE_REQUEST_SIZE     (10 * 1024 * 1024)  /* 10MB */
#define HTTP_LARGE_RESPONSE_SIZE    (50 * 1024 * 1024)  /* 50MB */
#define DNS_HIGH_FREQ_THRESHOLD     100                  /* Queries per minute */
#define ANOMALY_WINDOW              300                  /* 5 minutes */

/* ============================================================================
 * Port Scan Detection
 * ============================================================================ */

typedef struct port_scan_tracker {
    uint32_t src_ip;                    /* Scanner source IP */
    uint16_t ports_contacted[MAX_TRACKED_PORTS];  /* Contacted ports */
    uint16_t port_count;                /* Number of unique ports */

    time_t first_seen;                  /* First packet timestamp */
    time_t last_seen;                   /* Last packet timestamp */

    uint32_t syn_count;                 /* SYN packets sent */
    uint32_t syn_ack_count;             /* SYN-ACK responses received */
    uint32_t established_count;         /* Established connections */

    bool is_syn_scan;                   /* SYN scan detected */
    bool alerted;                       /* Alert already generated */

    struct port_scan_tracker *next;     /* Next in hash bucket */
} port_scan_tracker_t;

/* ============================================================================
 * Brute Force Detection
 * ============================================================================ */

typedef struct brute_force_tracker {
    uint32_t target_ip;                 /* Target IP */
    uint16_t target_port;               /* Target port */

    uint32_t failed_attempts;           /* Failed authentication count */
    uint32_t success_attempts;          /* Successful authentications */

    time_t window_start;                /* Time window start */
    time_t last_attempt;                /* Last attempt timestamp */

    bool alerted;                       /* Alert already generated */

    /* Protocol-specific */
    union {
        struct {
            uint32_t http_401_count;    /* HTTP 401 Unauthorized */
            uint32_t http_403_count;    /* HTTP 403 Forbidden */
        } http;
        struct {
            uint32_t failed_logins;     /* SSH failed logins */
        } ssh;
    } proto;

    struct brute_force_tracker *next;   /* Next in hash bucket */
} brute_force_tracker_t;

/* ============================================================================
 * Data Exfiltration Detection
 * ============================================================================ */

typedef struct data_exfil_tracker {
    uint32_t src_ip;                    /* Internal source IP */
    uint32_t dst_ip;                    /* External destination IP */

    uint64_t bytes_transferred;         /* Total bytes sent */
    uint32_t flow_count;                /* Number of flows */
    uint32_t packet_count;              /* Number of packets */

    time_t window_start;                /* Time window start */
    time_t last_transfer;               /* Last transfer timestamp */

    uint8_t protocol;                   /* Protocol used (TCP/UDP) */
    uint16_t app_proto;                 /* Application protocol */

    bool alerted;                       /* Alert already generated */
    bool non_standard_protocol;         /* Using non-HTTP/HTTPS */
    bool off_hours;                     /* Transfer during off-hours */

    struct data_exfil_tracker *next;    /* Next in hash bucket */
} data_exfil_tracker_t;

/* ============================================================================
 * Traffic Anomaly Detection
 * ============================================================================ */

typedef struct traffic_anomaly_tracker {
    uint32_t src_ip;                    /* Source IP */

    /* HTTP anomalies */
    uint32_t large_requests;            /* Abnormally large requests */
    uint32_t large_responses;           /* Abnormally large responses */
    uint64_t total_request_size;        /* Total request bytes */
    uint64_t total_response_size;       /* Total response bytes */

    /* DNS anomalies */
    uint32_t high_freq_queries;         /* High frequency queries */
    uint32_t nxdomain_count;            /* Non-existent domain queries */
    uint32_t total_queries;             /* Total DNS queries */

    /* TLS anomalies */
    uint32_t cert_errors;               /* Certificate errors */
    uint32_t version_downgrades;        /* TLS version downgrades */
    uint32_t weak_ciphers;              /* Weak cipher suite usage */

    time_t window_start;                /* Time window start */
    time_t last_seen;                   /* Last activity */

    bool alerted;                       /* Alert already generated */

    struct traffic_anomaly_tracker *next;  /* Next in hash bucket */
} traffic_anomaly_tracker_t;

/* ============================================================================
 * Main Behavioral Detector
 * ============================================================================ */

typedef struct behavioral_detector {
    /* Tracker hash tables */
    port_scan_tracker_t *scan_trackers[TRACKER_HASH_SIZE];
    brute_force_tracker_t *brute_trackers[TRACKER_HASH_SIZE];
    data_exfil_tracker_t *exfil_trackers[TRACKER_HASH_SIZE];
    traffic_anomaly_tracker_t *anomaly_trackers[TRACKER_HASH_SIZE];

    /* Configuration thresholds */
    uint32_t port_scan_threshold;       /* Ports to trigger alert */
    uint32_t brute_force_threshold;     /* Failed attempts */
    uint64_t data_exfil_threshold;      /* Bytes threshold */
    uint32_t dns_freq_threshold;        /* DNS queries per minute */
    uint64_t http_request_size_threshold;   /* Max request size */
    uint64_t http_response_size_threshold;  /* Max response size */

    /* Time windows */
    uint32_t port_scan_window;          /* Seconds */
    uint32_t brute_force_window;        /* Seconds */
    uint32_t data_exfil_window;         /* Seconds */
    uint32_t traffic_anomaly_window;    /* Seconds */

    /* Rule engine reference (for alert generation) */
    struct rule_engine *rule_engine;

    /* Statistics */
    uint64_t scans_detected;
    uint64_t brute_forces_detected;
    uint64_t exfiltrations_detected;
    uint64_t anomalies_detected;

    uint64_t trackers_created;
    uint64_t trackers_expired;

    /* Last cleanup time */
    time_t last_cleanup;
} behavioral_detector_t;

/* ============================================================================
 * Function Prototypes
 * ============================================================================ */

/**
 * @brief Initialize behavioral detector
 * @param rule_engine Rule engine for alert generation
 * @return Behavioral detector context or NULL on error
 */
behavioral_detector_t *behavioral_detector_init(struct rule_engine *rule_engine);

/**
 * @brief Free behavioral detector
 * @param detector Behavioral detector context
 */
void behavioral_detector_free(behavioral_detector_t *detector);

/**
 * @brief Inspect packet for behavioral anomalies
 * @param detector Behavioral detector context
 * @param flow Flow structure
 * @param packet Packet data
 * @param packet_len Packet length
 * @param tcp_flags TCP flags (NULL if not TCP)
 */
void behavioral_detector_inspect_packet(behavioral_detector_t *detector,
                                        struct flow *flow,
                                        const uint8_t *packet,
                                        uint32_t packet_len,
                                        const uint8_t *tcp_flags);

/**
 * @brief Inspect HTTP transaction for brute force
 * @param detector Behavioral detector context
 * @param flow Flow structure
 * @param http_tx HTTP transaction
 */
void behavioral_detector_inspect_http(behavioral_detector_t *detector,
                                      struct flow *flow,
                                      struct http_transaction *http_tx);

/**
 * @brief Get detector statistics
 * @param detector Behavioral detector context
 * @param buf Output buffer
 * @param buflen Buffer length
 */
void behavioral_detector_get_stats(behavioral_detector_t *detector,
                                   char *buf, size_t buflen);

/**
 * @brief Check if time is off-hours (10PM - 6AM)
 * @param timestamp Time to check
 * @return true if off-hours
 */
bool is_off_hours(time_t timestamp);

/**
 * @brief Calculate hash for IP address
 * @param ip IP address
 * @return Hash value
 */
static inline uint32_t ip_hash(uint32_t ip) {
    return ip % TRACKER_HASH_SIZE;
}

/**
 * @brief Calculate hash for IP pair
 * @param ip1 First IP
 * @param ip2 Second IP
 * @return Hash value
 */
static inline uint32_t ip_pair_hash(uint32_t ip1, uint32_t ip2) {
    return (ip1 ^ ip2) % TRACKER_HASH_SIZE;
}

#endif /* __BEHAVIORAL_DETECTOR_H__ */
