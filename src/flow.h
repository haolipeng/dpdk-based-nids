/*
 * NetDefender - Flow Management
 *
 * Based on Suricata's flow management, simplified for our use case
 */

#ifndef __FLOW_H__
#define __FLOW_H__

#include <stdint.h>
#include <sys/time.h>
#include <pthread.h>
#include <netinet/in.h>
#include "app_proto.h"

/* Forward declarations */
struct packet_info;
struct stream_buffer;

/* Flow directions */
#define FLOW_DIR_TOSERVER  0
#define FLOW_DIR_TOCLIENT  1

/* Flow flags */
#define FLOW_IPV4          (1 << 0)
#define FLOW_IPV6          (1 << 1)
#define FLOW_TO_SRC_SEEN   (1 << 2)
#define FLOW_TO_DST_SEEN   (1 << 3)

/* TCP states (standard TCP state machine) */
typedef enum {
    TCP_NONE = 0,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_CLOSING,
    TCP_CLOSED,
} tcp_state_t;

/* Flow address (can be IPv4 or IPv6) */
typedef struct flow_address {
    union {
        uint32_t addr_data32[4];  /* For both IPv4 (use [0]) and IPv6 */
        uint16_t addr_data16[8];
        uint8_t  addr_data8[16];
    };
} flow_address_t;

/* TCP session state */
typedef struct tcp_session {
    tcp_state_t state;       /* Current TCP state */

    /* Sequence numbers */
    uint32_t isn;            /* Initial sequence number */
    uint32_t next_seq;       /* Next expected sequence number */
    uint32_t max_ack;        /* Maximum ACK seen */

    /* Window */
    uint16_t window;

    /* Flags */
    uint8_t flags;
#define TCP_SESSION_TS_SEEN  (1 << 0)  /* ToServer packets seen */
#define TCP_SESSION_TC_SEEN  (1 << 1)  /* ToClient packets seen */

    /* Statistics */
    uint64_t seg_cnt;        /* Segment count */
    uint64_t byte_cnt;       /* Byte count */

    /* Stream reassembly buffers (bidirectional) */
    struct stream_buffer *toserver_sb;   /* Client -> Server reassembly */
    struct stream_buffer *toclient_sb;   /* Server -> Client reassembly */

    /* Application layer parsers */
    void *app_parser;                    /* Application-specific parser (e.g., http_conn_t) */

} tcp_session_t;

/* Flow structure - represents a bidirectional network flow */
typedef struct flow {
    /* Flow 5-tuple (immutable after creation) */
    flow_address_t src_addr;
    flow_address_t dst_addr;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;           /* IPPROTO_TCP, IPPROTO_UDP, etc. */

    /* Flow metadata */
    uint32_t flags;
    uint32_t flow_hash;      /* Hash value for this flow */

    /* Timestamps */
    struct timeval start_ts; /* Flow start time */
    struct timeval last_ts;  /* Last packet time */
    uint32_t timeout_policy; /* Timeout in seconds */

    /* Protocol-specific context */
    union {
        tcp_session_t *tcp;
        void *udp;           /* For future use */
    } protoctx;

    /* Application layer protocol detection */
    app_proto_t alproto;         /* Detected application protocol */
    uint8_t alproto_ts;          /* ToServer proto detection attempts */
    uint8_t alproto_tc;          /* ToClient proto detection attempts */
#define FLOW_ALPROTO_MAX_ATTEMPTS 5  /* Max detection attempts per direction */

    /* Statistics */
    uint64_t toserver_pkt_cnt;
    uint64_t toclient_pkt_cnt;
    uint64_t toserver_byte_cnt;
    uint64_t toclient_byte_cnt;

    /* Reference counting */
    uint16_t use_cnt;

    /* Hash table linkage */
    struct flow *next;       /* Next flow in hash bucket */

    /* Thread safety */
    pthread_mutex_t lock;

} flow_t;

/* Flow hash table bucket */
typedef struct flow_bucket {
    flow_t *head;            /* Head of flow list */
    pthread_mutex_t lock;    /* Bucket lock */
} flow_bucket_t;

/* Flow table configuration */
typedef struct flow_config {
    uint32_t hash_size;      /* Size of hash table */
    uint32_t max_flows;      /* Maximum number of flows */
    uint32_t timeout_new;    /* Timeout for new flows (seconds) */
    uint32_t timeout_est;    /* Timeout for established flows (seconds) */
    uint64_t flow_memcap;    /* Memory cap for flows */
} flow_config_t;

/* Flow table statistics */
typedef struct flow_stats {
    uint64_t flows_created;
    uint64_t flows_removed;
    uint64_t flows_timeout;
    uint64_t flows_active;
    uint64_t hash_collisions;
} flow_stats_t;

/* Global flow table */
extern flow_bucket_t *flow_hash_table;
extern flow_config_t flow_config;
extern flow_stats_t flow_stats;

/**
 * @brief Initialize flow management system
 *
 * @param hash_size Size of hash table (must be power of 2)
 * @param max_flows Maximum number of flows
 * @return 0 on success, -1 on error
 */
int flow_init(uint32_t hash_size, uint32_t max_flows);

/**
 * @brief Cleanup flow management system
 */
void flow_cleanup(void);

/**
 * @brief Get or create a flow for a packet
 *
 * @param pkt_info Packet information from decoder
 * @return Pointer to flow, or NULL on error
 */
flow_t *flow_get(const struct packet_info *pkt_info);

/**
 * @brief Update flow with packet information
 *
 * @param flow Flow to update
 * @param pkt_info Packet information
 * @param direction FLOW_DIR_TOSERVER or FLOW_DIR_TOCLIENT
 */
void flow_update(flow_t *flow, const struct packet_info *pkt_info, int direction);

/**
 * @brief Release flow reference (decrement use count)
 *
 * @param flow Flow to release
 */
void flow_release(flow_t *flow);

/**
 * @brief Cleanup expired flows
 *
 * @param now Current time
 * @return Number of flows removed
 */
int flow_cleanup_expired(struct timeval *now);

/**
 * @brief Get flow statistics
 *
 * @param stats Output statistics structure
 */
void flow_get_stats(flow_stats_t *stats);

/**
 * @brief Convert TCP state to string
 *
 * @param state TCP state
 * @return String representation
 */
const char *tcp_state_to_string(tcp_state_t state);

#endif /* __FLOW_H__ */
