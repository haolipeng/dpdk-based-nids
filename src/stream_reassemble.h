/*
 * NetDefender - TCP Stream Reassembly Module
 *
 * This module provides TCP stream reassembly functionality,
 * handling out-of-order segments and producing application-layer data.
 */

#ifndef __STREAM_REASSEMBLE_H__
#define __STREAM_REASSEMBLE_H__

#include <stdint.h>
#include <rte_mbuf.h>

/* Forward declarations */
struct packet_info;

/* OS reassembly policies (different OSes handle overlaps differently) */
typedef enum {
    OS_POLICY_BSD = 0,      /* Default: favor old data */
    OS_POLICY_LINUX,        /* Favor new data */
    OS_POLICY_WINDOWS,      /* Favor new data, different overlap handling */
    OS_POLICY_FIRST,        /* Always favor first seen data */
    OS_POLICY_LAST,         /* Always favor last seen data */
} os_policy_t;

/* TCP segment structure - stores out-of-order segments */
typedef struct tcp_segment {
    uint32_t seq;                   /* Sequence number */
    uint16_t payload_len;           /* Payload length */
    uint8_t *payload;               /* Payload data (owned by this segment) */
    struct tcp_segment *next;       /* Next segment in list */
} tcp_segment_t;

/* Stream buffer - stores reassembled continuous data */
typedef struct stream_buffer {
    uint8_t *data;                  /* Buffer for reassembled data */
    uint32_t size;                  /* Total buffer size */
    uint32_t data_len;              /* Current data length in buffer */

    uint32_t base_seq;              /* Base sequence number (start of buffer) */
    uint32_t next_seq;              /* Next expected sequence number */

    /* Out-of-order segments waiting for reassembly */
    tcp_segment_t *seg_list;        /* Linked list of segments */
    uint32_t seg_count;             /* Number of segments in list */

    /* Configuration */
    os_policy_t os_policy;          /* OS reassembly policy */
    uint32_t max_buffer_size;       /* Maximum buffer size (memory limit) */

    /* Statistics */
    uint64_t total_reassembled;     /* Total bytes reassembled */
    uint64_t overlap_count;         /* Number of overlapping segments */
    uint64_t gap_count;             /* Number of gaps detected */
} stream_buffer_t;

/* Stream reassembly configuration */
typedef struct stream_config {
    uint32_t max_buffer_size;       /* Max buffer per stream (default: 256KB) */
    uint32_t max_segments;          /* Max segments per stream (default: 100) */
    os_policy_t default_policy;     /* Default OS policy */
} stream_config_t;

/**
 * @brief Initialize stream reassembly system
 *
 * @param config Configuration parameters
 * @return 0 on success, -1 on error
 */
int stream_reassemble_init(const stream_config_t *config);

/**
 * @brief Cleanup stream reassembly system
 */
void stream_reassemble_cleanup(void);

/**
 * @brief Initialize a stream buffer
 *
 * @param sb Stream buffer to initialize
 * @param initial_seq Initial sequence number
 * @param policy OS reassembly policy
 * @return 0 on success, -1 on error
 */
int stream_buffer_init(stream_buffer_t *sb, uint32_t initial_seq, os_policy_t policy);

/**
 * @brief Free a stream buffer and all its segments
 *
 * @param sb Stream buffer to free
 */
void stream_buffer_free(stream_buffer_t *sb);

/**
 * @brief Insert a TCP segment into the stream buffer
 *
 * This handles:
 * - In-order segments (immediate reassembly)
 * - Out-of-order segments (queue for later)
 * - Overlapping segments (according to OS policy)
 * - Retransmissions
 *
 * @param sb Stream buffer
 * @param seq Sequence number
 * @param payload Payload data
 * @param payload_len Payload length
 * @return Number of bytes added to reassembled stream, -1 on error
 */
int stream_buffer_insert_segment(stream_buffer_t *sb, uint32_t seq,
                                  const uint8_t *payload, uint16_t payload_len);

/**
 * @brief Check if reassembled data is available
 *
 * @param sb Stream buffer
 * @return Number of bytes available for consumption
 */
uint32_t stream_buffer_data_available(const stream_buffer_t *sb);

/**
 * @brief Get pointer to reassembled data
 *
 * @param sb Stream buffer
 * @param data_len Output: length of available data
 * @return Pointer to data buffer (do not free)
 */
const uint8_t *stream_buffer_get_data(const stream_buffer_t *sb, uint32_t *data_len);

/**
 * @brief Consume (remove) data from the stream buffer
 *
 * This slides the buffer forward, making room for new data.
 *
 * @param sb Stream buffer
 * @param consume_len Number of bytes to consume
 * @return 0 on success, -1 on error
 */
int stream_buffer_consume(stream_buffer_t *sb, uint32_t consume_len);

/**
 * @brief Get stream buffer statistics (for debugging)
 *
 * @param sb Stream buffer
 * @param buf Output buffer for statistics string
 * @param buf_size Size of output buffer
 */
void stream_buffer_stats(const stream_buffer_t *sb, char *buf, size_t buf_size);

/**
 * @brief Helper: Compare sequence numbers (handles wraparound)
 *
 * @return 1 if seq1 > seq2, 0 if equal, -1 if seq1 < seq2
 */
static inline int seq_compare(uint32_t seq1, uint32_t seq2)
{
    if (seq1 == seq2)
        return 0;

    /* Handle wraparound: difference should be < 2^31 for valid comparison */
    if ((seq1 - seq2) & 0x80000000)
        return -1;  /* seq1 < seq2 */
    else
        return 1;   /* seq1 > seq2 */
}

/**
 * @brief Helper: Check if sequence is between two values
 */
static inline int seq_between(uint32_t seq, uint32_t start, uint32_t end)
{
    return (seq_compare(seq, start) >= 0 && seq_compare(seq, end) < 0);
}

#endif /* __STREAM_REASSEMBLE_H__ */
