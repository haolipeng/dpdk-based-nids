/*
 * NetDefender - TCP Stream Reassembly Implementation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rte_log.h>
#include <rte_malloc.h>

#include "stream_reassemble.h"
#include "packet_decode.h"

#define RTE_LOGTYPE_REASSEMBLE RTE_LOGTYPE_USER1

/* Global configuration */
static stream_config_t global_config = {
    .max_buffer_size = 256 * 1024,  /* 256 KB */
    .max_segments = 100,
    .default_policy = OS_POLICY_LINUX,  /* Linux: favor new data */
};

/* Statistics */
static struct {
    uint64_t segments_inserted;
    uint64_t segments_in_order;
    uint64_t segments_out_of_order;
    uint64_t segments_overlap;
    uint64_t segments_dropped;
    uint64_t bytes_reassembled;
    uint64_t memory_used;           /* Current memory usage */
    uint64_t memory_peak;           /* Peak memory usage */
} reassembly_stats = {0};

/* Forward declarations */
static void handle_queue_overlaps(stream_buffer_t *sb, tcp_segment_t *new_seg);
static int process_segment_queue(stream_buffer_t *sb);

/**
 * Initialize stream reassembly system
 */
int stream_reassemble_init(const stream_config_t *config)
{
    if (config != NULL) {
        global_config = *config;
    }

    RTE_LOG(INFO, REASSEMBLE,
            "Stream reassembly initialized: max_buffer=%u, max_segments=%u, policy=%d\n",
            global_config.max_buffer_size, global_config.max_segments,
            global_config.default_policy);

    return 0;
}

/**
 * Cleanup stream reassembly system
 */
void stream_reassemble_cleanup(void)
{
    RTE_LOG(INFO, REASSEMBLE,
            "Stream reassembly stats: segments=%lu (in_order=%lu, out_of_order=%lu, "
            "overlap=%lu, dropped=%lu), bytes=%lu\n",
            reassembly_stats.segments_inserted,
            reassembly_stats.segments_in_order,
            reassembly_stats.segments_out_of_order,
            reassembly_stats.segments_overlap,
            reassembly_stats.segments_dropped,
            reassembly_stats.bytes_reassembled);

    RTE_LOG(INFO, REASSEMBLE,
            "Memory usage: current=%lu bytes, peak=%lu bytes\n",
            reassembly_stats.memory_used,
            reassembly_stats.memory_peak);
}

/**
 * Initialize a stream buffer
 */
int stream_buffer_init(stream_buffer_t *sb, uint32_t initial_seq, os_policy_t policy)
{
    if (sb == NULL) {
        return -1;
    }

    memset(sb, 0, sizeof(stream_buffer_t));

    /* Allocate initial buffer */
    sb->size = global_config.max_buffer_size;
    sb->data = rte_malloc("stream_buffer", sb->size, 0);
    if (sb->data == NULL) {
        RTE_LOG(ERR, REASSEMBLE, "Failed to allocate stream buffer\n");
        return -1;
    }

    sb->base_seq = initial_seq;
    sb->next_seq = initial_seq;
    sb->os_policy = policy;
    sb->max_buffer_size = global_config.max_buffer_size;
    sb->seg_list = NULL;
    sb->seg_count = 0;

    /* Update memory statistics */
    reassembly_stats.memory_used += sb->size;
    if (reassembly_stats.memory_used > reassembly_stats.memory_peak) {
        reassembly_stats.memory_peak = reassembly_stats.memory_used;
    }

    return 0;
}

/**
 * Free a stream buffer and all its segments
 */
void stream_buffer_free(stream_buffer_t *sb)
{
    if (sb == NULL) {
        return;
    }

    /* Free all segments in the list */
    tcp_segment_t *seg = sb->seg_list;
    while (seg != NULL) {
        tcp_segment_t *next = seg->next;
        if (seg->payload != NULL) {
            reassembly_stats.memory_used -= seg->payload_len;
            rte_free(seg->payload);
        }
        reassembly_stats.memory_used -= sizeof(tcp_segment_t);
        rte_free(seg);
        seg = next;
    }

    /* Free the buffer */
    if (sb->data != NULL) {
        reassembly_stats.memory_used -= sb->size;
        rte_free(sb->data);
        sb->data = NULL;
    }

    memset(sb, 0, sizeof(stream_buffer_t));
}

/**
 * Create a new segment (allocate and copy payload)
 */
static tcp_segment_t *segment_alloc(uint32_t seq, const uint8_t *payload, uint16_t payload_len)
{
    tcp_segment_t *seg = rte_malloc("tcp_segment", sizeof(tcp_segment_t), 0);
    if (seg == NULL) {
        return NULL;
    }

    seg->seq = seq;
    seg->payload_len = payload_len;
    seg->next = NULL;

    /* Copy payload data */
    seg->payload = rte_malloc("segment_payload", payload_len, 0);
    if (seg->payload == NULL) {
        rte_free(seg);
        return NULL;
    }
    memcpy(seg->payload, payload, payload_len);

    /* Update memory statistics */
    reassembly_stats.memory_used += sizeof(tcp_segment_t) + payload_len;
    if (reassembly_stats.memory_used > reassembly_stats.memory_peak) {
        reassembly_stats.memory_peak = reassembly_stats.memory_used;
    }

    return seg;
}

/**
 * Free a segment
 */
static void segment_free(tcp_segment_t *seg)
{
    if (seg == NULL) {
        return;
    }

    /* Update memory statistics */
    if (seg->payload != NULL) {
        reassembly_stats.memory_used -= seg->payload_len;
        rte_free(seg->payload);
    }
    reassembly_stats.memory_used -= sizeof(tcp_segment_t);
    rte_free(seg);
}

/**
 * Try to merge adjacent or overlapping segments
 * This reduces memory usage and segment count
 */
static void try_merge_segments(stream_buffer_t *sb)
{
    tcp_segment_t *curr = sb->seg_list;

    while (curr != NULL && curr->next != NULL) {
        tcp_segment_t *next = curr->next;
        uint32_t curr_end = curr->seq + curr->payload_len;

        /* Check if segments are adjacent or overlapping */
        if (seq_compare(curr_end, next->seq) >= 0) {
            uint32_t next_end = next->seq + next->payload_len;

            /* Check if next is completely contained in curr */
            if (seq_compare(next_end, curr_end) <= 0) {
                /* next is completely contained, remove it */
                curr->next = next->next;
                segment_free(next);
                sb->seg_count--;
                continue;
            }

            /* Segments can be merged - reallocate curr to hold both */
            uint32_t merged_len = next_end - curr->seq;
            uint8_t *new_payload = rte_malloc("segment_payload", merged_len, 0);

            if (new_payload != NULL) {
                /* Copy curr's data */
                memcpy(new_payload, curr->payload, curr->payload_len);

                /* Copy non-overlapping part of next */
                uint32_t overlap = curr_end - next->seq;
                if (overlap < next->payload_len) {
                    memcpy(new_payload + curr->payload_len,
                           next->payload + overlap,
                           next->payload_len - overlap);
                }

                /* Replace curr's payload */
                rte_free(curr->payload);
                curr->payload = new_payload;
                curr->payload_len = merged_len;

                /* Remove next */
                curr->next = next->next;
                segment_free(next);
                sb->seg_count--;
                continue;
            }
        }

        curr = curr->next;
    }
}

/**
 * Insert segment into the out-of-order queue (sorted by seq)
 * This now handles overlaps with queued segments
 */
static int insert_segment_queue(stream_buffer_t *sb, tcp_segment_t *new_seg)
{
    /* Check segment limit */
    if (sb->seg_count >= global_config.max_segments) {
        RTE_LOG(WARNING, REASSEMBLE,
                "Segment queue full (%u segments), dropping segment seq=%u\n",
                sb->seg_count, new_seg->seq);
        segment_free(new_seg);
        reassembly_stats.segments_dropped++;
        return -1;
    }

    /* Handle overlaps with existing queued segments */
    handle_queue_overlaps(sb, new_seg);

    /* Check if segment was dropped by overlap handling */
    if (new_seg->payload_len == 0) {
        segment_free(new_seg);
        return 0;
    }

    /* Find insertion point (keep list sorted by seq) */
    tcp_segment_t **pprev = &sb->seg_list;
    tcp_segment_t *curr = sb->seg_list;

    while (curr != NULL) {
        int cmp = seq_compare(new_seg->seq, curr->seq);

        if (cmp == 0) {
            /* Exact duplicate seq - check if same data */
            if (new_seg->payload_len == curr->payload_len) {
                /* Exact duplicate, drop new segment */
                segment_free(new_seg);
                return 0;
            }
            /* Different length - overlap handling should have resolved this */
        }

        if (cmp < 0) {
            /* Insert before current */
            break;
        }

        pprev = &curr->next;
        curr = curr->next;
    }

    /* Insert segment */
    new_seg->next = curr;
    *pprev = new_seg;
    sb->seg_count++;

    /* Try to merge adjacent segments to save memory */
    if (sb->seg_count > 10) {  /* Only merge if we have enough segments */
        try_merge_segments(sb);
    }

    return 0;
}

/**
 * Try to reassemble segments from the queue
 */
static int process_segment_queue(stream_buffer_t *sb)
{
    int reassembled_bytes = 0;

    while (sb->seg_list != NULL) {
        tcp_segment_t *seg = sb->seg_list;

        /* Check if this segment is the next expected one */
        if (seg->seq != sb->next_seq) {
            /* Gap detected - cannot reassemble yet */
            int32_t gap = (int32_t)(seg->seq - sb->next_seq);
            if (gap > 0) {
                sb->gap_count++;
                break;  /* Wait for missing segment */
            } else {
                /* Overlapping or already processed - should not happen */
                RTE_LOG(WARNING, REASSEMBLE,
                        "Unexpected segment seq=%u, expected=%u (gap=%d)\n",
                        seg->seq, sb->next_seq, gap);
                sb->seg_list = seg->next;
                segment_free(seg);
                sb->seg_count--;
                continue;
            }
        }

        /* Check if we have space in buffer */
        if (sb->data_len + seg->payload_len > sb->max_buffer_size) {
            RTE_LOG(WARNING, REASSEMBLE,
                    "Buffer full (%u/%u), cannot add %u bytes\n",
                    sb->data_len, sb->max_buffer_size, seg->payload_len);
            break;  /* Buffer full */
        }

        /* Copy segment data to buffer */
        memcpy(sb->data + sb->data_len, seg->payload, seg->payload_len);
        sb->data_len += seg->payload_len;
        sb->next_seq += seg->payload_len;
        reassembled_bytes += seg->payload_len;
        sb->total_reassembled += seg->payload_len;

        /* Remove segment from queue */
        sb->seg_list = seg->next;
        segment_free(seg);
        sb->seg_count--;
    }

    return reassembled_bytes;
}

/**
 * Handle overlap with already reassembled data (in buffer)
 * Returns: 0 if segment is completely overlapped (drop it)
 *          >0 adjusted payload_len after removing overlap
 */
static uint16_t handle_buffer_overlap(stream_buffer_t *sb, uint32_t *seq,
                                       const uint8_t **payload, uint16_t payload_len)
{
    uint32_t seg_end = *seq + payload_len;

    /* Check if segment overlaps with already reassembled data */
    if (seq_compare(*seq, sb->next_seq) < 0) {
        /* Segment starts before next_seq */
        if (seq_compare(seg_end, sb->next_seq) <= 0) {
            /* Completely before next_seq - already reassembled */
            return 0;
        }

        /* Partial overlap - trim the overlapping part */
        uint32_t overlap_len = sb->next_seq - *seq;

        sb->overlap_count++;
        reassembly_stats.segments_overlap++;

        /* For overlap with reassembled data, we always skip old data
         * (already in buffer), regardless of OS policy */
        *payload += overlap_len;
        payload_len -= overlap_len;
        *seq = sb->next_seq;
    }

    return payload_len;
}

/**
 * Handle overlaps with queued segments and merge if needed
 * This implements OS-specific overlap handling for Linux vs BSD
 */
static void handle_queue_overlaps(stream_buffer_t *sb, tcp_segment_t *new_seg)
{
    uint32_t new_end = new_seg->seq + new_seg->payload_len;
    tcp_segment_t **pprev = &sb->seg_list;
    tcp_segment_t *curr = sb->seg_list;

    while (curr != NULL) {
        uint32_t curr_end = curr->seq + curr->payload_len;

        /* Case 1: new_seg completely contains curr */
        if (seq_compare(new_seg->seq, curr->seq) <= 0 &&
            seq_compare(new_end, curr_end) >= 0) {

            switch (sb->os_policy) {
            case OS_POLICY_LINUX:
            case OS_POLICY_WINDOWS:
            case OS_POLICY_LAST:
                /* Linux: favor new data - remove old segment */
                *pprev = curr->next;
                segment_free(curr);
                sb->seg_count--;
                curr = *pprev;
                sb->overlap_count++;
                continue;

            case OS_POLICY_BSD:
            case OS_POLICY_FIRST:
                /* BSD: favor old data - drop new segment */
                segment_free(new_seg);
                return;

            default:
                break;
            }
        }

        /* Case 2: Partial overlap - new_seg overlaps start of curr */
        if (seq_compare(new_seg->seq, curr->seq) < 0 &&
            seq_compare(new_end, curr->seq) > 0 &&
            seq_compare(new_end, curr_end) < 0) {

            switch (sb->os_policy) {
            case OS_POLICY_LINUX:
            case OS_POLICY_WINDOWS:
            case OS_POLICY_LAST: {
                /* Linux: favor new data - trim old segment's start */
                uint32_t overlap_len = new_end - curr->seq;
                curr->seq = new_end;
                memmove(curr->payload, curr->payload + overlap_len,
                        curr->payload_len - overlap_len);
                curr->payload_len -= overlap_len;
                sb->overlap_count++;
                break;
            }

            case OS_POLICY_BSD:
            case OS_POLICY_FIRST:
                /* BSD: favor old data - trim new segment's end */
                new_seg->payload_len = curr->seq - new_seg->seq;
                sb->overlap_count++;
                break;

            default:
                break;
            }
        }

        /* Case 3: Partial overlap - new_seg overlaps end of curr */
        if (seq_compare(new_seg->seq, curr->seq) > 0 &&
            seq_compare(new_seg->seq, curr_end) < 0 &&
            seq_compare(new_end, curr_end) >= 0) {

            switch (sb->os_policy) {
            case OS_POLICY_LINUX:
            case OS_POLICY_WINDOWS:
            case OS_POLICY_LAST:
                /* Linux: favor new data - trim old segment's end */
                curr->payload_len = new_seg->seq - curr->seq;
                sb->overlap_count++;
                break;

            case OS_POLICY_BSD:
            case OS_POLICY_FIRST: {
                /* BSD: favor old data - trim new segment's start */
                uint32_t overlap_len = curr_end - new_seg->seq;
                new_seg->seq = curr_end;
                memmove(new_seg->payload, new_seg->payload + overlap_len,
                        new_seg->payload_len - overlap_len);
                new_seg->payload_len -= overlap_len;
                sb->overlap_count++;
                break;
            }

            default:
                break;
            }
        }

        pprev = &curr->next;
        curr = curr->next;
    }
}

/**
 * Insert a TCP segment into the stream buffer
 */
int stream_buffer_insert_segment(stream_buffer_t *sb, uint32_t seq,
                                  const uint8_t *payload, uint16_t payload_len)
{
    /* Validate parameters */
    if (sb == NULL || payload == NULL || payload_len == 0) {
        return -1;
    }

    /* Check if buffer was initialized */
    if (sb->data == NULL) {
        RTE_LOG(WARNING, REASSEMBLE,
                "Stream buffer not initialized, dropping segment\n");
        return -1;
    }

    /* Sanity check: reject unreasonably large segments (>64KB is suspicious) */
    /* Note: payload_len is uint16_t, so this check is for clarity only */
    if (unlikely(payload_len > 60000)) {
        RTE_LOG(WARNING, REASSEMBLE,
                "Segment unusually large (%u bytes)\n", payload_len);
    }

    reassembly_stats.segments_inserted++;

    /* Check if segment is before base_seq (already consumed) */
    if (seq_compare(seq + payload_len, sb->base_seq) <= 0) {
        /* Segment is completely before our window */
        return 0;
    }

    /* Adjust if segment starts before base_seq */
    if (seq_compare(seq, sb->base_seq) < 0) {
        uint32_t skip = sb->base_seq - seq;
        if (skip >= payload_len) {
            return 0;
        }
        payload += skip;
        payload_len -= skip;
        seq = sb->base_seq;
    }

    /* Check if this is the next expected segment (in-order) */
    if (seq == sb->next_seq) {
        reassembly_stats.segments_in_order++;

        /* Check buffer space */
        if (sb->data_len + payload_len > sb->max_buffer_size) {
            RTE_LOG(WARNING, REASSEMBLE,
                    "Buffer full (%u/%u), cannot add %u bytes (in-order)\n",
                    sb->data_len, sb->max_buffer_size, payload_len);
            reassembly_stats.segments_dropped++;
            return -1;
        }

        /* Copy directly to buffer */
        memcpy(sb->data + sb->data_len, payload, payload_len);
        sb->data_len += payload_len;
        sb->next_seq += payload_len;
        sb->total_reassembled += payload_len;
        reassembly_stats.bytes_reassembled += payload_len;

        /* Try to process queued segments */
        process_segment_queue(sb);

        return payload_len;
    }

    /* Out-of-order segment */
    reassembly_stats.segments_out_of_order++;

    /* Handle overlap with already reassembled data */
    payload_len = handle_buffer_overlap(sb, &seq, &payload, payload_len);
    if (payload_len == 0) {
        return 0;  /* Segment was fully overlapping with reassembled data */
    }

    /* Create new segment and add to queue */
    tcp_segment_t *new_seg = segment_alloc(seq, payload, payload_len);
    if (new_seg == NULL) {
        RTE_LOG(ERR, REASSEMBLE, "Failed to allocate segment\n");
        reassembly_stats.segments_dropped++;
        return -1;
    }

    if (insert_segment_queue(sb, new_seg) < 0) {
        return -1;
    }

    /* Try to reassemble */
    return process_segment_queue(sb);
}

/**
 * Check if reassembled data is available
 */
uint32_t stream_buffer_data_available(const stream_buffer_t *sb)
{
    if (sb == NULL) {
        return 0;
    }
    return sb->data_len;
}

/**
 * Get pointer to reassembled data
 */
const uint8_t *stream_buffer_get_data(const stream_buffer_t *sb, uint32_t *data_len)
{
    if (sb == NULL || data_len == NULL) {
        return NULL;
    }

    *data_len = sb->data_len;
    return sb->data;
}

/**
 * Consume (remove) data from the stream buffer
 */
int stream_buffer_consume(stream_buffer_t *sb, uint32_t consume_len)
{
    if (sb == NULL || consume_len == 0) {
        return -1;
    }

    /* Validate buffer is initialized */
    if (sb->data == NULL) {
        return -1;
    }

    if (consume_len > sb->data_len) {
        RTE_LOG(WARNING, REASSEMBLE,
                "Attempting to consume %u bytes, only %u available\n",
                consume_len, sb->data_len);
        consume_len = sb->data_len;
    }

    /* Slide buffer forward */
    if (consume_len < sb->data_len) {
        memmove(sb->data, sb->data + consume_len, sb->data_len - consume_len);
    }

    sb->data_len -= consume_len;
    sb->base_seq += consume_len;

    /* Try to reassemble any queued segments after consuming */
    if (sb->seg_list != NULL) {
        process_segment_queue(sb);
    }

    return 0;
}

/**
 * Get stream buffer statistics
 */
void stream_buffer_stats(const stream_buffer_t *sb, char *buf, size_t buf_size)
{
    if (sb == NULL || buf == NULL || buf_size == 0) {
        return;
    }

    snprintf(buf, buf_size,
             "base_seq=%u next_seq=%u data_len=%u/%u segments=%u "
             "total=%lu overlaps=%lu gaps=%lu",
             sb->base_seq, sb->next_seq, sb->data_len, sb->size,
             sb->seg_count, sb->total_reassembled, sb->overlap_count,
             sb->gap_count);
}
