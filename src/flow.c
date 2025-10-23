/*
 * NetDefender - Flow Management Implementation
 */

#include "flow.h"
#include "packet_decode.h"
#include "stream_reassemble.h"
#include <stdlib.h>
#include <string.h>
#include <rte_log.h>
#include <rte_cycles.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>

#define RTE_LOGTYPE_FLOW RTE_LOGTYPE_USER3

/* Global flow table and configuration */
flow_bucket_t *flow_hash_table = NULL;
flow_config_t flow_config;
flow_stats_t flow_stats;

/* Forward declarations */
static uint32_t flow_hash_calculate(const packet_info_t *pkt_info);
static flow_t *flow_alloc(void);
static void flow_free(flow_t *flow);
static int flow_match(const flow_t *flow, const packet_info_t *pkt_info);

/**
 * @brief Initialize flow management system
 */
int flow_init(uint32_t hash_size, uint32_t max_flows)
{
    int i;

    /* Validate parameters */
    if (hash_size == 0 || (hash_size & (hash_size - 1)) != 0) {
        RTE_LOG(ERR, FLOW, "Hash size must be power of 2\n");
        return -1;
    }

    /* Initialize configuration */
    memset(&flow_config, 0, sizeof(flow_config));
    flow_config.hash_size = hash_size;
    flow_config.max_flows = max_flows;
    flow_config.timeout_new = 30;        /* 30 seconds for new flows */
    flow_config.timeout_est = 3600;      /* 1 hour for established flows */
    flow_config.flow_memcap = 512 * 1024 * 1024; /* 512MB */

    /* Initialize statistics */
    memset(&flow_stats, 0, sizeof(flow_stats));

    /* Allocate hash table */
    flow_hash_table = calloc(hash_size, sizeof(flow_bucket_t));
    if (flow_hash_table == NULL) {
        RTE_LOG(ERR, FLOW, "Failed to allocate flow hash table\n");
        return -1;
    }

    /* Initialize bucket locks */
    for (i = 0; i < (int)hash_size; i++) {
        pthread_mutex_init(&flow_hash_table[i].lock, NULL);
        flow_hash_table[i].head = NULL;
    }

    RTE_LOG(INFO, FLOW, "Flow table initialized: hash_size=%u, max_flows=%u\n",
            hash_size, max_flows);

    return 0;
}

/**
 * @brief Cleanup flow management system
 */
void flow_cleanup(void)
{
    uint32_t i;
    flow_t *flow, *next;

    if (flow_hash_table == NULL) {
        return;
    }

    /* Free all flows */
    for (i = 0; i < flow_config.hash_size; i++) {
        pthread_mutex_lock(&flow_hash_table[i].lock);

        flow = flow_hash_table[i].head;
        while (flow != NULL) {
            next = flow->next;
            flow_free(flow);
            flow = next;
        }

        pthread_mutex_unlock(&flow_hash_table[i].lock);
        pthread_mutex_destroy(&flow_hash_table[i].lock);
    }

    free(flow_hash_table);
    flow_hash_table = NULL;

    RTE_LOG(INFO, FLOW, "Flow table cleaned up\n");
}

/**
 * @brief Calculate flow hash using CRC32
 */
static uint32_t flow_hash_calculate(const packet_info_t *pkt_info)
{
    uint32_t hash = 0;
    uint32_t data[10]; /* Buffer for hash input */
    int idx = 0;

    /* Add IP addresses */
    if (pkt_info->ip_version == 4) {
        data[idx++] = pkt_info->ipv4_hdr->src_addr;
        data[idx++] = pkt_info->ipv4_hdr->dst_addr;
    } else if (pkt_info->ip_version == 6) {
        memcpy(&data[idx], &pkt_info->ipv6_hdr->src_addr, 16);
        idx += 4;
        memcpy(&data[idx], &pkt_info->ipv6_hdr->dst_addr, 16);
        idx += 4;
    }

    /* Add ports and protocol */
    data[idx++] = (pkt_info->src_port << 16) | pkt_info->dst_port;
    data[idx++] = pkt_info->ip_proto;

    /* Calculate CRC32 hash */
    hash = rte_hash_crc(data, idx * 4, 0);

    return hash;
}

/**
 * @brief Check if flow matches packet
 */
static int flow_match(const flow_t *flow, const packet_info_t *pkt_info)
{
    /* Check protocol */
    if (flow->proto != pkt_info->ip_proto) {
        return 0;
    }

    /* Check IP version */
    if ((flow->flags & FLOW_IPV4) && pkt_info->ip_version != 4) {
        return 0;
    }
    if ((flow->flags & FLOW_IPV6) && pkt_info->ip_version != 6) {
        return 0;
    }

    /* Check addresses and ports (bidirectional) */
    int forward_match = 0, reverse_match = 0;

    if (pkt_info->ip_version == 4) {
        /* Forward direction */
        if (flow->src_addr.addr_data32[0] == pkt_info->ipv4_hdr->src_addr &&
            flow->dst_addr.addr_data32[0] == pkt_info->ipv4_hdr->dst_addr &&
            flow->src_port == pkt_info->src_port &&
            flow->dst_port == pkt_info->dst_port) {
            forward_match = 1;
        }

        /* Reverse direction */
        if (flow->src_addr.addr_data32[0] == pkt_info->ipv4_hdr->dst_addr &&
            flow->dst_addr.addr_data32[0] == pkt_info->ipv4_hdr->src_addr &&
            flow->src_port == pkt_info->dst_port &&
            flow->dst_port == pkt_info->src_port) {
            reverse_match = 1;
        }
    } else if (pkt_info->ip_version == 6) {
        /* IPv6 address comparison */
        if (memcmp(flow->src_addr.addr_data32, &pkt_info->ipv6_hdr->src_addr, 16) == 0 &&
            memcmp(flow->dst_addr.addr_data32, &pkt_info->ipv6_hdr->dst_addr, 16) == 0 &&
            flow->src_port == pkt_info->src_port &&
            flow->dst_port == pkt_info->dst_port) {
            forward_match = 1;
        }

        if (memcmp(flow->src_addr.addr_data32, &pkt_info->ipv6_hdr->dst_addr, 16) == 0 &&
            memcmp(flow->dst_addr.addr_data32, &pkt_info->ipv6_hdr->src_addr, 16) == 0 &&
            flow->src_port == pkt_info->dst_port &&
            flow->dst_port == pkt_info->src_port) {
            reverse_match = 1;
        }
    }

    return forward_match || reverse_match;
}

/**
 * @brief Allocate a new flow
 */
static flow_t *flow_alloc(void)
{
    flow_t *flow;

    flow = calloc(1, sizeof(flow_t));
    if (flow == NULL) {
        return NULL;
    }

    pthread_mutex_init(&flow->lock, NULL);
    flow->use_cnt = 1;

    return flow;
}

/**
 * @brief Free a flow
 */
static void flow_free(flow_t *flow)
{
    if (flow == NULL) {
        return;
    }

    /* Free protocol context */
    if (flow->proto == IPPROTO_TCP && flow->protoctx.tcp != NULL) {
        /* Free application layer parser */
        if (flow->protoctx.tcp->app_parser != NULL) {
            /* Free HTTP or TLS parser */
            if (flow->alproto == APP_PROTO_HTTP) {
                extern void http_parser_free(void *conn);
                http_parser_free(flow->protoctx.tcp->app_parser);
            } else if (flow->alproto == APP_PROTO_TLS) {
                extern void tls_parser_free(void *conn);
                tls_parser_free(flow->protoctx.tcp->app_parser);
            }
            flow->protoctx.tcp->app_parser = NULL;
        }

        /* Free stream reassembly buffers */
        if (flow->protoctx.tcp->toserver_sb != NULL) {
            stream_buffer_free(flow->protoctx.tcp->toserver_sb);
            rte_free(flow->protoctx.tcp->toserver_sb);
        }
        if (flow->protoctx.tcp->toclient_sb != NULL) {
            stream_buffer_free(flow->protoctx.tcp->toclient_sb);
            rte_free(flow->protoctx.tcp->toclient_sb);
        }

        free(flow->protoctx.tcp);
    }

    /* Free UDP protocol context (e.g., DNS parser) */
    if (flow->proto == IPPROTO_UDP && flow->protoctx.udp != NULL) {
        if (flow->alproto == APP_PROTO_DNS) {
            extern void dns_parser_free(void *conn);
            dns_parser_free(flow->protoctx.udp);
        }
        flow->protoctx.udp = NULL;
    }

    pthread_mutex_destroy(&flow->lock);
    free(flow);
}

/**
 * @brief Get or create a flow for a packet
 */
flow_t *flow_get(const packet_info_t *pkt_info)
{
    uint32_t hash;
    uint32_t bucket_idx;
    flow_bucket_t *bucket;
    flow_t *flow;
    int found = 0;

    if (pkt_info == NULL) {
        return NULL;
    }

    /* Calculate hash */
    hash = flow_hash_calculate(pkt_info);
    bucket_idx = hash & (flow_config.hash_size - 1);
    bucket = &flow_hash_table[bucket_idx];

    /* Lock bucket */
    pthread_mutex_lock(&bucket->lock);

    /* Search for existing flow */
    flow = bucket->head;
    while (flow != NULL) {
        if (flow->flow_hash == hash && flow_match(flow, pkt_info)) {
            found = 1;
            flow->use_cnt++;
            break;
        }
        flow = flow->next;
    }

    /* Create new flow if not found */
    if (!found) {
        /* Check flow limit */
        if (flow_stats.flows_active >= flow_config.max_flows) {
            RTE_LOG(WARNING, FLOW, "Flow table full, dropping new flow\n");
            pthread_mutex_unlock(&bucket->lock);
            return NULL;
        }

        flow = flow_alloc();
        if (flow == NULL) {
            pthread_mutex_unlock(&bucket->lock);
            return NULL;
        }

        /* Initialize flow */
        flow->flow_hash = hash;
        flow->proto = pkt_info->ip_proto;

        /* Set addresses */
        if (pkt_info->ip_version == 4) {
            flow->flags |= FLOW_IPV4;
            flow->src_addr.addr_data32[0] = pkt_info->ipv4_hdr->src_addr;
            flow->dst_addr.addr_data32[0] = pkt_info->ipv4_hdr->dst_addr;
        } else if (pkt_info->ip_version == 6) {
            flow->flags |= FLOW_IPV6;
            memcpy(flow->src_addr.addr_data32, &pkt_info->ipv6_hdr->src_addr, 16);
            memcpy(flow->dst_addr.addr_data32, &pkt_info->ipv6_hdr->dst_addr, 16);
        }

        flow->src_port = pkt_info->src_port;
        flow->dst_port = pkt_info->dst_port;

        /* Set timestamps */
        gettimeofday(&flow->start_ts, NULL);
        flow->last_ts = flow->start_ts;
        flow->timeout_policy = flow_config.timeout_new;

        /* Initialize TCP session if TCP */
        if (flow->proto == IPPROTO_TCP) {
            flow->protoctx.tcp = calloc(1, sizeof(tcp_session_t));
            if (flow->protoctx.tcp != NULL) {
                flow->protoctx.tcp->state = TCP_NONE;

                /* Allocate stream reassembly buffers */
                flow->protoctx.tcp->toserver_sb = rte_malloc("stream_buffer",
                                                              sizeof(stream_buffer_t), 0);
                flow->protoctx.tcp->toclient_sb = rte_malloc("stream_buffer",
                                                              sizeof(stream_buffer_t), 0);

                /* Initialize stream buffers (will be set up on first SYN) */
                if (flow->protoctx.tcp->toserver_sb != NULL) {
                    memset(flow->protoctx.tcp->toserver_sb, 0, sizeof(stream_buffer_t));
                }
                if (flow->protoctx.tcp->toclient_sb != NULL) {
                    memset(flow->protoctx.tcp->toclient_sb, 0, sizeof(stream_buffer_t));
                }
            }
        }

        /* Insert into hash table */
        flow->next = bucket->head;
        bucket->head = flow;

        /* Update statistics */
        flow_stats.flows_created++;
        flow_stats.flows_active++;

        /* Log new flow creation with key details */
        char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
        if (flow->flags & FLOW_IPV4) {
            inet_ntop(AF_INET, &flow->src_addr.addr_data32[0], src_str, sizeof(src_str));
            inet_ntop(AF_INET, &flow->dst_addr.addr_data32[0], dst_str, sizeof(dst_str));
            RTE_LOG(INFO, FLOW, "New flow created: %s:%u -> %s:%u proto=%u hash=0x%x\n",
                    src_str, flow->src_port, dst_str, flow->dst_port, flow->proto, hash);
        } else {
            inet_ntop(AF_INET6, flow->src_addr.addr_data32, src_str, sizeof(src_str));
            inet_ntop(AF_INET6, flow->dst_addr.addr_data32, dst_str, sizeof(dst_str));
            RTE_LOG(INFO, FLOW, "New flow created: [%s]:%u -> [%s]:%u proto=%u hash=0x%x\n",
                    src_str, flow->src_port, dst_str, flow->dst_port, flow->proto, hash);
        }
    }

    pthread_mutex_unlock(&bucket->lock);

    return flow;
}

/**
 * @brief Update flow with packet information
 */
void flow_update(flow_t *flow, const packet_info_t *pkt_info, int direction)
{
    if (flow == NULL || pkt_info == NULL) {
        return;
    }

    pthread_mutex_lock(&flow->lock);

    /* Update timestamp */
    gettimeofday(&flow->last_ts, NULL);

    /* Update statistics */
    if (direction == FLOW_DIR_TOSERVER) {
        flow->toserver_pkt_cnt++;
        flow->toserver_byte_cnt += pkt_info->payload_len;
        flow->flags |= FLOW_TO_DST_SEEN;
    } else {
        flow->toclient_pkt_cnt++;
        flow->toclient_byte_cnt += pkt_info->payload_len;

        /* Log when flow becomes bidirectional (first toclient packet) */
        if (!(flow->flags & FLOW_TO_SRC_SEEN)) {
            RTE_LOG(INFO, FLOW, "Flow now bidirectional (toserver: %lu pkts, toclient: %lu pkts)\n",
                    flow->toserver_pkt_cnt, flow->toclient_pkt_cnt);
        }
        flow->flags |= FLOW_TO_SRC_SEEN;
    }

    /* Update TCP state machine */
    if (flow->proto == IPPROTO_TCP && flow->protoctx.tcp != NULL && pkt_info->tcp_hdr != NULL) {
        tcp_session_t *tcp = flow->protoctx.tcp;
        uint8_t flags = pkt_info->tcp_hdr->tcp_flags;

        /* Complete TCP state machine (RFC 793) */
        switch (tcp->state) {
        case TCP_NONE:
            /* Initial state - waiting for first packet */
            if (flags & RTE_TCP_SYN_FLAG) {
                if (flags & RTE_TCP_ACK_FLAG) {
                    /* Midstream pickup: SYN-ACK seen first */
                    tcp->state = TCP_SYN_RECV;
                } else {
                    /* Normal: SYN seen (client initiating) */
                    tcp->state = TCP_SYN_SENT;
                }
            } else if (flags & RTE_TCP_RST_FLAG) {
                tcp->state = TCP_CLOSED;
            }
            break;

        case TCP_SYN_SENT:
            /* Client sent SYN, waiting for SYN-ACK */
            if (flags & RTE_TCP_SYN_FLAG && flags & RTE_TCP_ACK_FLAG) {
                tcp->state = TCP_SYN_RECV;  /* Received SYN-ACK */
            } else if (flags & RTE_TCP_SYN_FLAG) {
                /* Simultaneous open (rare) */
                tcp->state = TCP_SYN_RECV;
            } else if (flags & RTE_TCP_RST_FLAG) {
                tcp->state = TCP_CLOSED;
            }
            break;

        case TCP_SYN_RECV:
            /* Server sent SYN-ACK, waiting for ACK */
            if (flags & RTE_TCP_ACK_FLAG) {
                tcp->state = TCP_ESTABLISHED;  /* 3-way handshake complete */
                flow->timeout_policy = flow_config.timeout_est;
            } else if (flags & RTE_TCP_RST_FLAG) {
                tcp->state = TCP_CLOSED;
            }
            break;

        case TCP_ESTABLISHED:
            /* Connection established, data transfer */
            if (flags & RTE_TCP_FIN_FLAG) {
                /* One side initiated close */
                tcp->state = (direction == FLOW_DIR_TOSERVER) ?
                             TCP_FIN_WAIT1 : TCP_CLOSE_WAIT;
            } else if (flags & RTE_TCP_RST_FLAG) {
                tcp->state = TCP_CLOSED;
            }
            break;

        case TCP_FIN_WAIT1:
            /* Sent FIN, waiting for ACK or FIN */
            if (flags & RTE_TCP_FIN_FLAG) {
                if (flags & RTE_TCP_ACK_FLAG) {
                    /* Received FIN+ACK */
                    tcp->state = TCP_TIME_WAIT;
                } else {
                    /* Simultaneous close: both sent FIN */
                    tcp->state = TCP_CLOSING;
                }
            } else if (flags & RTE_TCP_ACK_FLAG) {
                /* Received ACK of our FIN */
                tcp->state = TCP_FIN_WAIT2;
            } else if (flags & RTE_TCP_RST_FLAG) {
                tcp->state = TCP_CLOSED;
            }
            break;

        case TCP_FIN_WAIT2:
            /* Our FIN was ACKed, waiting for peer's FIN */
            if (flags & RTE_TCP_FIN_FLAG) {
                tcp->state = TCP_TIME_WAIT;
            } else if (flags & RTE_TCP_RST_FLAG) {
                tcp->state = TCP_CLOSED;
            }
            break;

        case TCP_CLOSING:
            /* Simultaneous close: both sent FIN, waiting for ACK */
            if (flags & RTE_TCP_ACK_FLAG) {
                tcp->state = TCP_TIME_WAIT;
            } else if (flags & RTE_TCP_RST_FLAG) {
                tcp->state = TCP_CLOSED;
            }
            break;

        case TCP_TIME_WAIT:
            /* Waiting for 2*MSL (maximum segment lifetime) */
            /* In real implementation, this would timeout to CLOSED */
            /* For simplicity, we just mark it closed on RST */
            if (flags & RTE_TCP_RST_FLAG) {
                tcp->state = TCP_CLOSED;
            }
            /* TODO: Add timer to transition to CLOSED after 2*MSL */
            break;

        case TCP_CLOSE_WAIT:
            /* Received FIN, waiting for application to close */
            if (flags & RTE_TCP_FIN_FLAG) {
                /* Application closed, sending FIN */
                tcp->state = TCP_LAST_ACK;
            } else if (flags & RTE_TCP_RST_FLAG) {
                tcp->state = TCP_CLOSED;
            }
            break;

        case TCP_LAST_ACK:
            /* Sent FIN after receiving FIN, waiting for ACK */
            if (flags & RTE_TCP_ACK_FLAG) {
                tcp->state = TCP_CLOSED;
            } else if (flags & RTE_TCP_RST_FLAG) {
                tcp->state = TCP_CLOSED;
            }
            break;

        case TCP_CLOSED:
            /* Connection closed, no more transitions */
            break;

        default:
            break;
        }

        tcp->seg_cnt++;
        tcp->byte_cnt += pkt_info->payload_len;

        /* Stream reassembly: initialize buffers on first SYN */
        if (tcp->state == TCP_SYN_SENT && tcp->toserver_sb != NULL &&
            tcp->toserver_sb->data == NULL) {
            /* Initialize toserver buffer with ISN from SYN */
            uint32_t seq = rte_be_to_cpu_32(pkt_info->tcp_hdr->sent_seq);
            stream_buffer_init(tcp->toserver_sb, seq, OS_POLICY_LINUX);
        }
        if (tcp->state == TCP_SYN_RECV && tcp->toclient_sb != NULL &&
            tcp->toclient_sb->data == NULL) {
            /* Initialize toclient buffer with ISN from SYN-ACK */
            uint32_t seq = rte_be_to_cpu_32(pkt_info->tcp_hdr->sent_seq);
            stream_buffer_init(tcp->toclient_sb, seq, OS_POLICY_LINUX);
        }

        /* Insert segment into reassembly buffer (if we have payload) */
        if (pkt_info->payload_len > 0 && tcp->state == TCP_ESTABLISHED) {
            stream_buffer_t *sb = (direction == FLOW_DIR_TOSERVER) ?
                                  tcp->toserver_sb : tcp->toclient_sb;

            if (sb != NULL && sb->data != NULL) {
                uint32_t seq = rte_be_to_cpu_32(pkt_info->tcp_hdr->sent_seq);
                int ret = stream_buffer_insert_segment(sb, seq,
                                                       pkt_info->payload,
                                                       pkt_info->payload_len);
                if (ret < 0) {
                    /* Segment insertion failed (buffer full or error) */
                    RTE_LOG(WARNING, FLOW,
                            "Failed to insert segment seq=%u len=%u into stream buffer\n",
                            seq, pkt_info->payload_len);
                }
            }
        }
    }

    pthread_mutex_unlock(&flow->lock);
}

/**
 * @brief Release flow reference
 */
void flow_release(flow_t *flow)
{
    if (flow == NULL) {
        return;
    }

    pthread_mutex_lock(&flow->lock);
    if (flow->use_cnt > 0) {
        flow->use_cnt--;
    }
    pthread_mutex_unlock(&flow->lock);
}

/**
 * @brief Cleanup expired flows
 */
int flow_cleanup_expired(struct timeval *now)
{
    uint32_t i;
    flow_t *flow, *prev, *next;
    int removed = 0;

    if (now == NULL || flow_hash_table == NULL) {
        return 0;
    }

    for (i = 0; i < flow_config.hash_size; i++) {
        flow_bucket_t *bucket = &flow_hash_table[i];

        pthread_mutex_lock(&bucket->lock);

        prev = NULL;
        flow = bucket->head;

        while (flow != NULL) {
            next = flow->next;

            /* Check if flow has expired */
            uint32_t age = now->tv_sec - flow->last_ts.tv_sec;
            int should_remove = 0;

            if (flow->use_cnt == 0 && age > flow->timeout_policy) {
                should_remove = 1;
            }

            if (should_remove) {
                /* Remove from list */
                if (prev == NULL) {
                    bucket->head = next;
                } else {
                    prev->next = next;
                }

                flow_free(flow);
                removed++;
                flow_stats.flows_removed++;
                flow_stats.flows_timeout++;
                flow_stats.flows_active--;
            } else {
                prev = flow;
            }

            flow = next;
        }

        pthread_mutex_unlock(&bucket->lock);
    }

    if (removed > 0) {
        RTE_LOG(INFO, FLOW, "Cleaned up %d expired flows\n", removed);
    }

    return removed;
}

/**
 * @brief Get flow statistics
 */
void flow_get_stats(flow_stats_t *stats)
{
    if (stats != NULL) {
        *stats = flow_stats;
    }
}

/**
 * @brief Convert TCP state to string
 */
const char *tcp_state_to_string(tcp_state_t state)
{
    switch (state) {
    case TCP_NONE:        return "NONE";
    case TCP_LISTEN:      return "LISTEN";
    case TCP_SYN_SENT:    return "SYN_SENT";
    case TCP_SYN_RECV:    return "SYN_RECV";
    case TCP_ESTABLISHED: return "ESTABLISHED";
    case TCP_FIN_WAIT1:   return "FIN_WAIT1";
    case TCP_FIN_WAIT2:   return "FIN_WAIT2";
    case TCP_TIME_WAIT:   return "TIME_WAIT";
    case TCP_CLOSE_WAIT:  return "CLOSE_WAIT";
    case TCP_LAST_ACK:    return "LAST_ACK";
    case TCP_CLOSING:     return "CLOSING";
    case TCP_CLOSED:      return "CLOSED";
    default:              return "UNKNOWN";
    }
}
