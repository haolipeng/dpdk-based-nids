/*
 * NetDefender - DPDK to Packet Processing Bridge
 *
 * This module bridges DPDK mbufs to our packet processing pipeline
 */

#include "suricata_bridge.h"
#include "packet_decode.h"
#include "flow.h"
#include "stream_reassemble.h"
#include "proto_detect.h"
#include "app_proto.h"
#include "http_parser.h"
#include "dns_parser.h"
#include "tls_parser.h"
#include "rule_engine.h"
#include "output_json.h"
#include "behavioral_detector.h"

/* DPDK headers */
#include <rte_mbuf.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_log.h>

/* Standard headers */
#include <sys/time.h>
#include <string.h>

/* Logging */
#define RTE_LOGTYPE_BRIDGE RTE_LOGTYPE_USER1

/* Statistics */
static uint64_t packets_processed = 0;
static uint64_t packets_decoded = 0;
static uint64_t packets_tcp = 0;
static uint64_t packets_udp = 0;
static uint64_t packets_icmp = 0;
static uint64_t packets_other = 0;
static uint64_t packets_with_flow = 0;
static uint64_t protocols_detected = 0;

/* Per-lcore protocol detection context (TLS - Thread Local Storage) */
static __thread proto_detect_ctx_t *proto_detect_ctx = NULL;

/* Per-lcore rule engine context */
static __thread rule_engine_t *rule_engine = NULL;

/* Per-lcore JSON output context */
static __thread json_output_ctx_t *json_output = NULL;

/* Per-lcore behavioral detector context */
static __thread behavioral_detector_t *behavioral_detector = NULL;

/**
 * @brief Determine packet direction relative to flow
 */
static int get_packet_direction(const flow_t *flow, const packet_info_t *pkt_info)
{
    /* Check if packet is in same direction as flow was created */
    if (pkt_info->ip_version == 4) {
        if (flow->src_addr.addr_data32[0] == pkt_info->ipv4_hdr->src_addr &&
            flow->src_port == pkt_info->src_port) {
            return FLOW_DIR_TOSERVER;
        }
    } else if (pkt_info->ip_version == 6) {
        if (memcmp(flow->src_addr.addr_data32, &pkt_info->ipv6_hdr->src_addr, 16) == 0 &&
            flow->src_port == pkt_info->src_port) {
            return FLOW_DIR_TOSERVER;
        }
    }

    return FLOW_DIR_TOCLIENT;
}

/**
 * @brief Process a packet (decode + flow + analyze)
 *
 * This function:
 * 1. Decodes the packet (Ethernet -> IP -> TCP/UDP/ICMP)
 * 2. Gets or creates flow for the packet
 * 3. Updates TCP state machine
 * 4. Updates statistics
 */
int process_packet(struct rte_mbuf *mbuf, unsigned int lcore_id)
{
    packet_info_t pkt_info;
    flow_t *flow = NULL;
    int ret;
    int direction;

    if (unlikely(mbuf == NULL)) {
        return -1;
    }

    packets_processed++;

    /* Decode packet layers */
    ret = decode_packet(mbuf, &pkt_info);
    if (ret < 0) {
        RTE_LOG(DEBUG, BRIDGE, "[lcore %u] Failed to decode packet\n", lcore_id);
        return -1;
    }

    packets_decoded++;

    /* Update protocol statistics */
    if (pkt_info.flags & PKT_DECODED_TCP) {
        packets_tcp++;
    } else if (pkt_info.flags & PKT_DECODED_UDP) {
        packets_udp++;
    } else if (pkt_info.flags & PKT_DECODED_ICMP) {
        packets_icmp++;
    } else {
        packets_other++;
    }

    /* Get or create flow for TCP/UDP packets */
    if ((pkt_info.flags & PKT_DECODED_TCP) || (pkt_info.flags & PKT_DECODED_UDP)) {
        flow = flow_get(&pkt_info);
        if (flow != NULL) {
            packets_with_flow++;

            /* Determine packet direction */
            direction = get_packet_direction(flow, &pkt_info);

            /* Update flow with packet info */
            flow_update(flow, &pkt_info, direction);

            /* Protocol detection (only if not already detected) */
            if (flow->alproto == APP_PROTO_UNKNOWN &&
                (pkt_info.flags & PKT_DECODED_TCP)) {

                /* Initialize proto detection context if needed (per-lcore) */
                if (proto_detect_ctx == NULL) {
                    proto_detect_ctx = proto_detect_ctx_create();
                }

                /* Check if we have payload to detect on */
                if (pkt_info.tcp_hdr && pkt_info.payload_len > 0) {
                    /* Count detection attempts */
                    uint8_t *attempts = (direction == FLOW_DIR_TOSERVER) ?
                                        &flow->alproto_ts : &flow->alproto_tc;

                    /* Limit detection attempts to avoid wasting CPU */
                    if (*attempts < FLOW_ALPROTO_MAX_ATTEMPTS) {
                        proto_detect_result_t result;
                        uint8_t detect_dir = (direction == FLOW_DIR_TOSERVER) ?
                                             PROTO_DETECT_DIR_TOSERVER :
                                             PROTO_DETECT_DIR_TOCLIENT;

                        int ret = proto_detect_get_proto(proto_detect_ctx, flow,
                                                         pkt_info.payload,
                                                         pkt_info.payload_len,
                                                         detect_dir, &result);

                        if (ret == 0 && result.protocol != APP_PROTO_UNKNOWN) {
                            flow->alproto = result.protocol;
                            protocols_detected++;

                            RTE_LOG(INFO, BRIDGE,
                                    "[lcore %u] Protocol detected: %s (confidence: %d, direction: %s, attempts: %d)\n",
                                    lcore_id, app_proto_to_string(result.protocol),
                                    result.confidence,
                                    direction == FLOW_DIR_TOSERVER ? "toserver" : "toclient",
                                    *attempts + 1);
                        }

                        (*attempts)++;
                    }
                }
            }

            /* HTTP parsing (if HTTP protocol detected and we have TCP) */
            if (flow->alproto == APP_PROTO_HTTP && flow->protoctx.tcp != NULL) {
                tcp_session_t *tcp = flow->protoctx.tcp;

                /* Initialize HTTP parser if needed */
                if (tcp->app_parser == NULL) {
                    tcp->app_parser = http_parser_init(flow);
                    if (tcp->app_parser) {
                        RTE_LOG(DEBUG, BRIDGE, "[lcore %u] HTTP parser initialized\n", lcore_id);
                    }
                }

                /* Parse HTTP data from reassembled streams */
                if (tcp->app_parser != NULL) {
                    http_conn_t *http_conn = (http_conn_t *)tcp->app_parser;

                    /* Parse to-server data (requests) */
                    if (direction == FLOW_DIR_TOSERVER && tcp->toserver_sb != NULL) {
                        uint32_t data_len;
                        const uint8_t *data = stream_buffer_get_data(tcp->toserver_sb, &data_len);
                        if (data != NULL && data_len > 0) {
                            int parsed = http_parser_parse(http_conn, data, data_len, 0);
                            if (parsed > 0) {
                                RTE_LOG(DEBUG, BRIDGE,
                                        "[lcore %u] HTTP request parsed: %d bytes\n",
                                        lcore_id, parsed);
                            }
                        }
                    }

                    /* Parse to-client data (responses) */
                    if (direction == FLOW_DIR_TOCLIENT && tcp->toclient_sb != NULL) {
                        uint32_t data_len;
                        const uint8_t *data = stream_buffer_get_data(tcp->toclient_sb, &data_len);
                        if (data != NULL && data_len > 0) {
                            int parsed = http_parser_parse(http_conn, data, data_len, 1);
                            if (parsed > 0) {
                                RTE_LOG(DEBUG, BRIDGE,
                                        "[lcore %u] HTTP response parsed: %d bytes\n",
                                        lcore_id, parsed);
                            }
                        }
                    }

                    /* Initialize detection systems (once per lcore) */
                    if (rule_engine == NULL) {
                        /* Initialize JSON output */
                        char json_filename[256];
                        snprintf(json_filename, sizeof(json_filename),
                                 "eve-lcore%u.json", lcore_id);
                        json_output = json_output_init(json_filename, false);
                        if (json_output) {
                            RTE_LOG(INFO, BRIDGE,
                                    "[lcore %u] JSON output initialized: %s\n",
                                    lcore_id, json_filename);
                        }

                        /* Initialize rule engine */
                        rule_engine = rule_engine_init();
                        if (rule_engine) {
                            int rules_loaded = rule_engine_load_builtin_rules(rule_engine);

                            /* Link JSON output to rule engine */
                            if (json_output) {
                                rule_engine_set_json_output(rule_engine, json_output);
                            }

                            RTE_LOG(INFO, BRIDGE,
                                    "[lcore %u] Rule engine initialized: %d rules loaded\n",
                                    lcore_id, rules_loaded);
                        }

                        /* Initialize behavioral detector */
                        if (rule_engine) {
                            behavioral_detector = behavioral_detector_init(rule_engine);
                            if (behavioral_detector) {
                                RTE_LOG(INFO, BRIDGE,
                                        "[lcore %u] Behavioral detector initialized\n",
                                        lcore_id);
                            }
                        }
                    }

                    if (rule_engine != NULL) {
                        http_transaction_t *tx = http_get_current_transaction(http_conn);
                        if (tx != NULL) {
                            /* Rule engine inspection */
                            int alerts = rule_engine_inspect_http(rule_engine, flow, tx);
                            if (alerts > 0) {
                                RTE_LOG(NOTICE, BRIDGE,
                                        "[lcore %u] HTTP inspection: %d rule(s) triggered\n",
                                        lcore_id, alerts);
                            }

                            /* Output HTTP transaction to JSON */
                            if (json_output) {
                                json_output_http(json_output, tx, flow);
                            }
                        }
                    }
                }
            }

            /* DNS parsing (if DNS protocol detected) */
            if (flow->alproto == APP_PROTO_DNS && (pkt_info.flags & PKT_DECODED_UDP)) {
                /* DNS is primarily UDP, each packet is a complete transaction */

                /* Initialize DNS parser if needed (store in protoctx.udp for UDP flows) */
                if (flow->protoctx.udp == NULL) {
                    flow->protoctx.udp = dns_parser_init(flow);
                    if (flow->protoctx.udp) {
                        RTE_LOG(DEBUG, BRIDGE, "[lcore %u] DNS parser initialized\n", lcore_id);
                    }
                }

                /* Parse DNS data */
                if (flow->protoctx.udp != NULL && pkt_info.payload_len > 0) {
                    dns_conn_t *dns_conn = (dns_conn_t *)flow->protoctx.udp;

                    int ret = dns_parser_parse(dns_conn, pkt_info.payload,
                                              pkt_info.payload_len, false);
                    if (ret == 0) {
                        RTE_LOG(DEBUG, BRIDGE,
                                "[lcore %u] DNS packet parsed\n", lcore_id);
                    }

                    /* Rule engine inspection for DNS */
                    if (rule_engine != NULL) {
                        dns_transaction_t *tx = dns_get_latest_transaction(dns_conn);
                        if (tx != NULL) {
                            /* Rule engine inspection */
                            int alerts = rule_engine_inspect_dns(rule_engine, flow, tx);
                            if (alerts > 0) {
                                RTE_LOG(NOTICE, BRIDGE,
                                        "[lcore %u] DNS inspection: %d rule(s) triggered\n",
                                        lcore_id, alerts);
                            }

                            /* Output DNS transaction to JSON */
                            if (json_output) {
                                json_output_dns(json_output, tx, flow);
                            }
                        }
                    }
                }
            }

            /* TLS parsing (if TLS protocol detected and we have TCP) */
            if (flow->alproto == APP_PROTO_TLS && flow->protoctx.tcp != NULL) {
                tcp_session_t *tcp = flow->protoctx.tcp;

                /* Initialize TLS parser if needed */
                if (tcp->app_parser == NULL) {
                    tcp->app_parser = tls_parser_init(flow);
                    if (tcp->app_parser) {
                        RTE_LOG(DEBUG, BRIDGE, "[lcore %u] TLS parser initialized\n", lcore_id);
                    }
                }

                /* Parse TLS data from reassembled streams */
                if (tcp->app_parser != NULL) {
                    tls_conn_t *tls_conn = (tls_conn_t *)tcp->app_parser;

                    /* Parse to-server data (ClientHello, etc.) */
                    if (direction == FLOW_DIR_TOSERVER && tcp->toserver_sb != NULL) {
                        uint32_t data_len;
                        const uint8_t *data = stream_buffer_get_data(tcp->toserver_sb, &data_len);
                        if (data != NULL && data_len > 0) {
                            int parsed = tls_parser_parse(tls_conn, data, data_len, 0);
                            if (parsed > 0) {
                                RTE_LOG(DEBUG, BRIDGE,
                                        "[lcore %u] TLS to-server data parsed: %d bytes\n",
                                        lcore_id, parsed);
                            }
                        }
                    }

                    /* Parse to-client data (ServerHello, Certificate, etc.) */
                    if (direction == FLOW_DIR_TOCLIENT && tcp->toclient_sb != NULL) {
                        uint32_t data_len;
                        const uint8_t *data = stream_buffer_get_data(tcp->toclient_sb, &data_len);
                        if (data != NULL && data_len > 0) {
                            int parsed = tls_parser_parse(tls_conn, data, data_len, 1);
                            if (parsed > 0) {
                                RTE_LOG(DEBUG, BRIDGE,
                                        "[lcore %u] TLS to-client data parsed: %d bytes\n",
                                        lcore_id, parsed);
                            }
                        }
                    }

                    /* TLS rule inspection (after both directions have been parsed) */
                    if (rule_engine != NULL && tls_conn->client_hello != NULL) {
                        int alerts = rule_engine_inspect_tls(rule_engine, flow, tls_conn);
                        if (alerts > 0) {
                            RTE_LOG(NOTICE, BRIDGE,
                                    "[lcore %u] TLS inspection: %d rule(s) triggered\n",
                                    lcore_id, alerts);
                        }

                        /* Output TLS connection to JSON */
                        if (json_output) {
                            json_output_tls(json_output, tls_conn, flow);
                        }
                    }
                }
            }

            /* Behavioral analysis (port scan, brute force, data exfiltration) */
            if (behavioral_detector != NULL) {
                const uint8_t *tcp_flags = NULL;
                if (pkt_info.tcp_hdr != NULL) {
                    tcp_flags = &pkt_info.tcp_hdr->tcp_flags;
                }

                behavioral_detector_inspect_packet(behavioral_detector, flow,
                                                   pkt_info.payload,
                                                   pkt_info.payload_len,
                                                   tcp_flags);
            }

            /* Release flow reference */
            flow_release(flow);
        }
    }

    /* Print statistics every 10000 packets */
    if (unlikely(packets_processed % 10000 == 0)) {
        flow_stats_t flow_stats;
        flow_get_stats(&flow_stats);

        RTE_LOG(INFO, BRIDGE,
                "[lcore %u] Packets: total=%lu decoded=%lu TCP=%lu UDP=%lu ICMP=%lu with_flow=%lu\n",
                lcore_id, packets_processed, packets_decoded,
                packets_tcp, packets_udp, packets_icmp, packets_with_flow);

        RTE_LOG(INFO, BRIDGE,
                "[lcore %u] Flows: active=%lu created=%lu removed=%lu timeout=%lu\n",
                lcore_id, flow_stats.flows_active, flow_stats.flows_created,
                flow_stats.flows_removed, flow_stats.flows_timeout);

        RTE_LOG(INFO, BRIDGE,
                "[lcore %u] Protocols detected: %lu\n",
                lcore_id, protocols_detected);

        /* Print rule engine statistics */
        if (rule_engine != NULL) {
            char rule_stats[512];
            rule_engine_get_stats(rule_engine, rule_stats, sizeof(rule_stats));
            RTE_LOG(INFO, BRIDGE, "%s", rule_stats);
        }

        /* Print detailed info for one packet */
        print_packet_info(&pkt_info);

        /* Print flow info if available */
        if (flow != NULL && flow->proto == IPPROTO_TCP && flow->protoctx.tcp != NULL) {
            RTE_LOG(INFO, BRIDGE,
                    "  TCP State: %s, Application Protocol: %s\n",
                    tcp_state_to_string(flow->protoctx.tcp->state),
                    app_proto_to_string(flow->alproto));

            /* Print HTTP statistics if HTTP parser is active */
            tcp_session_t *tcp = flow->protoctx.tcp;
            if (flow->alproto == APP_PROTO_HTTP && tcp->app_parser != NULL) {
                http_conn_t *http_conn = (http_conn_t *)tcp->app_parser;
                char http_stats[256];
                http_get_stats(http_conn, http_stats, sizeof(http_stats));
                RTE_LOG(INFO, BRIDGE, "  %s\n", http_stats);

                /* Print current transaction details */
                http_transaction_t *tx = http_get_current_transaction(http_conn);
                if (tx && tx->request) {
                    http_request_t *req = tx->request;
                    RTE_LOG(INFO, BRIDGE, "  HTTP Request: %s %s\n",
                            http_method_to_string(req->method),
                            req->uri ? req->uri : "<null>");
                    if (req->host) {
                        RTE_LOG(INFO, BRIDGE, "    Host: %s\n", req->host);
                    }
                    if (req->user_agent) {
                        RTE_LOG(INFO, BRIDGE, "    User-Agent: %s\n", req->user_agent);
                    }
                }
                if (tx && tx->response) {
                    http_response_t *resp = tx->response;
                    RTE_LOG(INFO, BRIDGE, "  HTTP Response: %d %s\n",
                            resp->status_code,
                            resp->reason_phrase ? resp->reason_phrase : "<null>");
                    if (resp->content_type) {
                        RTE_LOG(INFO, BRIDGE, "    Content-Type: %s\n", resp->content_type);
                    }
                }
            }

            /* Print TLS statistics if TLS parser is active */
            if (flow->alproto == APP_PROTO_TLS && tcp->app_parser != NULL) {
                tls_conn_t *tls_conn = (tls_conn_t *)tcp->app_parser;
                char tls_stats[512];
                tls_get_stats(tls_conn, tls_stats, sizeof(tls_stats));
                RTE_LOG(INFO, BRIDGE, "  %s\n", tls_stats);

                /* Print ClientHello details */
                tls_client_hello_t *ch = tls_get_client_hello(tls_conn);
                if (ch) {
                    RTE_LOG(INFO, BRIDGE, "  TLS ClientHello: version=%s, ciphers=%u\n",
                            tls_version_to_string(ch->version), ch->cipher_suite_count);
                    if (ch->sni) {
                        RTE_LOG(INFO, BRIDGE, "    SNI: %s\n", ch->sni);
                    }
                    if (ch->alpn) {
                        RTE_LOG(INFO, BRIDGE, "    ALPN: %s\n", ch->alpn);
                    }
                    /* Print JA3 hash */
                    char ja3_hash_str[65];
                    for (int i = 0; i < 16; i++) {
                        snprintf(ja3_hash_str + i * 2, 3, "%02x", ch->ja3_hash[i]);
                    }
                    RTE_LOG(INFO, BRIDGE, "    JA3: %s\n", ja3_hash_str);
                }

                /* Print ServerHello details */
                tls_server_hello_t *sh = tls_get_server_hello(tls_conn);
                if (sh) {
                    RTE_LOG(INFO, BRIDGE, "  TLS ServerHello: version=%s, cipher=%s\n",
                            tls_version_to_string(sh->version), sh->cipher_suite_name);
                    /* Print JA3S hash */
                    char ja3s_hash_str[65];
                    for (int i = 0; i < 16; i++) {
                        snprintf(ja3s_hash_str + i * 2, 3, "%02x", sh->ja3s_hash[i]);
                    }
                    RTE_LOG(INFO, BRIDGE, "    JA3S: %s\n", ja3s_hash_str);
                }
            }

            /* Print DNS statistics if DNS parser is active */
            if (flow->alproto == APP_PROTO_DNS && flow->protoctx.udp != NULL) {
                dns_conn_t *dns_conn = (dns_conn_t *)flow->protoctx.udp;
                char dns_stats[256];
                dns_get_stats(dns_conn, dns_stats, sizeof(dns_stats));
                RTE_LOG(INFO, BRIDGE, "  %s\n", dns_stats);

                /* Print latest transaction details */
                dns_transaction_t *tx = dns_get_latest_transaction(dns_conn);
                if (tx && tx->questions) {
                    dns_question_t *q = tx->questions;
                    RTE_LOG(INFO, BRIDGE, "  DNS Query: %s type=%s\n",
                            q->qname ? q->qname : "<null>",
                            dns_type_to_string(q->qtype));
                }
                if (tx && tx->is_response) {
                    RTE_LOG(INFO, BRIDGE, "  DNS Response: rcode=%s answers=%u\n",
                            dns_rcode_to_string(tx->rcode),
                            tx->ancount);

                    /* Print first answer */
                    if (tx->answers) {
                        dns_rr_t *rr = tx->answers;
                        if (rr->type == DNS_TYPE_A) {
                            RTE_LOG(INFO, BRIDGE, "    A: %u.%u.%u.%u (TTL=%u)\n",
                                    rr->parsed.a.addr[0], rr->parsed.a.addr[1],
                                    rr->parsed.a.addr[2], rr->parsed.a.addr[3],
                                    rr->ttl);
                        } else if (rr->type == DNS_TYPE_AAAA) {
                            RTE_LOG(INFO, BRIDGE, "    AAAA: %02x%02x:%02x%02x:... (TTL=%u)\n",
                                    rr->parsed.aaaa.addr[0], rr->parsed.aaaa.addr[1],
                                    rr->parsed.aaaa.addr[2], rr->parsed.aaaa.addr[3],
                                    rr->ttl);
                        } else if (rr->type == DNS_TYPE_CNAME && rr->parsed.domain) {
                            RTE_LOG(INFO, BRIDGE, "    CNAME: %s (TTL=%u)\n",
                                    rr->parsed.domain, rr->ttl);
                        }
                    }
                }
            }

            /* Print stream reassembly statistics */
            if (tcp->toserver_sb != NULL && tcp->toserver_sb->data != NULL) {
                char sb_stats[256];
                stream_buffer_stats(tcp->toserver_sb, sb_stats, sizeof(sb_stats));
                RTE_LOG(INFO, BRIDGE, "  ToServer Stream: %s\n", sb_stats);

                /* Check if reassembled data is available */
                uint32_t data_len;
                const uint8_t *data = stream_buffer_get_data(tcp->toserver_sb, &data_len);
                if (data != NULL && data_len > 0) {
                    RTE_LOG(INFO, BRIDGE,
                            "  ToServer reassembled data available: %u bytes\n", data_len);
                    /* TODO: Pass to detection engine */
                }
            }
            if (tcp->toclient_sb != NULL && tcp->toclient_sb->data != NULL) {
                char sb_stats[256];
                stream_buffer_stats(tcp->toclient_sb, sb_stats, sizeof(sb_stats));
                RTE_LOG(INFO, BRIDGE, "  ToClient Stream: %s\n", sb_stats);

                /* Check if reassembled data is available */
                uint32_t data_len;
                const uint8_t *data = stream_buffer_get_data(tcp->toclient_sb, &data_len);
                if (data != NULL && data_len > 0) {
                    RTE_LOG(INFO, BRIDGE,
                            "  ToClient reassembled data available: %u bytes\n", data_len);
                    /* TODO: Pass to detection engine */
                }
            }
        }
    }

    /* TODO: Add detection engine here (will use reassembled stream data) */

    return 0;
}

/**
 * @brief Get processing statistics
 */
void get_bridge_statistics(uint64_t *total, uint64_t *decoded,
                            uint64_t *tcp, uint64_t *udp,
                            uint64_t *icmp, uint64_t *other)
{
    if (total) *total = packets_processed;
    if (decoded) *decoded = packets_decoded;
    if (tcp) *tcp = packets_tcp;
    if (udp) *udp = packets_udp;
    if (icmp) *icmp = packets_icmp;
    if (other) *other = packets_other;
}
