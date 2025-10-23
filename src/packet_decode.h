/*
 * NetDefender - Packet Protocol Decode Module
 *
 * This module provides protocol parsing using DPDK's rte_net library
 */

#ifndef __PACKET_DECODE_H__
#define __PACKET_DECODE_H__

#include <stdint.h>
#include <rte_mbuf.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_icmp.h>

/* Packet information structure */
typedef struct packet_info {
    /* Ethernet layer */
    struct rte_ether_hdr *eth_hdr;
    uint16_t ether_type;

    /* Network layer */
    uint8_t ip_version;  /* 4 or 6 */
    union {
        struct rte_ipv4_hdr *ipv4_hdr;
        struct rte_ipv6_hdr *ipv6_hdr;
    };
    uint8_t ip_proto;    /* IPPROTO_TCP, IPPROTO_UDP, etc. */
    uint16_t ip_len;

    /* Transport layer */
    union {
        struct rte_tcp_hdr *tcp_hdr;
        struct rte_udp_hdr *udp_hdr;
        struct rte_icmp_hdr *icmp_hdr;
    };
    uint16_t src_port;
    uint16_t dst_port;

    /* Payload */
    uint8_t *payload;
    uint16_t payload_len;

    /* Flags */
    uint32_t flags;
#define PKT_DECODED_ETH     (1 << 0)
#define PKT_DECODED_IPV4    (1 << 1)
#define PKT_DECODED_IPV6    (1 << 2)
#define PKT_DECODED_TCP     (1 << 3)
#define PKT_DECODED_UDP     (1 << 4)
#define PKT_DECODED_ICMP    (1 << 5)
#define PKT_ERROR           (1 << 31)

} packet_info_t;

/**
 * @brief Decode packet from mbuf
 *
 * @param mbuf DPDK mbuf containing packet data
 * @param pkt_info Output: parsed packet information
 * @return 0 on success, -1 on error
 */
int decode_packet(struct rte_mbuf *mbuf, packet_info_t *pkt_info);

/**
 * @brief Print packet information (for debugging)
 *
 * @param pkt_info Parsed packet information
 */
void print_packet_info(const packet_info_t *pkt_info);

#endif /* __PACKET_DECODE_H__ */
