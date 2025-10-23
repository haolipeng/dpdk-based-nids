/*
 * NetDefender - Packet Protocol Decode Implementation
 */

#include "packet_decode.h"
#include <rte_byteorder.h>
#include <rte_log.h>
#include <string.h>
#include <arpa/inet.h>

#define RTE_LOGTYPE_DECODE RTE_LOGTYPE_USER2

/**
 * @brief Decode Ethernet layer
 */
static int decode_ethernet(packet_info_t *pkt_info, const uint8_t *pkt_data, uint32_t pkt_len)
{
    if (pkt_len < sizeof(struct rte_ether_hdr)) {
        RTE_LOG(DEBUG, DECODE, "Packet too small for Ethernet header\n");
        pkt_info->flags |= PKT_ERROR;
        return -1;
    }

    pkt_info->eth_hdr = (struct rte_ether_hdr *)pkt_data;
    pkt_info->ether_type = rte_be_to_cpu_16(pkt_info->eth_hdr->ether_type);
    pkt_info->flags |= PKT_DECODED_ETH;

    return 0;
}

/**
 * @brief Decode IPv4 layer
 */
static int decode_ipv4(packet_info_t *pkt_info, const uint8_t *pkt_data, uint32_t pkt_len)
{
    if (pkt_len < sizeof(struct rte_ipv4_hdr)) {
        RTE_LOG(DEBUG, DECODE, "Packet too small for IPv4 header\n");
        pkt_info->flags |= PKT_ERROR;
        return -1;
    }

    pkt_info->ipv4_hdr = (struct rte_ipv4_hdr *)pkt_data;
    pkt_info->ip_version = 4;
    pkt_info->ip_proto = pkt_info->ipv4_hdr->next_proto_id;
    pkt_info->ip_len = rte_be_to_cpu_16(pkt_info->ipv4_hdr->total_length);
    pkt_info->flags |= PKT_DECODED_IPV4;

    /* Validate IP header length */
    uint8_t ihl = (pkt_info->ipv4_hdr->version_ihl & 0x0F) * 4;
    if (ihl < sizeof(struct rte_ipv4_hdr)) {
        RTE_LOG(DEBUG, DECODE, "Invalid IPv4 header length: %u\n", ihl);
        pkt_info->flags |= PKT_ERROR;
        return -1;
    }

    return (int)ihl;
}

/**
 * @brief Decode IPv6 layer
 */
static int decode_ipv6(packet_info_t *pkt_info, const uint8_t *pkt_data, uint32_t pkt_len)
{
    if (pkt_len < sizeof(struct rte_ipv6_hdr)) {
        RTE_LOG(DEBUG, DECODE, "Packet too small for IPv6 header\n");
        pkt_info->flags |= PKT_ERROR;
        return -1;
    }

    pkt_info->ipv6_hdr = (struct rte_ipv6_hdr *)pkt_data;
    pkt_info->ip_version = 6;
    pkt_info->ip_proto = pkt_info->ipv6_hdr->proto;
    pkt_info->ip_len = rte_be_to_cpu_16(pkt_info->ipv6_hdr->payload_len) + sizeof(struct rte_ipv6_hdr);
    pkt_info->flags |= PKT_DECODED_IPV6;

    /* TODO: Handle IPv6 extension headers if needed */

    return sizeof(struct rte_ipv6_hdr);
}

/**
 * @brief Decode TCP layer
 */
static int decode_tcp(packet_info_t *pkt_info, const uint8_t *pkt_data, uint32_t pkt_len)
{
    if (pkt_len < sizeof(struct rte_tcp_hdr)) {
        RTE_LOG(DEBUG, DECODE, "Packet too small for TCP header\n");
        pkt_info->flags |= PKT_ERROR;
        return -1;
    }

    pkt_info->tcp_hdr = (struct rte_tcp_hdr *)pkt_data;
    pkt_info->src_port = rte_be_to_cpu_16(pkt_info->tcp_hdr->src_port);
    pkt_info->dst_port = rte_be_to_cpu_16(pkt_info->tcp_hdr->dst_port);
    pkt_info->flags |= PKT_DECODED_TCP;

    /* Calculate TCP header length (data offset is in 32-bit words) */
    uint8_t tcp_hdr_len = ((pkt_info->tcp_hdr->data_off & 0xF0) >> 4) * 4;
    if (tcp_hdr_len < sizeof(struct rte_tcp_hdr)) {
        RTE_LOG(DEBUG, DECODE, "Invalid TCP header length: %u\n", tcp_hdr_len);
        pkt_info->flags |= PKT_ERROR;
        return -1;
    }

    return (int)tcp_hdr_len;
}

/**
 * @brief Decode UDP layer
 */
static int decode_udp(packet_info_t *pkt_info, const uint8_t *pkt_data, uint32_t pkt_len)
{
    if (pkt_len < sizeof(struct rte_udp_hdr)) {
        RTE_LOG(DEBUG, DECODE, "Packet too small for UDP header\n");
        pkt_info->flags |= PKT_ERROR;
        return -1;
    }

    pkt_info->udp_hdr = (struct rte_udp_hdr *)pkt_data;
    pkt_info->src_port = rte_be_to_cpu_16(pkt_info->udp_hdr->src_port);
    pkt_info->dst_port = rte_be_to_cpu_16(pkt_info->udp_hdr->dst_port);
    pkt_info->flags |= PKT_DECODED_UDP;

    return sizeof(struct rte_udp_hdr);
}

/**
 * @brief Decode ICMP layer
 */
static int decode_icmp(packet_info_t *pkt_info, const uint8_t *pkt_data, uint32_t pkt_len)
{
    if (pkt_len < sizeof(struct rte_icmp_hdr)) {
        RTE_LOG(DEBUG, DECODE, "Packet too small for ICMP header\n");
        pkt_info->flags |= PKT_ERROR;
        return -1;
    }

    pkt_info->icmp_hdr = (struct rte_icmp_hdr *)pkt_data;
    pkt_info->src_port = 0;
    pkt_info->dst_port = 0;
    pkt_info->flags |= PKT_DECODED_ICMP;

    return sizeof(struct rte_icmp_hdr);
}

/**
 * @brief Main packet decode function
 */
int decode_packet(struct rte_mbuf *mbuf, packet_info_t *pkt_info)
{
    const uint8_t *pkt_data;
    uint32_t pkt_len;
    uint32_t offset = 0;
    int ret;

    if (mbuf == NULL || pkt_info == NULL) {
        return -1;
    }

    /* Initialize packet info */
    memset(pkt_info, 0, sizeof(packet_info_t));

    /* Get packet data and length */
    pkt_data = rte_pktmbuf_mtod(mbuf, const uint8_t *);
    pkt_len = rte_pktmbuf_pkt_len(mbuf);

    if (pkt_data == NULL || pkt_len == 0) {
        return -1;
    }

    /* Decode Ethernet layer */
    ret = decode_ethernet(pkt_info, pkt_data + offset, pkt_len - offset);
    if (ret < 0) {
        return -1;
    }
    offset += sizeof(struct rte_ether_hdr);

    /* Decode Network layer based on EtherType */
    switch (pkt_info->ether_type) {
    case RTE_ETHER_TYPE_IPV4:
        ret = decode_ipv4(pkt_info, pkt_data + offset, pkt_len - offset);
        if (ret < 0) {
            return -1;
        }
        offset += ret;  /* IPv4 header length */
        break;

    case RTE_ETHER_TYPE_IPV6:
        ret = decode_ipv6(pkt_info, pkt_data + offset, pkt_len - offset);
        if (ret < 0) {
            return -1;
        }
        offset += ret;  /* IPv6 header length */
        break;

    case RTE_ETHER_TYPE_ARP:
        /* ARP packets - not processing for now */
        return 0;

    default:
        RTE_LOG(DEBUG, DECODE, "Unknown EtherType: 0x%04x\n", pkt_info->ether_type);
        return 0;  /* Not an error, just unsupported */
    }

    /* Decode Transport layer based on IP protocol */
    switch (pkt_info->ip_proto) {
    case IPPROTO_TCP:
        ret = decode_tcp(pkt_info, pkt_data + offset, pkt_len - offset);
        if (ret < 0) {
            return -1;
        }
        offset += ret;  /* TCP header length */
        break;

    case IPPROTO_UDP:
        ret = decode_udp(pkt_info, pkt_data + offset, pkt_len - offset);
        if (ret < 0) {
            return -1;
        }
        offset += ret;  /* UDP header length */
        break;

    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        ret = decode_icmp(pkt_info, pkt_data + offset, pkt_len - offset);
        if (ret < 0) {
            return -1;
        }
        offset += ret;  /* ICMP header length */
        break;

    default:
        RTE_LOG(DEBUG, DECODE, "Unknown IP protocol: %u\n", pkt_info->ip_proto);
        return 0;  /* Not an error, just unsupported */
    }

    /* Set payload pointer and length */
    if (offset < pkt_len) {
        pkt_info->payload = (uint8_t *)(pkt_data + offset);
        pkt_info->payload_len = pkt_len - offset;
    }

    return 0;
}

/**
 * @brief Print packet information for debugging
 */
void print_packet_info(const packet_info_t *pkt_info)
{
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];

    if (pkt_info == NULL) {
        return;
    }

    RTE_LOG(INFO, DECODE, "Packet Info:\n");
    RTE_LOG(INFO, DECODE, "  EtherType: 0x%04x\n", pkt_info->ether_type);

    if (pkt_info->flags & PKT_DECODED_IPV4) {
        inet_ntop(AF_INET, &pkt_info->ipv4_hdr->src_addr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &pkt_info->ipv4_hdr->dst_addr, dst_ip, sizeof(dst_ip));
        RTE_LOG(INFO, DECODE, "  IPv4: %s -> %s\n", src_ip, dst_ip);
        RTE_LOG(INFO, DECODE, "  Protocol: %u, Length: %u\n",
                pkt_info->ip_proto, pkt_info->ip_len);
    } else if (pkt_info->flags & PKT_DECODED_IPV6) {
        inet_ntop(AF_INET6, &pkt_info->ipv6_hdr->src_addr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET6, &pkt_info->ipv6_hdr->dst_addr, dst_ip, sizeof(dst_ip));
        RTE_LOG(INFO, DECODE, "  IPv6: %s -> %s\n", src_ip, dst_ip);
        RTE_LOG(INFO, DECODE, "  Protocol: %u, Length: %u\n",
                pkt_info->ip_proto, pkt_info->ip_len);
    }

    if (pkt_info->flags & PKT_DECODED_TCP) {
        RTE_LOG(INFO, DECODE, "  TCP: port %u -> %u\n",
                pkt_info->src_port, pkt_info->dst_port);
        RTE_LOG(INFO, DECODE, "  Flags: SYN=%d ACK=%d FIN=%d RST=%d\n",
                (pkt_info->tcp_hdr->tcp_flags & RTE_TCP_SYN_FLAG) ? 1 : 0,
                (pkt_info->tcp_hdr->tcp_flags & RTE_TCP_ACK_FLAG) ? 1 : 0,
                (pkt_info->tcp_hdr->tcp_flags & RTE_TCP_FIN_FLAG) ? 1 : 0,
                (pkt_info->tcp_hdr->tcp_flags & RTE_TCP_RST_FLAG) ? 1 : 0);
    } else if (pkt_info->flags & PKT_DECODED_UDP) {
        RTE_LOG(INFO, DECODE, "  UDP: port %u -> %u\n",
                pkt_info->src_port, pkt_info->dst_port);
    } else if (pkt_info->flags & PKT_DECODED_ICMP) {
        RTE_LOG(INFO, DECODE, "  ICMP: type=%u code=%u\n",
                pkt_info->icmp_hdr->icmp_type, pkt_info->icmp_hdr->icmp_code);
    }

    RTE_LOG(INFO, DECODE, "  Payload length: %u bytes\n", pkt_info->payload_len);
}
