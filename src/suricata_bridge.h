/*
 * NetDefender - DPDK to Packet Processing Bridge Header
 */

#ifndef __SURICATA_BRIDGE_H__
#define __SURICATA_BRIDGE_H__

#include <stdint.h>
#include <rte_mbuf.h>

/**
 * @brief Process a packet through the decode pipeline
 *
 * @param mbuf DPDK mbuf containing packet data
 * @param lcore_id ID of the lcore processing this packet
 * @return 0 on success, -1 on error
 */
int process_packet(struct rte_mbuf *mbuf, unsigned int lcore_id);

/**
 * @brief Get bridge processing statistics
 *
 * @param total Total packets processed
 * @param decoded Successfully decoded packets
 * @param tcp TCP packets
 * @param udp UDP packets
 * @param icmp ICMP packets
 * @param other Other protocol packets
 */
void get_bridge_statistics(uint64_t *total, uint64_t *decoded,
                            uint64_t *tcp, uint64_t *udp,
                            uint64_t *icmp, uint64_t *other);

#endif /* __SURICATA_BRIDGE_H__ */
