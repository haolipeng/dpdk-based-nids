/**
 * @file dpdk_init.h
 * @brief DPDK初始化和配置功能
 */

#ifndef NETDEFENDER_DPDK_INIT_H
#define NETDEFENDER_DPDK_INIT_H

#include <stdint.h>
#include <rte_eal.h>
#include <rte_ethdev.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief DPDK EAL初始化
 * 
 * @param argc 命令行参数数量
 * @param argv 命令行参数
 * @return int 成功返回0，失败返回负值
 */
int nd_dpdk_init(int argc, char **argv);

/**
 * @brief 初始化并配置指定的网口
 * 
 * @param port_id 要初始化的端口ID
 * @param nb_rx_queues 接收队列数量
 * @param nb_tx_queues 发送队列数量
 * @param rx_rings 每个接收队列的描述符数量
 * @param tx_rings 每个发送队列的描述符数量
 * @return int 成功返回0，失败返回负值
 */
int nd_port_init(uint16_t port_id, uint16_t nb_rx_queues, uint16_t nb_tx_queues, 
                 uint16_t rx_rings, uint16_t tx_rings);

/**
 * @brief 清理DPDK资源
 */
void nd_dpdk_cleanup(void);

/**
 * @brief 获取可用的网络端口数量
 * 
 * @return uint16_t 可用的端口数量
 */
uint16_t nd_get_available_ports(void);

#ifdef __cplusplus
}
#endif

#endif /* NETDEFENDER_DPDK_INIT_H */ 