/**
 * @file packet_capture.h
 * @brief 数据包捕获模块
 */

#ifndef NETDEFENDER_PACKET_CAPTURE_H
#define NETDEFENDER_PACKET_CAPTURE_H

#include <stdint.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 数据包处理回调函数类型
 * 
 * @param pkts 数据包指针数组
 * @param nb_pkts 数据包数量
 * @param user_data 用户自定义数据
 */
typedef void (*nd_packet_handler_t)(struct rte_mbuf **pkts, uint16_t nb_pkts, void *user_data);

/**
 * @brief 数据包捕获配置
 */
struct nd_capture_config {
    uint16_t port_id;          /**< 网络端口ID */
    uint16_t queue_id;         /**< 接收队列ID */
    uint16_t burst_size;       /**< 批量接收包的数量 */
    int is_promiscuous;        /**< 是否启用混杂模式 */
};

/**
 * @brief 初始化数据包捕获模块
 * 
 * @param config 捕获配置
 * @return int 成功返回0，失败返回负值
 */
int nd_packet_capture_init(struct nd_capture_config *config);

/**
 * @brief 开始捕获数据包并使用指定的处理函数处理
 * 
 * @param handler 数据包处理回调函数
 * @param user_data 传递给回调函数的用户数据
 * @return int 成功返回0，失败返回负值
 */
int nd_start_capture(nd_packet_handler_t handler, void *user_data);

/**
 * @brief 停止数据包捕获
 */
void nd_stop_capture(void);

/**
 * @brief 从指定端口的指定队列接收数据包
 * 
 * @param port_id 端口ID
 * @param queue_id 队列ID
 * @param rx_pkts 接收到的数据包将存储在这个数组中
 * @param nb_pkts 想要接收的数据包数量
 * @return uint16_t 实际接收到的数据包数量
 */
uint16_t nd_receive_packets(uint16_t port_id, uint16_t queue_id, 
                           struct rte_mbuf **rx_pkts, uint16_t nb_pkts);

#ifdef __cplusplus
}
#endif

#endif /* NETDEFENDER_PACKET_CAPTURE_H */ 