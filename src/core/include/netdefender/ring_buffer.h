/**
 * @file ring_buffer.h
 * @brief 基于DPDK rte_ring的环形缓冲区
 */

#ifndef NETDEFENDER_RING_BUFFER_H
#define NETDEFENDER_RING_BUFFER_H

#include <stdint.h>
#include <rte_ring.h>
#include <rte_mbuf.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief 环形缓冲区句柄
 */
typedef struct rte_ring* nd_ring_buffer_t;

/**
 * @brief 创建一个新的环形缓冲区
 * 
 * @param name 环形缓冲区的名称
 * @param count 环形缓冲区大小（元素数量）
 * @param socket_id 创建在哪个NUMA节点上，使用SOCKET_ID_ANY表示任意节点
 * @return nd_ring_buffer_t 成功返回环形缓冲区句柄，失败返回NULL
 */
nd_ring_buffer_t nd_ring_create(const char *name, unsigned count, int socket_id);

/**
 * @brief 释放环形缓冲区
 * 
 * @param ring 环形缓冲区句柄
 */
void nd_ring_free(nd_ring_buffer_t ring);

/**
 * @brief 将数据包入队到环形缓冲区
 * 
 * @param ring 环形缓冲区句柄
 * @param pkts 要入队的数据包数组
 * @param count 要入队的数据包数量
 * @return int 成功入队的数据包数量
 */
int nd_ring_enqueue_burst(nd_ring_buffer_t ring, struct rte_mbuf **pkts, uint16_t count);

/**
 * @brief 从环形缓冲区出队数据包
 * 
 * @param ring 环形缓冲区句柄
 * @param pkts 存储出队数据包的数组
 * @param count 想要出队的数据包数量
 * @return int 成功出队的数据包数量
 */
int nd_ring_dequeue_burst(nd_ring_buffer_t ring, struct rte_mbuf **pkts, uint16_t count);

/**
 * @brief 获取环形缓冲区中当前的元素数量
 * 
 * @param ring 环形缓冲区句柄
 * @return unsigned 元素数量
 */
unsigned nd_ring_count(nd_ring_buffer_t ring);

/**
 * @brief 获取环形缓冲区的空闲空间
 * 
 * @param ring 环形缓冲区句柄
 * @return unsigned 空闲空间大小
 */
unsigned nd_ring_free_count(nd_ring_buffer_t ring);

#ifdef __cplusplus
}
#endif

#endif /* NETDEFENDER_RING_BUFFER_H */ 