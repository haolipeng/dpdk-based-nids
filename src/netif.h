#ifndef __NDF_NETIF_H__
#define __NDF_NETIF_H__
#include <stdio.h>
#include <linux/if.h>

#include "global_data.h"
#include "dpdk.h"

/* max tx/rx queue number for each nic */
#define NETIF_MAX_QUEUES            16

/* max nic number used in the program */
#define NETIF_MAX_PORTS             4096

#define NETIF_PORT_ID_INVALID       NETIF_MAX_PORTS
#define NETIF_PORT_ID_ALL           NETIF_PORT_ID_INVALID

/* maximum pkt number at a single burst */
#define NETIF_MAX_PKT_BURST         32

/* maximum number of DPDK rte device */
#define NETIF_MAX_RTE_PORTS         64

/* rx/tx queue conf for lcore */
struct netif_queue_conf
{
    queueid_t id;
    uint16_t len;
    struct rte_mbuf* mbufs[NETIF_MAX_PKT_BURST];
}__rte_cache_aligned;

/*
 *rx/tx port conf for lcore.
 *multiple queues of a port may be processed by a lcore
 */
struct netif_port_conf{
    portid_t id;
    /* rx/tx queues for this lcore to process */
    int nrxq;
    int ntxq;
    
    /* rx/tx queue list for this lcore to process */
    struct netif_queue_conf rxqs[NETIF_MAX_QUEUES];
    struct netif_queue_conf txqs[NETIF_MAX_QUEUES];
}__rte_cache_aligned;

//lcore conf
//多个端口可能被一个lcore核心处理
struct netif_lcore_conf
{
    lcoreid_t id;
    enum ndf_lcore_role_type type;
    
    int nports; //此lcore处理的nic数量
    struct netif_port_conf pqs[NETIF_MAX_RTE_PORTS];
}__rte_cache_aligned;

struct netif_port {
    char name[IFNAMSIZ];
    portid_t id; //device id
    int n_rxq; //rx queue number
    int n_txq; //tx queue number
    int socket; //socket id
    struct rte_ether_addr   addr;                       /* MAC address */
    uint16_t mtu;
    struct rte_mempool  *mbuf_pool; //packet mempool
};

int netif_init(void);
int netif_term(void);

//根据dpdk的版本不同，调用不同的函数
static inline uint16_t ndf_rte_eth_dev_count(){
#if RTE_VERSION < RTE_VERSION_NUM(18, 11, 0, 0)
    return rte_eth_dev_count();
#else
    return rte_eth_dev_count_avail();
#endif
}

#endif