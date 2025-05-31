#ifndef __NDF_NETIF_H__
#define __NDF_NETIF_H__
#include <stdio.h>
#include <linux/if.h>

#include "dpdk.h"

#ifndef NDF_MAX_LCORE
#define NDF_MAX_LCORE RTE_MAX_LCORE
#endif

/* maximum number of DPDK rte device */
#define NETIF_MAX_RTE_PORTS         64

struct netif_port_conf{
    portid_t id;
    /* rx/tx queues for this lcore to process */
    int nrxq;
    int ntxq;
    //TODO:
}

//lcore conf
//多个端口可能被一个lcore核心处理
struct netif_lcore_conf
{
    lcoreid_t id;
    enum ndf_lcore_role_type type;
    
    int ports; //此lcore处理的nic数量
    struct netif_port_conf pqsp[NETIF_MAX_RTE_PORTS];
};

struct netif_port {
    char name[IFNAMSIZ];
    portid_t id; //device id
    int n_rxq; //rx queue number
    int n_txq; //tx queue number
    int socket; //socket id
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