#ifndef __NDF_NETIF_H__
#define __NDF_NETIF_H__
#include <stdio.h>
#include <linux/if.h>

#include "global_data.h"
#include "dpdk.h"
#include "list.h"

enum {
    NETIF_PORT_FLAG_ENABLED                 = (0x1<<0),
    NETIF_PORT_FLAG_RUNNING                 = (0x1<<1),
    NETIF_PORT_FLAG_STOPPED                 = (0x1<<2),
    NETIF_PORT_FLAG_RX_IP_CSUM_OFFLOAD      = (0x1<<3),
    NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD      = (0x1<<4),
    NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD     = (0x1<<5),
    NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD     = (0x1<<6),
    NETIF_PORT_FLAG_TX_VLAN_INSERT_OFFLOAD  = (0x1<<7),
    NETIF_PORT_FLAG_RX_VLAN_STRIP_OFFLOAD   = (0x1<<8),
    NETIF_PORT_FLAG_FORWARD2KNI             = (0x1<<9),
    NETIF_PORT_FLAG_TC_EGRESS               = (0x1<<10),
    NETIF_PORT_FLAG_TC_INGRESS              = (0x1<<11),
    NETIF_PORT_FLAG_NO_ARP                  = (0x1<<12),
    NETIF_PORT_FLAG_TX_MBUF_FAST_FREE       = (0x1<<13),
};

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

/* max mtu and default mtu */
#define NETIF_MAX_ETH_MTU           9000
#define NETIF_DEFAULT_ETH_MTU       1500

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

/************************ data type for NIC ****************************/
typedef enum {
    PORT_TYPE_GENERAL,
    PORT_TYPE_VLAN,
    PORT_TYPE_TUNNEL,
    PORT_TYPE_INVAL,
} port_type_t;

struct netif_port {
    char name[IFNAMSIZ];
    portid_t id; //device id
    port_type_t   type;                       /* device type */
    uint16_t flag;                       /* device flag */
    int n_rxq; //rx queue number
    int n_txq; //tx queue number
    uint16_t                rxq_desc_nb;                /* rx queue descriptor number */
    uint16_t                txq_desc_nb;                /* tx queue descriptor number */
    int socket; //socket id
    struct rte_ether_addr   addr;                       /* MAC address */
    uint16_t mtu;

    struct list_head        list;                       /* device list node hashed by id */

    struct rte_mempool  *mbuf_pool; //packet mempool
    struct rte_eth_dev_info dev_info;                   /* PCI Info + driver name */
    struct rte_eth_conf     dev_conf;                   /* device configuration */
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