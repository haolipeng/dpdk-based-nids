#include <stdio.h>
#include <linux/if.h>
#include <rte_mempool.h>

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
#if RTE_VERION < RTE_VERSION_NUM(18, 11, 0, 0)S
    return rte_eth_dev_count();
#else
    return rte_eth_dev_count_avail();
#endif
}