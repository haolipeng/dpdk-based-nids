#include "common.h"
#include "netif.h"

#define NETIF_PKTPOOL_NB_MBUF_DEF   65535
#define NETIF_PKTPOOL_NB_MBUF_MIN   1023
#define NETIF_PKTPOOL_NB_MBUF_MAX   134217727
int netif_pktpool_nb_mbuf = NETIF_PKTPOOL_NB_MBUF_DEF;

#define NETIF_PKTPOOL_MBUF_CACHE_DEF    256
#define NETIF_PKTPOOL_MBUF_CACHE_MIN    32
#define NETIF_PKTPOOL_MBUF_CACHE_MAX    8192
int netif_pktpool_mbuf_cache = NETIF_PKTPOOL_MBUF_CACHE_DEF;

int netif_init(void)
{
    return ENDF_OK;
}

int netif_term(void)
{
    return ENDF_OK;
}

/********************************************* mbufpool *******************************************/
struct rte_mempool *pktmbuf_pool[NDF_MAX_SOCKET];
static void netif_pktmbuf_pool_init(){
    int i;
    char poolname[32];
    for(int i = 0; i < get_numa_nodes(); i++){
        snprintf(poolname, sizeof(poolname), "mbuf_pool_%d", i);
        pktmbuf_pool[i] = rte_pktmbuf_pool_create(poolname, netif_pktpool_nb_mbuf, netif_pktpool_mbuf_cache, 0, RTE_MBUF_DEFAULT_BUF_SIZE, i);
        if(NULL == pktmbuf_pool[i]){
            rte_exit(EXIT_FAILURE, "Cannot init mbuf pool on socket %d", i);
        }
    }
}

/****************************************** lcore  conf ********************************************/
/* worker configuration array */
static struct netif_lcore_conf lcore_conf[NDF_MAX_LCORE];

static void lcore_job_recv_fwd(void* arg){
    int i,j;
    lcoreid_t cid;

    cid = rte_lcore_id();
    assert(cid != LCORE_ID_ANY);

    for(i = 0; i < lcore)
}