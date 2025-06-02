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
lcoreid_t lcore2index[NDF_MAX_LCORE + 1]; //维护port索引和lcore索引的映射关系

static int lcore_index_init(void)
{
    lcoreid_t cid;
    int i;

    for(i = 0; i <= NDF_MAX_LCORE; i++){
        lcore2index[i] = NDF_MAX_LCORE;
    }

    for(i = 0; lcore_conf[i].ports > 0; i++){
        cid = lcore_conf[i].id;
        if(!rte_lcore_is_enabled(cid))
            return ENDF_NONEALCORE;
        lcore2index[cid] = i;
    }

#ifdef CONFIG_NDF_NETIF_DEBUG
    printf("lcore fast searching table: \n");
    for (i = 0; i <= NDF_MAX_LCORE; i++) {
        if (lcore2index[i] != NDF_MAX_LCORE)
            printf("\tcid: %2d --> %2d\n", i, lcore2index[i]);
    }
#endif
}

static void netif_lcore_init(){
    int i, err;
    lcoreid_t cid;

    //build lcore fst searching table
    err = lcore_index_init();
    if(err != ENDF_OK){
        rte_exit(EXIT_FAILURE, "%s: lcore_index_init failed (cause: %s), exit ...\n",
                __func__, ndf_strerror(err));
    }
}

static void lcore_job_recv_fwd(/* void* arg */){
    int i,j;
    lcoreid_t cid;

    cid = rte_lcore_id();

    for (i = 0; i < lcore_conf[lcore2index[cid]].ports; i++)
    {

    }
}