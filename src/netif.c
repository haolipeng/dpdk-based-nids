#include "common.h"
#include "netif.h"
#include "list.h"
#include "scheduler.h"

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
    //TODO:need finished
    return ENDF_OK;
}

int netif_term(void)
{
    //TODO:need finished
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
/* per-lcore isolated reception queues */
static struct list_head isol_rxq_tab[NDF_MAX_LCORE];

/* worker configuration array */
static struct netif_lcore_conf lcore_conf[NDF_MAX_LCORE];
lcoreid_t lcore2index[NDF_MAX_LCORE + 1]; //维护port索引和lcore索引的映射关系
portid_t port2index[NDF_MAX_LCORE][NETIF_MAX_PORTS];

static int lcore_index_init(void)
{
    lcoreid_t cid;
    int i;

    for(i = 0; i <= NDF_MAX_LCORE; i++){
        lcore2index[i] = NDF_MAX_LCORE;
    }

    for(i = 0; lcore_conf[i].nports > 0; i++){
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

static void port_index_init(void){
    int i,j,k;
    lcoreid_t cid;
    portid_t pid;

    for(i = 0; i < NDF_MAX_LCORE; i++){
        for(j = 0; j < NETIF_MAX_PORTS; j++)
        {
            port2index[i][j] = NETIF_PORT_ID_INVALID;
        }
    }

    for(i = 0; i < NDF_MAX_LCORE; i++){
        k = 0;
        for(j = 0; j < lcore_conf[i].nports; j++) //遍历当前端口数量
        {
            cid = lcore_conf[i].id;//core id
            pid = lcore_conf[i].pqs[j].id;//port id
            port2index[cid][pid] = k++;
        }
    }
#ifdef CONFIG_NDF_NETIF_DEBUG
    printf("port fast searching table(port2index[cid][pid]): \n");
    for (ii = 0; ii < NDF_MAX_LCORE; ii++) {
        for (jj = 0; jj < NETIF_MAX_PORTS; jj++) {
            if (port2index[ii][jj] != NETIF_PORT_ID_INVALID)
                printf("\tcid: %2d, pid: %2d --> index: %2d\n", ii, jj, port2index[ii][jj]);
        }
    }
#endif
}

static void build_lcore_index(void)
{
    int cid, idx = 0;

    //将主核心(master lcore)放在索引0位置
    g_lcore_index2id[idx++] = rte_get_main_lcore();

    //按照角色顺序排列核心
    //添加转发-工作核心
    for (cid = 0; cid < NDF_MAX_LCORE; cid++)
        if (g_lcore_role[cid] == LCORE_ROLE_FWD_WORKER)
            g_lcore_index2id[idx++] = cid;

    //添加隔离-工作核心
    for (cid = 0; cid < NDF_MAX_LCORE; cid++)
        if (g_lcore_role[cid] == LCORE_ROLE_ISOLRX_WORKER)
            g_lcore_index2id[idx++] = cid;
    
    g_lcore_num = idx;

    //建立反向映射表
    for (idx = 0; idx < NDF_MAX_LCORE; idx++) {
        cid = g_lcore_index2id[idx];
        if (cid >= 0 && cid < NDF_MAX_LCORE)
            g_lcore_id2index[cid] = idx;
    }
}

static inline void dump_lcore_role(void)
{
    ndf_lcore_role_t role;
    lcoreid_t cid;
    char bufs[LCORE_ROLE_MAX+1][1024];
    char results[sizeof bufs];

    for (role = 0; role < LCORE_ROLE_MAX; role++)
        snprintf(bufs[role], sizeof(bufs[role]), "\t%s: ",
                dpvs_lcore_role_str(role));

    for (cid = 0; cid < NDF_MAX_LCORE; cid++) {
        role = g_lcore_role[cid];
        snprintf(&bufs[role][strlen(bufs[role])], sizeof(bufs[role])
                    - strlen(bufs[role]), "%-4d", cid);
    }

    snprintf(results, sizeof(results), "%s", bufs[0]);
    for (role = 1; role < LCORE_ROLE_MAX; role++) {
        strncat(results, "\n", sizeof(results) - strlen(results) - 1);
        strncat(results, bufs[role], sizeof(results) - strlen(results) - 1);
    }

    //RTE_LOG(INFO, NETIF, "LCORE ROLES:\n%s\n", results);
}

static void lcore_role_init(void)
{
    int i, cid;

    for (cid = 0; cid < NDF_MAX_LCORE; cid++)
        if (!rte_lcore_is_enabled(cid))
            /* invalidate the disabled cores */
            g_lcore_role[cid] = LCORE_ROLE_MAX;

    //获取主核逻辑核心id，并将其角色设置为LCORE_ROLE_MASTER
    cid = rte_get_main_lcore();

    assert(g_lcore_role[cid] == LCORE_ROLE_IDLE);
    g_lcore_role[cid] = LCORE_ROLE_MASTER;

    i = 0;
    while (lcore_conf[i].nports > 0) {
        cid = lcore_conf[i].id;
        assert(g_lcore_role[cid] == LCORE_ROLE_IDLE);
        g_lcore_role[cid] = lcore_conf[i].type;
        i++;
    }

    for (cid = 0; cid < NDF_MAX_LCORE; cid++) {
        if (!list_empty(&isol_rxq_tab[cid])) {
            assert(g_lcore_role[cid] == LCORE_ROLE_IDLE);
            g_lcore_role[cid] =  LCORE_ROLE_ISOLRX_WORKER;
        }
    }

    build_lcore_index();
    dump_lcore_role();
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

    //build port fast searching table
    port_index_init();
}

static void lcore_job_recv_fwd(/* void* arg */){
    int i,j;
    lcoreid_t cid;

    cid = rte_lcore_id();

    for (i = 0; i < lcore_conf[lcore2index[cid]].nports; i++)
    {

    }
}