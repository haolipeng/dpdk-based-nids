#include <linux/if_ether.h>

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

#define NETIF_NB_RX_DESC_DEF    256
#define NETIF_NB_RX_DESC_MIN    16
#define NETIF_NB_RX_DESC_MAX    8192

#define NETIF_NB_TX_DESC_DEF    512
#define NETIF_NB_TX_DESC_MIN    16
#define NETIF_NB_TX_DESC_MAX    8192

#define RETA_CONF_SIZE  (RTE_ETH_RSS_RETA_SIZE_512 / RTE_ETH_RETA_GROUP_SIZE)

#define RTE_LOGTYPE_NETIF RTE_LOGTYPE_USER1

struct port_conf_stream {
    int port_id;                    // 端口ID，用于标识网络端口
    char name[32];                  // 端口名称，最大32字符

    int rx_queue_nb;                // 接收队列数量
    int rx_desc_nb;                 // 接收描述符数量
    char rss[32];                   // RSS(Receive Side Scaling)配置，用于多队列负载均衡
    int mtu;                        // 最大传输单元(Maximum Transmission Unit)

    int tx_queue_nb;                // 发送队列数量
    int tx_desc_nb;                 // 发送描述符数量
    bool tx_mbuf_fast_free;         // 是否启用快速释放发送mbuf的优化

    bool promisc_mode;              // 是否启用混杂模式(接收所有网络流量)
    bool allmulticast;              // 是否接收所有组播报文

    struct list_head port_list_node; // 链表节点，用于将端口连接到端口列表中
};

/* just for print */
struct port_queue_lcore_map {
    portid_t pid;
    char mac_addr[18];
    queueid_t rx_qid[NETIF_MAX_QUEUES];
    queueid_t tx_qid[NETIF_MAX_QUEUES];
};
portid_t netif_max_pid;
queueid_t netif_max_qid;
struct port_queue_lcore_map pql_map[NETIF_MAX_PORTS];

static portid_t port_id_end = 0;
static uint16_t g_nports;

static struct list_head port_list;      /* device configurations from cfgfile */
static struct list_head worker_list;    /* lcore configurations from cfgfile */

#define NETIF_PORT_TABLE_BITS 8
#define NETIF_PORT_TABLE_BUCKETS (1 << NETIF_PORT_TABLE_BITS)
#define NETIF_PORT_TABLE_MASK (NETIF_PORT_TABLE_BUCKETS - 1)
static struct list_head port_tab[NETIF_PORT_TABLE_BUCKETS]; /* hashed by id */
static struct list_head port_ntab[NETIF_PORT_TABLE_BUCKETS]; /* hashed by name */

/* physical nic id = phy_pid_base + index */
static portid_t phy_pid_base = 0;
static portid_t phy_pid_end = -1; // not inclusive

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
    return ENDF_OK;
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
                ndf_lcore_role_str(role));

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

    RTE_LOG(INFO, NETIF, "LCORE ROLES:\n%s\n", results);
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

static inline uint16_t netif_rx_burst(portid_t pid, struct netif_queue_conf* qconf){
    struct rte_mbuf* mbuf;
    int nrx = 0;

    nrx = rte_eth_rx_burst(pid, qconf->id, qconf->mbufs, NETIF_MAX_PKT_BURST);
    RTE_LOG(DEBUG, NETIF, "port id: %u ,queue id:%u recv:%d\n", pid, qconf->id, nrx);

    return nrx;
}

static void lcore_job_recv_fwd(void* arg __attribute__((unused)))
{
    int i,j;
    portid_t pid;
    lcoreid_t cid;
    struct netif_queue_conf *qconf;

    cid = rte_lcore_id();
    for (i = 0; i < lcore_conf[lcore2index[cid]].nports; i++) {
        pid = lcore_conf[lcore2index[cid]].pqs[i].id;

        for (j = 0; j < lcore_conf[lcore2index[cid]].pqs[i].nrxq; j++) {
            qconf = &lcore_conf[lcore2index[cid]].pqs[i].rxqs[j];

            qconf->len = netif_rx_burst(pid, qconf);

            //TODO:need to process packets
            //lcore_process_packets(qconf->mbufs, cid, qconf->len, 0);
        }
    }
}

//网络工作任务的最大值
#define NETIF_JOB_MAX   6

static struct ndf_lcore_job_array netif_jobs[NETIF_JOB_MAX] = {
    [0] = {
        .role = LCORE_ROLE_FWD_WORKER,
        .job.name = "recv_fwd",
        .job.type = LCORE_JOB_LOOP,
        .job.func = lcore_job_recv_fwd,//收包和转发
    },

    /* [1] = {
        .role = LCORE_ROLE_FWD_WORKER,
        .job.name = "xmit",
        .job.type = LCORE_JOB_LOOP,
        .job.func = lcore_job_xmit,//发送数据包
    }, 

    [2] = {
        .role = LCORE_ROLE_FWD_WORKER,
        .job.name = "timer_manage",
        .job.type = LCORE_JOB_LOOP,
        .job.func = lcore_job_timer_manage,
    },

    [3] = {
        .role = LCORE_ROLE_ISOLRX_WORKER,
        .job.name = "isol_pkt_rcv",
        .job.type = LCORE_JOB_LOOP,
        .job.func = recv_on_isol_lcore,
    },

    [4] = {
        .role = LCORE_ROLE_MASTER,
        .job.name = "timer_manage",
        .job.type = LCORE_JOB_LOOP,
        .job.func = lcore_job_timer_manage,
    },
    */
};

static void netif_lcore_init(){
    size_t i;
    int err;
    lcoreid_t cid;

    //build lcore fst searching table
    err = lcore_index_init();
    if(err != ENDF_OK){
        rte_exit(EXIT_FAILURE, "%s: lcore_index_init failed (cause: %s), exit ...\n",
                __func__, ndf_strerror(err));
    }

    //build port fast searching table
    port_index_init();

    for (i = 0; i < NELEMS(netif_jobs); i++) {
        err = ndf_lcore_job_register(&netif_jobs[i].job, netif_jobs[i].role);
        if (err < 0) {
            rte_exit(EXIT_FAILURE, "%s: fail to register lcore job '%s', exit ...\n",
                    __func__, netif_jobs[i].job.name);
            break;
        }
    }
}

static inline struct port_conf_stream *get_port_conf_stream(const char *name)
{
    struct port_conf_stream *current_cfg;

    list_for_each_entry(current_cfg, &port_list, port_list_node) {
        if (!strcmp(name, current_cfg->name))
            return current_cfg;
    }

    return NULL;
}

/*
 * params:
 *   @pid: [in] port id
 *   @qids: [out] queue id array containing rss queues when return
 *   @n_queues: [in,out], `qids` array length when input, rss queue number when return
 */
static int get_configured_rss_queues(portid_t pid, queueid_t *qids, int *n_queues)
{
    int i, j, k, tk = 0;
    if (!qids || !n_queues || *n_queues < NETIF_MAX_QUEUES)
        return ENDF_INVAL;

    for (i = 0; lcore_conf[i].nports > 0; i++) {
        if (lcore_conf[i].type != LCORE_ROLE_FWD_WORKER)
            continue;

        for (j = 0; j < lcore_conf[i].nports; j++) {
            if (lcore_conf[i].pqs[j].id == pid)
                break;
        }

        if (lcore_conf[i].pqs[j].id != pid)
            return ENDF_INVAL;

        for (k = 0; k < lcore_conf[i].pqs[j].nrxq; k++) {
            qids[tk++] = lcore_conf[i].pqs[j].txqs[k].id;
            if (tk > *n_queues)
                return ENDF_NOMEM;
        }
    }
    *n_queues = tk;
    return ENDF_OK;
}

static int port_rx_queues_get(portid_t pid)
{
    int i = 0, j;
    int rx_ports = 0;

    while (lcore_conf[i].nports > 0) {
        for (j = 0;  j < lcore_conf[i].nports; j++) {
            if (lcore_conf[i].pqs[j].id == pid)
                rx_ports += lcore_conf[i].pqs[j].nrxq;
        }
        i++;
    }
    return rx_ports;
}

static int port_tx_queues_get(portid_t pid)
{
    int i = 0, j;
    int tx_ports = 0;

    while (lcore_conf[i].nports > 0) {
        for (j = 0;  j < lcore_conf[i].nports; j++) {
            if (lcore_conf[i].pqs[j].id == pid)
                tx_ports += lcore_conf[i].pqs[j].ntxq;
        }
        i++;
    }
    return tx_ports;
}

static int rss_resolve_proc(char *rss)
{
    int rss_value = 0;

    if (!strcmp(rss, "all"))
        rss_value = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP;
    else if (!strcmp(rss, "ip"))
        rss_value = RTE_ETH_RSS_IP;
    else if (!strcmp(rss, "tcp"))
        rss_value = RTE_ETH_RSS_TCP;
    else if (!strcmp(rss, "udp"))
        rss_value = RTE_ETH_RSS_UDP;
    else if (!strcmp(rss, "sctp"))
        rss_value = RTE_ETH_RSS_SCTP;
    else if (!strcmp(rss, "ether"))
        rss_value = RTE_ETH_RSS_L2_PAYLOAD;
    else if (!strcmp(rss, "port"))
        rss_value = RTE_ETH_RSS_PORT;
    else if (!strcmp(rss, "tunnel"))
        rss_value = RTE_ETH_RSS_TUNNEL;

    return rss_value;
}

/* check and adapt device offloading/rss features */
static void adapt_device_conf(portid_t port_id, uint64_t *rss_hf,
        uint64_t *rx_offload, uint64_t *tx_offload)
{
    struct rte_eth_dev_info dev_info;

    if (unlikely(rte_eth_dev_info_get(port_id, &dev_info) != 0)) {
        RTE_LOG(WARNING, NETIF, "%s: fail to get dev_info of port %d\n", __func__, port_id);
        return;
    }

    if ((dev_info.flow_type_rss_offloads | *rss_hf) !=
        dev_info.flow_type_rss_offloads) {
        RTE_LOG(WARNING, NETIF,
                "Ethdev port_id=%u invalid rss_hf: 0x%"PRIx64", valid value: 0x%"PRIx64"\n",
                port_id, *rss_hf, dev_info.flow_type_rss_offloads);
        /* mask the unsupported rss_hf */
        *rss_hf &= dev_info.flow_type_rss_offloads;
    }

    if ((dev_info.rx_offload_capa | *rx_offload) != dev_info.rx_offload_capa) {
        RTE_LOG(WARNING, NETIF,
                "Ethdev port_id=%u invalid rx_offload: 0x%"PRIx64", valid value: 0x%"PRIx64"\n",
                port_id, *rx_offload, dev_info.rx_offload_capa);
        /* mask the unsupported rx_offload */
        *rx_offload &= dev_info.rx_offload_capa;
    }

    if ((dev_info.tx_offload_capa | *tx_offload) != dev_info.tx_offload_capa) {
        RTE_LOG(WARNING, NETIF,
                "Ethdev port_id=%u invalid tx_offload: 0x%"PRIx64", valid value: 0x%"PRIx64"\n",
                port_id, *tx_offload, dev_info.tx_offload_capa);
        /* mask the unsupported tx_offload */
        *tx_offload &= dev_info.tx_offload_capa;
    }
}

/* fill in rx/tx queue configurations, including queue number,
 * decriptor number, bonding device's rss */
static void fill_port_config(struct netif_port *port, char *promisc_on, char *allmulticast)
{
    assert(port);

    char rss[256] = {0};
    size_t index = 0;
    int rss_index = 0;
    struct port_conf_stream *cfg_stream;

    port->n_rxq = port_rx_queues_get(port->id);
    port->n_txq = port_tx_queues_get(port->id);

    cfg_stream = get_port_conf_stream(port->name);
    if (cfg_stream) {
        /* device specific configurations from cfgfile */
        port->dev_conf.rx_adv_conf.rss_conf.rss_hf = 0;
        for (index = 0; index < strlen(cfg_stream->rss); index++) {
            if (cfg_stream->rss[index] == ' ') {
                continue;
            } else if (cfg_stream->rss[index] != '|') {
                rss[rss_index++] = cfg_stream->rss[index];
            } else {
                rss[rss_index] = '\0';
                rss_index = 0;
                port->dev_conf.rx_adv_conf.rss_conf.rss_hf |= rss_resolve_proc(rss);
                memset(rss, 0, sizeof(rss));
            }
        }

        if (rss[0]) {
            port->dev_conf.rx_adv_conf.rss_conf.rss_hf |= rss_resolve_proc(rss);
        }

        port->mtu = cfg_stream->mtu;
        if (cfg_stream->rx_queue_nb > 0 && port->n_rxq > cfg_stream->rx_queue_nb) {
            RTE_LOG(WARNING, NETIF, "%s: rx-queues configured in workers (%d) != "
                    "rx-queues configured in device (%d), setup %d rx-queues for %s\n",
                    port->name, port->n_rxq, cfg_stream->rx_queue_nb,
                    port->n_rxq, port->name);
        }
        if (cfg_stream->tx_queue_nb > 0 && port->n_txq > cfg_stream->tx_queue_nb) {
            RTE_LOG(WARNING, NETIF, "%s: tx-queues configured in workers (%d) != "
                    "tx-queues configured in device (%d), setup %d tx-queues for %s\n",
                    port->name, port->n_txq, cfg_stream->tx_queue_nb,
                    port->n_txq, port->name);
        }
        port->rxq_desc_nb = cfg_stream->rx_desc_nb;
        port->txq_desc_nb = cfg_stream->tx_desc_nb;
        if (cfg_stream->tx_mbuf_fast_free)
            port->flag |= NETIF_PORT_FLAG_TX_MBUF_FAST_FREE;
    } else {
        /* using default configurations */
        port->rxq_desc_nb = NETIF_NB_RX_DESC_DEF;
        port->txq_desc_nb = NETIF_NB_TX_DESC_DEF;
        port->mtu = NETIF_DEFAULT_ETH_MTU;
    }
 
    /* enable promicuous mode if configured */
    if (promisc_on) {
        if (cfg_stream && cfg_stream->promisc_mode)
            *promisc_on = 1;
        else
            *promisc_on = 0;
    }
    if (allmulticast) {
        if (cfg_stream && cfg_stream->allmulticast)
            *allmulticast = 1;
        else
            *allmulticast = 0;
    }
}

static struct rte_eth_conf default_port_conf = {
    .rxmode = {
        .mq_mode    = RTE_ETH_MQ_RX_RSS,
        .mtu        = RTE_ETHER_MTU,
        .offloads   = RTE_ETH_RX_OFFLOAD_IPV4_CKSUM,
    },
    .rx_adv_conf = {
        .rss_conf = {
            .rss_key = NULL,
            .rss_hf  = /*RTE_ETH_RSS_IP*/ RTE_ETH_RSS_TCP,
        },
    },
    .txmode = {
        .mq_mode = RTE_ETH_MQ_TX_NONE,
    },
};

int netif_print_port_conf(const struct rte_eth_conf *port_conf, char *buf, int *len)
{
    char tbuf1[256], tbuf2[128];
    if (unlikely(NULL == buf) || 0 == len)
        return ENDF_INVAL;
    if (port_conf == NULL)
        port_conf = &default_port_conf;

    memset(buf, 0, *len);
    if (port_conf->rxmode.mq_mode == RTE_ETH_MQ_RX_RSS) {
        memset(tbuf2, 0, sizeof(tbuf2));
        if (port_conf->rx_adv_conf.rss_conf.rss_hf) {
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_IP)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "ETH_RSS_IP ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_TCP)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "ETH_RSS_TCP ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_UDP)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "ETH_RSS_UDP ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_SCTP)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "ETH_RSS_SCTP ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_L2_PAYLOAD)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "ETH_RSS_L2_PAYLOAD ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_PORT)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "ETH_RSS_PORT ");
            if (port_conf->rx_adv_conf.rss_conf.rss_hf & RTE_ETH_RSS_TUNNEL)
                snprintf(tbuf2 + strlen(tbuf2), sizeof(tbuf2) - strlen(tbuf2), "ETH_RSS_TUNNEL ");
        } else {
            snprintf(tbuf2, sizeof(tbuf2), "Inhibited");
        }

        memset(tbuf1, 0, sizeof(tbuf1));
        snprintf(tbuf1, sizeof(tbuf1), "RSS: %s\n", tbuf2);
        if (*len - strlen(buf) - 1 < strlen(tbuf1)) {
            RTE_LOG(WARNING, NETIF, "[%s] no enough buf\n", __func__);
            return ENDF_INVAL;
        }
        strncat(buf, tbuf1, *len - strlen(buf) - 1);
    }

    *len = strlen(buf);
    return ENDF_OK;
}

/********************************************* port *************************************************/

static void netif_dump_rss_reta(struct netif_port *port)
{
    int i, pos;
    size_t len;
    uint32_t reta_id, reta_pos;
    char buf[RTE_ETH_RSS_RETA_SIZE_512 * 8];
    struct rte_eth_rss_reta_entry64 reta_info[RETA_CONF_SIZE];

    if (port->type != PORT_TYPE_GENERAL)
        return;

    if (unlikely(port->dev_info.reta_size == 0))
        if (unlikely(rte_eth_dev_info_get(port->id, &port->dev_info) != 0))
            return;

    memset(reta_info, 0, sizeof(reta_info));
    for (i = 0; i < port->dev_info.reta_size; i++)
        reta_info[i / RTE_ETH_RETA_GROUP_SIZE].mask = UINT64_MAX;

    if (unlikely(rte_eth_dev_rss_reta_query(port->id, reta_info, port->dev_info.reta_size)))
        return;

    buf[0] = '\0';
    len = pos = 0;
    for (i = 0; i < port->dev_info.reta_size; i++) {
        reta_id = i / RTE_ETH_RETA_GROUP_SIZE;
        reta_pos = i % RTE_ETH_RETA_GROUP_SIZE;
        if (i % 8 == 0) {
            len = snprintf(&buf[pos], sizeof(buf) - pos, "\n%4d: ", i);
            if (len >= sizeof(buf) - pos) {
                snprintf(&buf[sizeof(buf)-16], 16, "%s", "(truncated)");
                break;
            }
            pos += len;
        }
        len = snprintf(&buf[pos], sizeof(buf)-pos, "%-4d", reta_info[reta_id].reta[reta_pos]);
        if (len >= sizeof(buf) - pos) {
            snprintf(&buf[sizeof(buf)-16], 16, "%s", "(truncated)");
            break;
        }
        pos += len;
    }

    RTE_LOG(INFO, NETIF, "RSS RETA(%s):%s\n", port->name, buf);
}

static int __netif_update_rss_reta(struct netif_port *port)
{
    int i, err;
    int nrssq = NETIF_MAX_QUEUES;
    queueid_t rssq[NETIF_MAX_QUEUES];
    uint32_t reta_id, reta_pos;
    struct rte_eth_rss_reta_entry64 reta_conf[RETA_CONF_SIZE];

    if (port->type != PORT_TYPE_GENERAL)
        return ENDF_NOTSUPP;

    err = get_configured_rss_queues(port->id, rssq, &nrssq);
    if (err != ENDF_OK)
        return err;
#ifdef CONFIG_DPVS_NETIF_DEBUG
    printf("RSS QUEUES(%s): ", port->name);
    for (i = 0; i < nrssq; i++) {
        printf("%-4d", rssq[i]);
    }
    printf("\n");
#endif

    memset(reta_conf, 0, sizeof(reta_conf));
    for (i = 0; i < port->dev_info.reta_size; i++) {
        reta_id = i / RTE_ETH_RETA_GROUP_SIZE;
        reta_pos = i % RTE_ETH_RETA_GROUP_SIZE;
        reta_conf[reta_id].mask = UINT64_MAX;
        reta_conf[reta_id].reta[reta_pos] = (uint16_t)(rssq[i % nrssq]);
    }

    if (rte_eth_dev_rss_reta_update(port->id, reta_conf, port->dev_info.reta_size))
        return ENDF_DPDKAPIFAIL;

    netif_dump_rss_reta(port);
    return ENDF_OK;
}

static inline portid_t netif_port_id_alloc(void)
{
    // The netif_port_id_alloc ensures the relation `g_nports == port_id_end` always stands,
    // which means all ids in range [0, port_id_end) are assgined to ports.
    portid_t pid;

    if (port_id_end > g_nports) {
        for (pid = port_id_end - 1; pid != 0; pid--) {
            if (netif_port_get(pid) == NULL)
                return pid;
        }
    }

    return port_id_end++;
}

struct netif_port *netif_alloc(portid_t id, size_t priv_size, const char *namefmt,
                               unsigned int nrxq, unsigned int ntxq,
                               void (*setup)(struct netif_port *))
{
    int ii;
    struct netif_port *dev;
    static const uint8_t mac_zero[6] = {0};

    size_t alloc_size;

    alloc_size = sizeof(struct netif_port);
    if (priv_size) {
        /* ensure 32-byte alignment of private area */
        alloc_size = __ALIGN_KERNEL(alloc_size, NETIF_ALIGN);
        alloc_size += priv_size;
    }

    dev = rte_zmalloc("netif", alloc_size, RTE_CACHE_LINE_SIZE);
    if (!dev) {
        RTE_LOG(ERR, NETIF, "%s: no memory\n", __func__);
        return NULL;
    }

    if (id != NETIF_PORT_ID_INVALID && !netif_port_get(id))
        dev->id = id;
    else
        dev->id = netif_port_id_alloc();

    if (strstr(namefmt, "%d"))
        snprintf(dev->name, sizeof(dev->name), namefmt, dev->id);
    else
        snprintf(dev->name, sizeof(dev->name), "%s", namefmt);

    rte_rwlock_init(&dev->dev_lock);
    dev->socket = SOCKET_ID_ANY;
    dev->hw_header_len = sizeof(struct rte_ether_hdr); /* default */

    if (setup)
        setup(dev);

    /* flag may set by setup() routine */
    dev->flag |= NETIF_PORT_FLAG_ENABLED;
    dev->n_rxq = nrxq;
    dev->n_txq = ntxq;

    /* virtual dev has no NUMA-node */
    if (dev->socket == SOCKET_ID_ANY)
        dev->socket = rte_socket_id();
    dev->mbuf_pool = pktmbuf_pool[dev->socket];

    if (memcmp(&dev->addr, &mac_zero, sizeof(dev->addr)) == 0) {
        //TODO: use random lladdr ?
    }

    if (dev->mtu == 0)
        dev->mtu = ETH_DATA_LEN;

    //netif_mc_init(dev); TODO: fix this bug

    return dev;
}

static int netif_update_rss_reta(struct netif_port *port)
{
    switch (port->type) {
        case PORT_TYPE_GENERAL:
            return __netif_update_rss_reta(port);
        default:
            return ENDF_OK;
    }
}

static inline int port_tab_hashkey(portid_t id)
{
    return id & NETIF_PORT_TABLE_MASK;
}

static unsigned int port_ntab_hashkey(const char *name, size_t len)
{
    int i;
    unsigned int hash=1315423911;
    for (i = 0; i < (int)len; i++)
    {
        if (name[i] == '\0')
            break;
        hash^=((hash<<5)+name[i]+(hash>>2));
    }

    return (hash % NETIF_PORT_TABLE_BUCKETS);
}

static inline void setup_dev_of_flags(struct netif_port *port)
{
    port->flag |= NETIF_PORT_FLAG_ENABLED;

    /* tx offload conf and flags */
    if (port->dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_IPV4_CKSUM)
        port->flag |= NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD;

    if (port->dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_TCP_CKSUM)
        port->flag |= NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD;

    if (port->dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_UDP_CKSUM)
        port->flag |= NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD;

    // Device supports optimization for fast release of mbufs.
    // The feature is configurable via setting.conf.
    // When set application must guarantee that per-queue all mbufs comes from
    // the same mempool and has refcnt = 1.
    // https://doc.dpdk.org/api/rte__ethdev_8h.html#a43f198c6b59d965130d56fd8f40ceac1
    if (!(port->dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE))
        port->flag &= ~NETIF_PORT_FLAG_TX_MBUF_FAST_FREE;

    /* FIXME: may be a bug in dev_info get for virtio device,
     *        set the txq_of_flags manually for this type device */
    if (strncmp(port->dev_info.driver_name, "net_virtio", strlen("net_virtio")) == 0) {
        port->flag |= NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD;
        port->flag &= ~NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD;
        port->flag &= ~NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD;
    }

    /*
     * we may have multiple vlan dev on one rte_ethdev,
     * and mbuf->vlan_tci is RX only!
     * while there's only one PVID (RTE_ETH_TX_OFFLOAD_VLAN_INSERT),
     * to make things easier, do not support TX VLAN instert offload.
     * or we have to check if VID is PVID (than to tx offload it).
     */
#if 0
    if (dev_info->tx_offload_capa & RTE_ETH_TX_OFFLOAD_VLAN_INSERT) {
        port->flag |= NETIF_PORT_FLAG_TX_VLAN_INSERT_OFFLOAD;
        port->dev_conf.txmode.hw_vlan_insert_pvid = 1;
        rte_eth_dev_set_vlan_pvid();
    }
#endif

    /* rx offload conf and flags */
    if (port->dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_VLAN_STRIP)
        port->flag |= NETIF_PORT_FLAG_RX_VLAN_STRIP_OFFLOAD;
    if (port->dev_info.rx_offload_capa & RTE_ETH_RX_OFFLOAD_IPV4_CKSUM)
        port->flag |= NETIF_PORT_FLAG_RX_IP_CSUM_OFFLOAD;
}

struct netif_port* netif_port_get(portid_t id)
{
    int hash = port_tab_hashkey(id);
    struct netif_port *port;
    assert(id <= NETIF_MAX_PORTS);

    list_for_each_entry(port, &port_tab[hash], list) {
        if (port->id == id) {
            return port;
        }
    }

    return NULL;
}

int netif_print_lcore_conf(char *buf, int *len, bool is_all, portid_t pid)
{
    int i, j;
    char tbuf[256], tbuf2[256], line[1024];
    char rxbuf[16], txbuf[16];
    int left_len;
    struct netif_port *port;

    /* format map in string */
    memset(buf, 0, *len);
    if (is_all) {
        snprintf(line, sizeof(line) - 1, "    %-12s", "");
        for (i = 0; i <= netif_max_pid; i++) {
            port = netif_port_get(i);
            assert(port);
            snprintf(tbuf2, sizeof(tbuf2) - 1, "%s: %s ", port->name, pql_map[i].mac_addr);
            snprintf(tbuf, sizeof(tbuf) - 1, "%-25s", tbuf2);
            strncat(line, tbuf, sizeof(line) - strlen(line) - 1);
        }
        strncat(line, "\n", sizeof(line) - strlen(line) - 1);
        left_len = *len - strlen(buf);
        if (unlikely(left_len < 0)) {
            RTE_LOG(WARNING, NETIF, "buffer not enough for '%s'\n", __func__);
            *len = strlen(buf);
            return ENDF_INVAL;
        }
        strncat(buf, line, left_len - 1);
    }

    for (i = 0; i <= netif_max_qid; i++) {
        snprintf(tbuf2, sizeof(tbuf2) - 1, "rx%d-tx%d", i, i);
        snprintf(line, sizeof(line) - 1, "    %-12s", tbuf2);
        for (j = 0; j <= netif_max_pid; j++) {
            if (!is_all && pid != j)
                continue;
            if (NETIF_PORT_ID_INVALID == pql_map[j].rx_qid[i])
                snprintf(rxbuf, sizeof(rxbuf) - 1, "xx");
            else
                snprintf(rxbuf, sizeof(rxbuf) - 1, "cpu%d", pql_map[j].rx_qid[i]);
            if (NETIF_PORT_ID_INVALID == pql_map[j].tx_qid[i])
                snprintf(txbuf, sizeof(txbuf) - 1, "xx");
            else
                snprintf(txbuf, sizeof(txbuf) - 1, "cpu%d", pql_map[j].tx_qid[i]);

            snprintf(tbuf2, sizeof(tbuf2) - 1, "%s-%s", rxbuf, txbuf);
            snprintf(tbuf, sizeof(tbuf) - 1, "%-25s", tbuf2);
            strncat(line, tbuf, sizeof(line) - strlen(line) - 1);
        }
        strncat(line, "\n", sizeof(line) - strlen(line) - 1);
        left_len = *len - strlen(buf);
        if (unlikely(left_len <= 0)) {
            RTE_LOG(WARNING, NETIF, "buffer not enough for '%s'\n", __func__);
            *len = strlen(buf);
            return ENDF_INVAL;
        }
        strncat(buf, line, left_len - 1);
    }

    *len = strlen(buf);
    return ENDF_OK;
}

static int build_port_queue_lcore_map(void)
{
    int i, j, k;
    lcoreid_t cid;
    portid_t pid;
    queueid_t qid;
    int bflag = 0;
    struct netif_port *dev;

    /* init map struct */
    for (i = 0; i < NETIF_MAX_PORTS; i++) {
        pql_map[i].pid = NETIF_PORT_ID_INVALID;
        snprintf(&pql_map[i].mac_addr[0], 18, "xx:xx:xx:xx:xx:xx");
        for (j = 0; j < NETIF_MAX_QUEUES; j++) {
            pql_map[i].rx_qid[j] = NETIF_PORT_ID_INVALID;
            pql_map[i].tx_qid[j] = NETIF_PORT_ID_INVALID;
        }
    }

    /* fill in map struct */
    i = 0;
    while (lcore_conf[i].nports > 0) {
        cid = lcore_conf[i].id;
        for (j = 0; j < lcore_conf[i].nports; j++) {
            pid = lcore_conf[i].pqs[j].id;
            if (pid > netif_max_pid)
                netif_max_pid = pid;
            if (pql_map[pid].pid == NETIF_PORT_ID_INVALID) {
                pql_map[pid].pid = pid;

                dev = netif_port_get(pid);
                if (dev) {
                    rte_ether_format_addr(pql_map[pid].mac_addr,
                            sizeof(pql_map[pid].mac_addr), &dev->addr);
                }
            }
            else if (pql_map[pid].pid != pid) {
                RTE_LOG(ERR, NETIF, "%s: port id not consistent\n", __func__);
                bflag = 1;
                break;
            }
            for (k = 0; k < lcore_conf[i].pqs[j].nrxq; k++) {
                qid = lcore_conf[i].pqs[j].rxqs[k].id;
                if (qid > netif_max_qid)
                    netif_max_qid = qid;
                pql_map[pid].rx_qid[qid] = cid;
            }
            for (k = 0; k < lcore_conf[i].pqs[j].ntxq; k++) {
                qid = lcore_conf[i].pqs[j].txqs[k].id;
                if (qid > netif_max_qid)
                    netif_max_qid = qid;
                pql_map[pid].tx_qid[qid] = cid;
            }
        }
        if (bflag)
            break;
        i++;
    }
    return ENDF_OK;
}

/*
 * Note: Invoke the function after port is allocated and lcores are configured.
 */
int netif_port_start(struct netif_port *port)
{
    int ii, ret;
    queueid_t qid;
    char promisc_on, allmulticast;
    char buf[512];
    struct rte_eth_txconf txconf;
    struct rte_eth_link link;
    const int wait_link_up_msecs = 30000; //30s
    int buflen = sizeof(buf);

    if (unlikely(NULL == port))
        return ENDF_INVAL;

    fill_port_config(port, &promisc_on, &allmulticast);
    if (!port->n_rxq && !port->n_txq) {
        RTE_LOG(WARNING, NETIF, "%s: no queues to setup for %s\n", __func__, port->name);
        return ENDF_DPDKAPIFAIL;
    }

    if (port->n_rxq > port->dev_info.max_rx_queues ||
            port->n_txq > port->dev_info.max_tx_queues) {
        rte_exit(EXIT_FAILURE, "%s: %s supports %d rx-queues and %d tx-queues at max, "
                "but %d rx-queues and %d tx-queues are configured.\n", __func__,
                port->name, port->dev_info.max_rx_queues,
                port->dev_info.max_tx_queues, port->n_rxq, port->n_txq);
    }

    if (port->flag & NETIF_PORT_FLAG_RX_IP_CSUM_OFFLOAD)
        port->dev_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_IPV4_CKSUM;

    if (port->flag & NETIF_PORT_FLAG_RX_VLAN_STRIP_OFFLOAD)
        port->dev_conf.rxmode.offloads |= RTE_ETH_RX_OFFLOAD_VLAN_STRIP;

    if (port->flag & NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD)
        port->dev_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_IPV4_CKSUM;

    if (port->flag & NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD)
        port->dev_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_UDP_CKSUM;

    if (port->flag & NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD)
        port->dev_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_TCP_CKSUM;

    if (port->flag & NETIF_PORT_FLAG_TX_MBUF_FAST_FREE)
        port->dev_conf.txmode.offloads |= RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

    adapt_device_conf(port->id, &port->dev_conf.rx_adv_conf.rss_conf.rss_hf,
            &port->dev_conf.rxmode.offloads, &port->dev_conf.txmode.offloads);

    ret = rte_eth_dev_configure(port->id, port->n_rxq, port->n_txq, &port->dev_conf);
    if (ret < 0 ) {
        RTE_LOG(ERR, NETIF, "%s: fail to config %s\n", __func__, port->name);
        return ENDF_DPDKAPIFAIL;
    }

    // setup rx queues
    if (port->n_rxq > 0) {
        for (qid = 0; qid < port->n_rxq; qid++) {
            ret = rte_eth_rx_queue_setup(port->id, qid, port->rxq_desc_nb,
                    port->socket, NULL, pktmbuf_pool[port->socket]);
            if (ret < 0) {
                RTE_LOG(ERR, NETIF, "%s: fail to config %s:rx-queue-%d\n",
                        __func__, port->name, qid);
                return ENDF_DPDKAPIFAIL;
            }
        }
    }

    // setup tx queues
    if (port->n_txq > 0) {
        for (qid = 0; qid < port->n_txq; qid++) {
            memcpy(&txconf, &port->dev_info.default_txconf, sizeof(struct rte_eth_txconf));
#if RTE_VERSION < RTE_VERSION_NUM(18, 11, 0, 0)
            if (port->dev_conf.rxmode.jumbo_frame
                    || (port->flag & NETIF_PORT_FLAG_TX_IP_CSUM_OFFLOAD)
                    || (port->flag & NETIF_PORT_FLAG_TX_UDP_CSUM_OFFLOAD)
                    || (port->flag & NETIF_PORT_FLAG_TX_TCP_CSUM_OFFLOAD))
                txconf.txq_flags = 0;
#endif
            txconf.offloads = port->dev_conf.txmode.offloads;
            ret = rte_eth_tx_queue_setup(port->id, qid, port->txq_desc_nb,
                    port->socket, &txconf);
            if (ret < 0) {
                RTE_LOG(ERR, NETIF, "%s: fail to config %s:tx-queue-%d\n",
                        __func__, port->name, qid);
                return ENDF_DPDKAPIFAIL;
            }
        }
    }

    // device configure
    if ((ret = rte_eth_dev_set_mtu(port->id,port->mtu)) != ENDF_OK)
        return ret;

    netif_print_port_conf(&port->dev_conf, buf, &buflen);
    RTE_LOG(INFO, NETIF, "device %s configuration:\n%s\n", port->name, buf);

    // build port-queue-lcore mapping array
    build_port_queue_lcore_map();

    // start the device
    ret = rte_eth_dev_start(port->id);
    if (ret < 0) {
        RTE_LOG(ERR, NETIF, "%s: fail to start %s\n", __func__, port->name);
        return ENDF_DPDKAPIFAIL;
    }

    // wait the device link up
    RTE_LOG(INFO, NETIF, "Waiting for %s link up, be patient ...\n", port->name);
    for (ii = 0; ii < wait_link_up_msecs; ii++) {
        ret = rte_eth_link_get_nowait(port->id, &link);
        if (!ret && link.link_status) {
            RTE_LOG(INFO, NETIF, ">> %s: link up - speed %u Mbps - %s\n",
                    port->name, (unsigned)link.link_speed,
                    (link.link_duplex == RTE_ETH_LINK_FULL_DUPLEX) ?
                    "full-duplex" : "half-duplex");
            break;
        }
        rte_delay_ms(1);
    }
    if (!link.link_status) {
        RTE_LOG(ERR, NETIF, "%s: fail to bring up %s\n", __func__, port->name);
        return ENDF_DPDKAPIFAIL;
    }

    port->flag |= NETIF_PORT_FLAG_RUNNING;

    // enable promicuous mode if configured
    if (promisc_on) {
        RTE_LOG(INFO, NETIF, "promiscous mode enabled for device %s\n", port->name);
        rte_eth_promiscuous_enable(port->id);
    }

    // enable allmulticast mode if configured
    if (allmulticast) {
        RTE_LOG(INFO, NETIF, "allmulticast enabled for device %s\n", port->name);
        rte_eth_allmulticast_enable(port->id);
    }

    /* update rss reta */
    if ((ret = netif_update_rss_reta(port)) != ENDF_OK)
        RTE_LOG(WARNING, NETIF, "%s: %s update rss reta failed (cause: %s)\n",
                __func__, port->name, ndf_strerror(ret));

    return ENDF_OK;
}

int netif_port_stop(struct netif_port *port)
{
    int ret;

    if (unlikely(NULL == port))
        return ENDF_INVAL;

    rte_eth_dev_stop(port->id);
    ret = rte_eth_dev_set_link_down(port->id);
    if (ret < 0) {
        RTE_LOG(WARNING, NETIF, "%s: fail to set %s link down\n", __func__, port->name);
        return ENDF_DPDKAPIFAIL;
    }

    port->flag |= NETIF_PORT_FLAG_STOPPED;
    return ENDF_OK;
}


int netif_port_register(struct netif_port *port)
{
    struct netif_port *cur;
    int hash, nhash;
    int err;

    if (unlikely(NULL == port))
        return ENDF_INVAL;

    hash = port_tab_hashkey(port->id);
    list_for_each_entry(cur, &port_tab[hash], list) {
        if (cur->id == port->id || strcmp(cur->name, port->name) == 0) {
            return ENDF_EXIST;
        }
    }

    nhash = port_ntab_hashkey(port->name, sizeof(port->name));
    list_for_each_entry(cur, &port_ntab[hash], nlist) {
        if (cur->id == port->id || strcmp(cur->name, port->name) == 0) {
            return ENDF_EXIST;
        }
    }

    list_add_tail(&port->list, &port_tab[hash]);
    list_add_tail(&port->nlist, &port_ntab[nhash]);
    g_nports++;

    /* if (port->netif_ops->op_init) {
        err = port->netif_ops->op_init(port);
        if (err != ENDF_OK) {
            netif_port_unregister(port);
            return err;
        }
    } */

    return ENDF_OK;
}

static inline void port_tab_init(void)
{
    int i;
    for (i = 0; i < NETIF_PORT_TABLE_BUCKETS; i++)
        INIT_LIST_HEAD(&port_tab[i]);
}

static inline void port_ntab_init(void)
{
    int i;
    for (i = 0; i < NETIF_PORT_TABLE_BUCKETS; i++)
        INIT_LIST_HEAD(&port_ntab[i]);
}

static void dpdk_port_setup(struct netif_port *dev)
{
    dev->type      = PORT_TYPE_GENERAL;
    //dev->netif_ops = &dpdk_netif_ops; //TODO:comment by haolipeng
    dev->socket    = rte_eth_dev_socket_id(dev->id);
    dev->dev_conf  = default_port_conf;

    rte_eth_macaddr_get(dev->id, &dev->addr);
    rte_eth_dev_get_mtu(dev->id, &dev->mtu);
    if (rte_eth_dev_info_get(dev->id, &dev->dev_info))
        memset(&dev->dev_info, 0, sizeof(dev->dev_info));
    setup_dev_of_flags(dev);
}

static inline int port_name_alloc(portid_t pid, char *pname, size_t buflen)
{
    assert(pname && buflen > 0);
    memset(pname, 0, buflen);
    if (is_physical_port(pid)) {
        struct port_conf_stream *current_cfg;
        list_for_each_entry_reverse(current_cfg, &port_list, port_list_node) {
            if (current_cfg->port_id < 0) {
                current_cfg->port_id = pid;
                if (current_cfg->name[0])
                    snprintf(pname, buflen, "%s", current_cfg->name);
                else
                    snprintf(pname, buflen, "dpdk%d", pid);
                return ENDF_OK;
            }
        }
        RTE_LOG(ERR, NETIF, "%s: not enough ports configured in setting.conf\n", __func__);
        return ENDF_NOTEXIST;
    }

    return ENDF_INVAL;
}

bool is_physical_port(portid_t pid)
{
    return pid >= phy_pid_base && pid < phy_pid_end;
}

/* Allocate and register all DPDK ports available */
static void netif_port_init(void)
{
    int nports, nports_cfg;
    portid_t pid;
    struct netif_port *port;
    char ifname[IFNAMSIZ];

    nports = ndf_rte_eth_dev_count();
    if (nports <= 0)
        rte_exit(EXIT_FAILURE, "No dpdk ports found!\n"
                "Possibly nic or driver is not dpdk-compatible.\n");

    nports_cfg = list_elems(&port_list);
    if (nports_cfg < nports)
        rte_exit(EXIT_FAILURE, "ports in DPDK RTE (%d) != ports in setting.conf(%d)\n",
                nports, nports_cfg);

    port_tab_init();
    port_ntab_init();

    for (pid = 0; pid < nports; pid++) {
        if (port_name_alloc(pid, ifname, sizeof(ifname)) != ENDF_OK)
            rte_exit(EXIT_FAILURE, "Port name allocation failed, exiting...\n");

        /* queue number will be filled on device start */
        port = NULL;
        if (is_physical_port(pid))
            port = netif_alloc(pid, sizeof(union netif_bond), ifname, 0, 0, dpdk_port_setup);
        if (!port)
            rte_exit(EXIT_FAILURE, "Port allocation failed, exiting...\n");

        if (netif_port_register(port) < 0)
            rte_exit(EXIT_FAILURE, "Port registration failed, exiting...\n");
    }
}

int netif_init(void)
{
    netif_pktmbuf_pool_init();
    netif_port_init();
    netif_lcore_init();
    return ENDF_OK;
}

int netif_term(void)
{
    //TODO:need finished
    return ENDF_OK;
}