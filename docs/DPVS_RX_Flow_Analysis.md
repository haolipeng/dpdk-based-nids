# DPVS收包流程深度分析文档

**文档版本:** 1.0
**分析日期:** 2025-10-22
**目标:** 为NetDefender NIDS项目集成DPVS收包流程
**排除内容:** KNI相关代码

---

## 一、DPVS收包架构总览

### 1.1 整体架构图

```
┌─────────────────────────────────────────────────────────────┐
│                    DPVS RX Architecture                      │
└─────────────────────────────────────────────────────────────┘

┌──────────────┐
│  NIC (DPDK)  │  物理网卡
└──────┬───────┘
       │ rte_eth_rx_burst()
       ▼
┌──────────────────────────────────────────────────────────────┐
│                 Lcore Worker Loop (Scheduler)                 │
│  ┌────────────────────────────────────────────────────────┐  │
│  │  Job Execution: INIT → LOOP → SLOW                     │  │
│  │  - lcore_job_recv_fwd()  [LCORE_JOB_LOOP]             │  │
│  │  - timer_manage()         [LCORE_JOB_SLOW]            │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│              Normal RX Path (lcore_job_recv_fwd)             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ 1. netif_rx_burst()  [per queue]                    │    │
│  │    └─> rte_eth_rx_burst(port, queue, mbufs, 32)    │    │
│  │                                                      │    │
│  │ 2. lcore_process_packets()                          │    │
│  │    └─> prefetch + netif_deliver_mbuf()             │    │
│  │                                                      │    │
│  │ 3. netif_deliver_mbuf()                             │    │
│  │    ├─> eth_type_parse() [MAC classification]       │    │
│  │    └─> netif_rcv_mbuf() [L3 protocol dispatch]    │    │
│  └─────────────────────────────────────────────────────┘    │
└──────────────────┬───────────────────────────────────────────┘
                   │
                   ▼
┌──────────────────────────────────────────────────────────────┐
│          Protocol Dispatch (netif_rcv_mbuf)                  │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Hash Lookup: eth_type → pkt_type handlers          │    │
│  │  - IPv4: 0x0800                                     │    │
│  │  - IPv6: 0x86DD                                     │    │
│  │  - ARP:  0x0806 (broadcast to all lcores)          │    │
│  │  - VLAN: 0x8100 (recursive parse)                  │    │
│  └─────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────┐
│      Isolated RX Path (Optional, for latency reduction)      │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  Dedicated RX Lcore (LCORE_ROLE_ISOLRX_WORKER)     │    │
│  │  1. recv_on_isol_lcore()                            │    │
│  │     └─> rte_eth_rx_burst()                         │    │
│  │     └─> rte_ring_enqueue_burst() [to ring buffer] │    │
│  │                                                      │    │
│  │  2. FWD Worker dequeues from ring                   │    │
│  │     └─> rte_ring_dequeue_burst()                   │    │
│  │     └─> lcore_process_packets()                    │    │
│  └─────────────────────────────────────────────────────┘    │
└──────────────────────────────────────────────────────────────┘
```

### 1.2 Lcore角色定义

**源文件:** `source-references/dpvs/include/global_data.h:18-24`

```c
typedef enum lcore_role {
    LCORE_ROLE_IDLE = 0,          // 未使用
    LCORE_ROLE_MASTER,            // 控制面,运行master线程
    LCORE_ROLE_FWD_WORKER,        // 数据面,转发worker
    LCORE_ROLE_ISOLRX_WORKER,     // 独立收包worker (排除KNI)
    LCORE_ROLE_MAX
} lcore_role_t;
```

**说明:**
- `MASTER`: 主控制线程,处理配置、统计等
- `FWD_WORKER`: 数据面worker,执行收包→处理→发包
- `ISOLRX_WORKER`: 专门的收包lcore,将包放入ring buffer供FWD_WORKER消费

---

## 二、核心收包函数分析

### 2.1 主收包入口: `lcore_job_recv_fwd()`

**文件位置:** `source-references/dpvs/src/netif.c:2633-2654`

```c
static int lcore_job_recv_fwd(void *arg)
{
    portid_t pid;
    queueid_t qid;
    struct rx_partner *port_queue;
    struct netif_queue_conf *qconf;
    lcoreid_t cid = rte_lcore_id();

    // 遍历当前lcore绑定的所有端口和队列
    list_for_each_entry(port_queue, &lcore_conf[cid].rx_partners, lcore_node) {
        pid = port_queue->port->id;
        qid = port_queue->queue_id;

        // 从硬件队列接收数据包(最多32个)
        qconf = &lcore_conf[cid].pqs[pid][qid];
        qconf->len = netif_rx_burst(pid, qid, qconf->mbufs);

        // 处理接收到的数据包
        lcore_process_packets(port_queue->port, qid,
                              qconf->mbufs, qconf->len, true);
    }

    return DTIMER_OK;
}
```

**关键点:**
1. 遍历lcore的所有绑定队列(`rx_partners`链表)
2. 每个队列调用`netif_rx_burst()`收包
3. 将收到的包送给`lcore_process_packets()`处理
4. 返回`DTIMER_OK`使调度器继续执行

**注册位置:** `netif.c:2887-2896`
```c
static struct dpvs_lcore_job lcore_jobs[LCORE_ROLE_MAX] = {
    {
        .name = "recv_fwd",
        .func = lcore_job_recv_fwd,  // 收包+转发job
        .data = NULL,
        .type = LCORE_JOB_LOOP,      // 高频循环job
    },
    // ...
};
```

---

### 2.2 核心收包函数: `netif_rx_burst()`

**文件位置:** `source-references/dpvs/src/netif.c:1810-1842`

```c
static inline uint16_t netif_rx_burst(portid_t pid, queueid_t qid,
                                       struct rte_mbuf **mbufs)
{
    uint16_t nb_rx;
    struct netif_port *dev;

    dev = netif_port_get(pid);
    if (unlikely(!dev))
        return 0;

    // 核心DPDK收包调用
    nb_rx = rte_eth_rx_burst(pid, qid, mbufs, NETIF_MAX_PKT_BURST);

    // 更新统计信息
    if (likely(dev->lcore_stats)) {
        dev->lcore_stats[rte_lcore_id()].ipackets += nb_rx;

        // 按burst大小分类统计
        if (nb_rx == NETIF_MAX_PKT_BURST)
            dev->lcore_stats[rte_lcore_id()].iburst_pkts[NETIF_BURST_FULL]++;
        else if (nb_rx > (NETIF_MAX_PKT_BURST >> 1))
            dev->lcore_stats[rte_lcore_id()].iburst_pkts[NETIF_BURST_HALF_FULL]++;
        else if (nb_rx > 0)
            dev->lcore_stats[rte_lcore_id()].iburst_pkts[NETIF_BURST_NON_EMPTY]++;
        else
            dev->lcore_stats[rte_lcore_id()].iburst_pkts[NETIF_BURST_EMPTY]++;
    }

    return nb_rx;
}
```

**参数:**
- `pid`: 端口ID
- `qid`: 队列ID
- `mbufs`: 输出缓冲区,最多32个mbuf指针

**返回:** 实际接收的包数量

**关键常量:**
- `NETIF_MAX_PKT_BURST = 32` (netif.h:44)

---

### 2.3 数据包处理: `lcore_process_packets()`

**文件位置:** `source-references/dpvs/src/netif.c:2577-2631`

```c
static inline void lcore_process_packets(struct netif_port *dev,
                                         queueid_t qid,
                                         struct rte_mbuf **mbufs,
                                         int count,
                                         bool pkts_from_ring)
{
    int i;

    // 预取优化:提前3个包加载到L1 cache
    for (i = 0; i < NETIF_PREFETCH_OFFSET && i < count; i++)
        rte_prefetch0(rte_pktmbuf_mtod(mbufs[i], void *));

    // 处理每个数据包
    for (i = 0; i < (count - NETIF_PREFETCH_OFFSET); i++) {
        // 预取下一个包
        rte_prefetch0(rte_pktmbuf_mtod(mbufs[i + NETIF_PREFETCH_OFFSET], void *));

        // 交给协议栈处理
        netif_deliver_mbuf(dev, qid, mbufs[i], pkts_from_ring);
    }

    // 处理剩余的包(无需预取)
    for (; i < count; i++)
        netif_deliver_mbuf(dev, qid, mbufs[i], pkts_from_ring);
}
```

**性能优化:**
1. **软件预取**: 提前3个包加载到cache,减少内存等待
2. **常量定义**: `NETIF_PREFETCH_OFFSET = 3` (netif.c:44)

---

### 2.4 以太网处理: `netif_deliver_mbuf()`

**文件位置:** `source-references/dpvs/src/netif.c:2419-2454`

```c
static inline void netif_deliver_mbuf(struct netif_port *dev,
                                       queueid_t queue_id,
                                       struct rte_mbuf *mbuf,
                                       bool pkts_from_ring)
{
    struct ether_hdr *eth_hdr;
    uint16_t eth_type;
    bool epad = false;

    // 获取以太网头部
    eth_hdr = rte_pktmbuf_mtod(mbuf, struct ether_hdr *);

    // 跳过VLAN标签,获取真实的EtherType
    eth_type = mbuf_eth_type_get(mbuf, &epad);

    // MAC地址类型分类
    mbuf->packet_type = eth_type_parse(eth_hdr, dev);

    // 更新字节统计
    if (likely(dev->lcore_stats))
        dev->lcore_stats[rte_lcore_id()].ibytes += mbuf->pkt_len;

    // 丢弃无效的包(错误MAC等)
    if (unlikely(mbuf->packet_type == 0)) {
        if (likely(dev->lcore_stats))
            dev->lcore_stats[rte_lcore_id()].dropped++;
        rte_pktmbuf_free(mbuf);
        return;
    }

    // 交给L3协议处理
    netif_rcv_mbuf(dev, queue_id, mbuf);
}
```

**功能:**
1. 解析以太网头部
2. 处理VLAN标签
3. MAC地址分类(单播/广播/组播)
4. 统计字节数
5. 丢弃无效包

---

### 2.5 协议分发: `netif_rcv_mbuf()`

**文件位置:** `source-references/dpvs/src/netif.c:2456-2534`

```c
static inline void netif_rcv_mbuf(struct netif_port *dev,
                                   queueid_t queue_id,
                                   struct rte_mbuf *mbuf)
{
    struct pkt_type *pt;
    struct list_head *head;
    bool res;

    // 1. 特殊处理:ARP需要广播到所有lcore
    if (mbuf->packet_type == ETH_PKT_BROADCAST) {
        uint16_t etype = mbuf_eth_type_get(mbuf, NULL);
        if (etype == rte_cpu_to_be_16(ETH_P_ARP)) {
            // 克隆ARP包到所有其他lcore
            arp_rcv_clone(dev, mbuf);
            return;
        }
    }

    // 2. 协议类型哈希查找
    head = &pkt_type_tab[mbuf_hashkey(mbuf)];

    // 3. 遍历注册的协议处理器
    list_for_each_entry(pt, head, list) {
        // 匹配端口、协议类型、MAC类型
        if (dev == pt->port &&
            pt->type == rte_be_to_cpu_16(mbuf->packet_type) &&
            mbuf_eth_type_get(mbuf, NULL) == pt->type) {

            // 调用协议处理函数
            res = pt->func(mbuf, dev);

            // 处理函数可能修改了mbuf,重新解析
            mbuf->packet_type = eth_type_parse(
                rte_pktmbuf_mtod(mbuf, struct ether_hdr *), dev);

            if (res) {
                rte_pktmbuf_free(mbuf);
                return;
            }
        }
    }

    // 4. 未知协议,丢弃
    rte_pktmbuf_free(mbuf);
}
```

**协议注册机制:**

**文件位置:** `netif.c:1615-1659`

```c
int netif_register_pkt(struct pkt_type *pt)
{
    struct list_head *head;

    if (!pt || !pt->func || !pt->port)
        return EDPVS_INVAL;

    // 计算哈希值(256个bucket)
    head = &pkt_type_tab[pkt_hashkey(pt)];

    // 加入链表
    list_add_tail(&pt->list, head);

    return EDPVS_OK;
}
```

**哈希函数:**
```c
static inline uint8_t pkt_hashkey(struct pkt_type *pt)
{
    return (uint8_t)(pt->type ^ (pt->type >> 8));  // 简单的XOR哈希
}
```

---

## 三、Isolated RX模式(可选)

### 3.1 设计目的

将收包和处理分离到不同lcore,减少收包延迟:
- **ISOLRX_WORKER**: 专职收包,不做任何处理,直接放入ring buffer
- **FWD_WORKER**: 从ring buffer取包,进行处理和转发

### 3.2 Isolated RX收包: `recv_on_isol_lcore()`

**文件位置:** `source-references/dpvs/src/netif.c:1749-1808`

```c
static inline uint16_t recv_on_isol_lcore(struct rx_partner *port_queue,
                                           struct rte_mbuf **mbufs)
{
    uint16_t nb_rx, nb_enq;
    struct netif_port *dev = port_queue->port;
    queueid_t qid = port_queue->queue_id;
    portid_t pid = dev->id;
    struct rte_ring *ring = port_queue->isol_rxq.ring;

    // 1. 从网卡接收数据包
    nb_rx = rte_eth_rx_burst(pid, qid, mbufs, NETIF_MAX_PKT_BURST);

    if (likely(nb_rx > 0)) {
        // 2. 放入ring buffer
        nb_enq = rte_ring_enqueue_burst(ring, (void **)mbufs, nb_rx, NULL);

        // 3. 统计
        if (likely(dev->lcore_stats)) {
            dev->lcore_stats[rte_lcore_id()].ipackets += nb_enq;
            for (int i = 0; i < nb_enq; i++)
                dev->lcore_stats[rte_lcore_id()].ibytes += mbufs[i]->pkt_len;
        }

        // 4. 如果ring满了,丢弃未入队的包
        if (unlikely(nb_enq < nb_rx)) {
            for (int i = nb_enq; i < nb_rx; i++)
                rte_pktmbuf_free(mbufs[i]);

            if (likely(dev->lcore_stats))
                dev->lcore_stats[rte_lcore_id()].dropped += (nb_rx - nb_enq);
        }
    }

    return nb_rx;
}
```

### 3.3 从Ring取包

**文件位置:** `netif.c:2636-2642` (在lcore_job_recv_fwd中)

```c
// 如果配置了isolated RX,从ring取包而非直接从网卡
if (port_queue->isol_rxq.ring) {
    qconf->len = rte_ring_dequeue_burst(
        port_queue->isol_rxq.ring,
        (void **)qconf->mbufs,
        NETIF_MAX_PKT_BURST,
        NULL);
}
```

---

## 四、关键数据结构

### 4.1 Lcore配置: `netif_lcore_conf`

**文件位置:** `source-references/dpvs/include/netif.h:182-199`

```c
struct netif_lcore_conf {
    uint16_t               pqs[NETIF_MAX_PORTS][NETIF_MAX_QUEUES]; // 端口队列索引
    struct netif_queue_conf pqs[NETIF_MAX_PORTS][NETIF_MAX_QUEUES]; // 队列配置
    struct list_head       rx_partners;  // 该lcore负责的RX队列链表
    struct list_head       tx_partners;  // 该lcore负责的TX队列链表
    uint8_t                nrx_partners; // RX队列数量
    uint8_t                ntx_partners; // TX队列数量
} __rte_cache_aligned;
```

### 4.2 队列配置: `netif_queue_conf`

**文件位置:** `netif.h:171-176`

```c
struct netif_queue_conf {
    struct rte_mbuf *mbufs[NETIF_MAX_PKT_BURST]; // mbuf缓冲区(32个)
    uint16_t        len;                          // 当前包数量
} __rte_cache_aligned;
```

### 4.3 RX Partner: `rx_partner`

**文件位置:** `netif.h:153-162`

```c
struct rx_partner {
    struct netif_port     *port;      // 所属端口
    queueid_t             queue_id;   // 队列ID
    struct isol_rxq_stats isol_rxq;   // Isolated RX统计(如有)
    struct list_head      lcore_node; // 链表节点
} __rte_cache_aligned;
```

### 4.4 Lcore统计: `netif_lcore_stats`

**文件位置:** `netif.h:122-138`

```c
struct netif_lcore_stats {
    uint64_t ipackets;  // 接收包数
    uint64_t opackets;  // 发送包数
    uint64_t ibytes;    // 接收字节数
    uint64_t obytes;    // 发送字节数
    uint64_t dropped;   // 丢包数
    uint64_t ierrors;   // 接收错误
    uint64_t oerrors;   // 发送错误

    // Burst大小分类统计
    uint64_t iburst_pkts[NETIF_BURST_MAX];
    uint64_t oburst_pkts[NETIF_BURST_MAX];
} __rte_cache_aligned;
```

**Burst分类:**
```c
enum {
    NETIF_BURST_EMPTY = 0,      // 0个包
    NETIF_BURST_NON_EMPTY,      // 1-15个包
    NETIF_BURST_HALF_FULL,      // 16-31个包
    NETIF_BURST_FULL,           // 32个包(满)
    NETIF_BURST_MAX
};
```

### 4.5 协议类型: `pkt_type`

**文件位置:** `netif.h:324-331`

```c
struct pkt_type {
    uint16_t             type;        // 协议类型(如0x0800=IPv4)
    struct netif_port    *port;       // 绑定的端口
    int (*func)(struct rte_mbuf *mbuf,
                struct netif_port *port); // 处理函数
    struct list_head     list;        // 哈希表链表节点
};
```

**全局哈希表:**
```c
#define PKT_TYPE_TAB_BITS 8
#define PKT_TYPE_TAB_SIZE (1 << PKT_TYPE_TAB_BITS)  // 256个bucket

static struct list_head pkt_type_tab[PKT_TYPE_TAB_SIZE];  // netif.c:76
```

---

## 五、与Scheduler集成

### 5.1 Job注册

**文件位置:** `netif.c:2887-2930`

```c
static struct dpvs_lcore_job lcore_jobs[LCORE_ROLE_MAX] = {
    {
        .name = "recv_fwd",
        .func = lcore_job_recv_fwd,  // 收包+转发
        .data = NULL,
        .type = LCORE_JOB_LOOP,      // 每次循环都执行
    },
    // 其他job...
};

static int netif_lcore_init(void *arg)
{
    // 注册当前lcore角色对应的job
    int role = netif_lcore_role();
    if (role >= 0 && role < LCORE_ROLE_MAX) {
        dpvs_lcore_job_register(&lcore_jobs[role], role);
    }
    return EDPVS_OK;
}
```

### 5.2 Scheduler执行流程

**文件位置:** `source-references/dpvs/src/scheduler.c:101-150`

```c
static int dpvs_job_loop(void *dummy)
{
    struct dpvs_lcore_job *job;
    int role = lcore_role[rte_lcore_id()];

    while (1) {
        this_poll_tick++;  // 全局tick计数器

        // 1. 执行INIT job(仅一次)
        list_for_each_entry(job, &lcore_jobs[role][LCORE_JOB_INIT], list) {
            // ...
        }

        // 2. 执行LOOP job(每次循环)
        list_for_each_entry(job, &lcore_jobs[role][LCORE_JOB_LOOP], list) {
            job->func(job->data);  // ← lcore_job_recv_fwd在这里被调用
        }

        // 3. 执行SLOW job(周期性)
        list_for_each_entry(job, &lcore_jobs[role][LCORE_JOB_SLOW], list) {
            if (this_poll_tick % job->skip_loops == 0) {
                job->func(job->data);
            }
        }
    }
}
```

**关键点:**
- `lcore_job_recv_fwd`作为`LCORE_JOB_LOOP`类型,每次循环都被调用
- 无阻塞,纯轮询模式
- 性能优先,避免上下文切换

---

## 六、完整收包调用链

### 6.1 正常收包路径(无Isolated RX)

```
main()
  └─> rte_eal_mp_remote_launch(dpvs_job_loop)
        └─> dpvs_job_loop()  [每个worker lcore]
              └─> lcore_job_recv_fwd()  [LCORE_JOB_LOOP]
                    └─> for each rx_partner:
                          ├─> netif_rx_burst(port, queue, mbufs)
                          │     └─> rte_eth_rx_burst()  [DPDK API]
                          │     └─> update statistics
                          │
                          └─> lcore_process_packets(mbufs, count)
                                ├─> prefetch mbufs[i+3]
                                │
                                └─> for each mbuf:
                                      └─> netif_deliver_mbuf(mbuf)
                                            ├─> parse ether header
                                            ├─> eth_type_parse()
                                            │
                                            └─> netif_rcv_mbuf(mbuf)
                                                  ├─> ARP special handling
                                                  │     └─> arp_rcv_clone()
                                                  │
                                                  └─> hash lookup pkt_type
                                                        └─> pt->func(mbuf)
                                                              [IPv4/IPv6/etc handlers]
```

### 6.2 Isolated RX路径

```
ISOLRX_WORKER lcore:
  dpvs_job_loop()
    └─> lcore_job_recv_fwd()
          └─> recv_on_isol_lcore()
                ├─> rte_eth_rx_burst()
                └─> rte_ring_enqueue_burst(ring, mbufs)

FWD_WORKER lcore:
  dpvs_job_loop()
    └─> lcore_job_recv_fwd()
          ├─> rte_ring_dequeue_burst(ring, mbufs)  [从ring取包]
          └─> lcore_process_packets(mbufs, count)
                └─> ... [同上normal path]
```

---

## 七、性能优化技术

### 7.1 软件预取(Prefetch)

```c
#define NETIF_PREFETCH_OFFSET 3

for (i = 0; i < count - NETIF_PREFETCH_OFFSET; i++) {
    rte_prefetch0(rte_pktmbuf_mtod(mbufs[i + 3], void *));
    netif_deliver_mbuf(..., mbufs[i], ...);
}
```

**原理:** 在处理`mbufs[i]`时,提前加载`mbufs[i+3]`到L1 cache,减少cache miss

### 7.2 Cache对齐

```c
struct netif_lcore_conf {
    // ...
} __rte_cache_aligned;  // 64字节对齐
```

**原理:** 防止false sharing,多个lcore不会竞争同一cache line

### 7.3 无锁设计

- **Per-lcore数据结构**: 每个lcore独立的`netif_lcore_conf`
- **Ring buffer**: 使用DPDK的无锁ring(单生产者/单消费者模式)
- **统计数据**: Per-lcore统计,避免原子操作

### 7.4 Burst处理

- **批量收包**: 一次最多32个包,减少函数调用开销
- **批量入队**: Ring buffer批量操作,减少CAS操作次数

---

## 八、NIDS集成建议

### 8.1 推荐复用的组件

1. **核心收包框架** ✅
   - `lcore_job_recv_fwd()` - 主收包循环
   - `netif_rx_burst()` - DPDK收包封装
   - `lcore_process_packets()` - 批量处理+预取

2. **数据结构** ✅
   - `netif_lcore_conf` - Lcore配置
   - `netif_queue_conf` - 队列缓冲区
   - `rx_partner` - 端口队列关系
   - `netif_lcore_stats` - 统计信息

3. **Isolated RX(可选)** ⚠️
   - 适用于高负载场景
   - 需要额外的lcore资源
   - Ring buffer配置需调优

### 8.2 需要修改的地方

1. **协议分发替换为IDS检测**
   ```c
   // DPVS原始:
   netif_rcv_mbuf() → 协议栈处理

   // NIDS修改:
   ids_packet_analyze() → 威胁检测 → 告警/阻断
   ```

2. **去除不需要的功能**
   - KNI相关代码(已排除)
   - TC/QoS功能
   - 转发/路由逻辑

3. **添加NIDS特定功能**
   - 流状态追踪(基于定时器)
   - 规则匹配引擎
   - 告警输出模块

### 8.3 集成检查点

对比`src/netif.c`应包含:

1. **必需函数:**
   - [x] `netif_rx_burst()` - 核心收包
   - [x] `lcore_process_packets()` - 批量处理
   - [x] `netif_deliver_mbuf()` - 以太网处理
   - [ ] `netif_rcv_mbuf()` - 协议分发(NIDS需改造为检测入口)

2. **必需数据结构:**
   - [x] `struct netif_lcore_conf`
   - [x] `struct netif_queue_conf`
   - [x] `struct rx_partner`
   - [x] `struct netif_lcore_stats`

3. **必需初始化:**
   - [x] Mbuf pool创建
   - [x] 端口/队列配置
   - [x] Lcore绑定
   - [x] Job注册

---

## 九、代码量估算

**DPVS netif.c总览:**
- 总行数: ~3,000行
- 收包相关: ~800行
- KNI相关: ~400行(需排除)
- TC/QoS: ~300行(可选排除)
- **核心收包代码**: ~500行

**推荐移植量:**
- 核心收包流程: 500行
- 数据结构定义: 200行
- 统计和辅助函数: 100行
- **合计**: ~800行

---

## 十、总结

### DPVS收包核心优势

1. **高性能**: Burst收包 + 预取 + 无锁设计
2. **灵活性**: 支持多队列、RSS、Isolated RX
3. **可扩展**: 协议注册机制,易于添加自定义处理
4. **成熟度**: 生产环境验证,稳定可靠

### 与NetDefender集成路径

```
阶段1: 基础收包 (当前)
  └─> 移植lcore_job_recv_fwd + netif_rx_burst
  └─> 配置端口/队列绑定
  └─> 验证收包正常

阶段2: IDS检测引擎
  └─> 替换netif_rcv_mbuf为ids_analyze_packet
  └─> 集成Suricata规则引擎
  └─> 实现流状态追踪(使用timer)

阶段3: 性能优化
  └─> 调优Isolated RX参数
  └─> 优化检测算法
  └─> 压测和profiling
```

---

**文档结束**

下一步: 对比`src/netif.c`进行差异分析
