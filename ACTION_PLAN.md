# NetDefender DPDK-Suricata集成实施计划

## 项目概述

**目标**: 构建基于DPDK和Suricata的高性能网络入侵检测系统(NIDS)

**架构设计**:
```
┌─────────────────────────────────────────────────────────────┐
│                     NetDefender 架构                         │
├─────────────────────────────────────────────────────────────┤
│  NIC → DPDK PMD → rte_mbuf → [桥接层] → Suricata Packet    │
│                                   ↓                          │
│                          Suricata检测引擎                    │
│                     (解码→重组→检测→输出)                    │
│                                   ↓                          │
│                            EVE JSON输出                      │
└─────────────────────────────────────────────────────────────┘
```

**技术栈**:
- **DPDK**: 零拷贝数据包接收（已完成基础RX循环）
- **DPVS组件**: Timer和Scheduler（已集成）
- **Suricata 6.0.10**: 完整IDS检测引擎（待集成）
- **规则库**: Emerging Threats官方规则
- **输出格式**: EVE JSON（标准Suricata JSON格式）

---

## 阶段3: 实现DPDK→Suricata桥接 (当前阶段)

### 3.1 创建桥接模块

**任务**: 创建桥接层文件

**文件**:
- `src/suricata_bridge.c`
- `src/suricata_bridge.h`

**核心函数**:

#### 3.1.1 mbuf_to_suricata_packet()

```c
/**
 * 将DPDK mbuf转换为Suricata Packet对象
 *
 * @param mbuf DPDK数据包缓冲区
 * @param tv 线程变量 (可选，用于统计)
 * @param dtv 解码线程变量 (可选，用于计数器)
 * @return Suricata Packet对象，失败返回NULL
 *
 * 注意事项:
 * - 使用拷贝模式（初期），后续可优化为零拷贝
 * - 不需要设置livedev（端口/队列信息）
 * - 不需要设置租户ID（单租户场景）
 * - 时间戳使用当前系统时间
 */
Packet *mbuf_to_suricata_packet(struct rte_mbuf *mbuf,
                                 ThreadVars *tv,
                                 DecodeThreadVars *dtv);
```

**实现要点**:
1. 从Suricata池获取Packet对象: `PacketGetFromQueueOrAlloc()`
2. 重置Packet: `PACKET_REINIT(p)`
3. **数据复制**: `PacketCopyData(p, mbuf数据, mbuf长度)` （拷贝模式）
4. **设置时间戳**: `gettimeofday(&p->ts, NULL)`
5. **设置数据链路类型**: `p->datalink = LINKTYPE_ETHERNET` (固定以太网)
6. **设置数据包来源**: `p->pkt_src = PKT_SRC_WIRE`
7. **重置校验和**: `PACKET_RESET_CHECKSUMS(p)`
8. **调用以太网解码器**: `DecodeEthernet(tv, dtv, p, 数据, 长度)`

**简化说明**:
- ❌ 不需要设置`p->livedev`（Suricata的LiveDevice仅用于原生捕获模式）
- ❌ 不需要设置端口/队列信息（DPDK已管理）
- ❌ 不需要设置`p->tenant_id`（单租户场景）
- ✅ 只需复制数据、设置基本元数据、调用解码器

#### 3.1.2 free_suricata_packet_and_mbuf()

```c
/**
 * 释放Suricata Packet和原始mbuf
 *
 * @param p Suricata Packet对象
 * @param mbuf 原始DPDK mbuf
 *
 * 释放顺序:
 * 1. 释放Packet (归还到Suricata池)
 * 2. 释放mbuf (归还到DPDK mempool)
 */
void free_suricata_packet_and_mbuf(Packet *p, struct rte_mbuf *mbuf);
```

**实现**:
```c
void free_suricata_packet_and_mbuf(Packet *p, struct rte_mbuf *mbuf)
{
    if (p != NULL) {
        PacketFreeOrRelease(p);  // 归还到Suricata数据包池
    }
    if (mbuf != NULL) {
        rte_pktmbuf_free(mbuf);  // 归还到DPDK mempool
    }
}
```

#### 3.1.3 suricata_thread_init()

```c
/**
 * 初始化Suricata线程上下文
 * 每个DPDK lcore调用一次
 *
 * @param lcore_id DPDK逻辑核ID
 * @return ThreadVars对象，失败返回NULL
 */
ThreadVars *suricata_thread_init(unsigned int lcore_id);
```

**实现要点**:
1. 创建线程名称: `Worker-L<lcore_id>`
2. 创建ThreadVars: `TmThreadCreatePacketHandler()`
3. 添加FlowWorker模块: `TmSlotSetFuncAppend(tv, "flowworker", NULL)`
4. 设置CPU亲和性: `TmThreadSetCPUAffinity(tv, lcore_id)`

---

### 3.2 集成到RX循环

**任务**: 修改`src/netif.c`的`lcore_job_recv_fwd()`函数

**修改点**:

```c
static void lcore_job_recv_fwd(void* arg __attribute__((unused)))
{
    // ... 现有变量声明 ...

    // 添加: 线程局部Suricata上下文
    static __thread ThreadVars *tv = NULL;
    static __thread DecodeThreadVars *dtv = NULL;

    // 添加: 首次初始化
    if (unlikely(tv == NULL)) {
        cid = rte_lcore_id();
        tv = suricata_thread_init(cid);
        dtv = DecodeThreadVarsAlloc(tv);
        if (tv == NULL || dtv == NULL) {
            RTE_LOG(CRIT, NETIF, "Failed to initialize Suricata on lcore %u\n", cid);
            return;
        }
    }

    cid = rte_lcore_id();

    for (i = 0; i < lcore_conf[lcore2index[cid]].nports; i++) {
        // ... 现有端口/队列循环 ...

        for (j = 0; j < lcore_conf[lcore2index[cid]].pqs[i].nrxq; j++) {
            qconf = &lcore_conf[lcore2index[cid]].pqs[i].rxqs[j];

            nb_rx = netif_rx_burst(pid, qconf);
            qconf->len = nb_rx;

            if (likely(nb_rx > 0)) {
                // 更新统计
                if (likely(dev->lcore_stats)) {
                    dev->lcore_stats[cid].ipackets += nb_rx;
                    for (k = 0; k < nb_rx; k++) {
                        dev->lcore_stats[cid].ibytes += qconf->mbufs[k]->pkt_len;
                    }
                }

                // 修改: 处理数据包
                for (k = 0; k < nb_rx; k++) {
                    struct rte_mbuf *mbuf = qconf->mbufs[k];

                    // 1. 桥接: mbuf → Suricata Packet
                    Packet *p = mbuf_to_suricata_packet(mbuf, tv, dtv);

                    if (likely(p != NULL)) {
                        // 2. 运行Suricata处理流水线
                        TmEcode r = TmThreadsSlotProcessPkt(tv, tv->tm_flowworker, p);

                        if (unlikely(r == TM_ECODE_FAILED)) {
                            RTE_LOG(WARNING, NETIF,
                                    "[lcore %u] Suricata processing failed\n", cid);
                        }

                        // 3. 释放Packet和mbuf
                        free_suricata_packet_and_mbuf(p, mbuf);
                    } else {
                        // 桥接失败，直接释放mbuf
                        rte_pktmbuf_free(mbuf);
                    }
                }

                // 调试日志 (每10000个数据包)
                if (unlikely(dev->lcore_stats[cid].ipackets % 10000 == 0)) {
                    RTE_LOG(INFO, NETIF,
                            "[lcore %u] port %u queue %u: processed %lu packets, "
                            "%lu bytes\n",
                            cid, pid, qconf->id,
                            dev->lcore_stats[cid].ipackets,
                            dev->lcore_stats[cid].ibytes);
                }
            }
        }
    }
}
```

**关键变化**:
- ✅ 使用`__thread`确保每个lcore有独立的ThreadVars
- ✅ 在首次执行时初始化Suricata上下文
- ✅ 逐个数据包进行桥接和处理
- ✅ 错误处理：桥接失败时释放mbuf，处理失败时记录日志
- ✅ 保持原有统计逻辑

---

## 阶段4: Suricata引擎初始化和配置

### 4.1 全局初始化

**任务**: 在`src/main.c`中添加Suricata全局初始化

**位置**: `main()`函数中，在DPDK初始化之后，lcore启动之前

**代码**:

```c
/* 在main()中添加 */

// ===== Suricata全局初始化 =====
RTE_LOG(INFO, NETIF, "Initializing Suricata engine...\n");

// 1. 全局预配置初始化
GlobalsInitPreConfig();

// 2. 日志系统初始化
SCLogInitLogModule(NULL);

// 3. 配置系统初始化
ConfigInit();

// 4. 签名表初始化
SigTableSetup();

// 5. 线程模块注册
TmModuleRegisterAllModules();

// 6. 数据包池初始化
PacketPoolInit();

// 7. 流引擎初始化
FlowInitConfig(FLOW_QUIET);

// 8. 解码器全局配置
DecodeGlobalConfig();
PacketAlertGetMaxConfig();

// 9. 输出模块注册
OutputRegisterModules();

RTE_LOG(INFO, NETIF, "Suricata engine initialized successfully\n");
```

---

### 4.2 配置文件加载

**任务**: 创建`conf/suricata.yaml`配置文件

**文件路径**: `/home/work/clionProject/dpdk-based-nids/conf/suricata.yaml`

**最小化配置** (针对DPDK集成):

```yaml
%YAML 1.1
---

# Suricata配置文件 (NetDefender集成版本)

# ===== 全局设置 =====
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000

# ===== 默认日志目录 =====
default-log-dir: /var/log/netdefender/

# ===== 输出配置 =====
outputs:
  # EVE JSON日志 (主输出)
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes           # 包含载荷数据
            payload-buffer-size: 4kb
            payload-printable: yes
            packet: yes            # 包含数据包信息
            metadata: yes          # 包含规则元数据

        - http:
            extended: yes          # HTTP扩展信息

        - dns:
            query: yes
            answer: yes

        - tls:
            extended: yes

        - files:
            force-magic: no
            force-hash: [md5]

        - smtp:
            extended: yes

        - flow

        - stats:
            totals: yes
            threads: yes

  # 快速日志 (可选)
  - fast:
      enabled: yes
      filename: fast.log

# ===== 规则文件 =====
default-rule-path: /etc/netdefender/rules
rule-files:
  - emerging-threats.rules      # Emerging Threats主规则文件

# ===== 流引擎配置 =====
flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 10000
  emergency-recovery: 30

# ===== 流超时配置 =====
flow-timeouts:
  default:
    new: 30
    established: 300
    closed: 0
    bypassed: 100
    emergency-new: 10
    emergency-established: 100
    emergency-closed: 0
    emergency-bypassed: 50
  tcp:
    new: 60
    established: 600
    closed: 60
    bypassed: 100
    emergency-new: 5
    emergency-established: 100
    emergency-closed: 10
    emergency-bypassed: 50
  udp:
    new: 30
    established: 300
    bypassed: 100
    emergency-new: 10
    emergency-established: 100
    emergency-bypassed: 50

# ===== 流重组配置 =====
stream:
  memcap: 64mb
  checksum-validation: yes
  inline: no                   # IDS模式
  reassembly:
    memcap: 256mb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560

# ===== 主机表配置 =====
host:
  hash-size: 4096
  prealloc: 1000
  memcap: 32mb

# ===== IP分片重组 =====
defrag:
  memcap: 32mb
  hash-size: 65536
  trackers: 65535
  max-frags: 65535
  prealloc: yes
  timeout: 60

# ===== 应用层协议配置 =====
app-layer:
  protocols:
    http:
      enabled: yes
      memcap: 64mb
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53
    smtp:
      enabled: yes
      detection-ports:
        dp: 25,587,465

# ===== 检测引擎配置 =====
detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000

# ===== 性能分析 =====
profiling:
  rules:
    enabled: no
  packets:
    enabled: no

# ===== 多线程配置 =====
# 注意: DPDK lcore会创建对应的Suricata worker线程
threading:
  set-cpu-affinity: no         # 由DPDK管理亲和性
  cpu-affinity:
    management-cpu-set:
      cpu: [ 0 ]
  detect-thread-ratio: 1.0

# ===== 日志级别 =====
logging:
  default-log-level: info
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        filename: /var/log/netdefender/suricata.log

# ===== 统计间隔 =====
stats:
  enabled: yes
  interval: 10                 # 每10秒输出统计

# ===== PCAP日志 (可选，用于取证) =====
pcap-log:
  enabled: no
  filename: log.pcap
  limit: 1000mb
  max-files: 100
  compression: none
  mode: normal
```

**配置要点**:
- ✅ EVE JSON作为主要输出格式
- ✅ 包含告警、HTTP、DNS、TLS等协议日志
- ✅ 流和重组使用合理的内存限制
- ✅ 禁用CPU亲和性设置（由DPDK管理）
- ✅ 简化的多线程配置

---

### 4.3 配置文件加载代码

**在main.c中添加**:

```c
/* 在Suricata初始化之后添加 */

// 加载配置文件
const char *config_file = "conf/suricata.yaml";
if (access(config_file, F_OK) != 0) {
    RTE_LOG(CRIT, NETIF, "Suricata config file not found: %s\n", config_file);
    return -1;
}

if (ConfYamlLoadFile(config_file) != 0) {
    RTE_LOG(CRIT, NETIF, "Failed to load Suricata config: %s\n", config_file);
    return -1;
}

RTE_LOG(INFO, NETIF, "Suricata configuration loaded from %s\n", config_file);

// 后配置初始化
GlobalsInitPostConfig();

// 创建检测引擎上下文
DetectEngineCtx *de_ctx = DetectEngineCtxInit();
if (de_ctx == NULL) {
    RTE_LOG(CRIT, NETIF, "Failed to initialize Suricata detection engine\n");
    return -1;
}

// 全局设置检测引擎上下文
DetectEngineCtxSetGlobal(de_ctx);
```

---

### 4.4 Emerging Threats规则加载

**任务**: 下载并配置Emerging Threats规则

**步骤**:

1. **创建规则目录**:
```bash
mkdir -p /etc/netdefender/rules
```

2. **下载Emerging Threats规则** (免费版):
```bash
cd /etc/netdefender/rules
wget https://rules.emergingthreats.net/open/suricata-6.0.10/emerging.rules.tar.gz
tar -xzvf emerging.rules.tar.gz
mv rules/* .
rmdir rules
```

3. **合并规则文件** (可选，简化管理):
```bash
cat *.rules > emerging-threats.rules
```

4. **加载规则代码** (在main.c中):

```c
/* 在检测引擎初始化之后添加 */

// 加载规则文件
const char *rule_file = "/etc/netdefender/rules/emerging-threats.rules";
if (access(rule_file, F_OK) != 0) {
    RTE_LOG(WARNING, NETIF, "Rule file not found: %s\n", rule_file);
    RTE_LOG(WARNING, NETIF, "Continuing without rules (detection disabled)\n");
} else {
    RTE_LOG(INFO, NETIF, "Loading Suricata rules from %s\n", rule_file);

    // 加载签名
    if (SigLoadSignatures(de_ctx, rule_file, 0) < 0) {
        RTE_LOG(CRIT, NETIF, "Failed to load Suricata rules\n");
        DetectEngineCtxFree(de_ctx);
        return -1;
    }

    RTE_LOG(INFO, NETIF, "Suricata rules loaded: %u signatures\n",
            de_ctx->sig_list ? de_ctx->sig_list->id : 0);
}

// 完成检测引擎配置
if (DetectEngineFinalize(de_ctx) != 0) {
    RTE_LOG(CRIT, NETIF, "Failed to finalize Suricata detection engine\n");
    DetectEngineCtxFree(de_ctx);
    return -1;
}

RTE_LOG(INFO, NETIF, "Suricata detection engine ready\n");
```

---

### 4.5 EVE JSON输出配置

**任务**: 配置EVE JSON输出

**已在suricata.yaml中配置**, 输出位置: `/var/log/netdefender/eve.json`

**创建日志目录** (启动脚本中):
```bash
mkdir -p /var/log/netdefender
chmod 755 /var/log/netdefender
```

**EVE JSON示例输出**:
```json
{
  "timestamp": "2025-10-22T10:30:45.123456+0800",
  "flow_id": 1234567890,
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "192.168.1.100",
  "src_port": 54321,
  "dest_ip": "93.184.216.34",
  "dest_port": 80,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2100498,
    "rev": 7,
    "signature": "GPL ATTACK_RESPONSE id check returned root",
    "category": "Potentially Bad Traffic",
    "severity": 2,
    "metadata": {
      "created_at": ["2010_09_23"],
      "updated_at": ["2010_09_23"]
    }
  },
  "http": {
    "hostname": "example.com",
    "url": "/exploit.php",
    "http_method": "GET",
    "protocol": "HTTP/1.1",
    "status": 200,
    "length": 1234
  },
  "payload": "R0VUIC9leHBsb2l0LnBocCBIVFRQLzEuMQ==",
  "payload_printable": "GET /exploit.php HTTP/1.1",
  "stream": 0,
  "packet": "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRo=",
  "packet_info": {
    "linktype": 1
  }
}
```

**不需要实时告警通知** - 所有告警写入JSON文件，可后续分析或对接SIEM系统。

---

## 阶段5: 编译和依赖管理

### 5.1 修改Makefile

**任务**: 更新Makefile以链接Suricata库

**在Makefile中添加**:

```makefile
# Suricata相关配置
SURICATA_DIR = source-references/suricata-6.0.10
SURICATA_CFLAGS = -I$(SURICATA_DIR)/src
SURICATA_LDFLAGS = -L$(SURICATA_DIR)/src/.libs
SURICATA_LIBS = -lsuricata

# 添加到CFLAGS
CFLAGS += $(SURICATA_CFLAGS)

# 添加到LDFLAGS
LDFLAGS += $(SURICATA_LDFLAGS) $(SURICATA_LIBS)

# 添加新的源文件
SRCS += src/suricata_bridge.c

# 依赖项
src/netif.o: src/suricata_bridge.h
src/suricata_bridge.o: src/suricata_bridge.h $(SURICATA_DIR)/src/decode.h
```

### 5.2 编译Suricata库

**步骤**:

```bash
cd source-references/suricata-6.0.10

# 配置Suricata (作为库编译)
./configure --prefix=/usr/local \
            --enable-dpdk \
            --disable-gccmarch-native \
            --enable-nfqueue \
            --enable-hiredis

# 编译 (仅编译库，不安装)
make -j$(nproc)

# 验证库文件存在
ls -lh src/.libs/libsuricata.so
```

---

## 阶段6: 测试和验证

### 6.1 单元测试

**测试1: 桥接函数**

创建`tests/test_suricata_bridge.c`:

```c
#include "suricata_bridge.h"
#include <rte_mbuf.h>
#include <assert.h>

void test_mbuf_to_packet_conversion() {
    // 模拟mbuf
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(pktmbuf_pool[0]);
    assert(mbuf != NULL);

    // 填充测试数据 (简单的以太网+IP+TCP)
    uint8_t test_pkt[] = {
        // Ethernet header
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,  // dst MAC
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,  // src MAC
        0x08, 0x00,                          // type: IPv4
        // IPv4 header
        0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00,
        0x40, 0x06, 0xb1, 0xe6, 0xc0, 0xa8, 0x01, 0x64,
        0xc0, 0xa8, 0x01, 0x01,
        // TCP header
        0xab, 0xcd, 0x00, 0x50, 0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x50, 0x02, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    memcpy(rte_pktmbuf_mtod(mbuf, void *), test_pkt, sizeof(test_pkt));
    mbuf->pkt_len = mbuf->data_len = sizeof(test_pkt);

    // 转换
    Packet *p = mbuf_to_suricata_packet(mbuf, NULL, NULL);
    assert(p != NULL);

    // 验证
    assert(p->pktlen == sizeof(test_pkt));
    assert(p->datalink == LINKTYPE_ETHERNET);
    assert(p->ethh != NULL);           // 以太网头已解析
    assert(p->ip4h != NULL);           // IPv4头已解析
    assert(p->tcph != NULL);           // TCP头已解析

    // 清理
    free_suricata_packet_and_mbuf(p, mbuf);

    printf("✓ test_mbuf_to_packet_conversion passed\n");
}

int main() {
    // 初始化DPDK和Suricata
    // ...

    test_mbuf_to_packet_conversion();

    return 0;
}
```

### 6.2 集成测试

**测试2: 端到端数据包处理**

```bash
# 1. 启动NetDefender
./netdefender -c netdefender.conf

# 2. 生成测试流量 (使用tcpreplay)
tcpreplay -i eth0 tests/pcaps/test_traffic.pcap

# 3. 检查日志
tail -f /var/log/netdefender/eve.json

# 4. 验证统计
cat /var/log/netdefender/eve.json | grep '"event_type":"stats"'
```

### 6.3 功能测试

**测试3: 告警生成**

```bash
# 使用包含恶意流量的PCAP
wget https://testmynids.org/uid/index.html -O /tmp/malware_test.html

# 触发告警 (应匹配ET规则)
curl http://testmynids.org/uid/index.html

# 验证告警
grep '"event_type":"alert"' /var/log/netdefender/eve.json
```

---

## 性能考虑（后续阶段）

### 当前实现特点
- ✅ **拷贝模式**: mbuf数据拷贝到Suricata Packet（简单可靠）
- ✅ **同步处理**: 每个数据包顺序处理（易于调试）
- ✅ **多核支持**: 每个DPDK lcore运行独立的Suricata worker

### 后续优化方向（不在当前计划）
- 零拷贝模式（减少内存拷贝）
- 批量处理优化（一次处理多个数据包）
- CPU缓存优化（预取、对齐）
- 流水线优化（Decode/Detect分离）

**当前目标**: 先确保功能正确，后续再做性能优化

---

## 项目文件结构

```
/home/work/clionProject/dpdk-based-nids/
├── src/
│   ├── main.c                      # [修改] 添加Suricata初始化
│   ├── netif.c                     # [修改] 集成桥接函数到RX循环
│   ├── netif.h
│   ├── suricata_bridge.c           # [新建] 桥接层实现
│   ├── suricata_bridge.h           # [新建] 桥接层头文件
│   ├── timer.c                     # [已完成] DPVS timer
│   └── timer.h
├── conf/
│   ├── netdefender.conf            # [现有] DPDK配置
│   └── suricata.yaml               # [新建] Suricata配置
├── source-references/
│   ├── suricata-6.0.10/            # Suricata 6.0.10源码
│   └── dpvs/                       # DPVS源码
├── docs/
│   ├── Suricata数据包处理流程分析.md  # [已完成] Suricata分析文档
│   ├── DPVS_RX_Flow_Analysis.md    # [已完成] DPVS RX分析
│   └── ...
├── tests/
│   ├── test_suricata_bridge.c      # [新建] 桥接层测试
│   └── pcaps/                      # 测试PCAP文件
└── 实施计划.md                      # [当前文件] 实施计划

/etc/netdefender/
└── rules/
    └── emerging-threats.rules      # Emerging Threats规则

/var/log/netdefender/
├── eve.json                        # EVE JSON输出
├── fast.log                        # 快速告警日志
└── suricata.log                    # Suricata系统日志
```

---

## 实施时间表

| 阶段 | 任务 | 预计时间 | 状态 |
|------|------|----------|------|
| 阶段1 | 修复DPDK RX循环 | 1天 | ✅ 已完成 |
| 阶段2 | 分析Suricata结构 | 1天 | ✅ 已完成 |
| **阶段3** | **实现桥接层** | **2-3天** | 🔄 进行中 |
| 阶段4 | Suricata初始化 | 2天 | ⏳ 待开始 |
| 阶段5 | 编译和依赖 | 1天 | ⏳ 待开始 |
| 阶段6 | 测试验证 | 2-3天 | ⏳ 待开始 |
| **总计** | | **8-10天** | |

---

## 下一步行动

### 立即执行（阶段3）

1. **创建`src/suricata_bridge.h`**
   - 声明桥接函数
   - 包含必要的头文件

2. **创建`src/suricata_bridge.c`**
   - 实现`mbuf_to_suricata_packet()`
   - 实现`free_suricata_packet_and_mbuf()`
   - 实现`suricata_thread_init()`

3. **修改`src/netif.c`**
   - 添加线程局部Suricata上下文
   - 集成桥接函数到RX循环
   - 添加错误处理

4. **验证编译**
   - 确保头文件路径正确
   - 解决符号依赖问题

---

## 关键设计决策总结

1. ✅ **拷贝模式 vs 零拷贝**: 初期使用拷贝模式（简单可靠）
2. ✅ **不设置livedev**: Suricata不需要知道DPDK端口信息
3. ✅ **不设置租户ID**: 单租户场景，默认为0
4. ✅ **使用Emerging Threats规则**: 免费、更新频繁、覆盖广
5. ✅ **EVE JSON输出**: 标准格式，易于集成SIEM
6. ✅ **不实时告警**: 写入文件，后续分析
7. ✅ **多核并行**: 每个DPDK lcore对应一个Suricata worker
8. ✅ **性能优化后置**: 先确保功能正确

---

**文档版本**: 1.0
**创建日期**: 2025-10-22
**状态**: 执行中 - 阶段3
