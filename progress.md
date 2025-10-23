# NetDefender (DPDK-based NIDS) 项目进度报告

**生成日期:** 2025-10-22
**项目版本:** v1.0.0
**项目目标:** 融合DPVS和Suricata精华组件，构建高性能网络入侵检测系统

---

## 一、项目概览

### 1.1 项目架构

```
NetDefender = DPDK (数据平面) + DPVS (调度框架) + Suricata (检测引擎)
```

**核心设计理念:**
- 使用DPDK实现零拷贝高速收包
- 复用DPVS的任务调度器和定时器管理
- 集成Suricata的规则匹配和威胁检测引擎

### 1.2 目录结构

```
dpdk-based-nids/
├── src/                          # 核心源代码
│   ├── main.c                    # 主程序入口 (268行)
│   ├── scheduler.{h,c}          # 任务调度器 (已完成, 159行)
│   ├── timer.{h,c}              # 定时器系统 (待完善, 17行stub)
│   ├── netif.{h,c}              # 网络接口管理 (已完成, 2325行)
│   ├── cfgfile.{h,c}            # 配置文件解析 (已完成)
│   ├── parser.{h,c}             # 配置解析引擎 (已完成)
│   ├── global_data.{h,c}        # 全局状态管理 (已完成)
│   └── ...
├── conf/
│   └── netdefender.conf          # 系统配置文件
├── source-references/
│   ├── dpvs/                     # DPVS参考实现
│   └── suricata-6.0.10/          # Suricata参考实现
├── examples/
│   ├── capture_demo.c            # 抓包示例
│   └── ids_demo.cpp              # IDS示例(待实现)
└── CMakeLists.txt                # CMake构建配置
```

---

## 二、组件完成度统计

### 2.1 已完成模块 ✅

| 模块 | 文件 | 代码行数 | 完成度 | 状态说明 |
|------|------|----------|--------|----------|
| **主程序框架** | main.c | 275 | 100% | 初始化流程完整，包括DPDK EAL、模块初始化、worker启动、timer模块 |
| **任务调度器** | scheduler.c/h | 159 | 100% | 已从DPVS改造，支持INIT/LOOP/SLOW三种job类型 |
| **定时器系统** | timer.c/h | 720 | 100% | 完整集成DPVS定时器，多层时间轮、O(1)复杂度、全局/per-lcore定时器 |
| **网络接口** | netif.c/h | 2325 | 100% | 支持多队列、RSS、isolated RX、mbuf池管理 |
| **配置解析** | cfgfile.c/h, parser.c/h | ~800 | 100% | 支持netif_defs、worker_defs、timer_defs配置段 |
| **全局数据** | global_data.c/h | ~200 | 100% | lcore角色管理、tick计数器、NUMA映射 |
| **辅助工具** | pidfile.c/h, common.c/h | ~150 | 100% | PID文件、错误码定义、日志宏 |

### 2.2 待完善模块 ⚠️

| 模块 | 文件 | 当前状态 | 缺失功能 | 优先级 |
|------|------|----------|----------|--------|
| **检测引擎** | 未创建 | 不存在 | 规则加载、模式匹配、告警生成 | 🔴 高 |
| **IDS示例** | ids_demo.cpp | 框架代码 | 实际检测逻辑未实现 | 🟡 中 |

### 2.3 未启动模块 ❌

| 模块 | 计划位置 | 功能描述 | 依赖关系 |
|------|----------|----------|----------|
| **Suricata规则引擎** | src/detect/ | 签名匹配、协议解析 | 需定时器支持 |
| **流状态追踪** | src/flow/ | TCP/UDP流重组 | 需定时器支持(超时管理) |
| **告警输出** | src/output/ | 日志、JSON、PCAP输出 | 依赖检测引擎 |
| **统计报表** | src/stats/ | 实时性能指标、流量统计 | - |
| **IPC控制接口** | src/ipc/ | 运行时命令接口 | 已预留ipc_file参数 |

---

## 三、DPVS组件集成状态

### 3.1 调度器集成 ✅ 已完成

**源文件:** `source-references/dpvs/src/scheduler.c` → `src/scheduler.c`

**改造内容:**
- 函数重命名: `dpvs_lcore_*` → `ndf_lcore_*`
- 数据结构: `dpvs_lcore_job` → `ndf_lcore_job`
- 保留了DPVS的三种job类型机制:
  ```c
  LCORE_JOB_INIT   // 一次性初始化任务
  LCORE_JOB_LOOP   // 高频循环任务(每次poll调用)
  LCORE_JOB_SLOW   // 低频周期任务(可配置skip_loops)
  ```

**集成效果:**
- netif.c已注册数据包处理job
- 支持master/slave/isolrx等lcore角色
- 全局tick计数器用于慢任务调度

**使用示例:**
```c
static struct ndf_lcore_job my_job = {
    .name = "packet_process",
    .func = packet_process_handler,
    .data = NULL,
    .type = LCORE_JOB_LOOP,
};
ndf_lcore_job_register(&my_job, LCORE_ROLE_FWD_WORKER);
```

### 3.2 定时器集成 ✅ 已完成 (2025-10-22)

**源文件:** `source-references/dpvs/src/timer.c` (782行) → `src/timer.c` (720行)

**DPVS定时器核心特性:**

1. **多层时间轮算法**
   - LEVEL_SIZE: 524,288 个时间槽
   - LEVEL_DEPTH: 2层深度
   - 覆盖范围: 0-524秒(L1) + 0-8.7年(L2)
   - 时间复杂度: O(1)插入/删除

2. **定时器类型**
   - **Global Timer**: 全局可见，带spinlock保护
   - **Per-lcore Timer**: 无锁设计，仅本地lcore访问
   - **One-shot Timer**: 单次触发
   - **Periodic Timer**: 周期性触发

3. **API接口 (已重命名为ndf_*前缀)**
   ```c
   // 相对延时调度(delay毫秒后触发)
   int ndf_timer_sched(struct ndf_timer *timer,
                        struct timeval *delay,
                        ndf_timer_cb_t handler,
                        void *arg, bool global);

   // 绝对时间调度(指定时间点触发)
   int ndf_timer_sched_abs(struct ndf_timer *timer,
                            struct timeval *expire,
                            ndf_timer_cb_t handler,
                            void *arg, bool global);

   // 周期性定时器
   int ndf_timer_sched_period(struct ndf_timer *timer,
                               struct timeval *intv,
                               ndf_timer_cb_t handler,
                               void *arg, bool global);

   // 定时器管理
   int ndf_timer_cancel(struct ndf_timer *timer, bool global);
   int ndf_timer_reset(struct ndf_timer *timer, bool global);
   int ndf_timer_update(struct ndf_timer *timer,
                         struct timeval *delay, bool global);
   ```

4. **集成完成情况 ✅**
   - ✅ 完整移植DPVS timer.c (720行,去除debug代码)
   - ✅ API重命名: `dpvs_timer_*` → `ndf_timer_*`
   - ✅ 错误码重命名: `EDPVS_*` → `ENDF_*`
   - ✅ 配置文件支持: timer_defs段,schedule_interval参数
   - ✅ 模块注册: 在main.c MODULE_TIMER位置
   - ✅ cfgfile集成: ndf_install_timer_keywords()
   - ✅ 使用示例: examples/timer_demo.c (350行,5个场景)

5. **实际应用场景 (已在timer_demo.c中实现)**
   - TCP/UDP流超时管理(60秒默认,可配置)
   - 周期性统计报表输出(5秒间隔)
   - 规则文件热更新检查(60秒间隔)
   - 定时器控制操作(取消/重置/更新)
   - 当前时间查询(全局/per-lcore)

---

## 四、Suricata组件集成规划

### 4.1 Suricata核心模块分析

**参考位置:** `source-references/suricata-6.0.10/`

**可复用的精华组件:**

| 组件 | Suricata路径 | 功能描述 | 集成难度 | 优先级 |
|------|--------------|----------|----------|--------|
| **规则解析器** | src/detect-parse.c | Snort规则语法解析 | 🟡 中 | 高 |
| **模式匹配引擎** | src/detect-engine-mpm.c | Aho-Corasick/Hyperscan | 🔴 高 | 高 |
| **协议解析器** | src/app-layer-*.c | HTTP/DNS/TLS/SSH等 | 🔴 高 | 中 |
| **流管理器** | src/flow.c | 五元组流表 | 🟡 中 | 高 |
| **告警框架** | src/output.c | 可扩展输出模块 | 🟢 低 | 中 |

### 4.2 检测引擎集成策略

**挑战点:**
1. Suricata是多线程模型，需改造为DPDK lcore模型
2. 内存管理需使用DPDK mbuf池而非malloc
3. 配置文件格式不同(suricata.yaml vs netdefender.conf)

**推荐方案:**
1. **第一阶段(MVP):** 实现基础签名检测
   - 加载简化版Snort规则(content关键字)
   - 使用AC自动机进行多模式匹配
   - 输出基础告警到日志文件

2. **第二阶段:** 协议感知检测
   - 集成HTTP/DNS协议解析器
   - 支持协议特定规则(http.uri, dns.query等)

3. **第三阶段:** 完整检测能力
   - 流重组和状态追踪
   - Lua脚本支持
   - 统计和性能分析

---

## 五、配置文件设计

### 5.1 当前配置 (netdefender.conf)

**已支持的配置段:**

#### netif_defs - 网络接口配置
```
netif_defs {
    pktpool_size    524287     # mbuf池大小
    pktpool_cache   256        # per-CPU缓存

    device dpdk0 {
        rx {
            queue_number 4
            descriptor_number 1024
            rss all
        }
        tx {
            queue_number 4
            descriptor_number 1024
        }
        mtu 1500
        promisc_mode on
        allmulticast on
    }
}
```

#### worker_defs - CPU工作核配置
```
worker_defs {
    worker cpu0 {
        type master        # 控制面
        cpu_id 0
    }

    worker cpu1 {
        type slave         # 数据面
        cpu_id 1
        port dpdk0 {
            rx_queue_ids 0
            tx_queue_ids 0
        }
    }
}
```

### 5.2 已添加配置段 ✅

#### timer_defs - 定时器配置 (已完成)
```
timer_defs {
    schedule_interval  10      # 定时器调度间隔(ms), 默认10, 范围1-10000000
}
```

**说明:**
- `schedule_interval`: DPDK rte_timer管理间隔,影响定时器精度
- 配置路径: `conf/netdefender.conf:13-15`
- 关键字处理: `src/timer.c:687-707`

### 5.3 待添加配置段 (TODO)

#### ids_defs - IDS检测配置 (未实现)
```
ids_defs {
    rule_files /etc/netdefender/rules/*.rules
    default_action pass        # alert/drop/pass

    flow_timeout {
        tcp 60s
        udp 30s
        icmp 10s
    }

    outputs {
        fast_log /var/log/netdefender/fast.log
        alert_json /var/log/netdefender/alerts.json
        pcap /var/log/netdefender/suspicious.pcap
    }
}
```

---

## 六、编译与运行状态

### 6.1 编译环境

- **CMake版本:** 3.12+
- **编译器:** GCC (C99) + G++ (C++11)
- **DPDK版本:** 24.11+ (pkg-config检测)
- **依赖库:** numa, pthread, dl, m, rt

**编译命令:**
```bash
mkdir build && cd build
cmake ..
make -j$(nproc)
```

**输出:** `build/dpdk_nids` (可执行文件)

### 6.2 运行要求

**硬件准备:**
```bash
# 1. 绑定网卡到DPDK驱动
modprobe vfio-pci
dpdk-devbind.py -b vfio-pci 0000:03:00.0

# 2. 配置大页内存
echo 1024 > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
mkdir -p /mnt/huge
mount -t hugetlbfs nodev /mnt/huge
```

**运行示例:**
```bash
# 基础运行(4个worker core)
sudo ./dpdk_nids -c /etc/netdefender.conf -- -l 0-4 -n 4

# 指定PID文件
sudo ./dpdk_nids -c ./conf/netdefender.conf -p /tmp/nids.pid -- -l 0-7 -n 4

# 查看帮助
./dpdk_nids -h
```

### 6.3 当前功能验证

**✅ 已验证功能:**
- [x] DPDK EAL初始化成功
- [x] 配置文件解析正常(netif_defs, worker_defs)
- [x] 网卡端口启动成功(link up检测)
- [x] Worker线程正常启动并绑核
- [x] Packet reception正常(从git历史"frame can receive packet"提交可见)

**❌ 待验证功能:**
- [ ] 定时器功能(当前为stub)
- [ ] IDS检测功能(未实现)
- [ ] 告警输出(未实现)
- [ ] 性能测试(吞吐量、延迟)

---

## 七、Git提交历史摘要

**最近5次提交:**
```
2ac00fe - commit .gitignore file
079a42c - fix bug
7b6f5a4 - good boy, frame can receive packet  ← 收包功能调通
ef2aac7 - add debug info to received packet ok
aaeb752 - fix compile error
```

**关键里程碑:**
- ✅ 2024年底: 移除DPVS原始代码，搭建独立框架
- ✅ 2025-01: 调度器和网络接口模块完成
- ✅ 2025-10: 收包功能调通
- ✅ 2025-10-22: DPVS定时器系统完整集成
- ⏳ 当前: 准备集成Suricata检测引擎

---

## 八、下一步工作计划

### ~~阶段一: 定时器集成~~ ✅ 已完成 (2025-10-22)

**任务清单:**
- [x] 将DPVS timer.c (782行)集成到src/timer.c
- [x] 批量重命名API: `dpvs_timer_*` → `ndf_timer_*`
- [x] 头文件timer.h完整移植并重命名
- [x] 在cfgfile.c添加timer_defs配置关键字
- [x] 在main.c添加MODULE_TIMER模块注册
- [x] 编写定时器使用示例(examples/timer_demo.c, 350行)
- [x] 更新配置文件添加timer_defs段

**集成成果:**
- ✅ 720行完整定时器系统代码
- ✅ 支持全局/per-lcore双模式定时器
- ✅ 多层时间轮算法(O(1)复杂度)
- ✅ 5个实际应用场景示例
- ✅ 完整的配置文件支持

### 阶段二: 基础IDS引擎 (1-2周)

**任务清单:**
- [ ] 实现简化版Snort规则解析器
- [ ] 集成AC自动机多模式匹配
- [ ] 实现TCP/UDP五元组流表
- [ ] 集成流超时管理(使用定时器)
- [ ] 实现基础告警输出(fast.log格式)
- [ ] 编写检测引擎使用文档

**验收标准:**
- 可加载标准Snort规则文件
- 可检测简单的content签名(如SQL注入特征)
- 告警准确率>95%(在标准测试集上)

### 阶段三: 性能优化 (1周)

**任务清单:**
- [ ] Packet批处理优化(burst size调优)
- [ ] Zero-copy流重组
- [ ] 规则集优化(减少冗余匹配)
- [ ] 使用perf/VTune进行性能分析
- [ ] 编写性能测试报告

**目标指标:**
- 单核处理能力: >10 Gbps
- 延迟: <100us (P99)
- 误报率: <1%

---

## 九、技术风险与缓解措施

### 风险1: Suricata集成复杂度高
**影响:** 可能导致项目延期
**缓解措施:**
- 采用渐进式集成策略(先MVP后完善)
- 优先实现最核心的签名检测功能
- 保持对原始Suricata代码的最小修改

### 风险2: 性能不达预期
**影响:** 无法满足10Gbps线速要求
**缓解措施:**
- 早期进行性能基线测试
- 使用DPDK PMD轮询模式减少延迟
- 考虑使用GPU加速(CUDA)或FPGA卸载

### 风险3: 内存泄漏和稳定性问题
**影响:** 长时间运行崩溃
**缓解措施:**
- 使用Valgrind/ASAN进行内存检测
- 实现完善的mbuf引用计数管理
- 添加资源监控和自动恢复机制

---

## 十、参考资源

### 源代码参考
- **DPVS:** `source-references/dpvs/` (v1.9)
- **Suricata:** `source-references/suricata-6.0.10/`
- **DPDK:** https://doc.dpdk.org/guides-24.11/

### 文档资源
- DPDK Programmer's Guide: https://doc.dpdk.org/guides/prog_guide/
- Suricata User Guide: https://docs.suricata.io/
- DPVS Tutorial: https://github.com/iqiyi/dpvs/blob/master/doc/tutorial.md

### 性能测试工具
- TRex Traffic Generator
- Scapy (包构造)
- iperf3 (吞吐量测试)

---

## 十一、联系与协作

**项目维护者:** [待填写]
**代码仓库:** [待填写]
**问题追踪:** [待填写]

---

**报告结束**

> 本报告由Claude Code自动生成，基于代码库分析和Git历史统计。
> 最后更新: 2025-10-22
