# NetDefender：基于DPDK的高性能网络入侵检测系统

NetDefender是一个高性能的网络入侵检测系统(NIDS)，基于DPDK构建，提供极低延迟和高吞吐量的网络流量分析和威胁检测能力。



## 功能特性

- 基于DPDK的高性能网络数据包捕获
- 可扩展的入侵检测引擎
- 高效的多模式匹配算法
- 支持自定义规则
- 实时告警和日志记录
- 可扩展的插件架构



## 依赖项

- 操作系统:  (推荐Ubuntu 20.04+)
- DPDK 24.11
- CMake 3.15+
- pkg-config
- libnuma-dev（可选，支持numa架构）
- libpcap-dev (可选，用于离线分析)



## DPDK环境安装

## 1、1 编译dpdk源代码

使用 meson-ninja 构建 DPDK，并为 DPDK 应用程序（eta加密流量分析）导出环境变量 PKG_CONFIG_PATH

```
#下载dpdk源代码后进入源码目录
cd dpdk-24.11

mkdir dpdklib                 # user desired install folder
mkdir dpdkbuild               # user desired build folder

meson -Denable_kmods=true -Dprefix=dpdklib dpdkbuild

#使用ninja编译
ninja -C dpdkbuild
cd dpdkbuild; 
ninja install

#导出环境变量
在/etc/profile文件中添加如下内容：
export PKG_CONFIG_PATH=$(pwd)/../dpdklib/lib64/pkgconfig/
```



## 1、2 为网口绑定dpdk驱动

dpdk的驱动分为以下几种，我们选择绑定什么驱动呢？

在测试时，我们选择uio_pci_generic驱动进行绑定，不过性能不是最佳，所以不能作为性能测试的配置。

等部署到客户环境时，根据客户的网卡来决定绑定什么网卡，比如客户的网卡是x710，那么就绑定x710网卡对应的驱动。



### 1）加载dpdk驱动

**加载vfio驱动（首选）**

modprobe vfio-pci



**uio_pci_generic驱动适合做基础测试，但是性能会低一些。**

modprobe uio_pci_generic



### 2）使用dpdk-devbind.py脚本来绑定指定网口

先使用ifconfig命令来停止网口
ifconfig  eno1 down



然后再执行dpdk-devbind.py脚本
./dpdk-devbind.py --bind=uio_pci_generic 0000:01:00.0



0000:00:19.0是我要绑定dpdk网卡驱动的网口

此时再次执行./dpdk-devbind.py --status命令，输出内容如下:

```
Network devices using DPDK-compatible driver (此处是绑定dpdk驱动的网卡)
============================================

0000:00:19.0 'Ethernet Connection (3) I218-LM 15a2' drv=uio_pci_generic unused=e1000e,vfio-pci

Network devices using kernel driver (此处是绑定内核驱动的网卡)
===================================

0000:03:00.0 'Wireless 7265 095b' if=wlp3s0 drv=iwlwifi unused=vfio-pci,uio_pci_generic *Active*
```



成功加载后，如果需要卸载网口

```
./dpdk-devbind.py -u 0000:01:00.0
```

然后再将网卡绑定到之前的驱动上

```
./dpdk-devbind.py -b e1000e 0000:01:00.0
```

e1000e是网卡在绑定dpdk驱动前，自身绑定的网卡。



Intel平台开启IOMMU配置

先检测是否为intel平台架构

```
lscpu | grep "Vendor ID"
BIOS Vendor ID:                       Intel
```



检测系统是否支持IOMMU的通用方法

```
# 检查IOMMU组（最可靠的方法）
ls /sys/kernel/iommu_groups/
```

如果结果中存在多个数字命名的文件夹，则代表支持iommu



如果上述驱动都无法加载，可以采用igb_uio驱动





## 1、3 配置大页内存

### 1、3、1 临时设置大页内存

echo 4 > /sys/devices/system/node/node0/hugepages/hugepages-1048576kB/nr_hugepages



设置大页内存后，显示结果如下

```
cat /proc/meminfo | grep Huge
AnonHugePages:         0 kB
ShmemHugePages:        0 kB
FileHugePages:         0 kB
HugePages_Total:       3
HugePages_Free:        3
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:    1048576 kB
Hugetlb:         3145728 kB
root@haolipeng-ThinkPad-T450:/home/work/dpdk-stable-24.11.1/usertools#
```



如果系统不支持1G大小的大页内存，可以先使用2M大小的大页内存。

```
root@r630-PowerEdge-R630:~# cat /proc/meminfo | grep Huge
AnonHugePages:         0 kB
ShmemHugePages:        0 kB
FileHugePages:         0 kB
HugePages_Total:    4096
HugePages_Free:     4096
HugePages_Rsvd:        0
HugePages_Surp:        0
Hugepagesize:       2048 kB
Hugetlb:        18874368 kB
```



### 1、3、2 永久设置大页内存，开机启动

大页内存也可以在开机自启动时，永久的设置到系统中。

编辑GRUB配置文件：

```
vim /etc/default/grub
```



修改`GRUB_CMDLINE_LINUX_DEFAULT`行，添加大页内存参数

```
GRUB_CMDLINE_LINUX_DEFAULT="quiet splash hugepagesz=1G hugepages=4"
```



更新GRUB配置

```
update-grub
```



验证大页内存的配置

```
cat /proc/meminfo | grep Huge
```



## 使用方法

### 运行捕获示例

```bash
./build/dpdk_nids -c conf/netdefender.conf -- -l 0-4 -n 4
```

参数说明：
- `-l 0-4`: 使用CPU核心0到4
- `-n 4`: 使用4个内存通道



**程序运行日志**

```
root@r630-PowerEdge-R630:/home/work/clionProject/dpdk-based-nids# ./build/dpdk_nids -c conf/netdefender.conf 
EAL: Detected CPU lcores: 72
EAL: Detected NUMA nodes: 2
EAL: Detected shared linkage of DPDK
EAL: Multi-process socket /var/run/dpdk/rte/mp_socket
EAL: Selected IOVA mode 'VA'
EAL: 10 hugepages of size 1073741824 reserved, but no mounted hugetlbfs found for that size
EAL: VFIO support initialized
EAL: Using IOMMU type 1 (Type 1)

//////////////////////////////////port配置信息///////////////////////////////////
CFG_FILE: Opening configuration file 'conf/netdefender.conf'. //打开配置文件
NETIF: pktpool_size = 524287 (round to 2^n-1)
NETIF: pktpool_cache_size = 256 (round to 2^n)
NETIF: netif device config: dpdk0
NETIF: Added device dpdk0 to port_list, total devices: 1      //将dpdk0添加到port_list链表中
NETIF: dpdk0:rx_queue_number = 8
NETIF: dpdk0:nb_rx_desc = 1024 (round to 2^n)
NETIF: dpdk0:rss = all
NETIF: dpdk0:tx_queue_number = 8
NETIF: dpdk0:nb_tx_desc = 1024 (round to 2^n)
NETIF: dpdk0:mtu = 1500

//////////////////////////////////worker配置信息///////////////////////////////////
NETIF: netif worker config: cpu0    //cpu0配置
NETIF: cpu0:type = master
NETIF: cpu0:cpu_id = 0

NETIF: netif worker config: cpu1	//cpu1配置
NETIF: cpu1:type = slave
NETIF: cpu1:cpu_id = 1
NETIF: worker cpu1:dpdk0 queue config
NETIF: worker cpu1:dpdk0 rx_queue_id += 0
NETIF: worker cpu1:dpdk0 tx_queue_id += 0

NETIF: netif worker config: cpu2	//cpu2配置
NETIF: cpu2:type = slave
NETIF: cpu2:cpu_id = 2
NETIF: worker cpu2:dpdk0 queue config
NETIF: worker cpu2:dpdk0 rx_queue_id += 1
NETIF: worker cpu2:dpdk0 tx_queue_id += 1

NETIF: netif worker config: cpu3	//cpu3配置
NETIF: cpu3:type = slave
NETIF: cpu3:cpu_id = 3
NETIF: worker cpu3:dpdk0 queue config
NETIF: worker cpu3:dpdk0 rx_queue_id += 2
NETIF: worker cpu3:dpdk0 tx_queue_id += 2

//////////////////////////////////打印lcore的开启状态和角色///////////////////////////////////
NETIF: DPDK detected 1 ports, config file has 1 ports
NETIF: LCORE STATUS
	enabled:    0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15  16  17  18  19  20  21  22  23  24  25  26  27  28  29  30  31  32  33  34  35  36  37  38  39  404  55  56  57  58  59  60  61  62  63  64  65  66  67  68  69  70  71
	disabled:   72  73  74  75  76  77  78  79  80  81  82  83  84  85  86  87  88  89  90  91  92  93  94  95  96  97  98  99 100 101 102 103 104 105 106 107 108 109 110 111 1126 127
NETIF: LCORE ROLES:
	lcre_role_idle: 4   5   6   7   8   9   10  11  12  13  14  15  16  17  18  19  20  21  22  23  24  25  26  27  28  29  30  31  32  33  34  35  36  37  38  39  40  41  42  457  58  59  60  61  62  63  64  65  66  67  68  69  70  71  
	lcre_role_master: 0   
	lcre_role_fwd_worker: 1   2   3   
	lcre_role_isolrx_worker: 
	lcore_role_kni_worker: 
	
//程序自动屏蔽了不支持的RSS哈希函数，只保留了网卡支持的部分。
NETIF: Ethdev port_id=0 invalid rss_hf: 0x3afbc, valid value: 0x38d34
NETIF: Ethdev port_id=0 invalid tx_offload: 0x1000e, valid value: 0x2a03f
NETIF: device dpdk0 configuration:
RSS: ETH_RSS_IP ETH_RSS_TCP ETH_RSS_UDP 

//等待dpdk端口启动，就是start函数
NETIF: Waiting for dpdk0 link up, be patient ...
NETIF: >> dpdk0: link up - speed 10000 Mbps - full-duplex
NETIF: promiscous mode enabled for device dpdk0
NETIF: allmulticast enabled for device dpdk0
NETIF: RSS RETA(dpdk0):
   0: 0   1   2   0   1   2   0   1   
   8: 2   0   1   2   0   1   2   0   
  16: 1   2   0   1   2   0   1   2   
  24: 0   1   2   0   1   2   0   1   
  32: 2   0   1   2   0   1   2   0   
  40: 1   2   0   1   2   0   1   2   
  48: 0   1   2   0   1   2   0   1   
  56: 2   0   1   2   0   1   2   0   
  64: 1   2   0   1   2   0   1   2   
  72: 0   1   2   0   1   2   0   1   
  80: 2   0   1   2   0   1   2   0   
  88: 1   2   0   1   2   0   1   2   
  96: 0   1   2   0   1   2   0   1   
 104: 2   0   1   2   0   1   2   0   
 112: 1   2   0   1   2   0   1   2   
 120: 0   1   2   0   1   2   0   1  
 
//////////////////////////////////port-queue-lcore的映射关系///////////////////////////////////
//明确下是否开启了网卡多队列没
MAIN: port-queue-lcore relation array: 
                dpdk0: 24:6E:96:8B:F1:E8 
    rx0-tx0     cpu1-cpu1                
    rx1-tx1     cpu2-cpu2                
    rx2-tx2     cpu3-cpu3                

DSCHED: lcore 01 enter lcre_role_fwd_worker loop
DSCHED: lcore 02 enter lcre_role_fwd_worker loop
DSCHED: lcore 03 enter lcre_role_fwd_worker loop
```



支持的哈希值

当配置rss为all时，rss_resolve_proc解析all为rss_value = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP

```
NETIF: Ethdev port_id=0 invalid rss_hf: 0x3afbc, valid value: 0x38d34
NETIF: Ethdev port_id=0 invalid tx_offload: 0x1000e, valid value: 0x2a03f
```

- 配置的RSS值: 0x3afbc = RTE_ETH_RSS_IP | RTE_ETH_RSS_TCP | RTE_ETH_RSS_UDP

- 网卡支持的RSS值: 0x38d34

让我们分析 0x3afbc 和 0x38d34 的差异：

```
0x3afbc = 00111010111110111100 (二进制)
0x38d34 = 00111000110100110100 (二进制)

差异位:   00000010001010001000 = 0x02288
```

这意味着网卡不支持以下RSS哈希函数：

- RTE_ETH_RSS_FRAG_IPV4 (bit 3)

- RTE_ETH_RSS_NONFRAG_IPV4_SCTP (bit 6)

- RTE_ETH_RSS_FRAG_IPV6 (bit 9)

- RTE_ETH_RSS_NONFRAG_IPV6_SCTP (bit 12)

- RTE_ETH_RSS_IPV6_EX (bit 15)

通俗易懂点说为，网卡不支持的hash函数有以下三种：

1、分片IP包的RSS哈希：RTE_ETH_RSS_FRAG_IPV4 和 RTE_ETH_RSS_FRAG_IPV6

2、SCTP协议的RSS哈希：RTE_ETH_RSS_NONFRAG_IPV4_SCTP 和 RTE_ETH_RSS_NONFRAG_IPV6_SCTP

3、扩展IPv6的RSS哈希：RTE_ETH_RSS_IPV6_EX

但是网卡支持：

- TCP和UDP的RSS哈希
- 非分片IP的RSS哈希
- 其他IP协议的RSS哈希

今日把代码能跑起来，然后能收到数据包才算完成。



## 项目结构（更新下）

```
NetDefender/
├── CMakeLists.txt      # 主CMake配置
├── src/                # 源代码
│   ├── core/           # DPDK核心功能 (C)
│   ├── detection/      # 检测引擎 (C++)
│   ├── analysis/       # 分析模块 (C++)
│   └── common/         # 公共组件
├── include/            # 公共头文件
├── tests/              # 单元测试和集成测试
├── examples/           # 示例程序
├── scripts/            # 构建和安装脚本
└── docs/               # 文档
```

## 架构设计
每个核心做各自逻辑核心的事情，为每个核心定义了不同的角色，不同角色做不同的逻辑流程。



## 构建配置选项

### NDF_MAX_SOCKET 配置

`NDF_MAX_SOCKET` 定义了系统支持的最大套接字数量。您可以通过以下方式配置：

#### 使用 CMake 命令行参数：
```bash
cmake .. -DNDF_MAX_SOCKET=4
```



#### 默认值：

如果未指定，默认值为 32。

#### 示例：
```bash
# 设置最大套接字数为 4
mkdir build && cd build
cmake .. -DNDF_MAX_SOCKET=4
make

# 设置最大套接字数为 16  
cmake .. -DNDF_MAX_SOCKET=16
make
```

这个配置选项替代了之前在 `src/common.h` 中的硬编码宏定义，使得在不修改源代码的情况下就能调整系统参数。 

对于我们来说，还是有很多东西都是可以做的。