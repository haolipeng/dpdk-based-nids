# NetDefender：基于DPDK的高性能网络入侵检测系统

NetDefender是一个高性能的网络入侵检测系统(NIDS)，基于DPDK构建，提供极低延迟和高吞吐量的网络流量分析和威胁检测能力。



## 特性

- 基于DPDK的高性能网络数据包捕获
- 可扩展的入侵检测引擎
- 高效的多模式匹配算法
- 支持自定义规则
- 实时告警和日志记录
- 可扩展的插件架构



## 依赖项

- 操作系统:  (推荐Ubuntu 20.04+)
- 编译器: GCC 9+
- DPDK 24.11
- CMake 3.12+
- pkg-config
- libnuma-dev
- libpcap-dev (可选，用于离线分析)



## 环境安装

编译源代码

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



加载dpdk驱动
modprobe uio_pci_generic



为网口绑定dpdk驱动

./dpdk-devbind.py -b uio_pci_generic 0000:00:19.0

加载驱动后，显示如下：

```
root@haolipeng-ThinkPad-T450:/home/work/dpdk-stable-24.11.1/usertools# ./dpdk-devbind.py --status

Network devices using DPDK-compatible driver
============================================
0000:00:19.0 'Ethernet Connection (3) I218-LM 15a2' drv=uio_pci_generic unused=e1000e,vfio-pci

Network devices using kernel driver
===================================
0000:03:00.0 'Wireless 7265 095b' if=wlp3s0 drv=iwlwifi unused=vfio-pci,uio_pci_generic *Active*
```



设置大页内存（可选项，推荐设置，未设置也可以启动程序）





## 使用方法

### 运行捕获示例

```bash
./build/dpdk_nids -c conf/netdefender.conf
```

参数说明：
- `-l 0-1`: 使用CPU核心0和1
- `-n 4`: 使用4个内存通道
- `-p 0`: 使用端口0进行捕获

### 运行IDS示例

```bash
sudo ./build/examples/ids_demo -l 0-3 -n 4 -- rules/default.rules
```

## 项目结构（需持续更新）

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