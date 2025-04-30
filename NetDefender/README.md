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

- 操作系统: Linux (推荐Ubuntu 20.04+或CentOS 8+)
- 编译器: GCC 7+
- DPDK 20.11+
- CMake 3.12+
- pkg-config
- libnuma-dev
- libpcap-dev (可选，用于离线分析)

## 构建和安装

### 快速安装（包括依赖项）

```bash
sudo ./scripts/install.sh --deps
```

### 手动构建

1. 安装DPDK及其依赖项

   Ubuntu/Debian:
   ```bash
   sudo apt-get update
   sudo apt-get install -y build-essential cmake pkg-config libnuma-dev
   sudo apt-get install -y dpdk dpdk-dev libdpdk-dev
   ```

   CentOS/RHEL/Fedora:
   ```bash
   sudo dnf install -y gcc gcc-c++ make cmake pkgconfig numactl-devel
   sudo dnf install -y dpdk dpdk-devel
   ```

2. 构建NetDefender

   ```bash
   ./scripts/build.sh
   ```

3. 安装（可选）

   ```bash
   sudo ./scripts/build.sh --install
   ```

### 构建选项

构建脚本支持多种选项：

```bash
./scripts/build.sh --help
```

常用选项：
- `--debug`: 构建Debug版本
- `--asan`: 启用地址消毒器
- `--clean`: 在构建前清理构建目录
- `--no-tests`: 不构建测试
- `--no-examples`: 不构建示例

## 使用方法

### 运行捕获示例

```bash
sudo ./build/examples/capture_demo -l 0-1 -n 4 -- -p 0
```

参数说明：
- `-l 0-1`: 使用CPU核心0和1
- `-n 4`: 使用4个内存通道
- `-p 0`: 使用端口0进行捕获

### 运行IDS示例

```bash
sudo ./build/examples/ids_demo -l 0-3 -n 4 -- rules/default.rules
```

## 项目结构

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

## 贡献指南

欢迎贡献代码、修复问题或添加新功能！请遵循以下步骤：

1. Fork项目
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m 'Add some amazing feature'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 创建Pull Request

## 许可证

本项目采用MIT许可证 - 详情请查看 [LICENSE](LICENSE) 文件 