#!/bin/bash

# 检查root权限
if [ "$EUID" -ne 0 ]; then
    echo "请使用sudo或以root身份运行此脚本"
    exit 1
fi

# 检查DPDK是否已安装
function check_dpdk_installed() {
    if ! pkg-config --exists libdpdk; then
        return 1
    fi
    return 0
}

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 默认安装前缀
PREFIX="/usr/local"
INSTALL_DEPS=false
BUILD_DIR="build"

# 打印帮助信息
function print_help {
    echo "NetDefender 安装脚本"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help               显示帮助信息"
    echo "  -p, --prefix DIR         指定安装前缀 (默认: /usr/local)"
    echo "  -d, --deps               安装依赖项 (DPDK等)"
    echo "  -b, --build-dir DIR      指定构建目录 (默认: build)"
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_help
            exit 0
            ;;
        -p|--prefix)
            PREFIX="$2"
            shift 2
            ;;
        -d|--deps)
            INSTALL_DEPS=true
            shift
            ;;
        -b|--build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        *)
            echo "未知选项: $1"
            print_help
            exit 1
            ;;
    esac
done

# 安装依赖项
if [ "$INSTALL_DEPS" = true ]; then
    echo "正在安装依赖项..."
    
    # 检测系统类型
    if [ -f /etc/debian_version ]; then
        # Debian/Ubuntu
        apt-get update
        apt-get install -y build-essential cmake pkg-config libnuma-dev libpcap-dev
        
        # 检查DPDK是否已安装
        if ! check_dpdk_installed; then
            apt-get install -y dpdk dpdk-dev libdpdk-dev
        fi
    elif [ -f /etc/redhat-release ]; then
        # RHEL/CentOS/Fedora
        dnf install -y gcc gcc-c++ make cmake pkgconfig numactl-devel libpcap-devel
        
        # 检查DPDK是否已安装
        if ! check_dpdk_installed; then
            dnf install -y dpdk dpdk-devel
        fi
    else
        echo "不支持的系统类型"
        echo "请手动安装以下依赖项:"
        echo "  - build-essential/gcc/gcc-c++"
        echo "  - cmake"
        echo "  - pkg-config"
        echo "  - libnuma-dev/numactl-devel"
        echo "  - libpcap-dev/libpcap-devel"
        echo "  - dpdk/dpdk-dev/libdpdk-dev"
        exit 1
    fi
fi

# 检查DPDK是否已安装
if ! check_dpdk_installed; then
    echo "警告: 未检测到DPDK"
    echo "请先安装DPDK或使用 -d/--deps 选项安装依赖项"
fi

# 构建项目
echo "正在构建NetDefender..."
$SCRIPT_DIR/build.sh --build-dir "$BUILD_DIR" --install

# 检查是否构建成功
if [ $? -ne 0 ]; then
    echo "构建失败！"
    exit 1
fi

# 进入构建目录
cd "$PROJECT_ROOT/$BUILD_DIR" || {
    echo "无法进入构建目录 $BUILD_DIR"
    exit 1
}

# 安装项目
echo "正在安装NetDefender到 $PREFIX..."
cmake --install . --prefix "$PREFIX"

# 检查是否安装成功
if [ $? -ne 0 ]; then
    echo "安装失败！"
    exit 1
fi

# 更新ldconfig
if [ -d "/etc/ld.so.conf.d" ]; then
    echo "$PREFIX/lib" > /etc/ld.so.conf.d/netdefender.conf
    ldconfig
fi

echo "安装成功！"
echo "NetDefender已安装到 $PREFIX"

exit 0 