#!/bin/bash

# 检查cmake是否安装
if ! command -v cmake &> /dev/null; then
    echo "Error: cmake could not be found"
    echo "Please install cmake first"
    exit 1
fi

# 默认参数
BUILD_TYPE="Release"
BUILD_DIR="build"
ENABLE_ASAN=OFF
BUILD_TESTS=ON
BUILD_EXAMPLES=ON
INSTALL=false
CLEAN=false
JOBS=$(nproc)
CMAKE_EXTRA_ARGS=""

# 打印帮助信息
function print_help {
    echo "NetDefender Build Script"
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  -h, --help               显示帮助信息"
    echo "  -d, --debug              使用Debug构建类型 (默认: Release)"
    echo "  -b, --build-dir DIR      指定构建目录 (默认: build)"
    echo "  -a, --asan               启用地址消毒器 (Address Sanitizer)"
    echo "  -t, --no-tests           禁用测试构建"
    echo "  -e, --no-examples        禁用示例构建"
    echo "  -i, --install            构建后安装"
    echo "  -c, --clean              清理构建目录"
    echo "  -j, --jobs N             并行构建任务数 (默认: 系统核心数)"
}

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            print_help
            exit 0
            ;;
        -d|--debug)
            BUILD_TYPE="Debug"
            shift
            ;;
        -b|--build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        -a|--asan)
            ENABLE_ASAN=ON
            shift
            ;;
        -t|--no-tests)
            BUILD_TESTS=OFF
            shift
            ;;
        -e|--no-examples)
            BUILD_EXAMPLES=OFF
            shift
            ;;
        -i|--install)
            INSTALL=true
            shift
            ;;
        -c|--clean)
            CLEAN=true
            shift
            ;;
        -j|--jobs)
            JOBS="$2"
            shift 2
            ;;
        --)
            shift
            CMAKE_EXTRA_ARGS="$@"
            break
            ;;
        *)
            echo "未知选项: $1"
            print_help
            exit 1
            ;;
    esac
done

# 获取脚本所在目录
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# 如果启用了清理，则删除构建目录
if [ "$CLEAN" = true ]; then
    echo "正在清理构建目录 $BUILD_DIR..."
    rm -rf "$PROJECT_ROOT/$BUILD_DIR"
fi

# 创建构建目录
mkdir -p "$PROJECT_ROOT/$BUILD_DIR"

# 进入构建目录
cd "$PROJECT_ROOT/$BUILD_DIR" || {
    echo "无法进入构建目录 $BUILD_DIR"
    exit 1
}

# 运行 CMake 配置
echo "正在配置 NetDefender 项目..."
cmake "$PROJECT_ROOT" \
    -DCMAKE_BUILD_TYPE="$BUILD_TYPE" \
    -DENABLE_ASAN="$ENABLE_ASAN" \
    -DBUILD_TESTS="$BUILD_TESTS" \
    -DBUILD_EXAMPLES="$BUILD_EXAMPLES" \
    $CMAKE_EXTRA_ARGS

# 检查配置是否成功
if [ $? -ne 0 ]; then
    echo "CMake 配置失败！"
    exit 1
fi

# 编译项目
echo "正在构建 NetDefender (类型: $BUILD_TYPE, 并行任务: $JOBS)..."
cmake --build . --config "$BUILD_TYPE" -j "$JOBS"

# 检查构建是否成功
if [ $? -ne 0 ]; then
    echo "构建失败！"
    exit 1
fi

echo "构建成功！"

# 如果启用了安装
if [ "$INSTALL" = true ]; then
    echo "正在安装 NetDefender..."
    cmake --install .

    if [ $? -ne 0 ]; then
        echo "安装失败！"
        exit 1
    fi

    echo "安装成功！"
fi

# 如果构建了测试
if [ "$BUILD_TESTS" = "ON" ]; then
    echo "可以使用以下命令运行测试:"
    echo "  cd $BUILD_DIR && ctest -V"
fi

# 如果构建了示例
if [ "$BUILD_EXAMPLES" = "ON" ]; then
    echo "示例程序位于: $BUILD_DIR/examples/"
fi

exit 0 