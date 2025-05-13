cmake_minimum_required(VERSION 3.12)
project(NetDefender VERSION 1.0.0 LANGUAGES C CXX)

# 设置C++标准 - 提高到C++11以更好地处理现代特性
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 设置C标准
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)

# 编译选项
option(BUILD_TESTS "Build test cases" OFF)
option(BUILD_EXAMPLES "Build examples" OFF)
option(ENABLE_ASAN "Enable address sanitizer" OFF)

# 项目架构选项
option(ENABLE_CPP_MODULES "Enable C++ implementation for specified modules" OFF)

# 支持C和C++之间的相互调用
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# 尝试查找DPDK库
# 首先尝试使用CMake的find_package
find_package(DPDK QUIET)

# 如果没找到，使用pkg-config尝试查找
if(NOT DPDK_FOUND)
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(DPDK libdpdk QUIET)
    endif()
endif()

# 如果仍然没找到，使用默认路径
if(NOT DPDK_FOUND AND NOT DPDK_INCLUDE_DIRS)
    message(STATUS "DPDK not found via find_package or pkg-config, using default path")
    set(DPDK_DIR "/home/work/dpdk-stable-24.11.1/dpdklib")
    set(DPDK_INCLUDE_DIRS "${DPDK_DIR}/include")
    set(DPDK_LIBRARY_DIRS "${DPDK_DIR}/lib")
    
    # 设置DPDK库列表
    set(DPDK_LIBRARIES 
        "-L${DPDK_LIBRARY_DIRS}" 
        "-Wl,--whole-archive" 
        "-ldpdk" 
        "-Wl,--no-whole-archive"
    )
    
    # 将DPDK库目录添加到链接器路径
    link_directories(${DPDK_LIBRARY_DIRS})
else()
    message(STATUS "DPDK found: ${DPDK_INCLUDE_DIRS}")
endif()

# 设置通用编译选项
add_compile_options(
    -Wall
    -Wextra
    -Werror
    -O2
)

# 特定语言的编译选项
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

if(ENABLE_ASAN)
    add_compile_options(-fsanitize=address)
    add_link_options(-fsanitize=address)
endif()

# 添加子目录
add_subdirectory(src)
add_subdirectory(third_party)

if(BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# 安装配置
include(GNUInstallDirs)
install(DIRECTORY include/
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
) 