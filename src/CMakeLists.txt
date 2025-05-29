# src目录CMakeLists.txt
# 使用根目录配置的DPDK变量

# 检查DPDK是否已配置
if(NOT DEFINED DPDK_INCLUDE_DIRS)
    message(FATAL_ERROR "DPDK configuration not found. Please ensure DPDK is properly configured in parent CMakeLists.txt")
endif()

# 源文件列表
set(SRC_FILES
    main.c
    global_data.c
    pidfile.c
    common.c
    scheduler.c
    netif.c
)

# 头文件列表
set(HEADER_FILES
    dpdk.h
    global_data.h
    pidfile.h
    common.h
    scheduler.h
    netif.h
)

# 创建可执行文件
add_executable(dpdk_nids ${SRC_FILES} ${HEADER_FILES})

# 设置包含目录 - 使用根目录配置的DPDK_INCLUDE_DIRS
target_include_directories(dpdk_nids PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${DPDK_INCLUDE_DIRS}
)

# 设置DPDK特定的编译选项
target_compile_options(dpdk_nids PRIVATE
    -march=native
    -DRTE_MACHINE_CPUFLAG_SSE
    -DRTE_MACHINE_CPUFLAG_SSE2
    -DRTE_MACHINE_CPUFLAG_SSE3
    -DRTE_MACHINE_CPUFLAG_SSSE3
    -DRTE_MACHINE_CPUFLAG_SSE4_1
    -DRTE_MACHINE_CPUFLAG_SSE4_2
)

# 链接库设置 - 使用根目录配置的DPDK_LIBRARY_DIRS（如果存在）
if(DEFINED DPDK_LIBRARY_DIRS)
    target_link_directories(dpdk_nids PRIVATE ${DPDK_LIBRARY_DIRS})
endif()

# 链接DPDK库和系统库
target_link_libraries(dpdk_nids PRIVATE
    # 使用根目录配置的DPDK库
    ${DPDK_LIBRARIES}
    
    # 系统依赖库
    numa
    pthread
    dl
    m
    rt
)

# 设置链接器选项
set_target_properties(dpdk_nids PROPERTIES
    LINK_FLAGS "-Wl,--no-as-needed -Wl,--export-dynamic"
)

# 安装目标
install(TARGETS dpdk_nids
    RUNTIME DESTINATION bin
)

# 安装头文件
install(FILES ${HEADER_FILES}
    DESTINATION include
) 