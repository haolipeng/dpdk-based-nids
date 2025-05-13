# C源文件 - DPDK核心功能和其他C模块
set(C_SRC_FILES
    main.c
    plugin_framework.c
    dpdk_capture.c
)

# C头文件
set(C_HEADER_FILES
    plugin_framework.h
    dpdk_capture.h
)

# 创建接口库，用于处理C和C++之间的交互
add_library(netdefender_core INTERFACE)
target_include_directories(netdefender_core INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${DPDK_INCLUDE_DIRS}
)

# 创建主程序可执行文件
add_executable(netdefender ${C_SRC_FILES})

# 设置包含目录
target_include_directories(netdefender PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/include
    ${DPDK_INCLUDE_DIRS}
)

# C模块使用的链接库
target_link_libraries(netdefender PRIVATE
    ${DPDK_LIBRARIES}
    -lnuma
    -lpthread
    -ldl
    -lm
    -lrt
)

# 添加链接器选项
set_target_properties(netdefender PROPERTIES
    LINK_FLAGS "-Wl,--no-as-needed"
)

# 安装可执行文件
install(TARGETS netdefender
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
) 