add_library(netdefender_core
    src/packet_capture.c
    src/ring_buffer.c
    src/dpdk_init.c
)

target_include_directories(netdefender_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${DPDK_INCLUDE_DIRS}
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(netdefender_core
    PUBLIC
        ${DPDK_LIBRARIES}
)

# 安装配置
install(TARGETS netdefender_core
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
) 