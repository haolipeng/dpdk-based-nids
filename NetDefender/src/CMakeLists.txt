add_subdirectory(core)
add_subdirectory(common)
add_subdirectory(detection)
add_subdirectory(analysis)

# 创建主库
add_library(netdefender INTERFACE)
target_link_libraries(netdefender
    INTERFACE
        netdefender_core
        netdefender_common
        netdefender_detection
        netdefender_analysis
)

# 安装配置
install(TARGETS netdefender
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
) 