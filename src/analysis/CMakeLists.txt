add_library(netdefender_analysis
    src/traffic_analyzer.cpp
    src/anomaly_detector.cpp
)

target_include_directories(netdefender_analysis
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(netdefender_analysis
    PUBLIC
        netdefender_core
        netdefender_detection
)

# 安装配置
install(TARGETS netdefender_analysis
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
) 