add_library(netdefender_detection
    src/ids_engine.cpp
    src/pattern_matcher.cpp
)

target_include_directories(netdefender_detection
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(netdefender_detection
    PUBLIC
        netdefender_core
)

# 安装配置
install(TARGETS netdefender_detection
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
) 