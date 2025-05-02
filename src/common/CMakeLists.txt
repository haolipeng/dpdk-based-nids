add_library(netdefender_common
    src/logger.cpp
    src/config_manager.cpp
    src/utilities.cpp
)

target_include_directories(netdefender_common
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# 安装配置
install(TARGETS netdefender_common
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
) 