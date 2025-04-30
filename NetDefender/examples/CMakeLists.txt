# C示例
add_executable(capture_demo
    capture_demo.c
)

target_link_libraries(capture_demo
    PRIVATE
        netdefender_core
)

# C++示例
add_executable(ids_demo
    ids_demo.cpp
)

target_link_libraries(ids_demo
    PRIVATE
        netdefender
)

# 安装配置
install(TARGETS capture_demo ids_demo
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/examples
) 