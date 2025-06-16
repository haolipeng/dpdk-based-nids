# 示例程序构建配置

# 设置示例程序的编译选项
set(EXAMPLE_COMPILE_OPTIONS
    -Wall
    -Wextra
    -Wno-unused-variable
    -Wno-unused-function
)

# C示例
add_executable(capture_demo
    capture_demo.c
)

target_compile_options(capture_demo PRIVATE ${EXAMPLE_COMPILE_OPTIONS})
target_link_libraries(capture_demo
    PRIVATE
        netdefender_core
)

# C++示例
add_executable(ids_demo
    ids_demo.cpp
)

target_compile_options(ids_demo PRIVATE ${EXAMPLE_COMPILE_OPTIONS})
target_link_libraries(ids_demo
    PRIVATE
        netdefender
)

# 安装编译后的可执行文件到指定目录
install(TARGETS capture_demo ids_demo
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}/examples
) 