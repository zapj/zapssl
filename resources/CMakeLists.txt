# 生成包含 cacert.pem 内容的 C++ 源文件
cmake_minimum_required(VERSION 3.15)

# 读取 cacert.pem 文件内容
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/cacert.pem" CACERT_CONTENT)

# 将内容转换为十六进制字符串
string(HEX CACERT_CONTENT CACERT_HEX)

# 将十六进制字符串转换为 C++ 数组格式
string(LENGTH "${CACERT_HEX}" HEX_LENGTH)
math(EXPR BYTE_COUNT "${HEX_LENGTH} / 2")

set(CACERT_HEX_ARRAY "")
set(LINE "")
set(COUNT 0)

# 每16个字节一行，每个字节用0x前缀
foreach(IDX RANGE 0 ${BYTE_COUNT})
    if(NOT IDX EQUAL ${BYTE_COUNT})
        math(EXPR START "${IDX} * 2")
        string(SUBSTRING "${CACERT_HEX}" ${START} 2 BYTE)
        string(APPEND LINE "0x${BYTE},")
        math(EXPR COUNT "${COUNT} + 1")
        
        if(COUNT EQUAL 16)
            string(APPEND CACERT_HEX_ARRAY "${LINE}\n    ")
            set(LINE "")
            set(COUNT 0)
        endif()
    endif()
endforeach()

# 添加最后一行（如果有）
if(NOT "${LINE}" STREQUAL "")
    string(APPEND CACERT_HEX_ARRAY "${LINE}\n    ")
endif()

# 创建 C++ 源文件
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cacert_resource.cpp.in"
    "${CMAKE_CURRENT_BINARY_DIR}/cacert_resource.cpp"
    @ONLY
)

# 添加生成的源文件到库
add_library(resources STATIC "${CMAKE_CURRENT_BINARY_DIR}/cacert_resource.cpp")

# 添加MSVC静态运行时库设置
if(MSVC)
    target_compile_options(resources PRIVATE
        $<$<CONFIG:>:/MT> #---------|
        $<$<CONFIG:Debug>:/MTd> #---|-- Statically link the runtime libraries
        $<$<CONFIG:Release>:/MT> #--|
    )
endif()

# 添加包含目录，以便其他目标可以包含生成的头文件
target_include_directories(resources PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
