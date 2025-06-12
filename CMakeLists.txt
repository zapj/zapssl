cmake_minimum_required(VERSION 3.15)


# Enable vcpkg integration
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
            CACHE STRING "")
endif()

set(VCPKG_TARGET_TRIPLET x64-windows-static)

project(zapssl)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(
            -DUNICODE -D_UNICODE
            -DwxUSE_UNICODE
            -D__ZAPDEBUG__
    )
elseif (CMAKE_BUILD_TYPE STREQUAL "Release")
    add_definitions(
            -DUNICODE -D_UNICODE
            -DwxUSE_UNICODE
    )
endif()

# 设置资源文件的路径
set(RESOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/resources")

# 添加子目录来处理资源文件
add_subdirectory(resources)

# Find required packages
find_package(wxWidgets CONFIG REQUIRED COMPONENTS core base)
find_package(OpenSSL REQUIRED)

# Add wxWidgets definitions
add_definitions(${wxWidgets_DEFINITIONS})


if(MSVC)
    add_definitions(
            -D__WXMSW__
            -DwxUSE_DPI_AWARE_MANIFEST
    )


    #静态编译
    add_compile_options(
            $<$<CONFIG:>:/MT> #---------|
            $<$<CONFIG:Debug>:/MTd> #---|-- Statically link the runtime libraries
            $<$<CONFIG:Release>:/MT> #--|
    )

endif()


# Source files
set(SOURCE_FILES
    main.cpp
    main_frame.cpp
    ssl_checker.cpp
    logger.cpp
)

# Header files
set(HEADER_FILES
    main_frame.h
    ssl_checker.h
    logger.h
)

# Add executable

if(WIN32)
    add_executable(${PROJECT_NAME} WIN32 ${SOURCE_FILES} ${HEADER_FILES} resources.rc)
else()
    add_executable(${PROJECT_NAME} WIN32 ${SOURCE_FILES} ${HEADER_FILES})
endif()


# Link libraries
target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
    ${wxWidgets_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    resources
)

# Platform specific libraries
if(WIN32)
    target_link_libraries(${PROJECT_NAME} 
        PRIVATE 
        Crypt32
        Cryptui
    )
elseif(APPLE)
    # macOS specific libraries if needed
    # target_link_libraries(${PROJECT_NAME} PRIVATE ...)
elseif(UNIX AND NOT APPLE)
    # Linux specific libraries if needed
    # target_link_libraries(${PROJECT_NAME} PRIVATE ...)
endif()

# Add compiler definitions for Windows
if(WIN32)
    target_compile_definitions(${PROJECT_NAME} 
        PRIVATE 
        WXUSINGDLL
        _UNICODE
        UNICODE
    )
endif()

# Installation
install(TARGETS ${PROJECT_NAME}
    RUNTIME DESTINATION bin
)
