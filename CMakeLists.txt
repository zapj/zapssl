cmake_minimum_required(VERSION 3.15)


# Enable vcpkg integration
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE "$ENV{VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
            CACHE STRING "")
endif()
set(VCPKG_TARGET_TRIPLET x64-mingw-dynamic)

project(zapssl)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


# Find required packages
find_package(wxWidgets CONFIG REQUIRED COMPONENTS core base)
find_package(OpenSSL REQUIRED)

# Add wxWidgets definitions
add_definitions(${wxWidgets_DEFINITIONS})

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
        cacert.h
)

# Add executable
add_executable(${PROJECT_NAME} WIN32 ${SOURCE_FILES} ${HEADER_FILES})

# Link libraries
target_link_libraries(${PROJECT_NAME} 
    PRIVATE 
    ${wxWidgets_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    Crypt32
    Cryptui
)

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
