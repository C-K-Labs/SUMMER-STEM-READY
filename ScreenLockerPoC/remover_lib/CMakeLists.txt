# ScreenLockerPoC/remover_lib/CMakeLists.txt

cmake_minimum_required(VERSION 3.10)
project(RemoverLib)

set(CMAKE_CXX_STANDARD 17)

# Add static library target
add_library(remover_lib STATIC
    src/remover.cpp
)

# Set include directories for the library
target_include_directories(remover_lib PUBLIC
    include
    # Add ScreenLockerPoC/include folder (StringUtils.h, Constants.h)
    ${CMAKE_SOURCE_DIR}/include
)

# Link Windows libraries used by the library
target_link_libraries(remover_lib PUBLIC
    user32
    kernel32
    shell32
    psapi
)