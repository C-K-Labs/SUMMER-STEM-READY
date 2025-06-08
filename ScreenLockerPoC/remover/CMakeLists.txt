cmake_minimum_required(VERSION 3.10)
project(Remover)

set(CMAKE_CXX_STANDARD 17)

if(MSVC)
    add_compile_options(/utf-8)
endif()

set(CMAKE_WIN32_EXECUTABLE TRUE)
add_definitions(-DUNICODE -D_UNICODE)

# create executable
add_executable(remover
    src/main.cpp
    src/remover.cpp
)

# add include directory
target_include_directories(remover PUBLIC include)

# add link library
target_link_libraries(remover 
    user32 
    kernel32
    shell32
    psapi
)