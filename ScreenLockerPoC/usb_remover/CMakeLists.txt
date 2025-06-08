cmake_minimum_required(VERSION 3.10)
project(UsbRemover)

set(CMAKE_CXX_STANDARD 17)

if(MSVC)
    add_compile_options(/utf-8)
endif()

set(CMAKE_WIN32_EXECUTABLE TRUE)
add_definitions(-DUNICODE -D_UNICODE)

add_executable(usb_remover
    src/main.cpp
    src/remover.cpp
)

target_include_directories(usb_remover PUBLIC include)

target_link_libraries(usb_remover 
    user32 
    kernel32
    shell32
    psapi
)