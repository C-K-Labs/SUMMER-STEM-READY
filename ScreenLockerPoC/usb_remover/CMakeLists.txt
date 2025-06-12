# ScreenLockerPoC/usb_remover/CMakeLists.txt

cmake_minimum_required(VERSION 3.10)
project(UsbRemover)

set(CMAKE_CXX_STANDARD 17)
if(MSVC)
    add_compile_options(/utf-8)
endif()

set(CMAKE_WIN32_EXECUTABLE TRUE)
add_definitions(-DUNICODE -D_UNICODE)

# Create executable file with only main.cpp
add_executable(usb_remover
    src/main.cpp
)

# Link remover_lib library
target_link_libraries(usb_remover PRIVATE remover_lib)