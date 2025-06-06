cmake_minimum_required(VERSION 3.10)
project(ScreenLockerPoC)

set(CMAKE_CXX_STANDARD 17)

if(MSVC)
    add_compile_options(/utf-8)
endif()

set(CMAKE_WIN32_EXECUTABLE TRUE)
add_definitions(-DUNICODE -D_UNICODE)

add_subdirectory(remover)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# app.manifest가 없는지 확인!
add_executable(ScreenLockerPoC
    src/main.cpp
    src/ScreenLocker.cpp
    resource.rc
)

add_dependencies(ScreenLockerPoC remover)

target_link_libraries(ScreenLockerPoC 
    user32 
    gdi32 
    iphlpapi 
    shell32 
    ole32 
    oleaut32 
    uuid 
    comctl32
    winhttp
)

# 링커에게 UAC 권한 수준을 직접 알려주어 충돌을 방지합니다.
target_link_options(ScreenLockerPoC PRIVATE "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")