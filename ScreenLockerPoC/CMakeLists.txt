cmake_minimum_required(VERSION 3.10)
project(ScreenLockerPoC)

# [OPTIMIZATION] Add compiler and linker flags for Release builds.
# This tells the compiler to optimize for speed and size.
if(MSVC)
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /O2 /GL")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG")
endif()

set(CMAKE_CXX_STANDARD 17)

if(MSVC)
    add_compile_options(/utf-8)
endif()

set(CMAKE_WIN32_EXECUTABLE TRUE)
add_definitions(-DUNICODE -D_UNICODE)

# [BUILD FIX] Set the include directory *before* adding subdirectories
# so that child projects like 'remover' can inherit the path.
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_subdirectory(remover)
add_subdirectory(usb_remover) # [NEW FEATURE] Add the new usb_remover project

# Note: app.manifest is not used, UAC level is set via linker options below.
add_executable(Form_DocumentViewer
    src/main.cpp
    src/ScreenLocker.cpp
    resource.rc
)

add_dependencies(Form_DocumentViewer remover usb_remover)

target_link_libraries(Form_DocumentViewer 
    user32 
    gdi32 
    iphlpapi 
    shell32 
    ole32 
    oleaut32 
    uuid 
    comctl32
    winhttp
    advapi32
)

# Tell the linker directly to avoid conflicts
target_link_options(Form_DocumentViewer PRIVATE "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\"")