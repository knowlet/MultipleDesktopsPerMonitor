cmake_minimum_required(VERSION 3.24)

project(per-monitor-vd
        VERSION 0.1.0
        DESCRIPTION "Read-only feasibility probe for native per-monitor virtual desktops on Windows 11"
        LANGUAGES CXX)

if(NOT WIN32)
    message(FATAL_ERROR "per-monitor-vd is Windows-only.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

add_executable(vdprobe
        src/main.cpp
        src/util.cpp
        src/comraw.cpp
        src/vdids.cpp
        src/vdlayout.cpp
        src/phase1.cpp
        src/phase2.cpp
        src/workspace_engine.cpp
        src/window_discovery.cpp
        src/workspace_assignment.cpp
        src/window_lifecycle.cpp
        src/workspace_coordinator.cpp
        src/workspace_startup.cpp
        src/workspace_readonly_host.cpp
        src/workspace_live_lifecycle.cpp
        src/workspace_live_focus.cpp
        src/workspace_manager.cpp
        src/workspace_host_resilience.cpp
        src/workspace_stress.cpp
        src/notifysink.cpp
)

target_include_directories(vdprobe PRIVATE src)

target_compile_definitions(vdprobe PRIVATE
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
        _WIN32_WINNT=0x0A00
        WINVER=0x0A00
)

# Only libraries whose imports are statically bound are listed here.  Anything
# that may be absent on some SKU (shcore, combase) is bound lazily at runtime so
# that vdprobe never fails to start on a machine that lacks it.
target_link_libraries(vdprobe PRIVATE
        ole32
        oleaut32
        uuid
        user32
        gdi32
        shell32
        shlwapi
        version
        advapi32
)

if(MSVC)
    target_compile_options(vdprobe PRIVATE /W4 /permissive- /utf-8 /EHsc)
else()
    target_compile_options(vdprobe PRIVATE -Wall -Wextra -Wno-unknown-pragmas
            # GetProcAddress necessarily casts FARPROC to a typed function
            # pointer; the casts are checked by hand against the SDK signatures.
            -Wno-cast-function-type)
    # A self-contained exe is convenient for a probe that gets copied around,
    # and avoids a libwinpthread-1.dll runtime dependency.
    target_link_options(vdprobe PRIVATE -static)
endif()

install(TARGETS vdprobe RUNTIME DESTINATION bin)
