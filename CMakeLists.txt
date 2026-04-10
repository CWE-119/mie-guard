cmake_minimum_required(VERSION 3.16)
project(mei-guard C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# ------------------------------------------------------------------ #
#  Hardening flags                                                     #
# ------------------------------------------------------------------ #
if (UNIX)
    add_compile_options(
        -Wall -Wextra -Wpedantic -Wformat=2
        -fstack-protector-strong
        -D_FORTIFY_SOURCE=2
        -fPIE
    )
    add_link_options(-pie -Wl,-z,relro,-z,now)
endif()

if (MSVC)
    add_compile_options(/W4 /WX /GS /sdl)
endif()

# ------------------------------------------------------------------ #
#  Platform detection                                                  #
# ------------------------------------------------------------------ #
if (WIN32)
    add_definitions(-DPLAT_WINDOWS=1)
else()
    add_definitions(-DPLAT_LINUX=1)
endif()

# ------------------------------------------------------------------ #
#  Sources                                                             #
# ------------------------------------------------------------------ #
set(PLATFORM_SRC)
if (WIN32)
    list(APPEND PLATFORM_SRC src/platform/windows.c)
else()
    list(APPEND PLATFORM_SRC src/platform/linux.c)
endif()

set(CHECK_SRCS
    src/checks/heci_monitor.c
    src/checks/microcode_verifier.c
    src/checks/mei_status.c
    src/checks/dmi_latency.c
)

add_executable(mei-guard
    src/main.c
    ${PLATFORM_SRC}
    ${CHECK_SRCS}
)

target_include_directories(mei-guard PRIVATE src)

# ------------------------------------------------------------------ #
#  Link libraries                                                      #
# ------------------------------------------------------------------ #
if (UNIX)
    find_library(MATH_LIB m REQUIRED)
    target_link_libraries(mei-guard PRIVATE
        ${MATH_LIB}
        pthread
    )
endif()

if (WIN32)
    target_link_libraries(mei-guard PRIVATE
        setupapi.lib cfgmgr32.lib
    )
endif()

# ------------------------------------------------------------------ #
#  Install                                                             #
# ------------------------------------------------------------------ #
include(GNUInstallDirs)
install(TARGETS mei-guard DESTINATION ${CMAKE_INSTALL_BINDIR})
install(FILES config/notify.json.example
        DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/mei-guard
        RENAME notify.json.example)

# ------------------------------------------------------------------ #
#  Tests                                                               #
# ------------------------------------------------------------------ #
enable_testing()
add_subdirectory(tests)