cmake_minimum_required(VERSION 3.25)

include(cmake/DebianHardening.cmake)
include(cmake/RaspberryPiHardening.cmake)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)
FetchContent_Declare(drogon
 GIT_REPOSITORY https://github.com/drogonframework/drogon.git
 GIT_TAG        v1.9.10
)
FetchContent_Declare(fmt
 GIT_REPOSITORY https://github.com/fmtlib/fmt.git
 GIT_TAG        11.1.4
)
FetchContent_MakeAvailable(fmt)
set(BUILD_EXAMPLES OFF)
set(BUILD_CTL ON)
set(BUILD_ORM OFF)
set(BUILD_BROTLI OFF)
set(BUILD_YAML_CONFIG OFF)

# Store original flags
set(ORIGINAL_CXX_FLAGS ${CMAKE_CXX_FLAGS})
# Disable format-nonliteral warning only for Drogon, which is a third party library
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=format-nonliteral")
FetchContent_MakeAvailable(drogon)
# Restore original flags
set(CMAKE_CXX_FLAGS ${ORIGINAL_CXX_FLAGS})

unset(BUILD_YAML_CONFIG)
unset(BUILD_BROTLI)
unset(BUILD_ORM)
unset(BUILD_CTL)
unset(BUILD_EXAMPLES)

project(provisioner)

find_package(SQLite3 REQUIRED)
find_package(jsoncpp REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(systemd REQUIRED libsystemd)

# Define the views directory and output directory for compiled templates
set(VIEWS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src/views)
set(CSP_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/views_output)

# Create output directory
file(MAKE_DIRECTORY ${CSP_OUTPUT_DIR})

# Find all .csp files in the views directory
file(GLOB_RECURSE CSP_FILES ${VIEWS_DIR}/*.csp)

# Process each CSP file individually
set(VIEW_SOURCES "")
foreach(cspFile ${CSP_FILES})
  get_filename_component(cspFileName ${cspFile} NAME_WE)
  add_custom_command(
    OUTPUT ${CSP_OUTPUT_DIR}/${cspFileName}.h ${CSP_OUTPUT_DIR}/${cspFileName}.cc
    COMMAND $<TARGET_FILE:drogon_ctl> create view ${cspFile} -o ${CSP_OUTPUT_DIR}
    DEPENDS ${cspFile}
    COMMENT "Compiling CSP template: ${cspFileName}"
    VERBATIM
  )
  list(APPEND VIEW_SOURCES ${CSP_OUTPUT_DIR}/${cspFileName}.cc)
endforeach()

# Create a custom target for CSP compilation
add_custom_target(compile_views DEPENDS ${VIEW_SOURCES})

add_executable(provisioner)

# Add dependency on the compile_views target
add_dependencies(provisioner compile_views)

target_sources(provisioner
    PRIVATE
    src/main.cpp
    src/images.cpp
    src/options.cpp
    src/devices.cpp
    src/customisation.cpp
    src/services.cpp
    src/manufacturing.cpp
    ${VIEW_SOURCES}
)

target_include_directories(provisioner
    PRIVATE
    src/include
    ${SQLite3_INCLUDE_DIR}
    ${CSP_OUTPUT_DIR}  # Include the compiled templates
)

target_link_libraries(provisioner
    PRIVATE
    fmt
    ${jsoncpp_LIBRARY}
    drogon
    ${systemd_LIBRARIES}
    ${SQLite3_LIBRARY}
)

# Install directives
install(TARGETS provisioner
    RUNTIME DESTINATION /usr/bin
)

# Install systemd service file if it exists
if(EXISTS "${CMAKE_SOURCE_DIR}/debian/provisioner.service")
    install(FILES "${CMAKE_SOURCE_DIR}/debian/provisioner.service"
            DESTINATION /usr/lib/systemd/system
            PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
endif()