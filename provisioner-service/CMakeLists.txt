cmake_minimum_required(VERSION 3.25)

if (CMAKE_BUILD_TYPE STREQUAL "Release")
    include(cmake/DebianHardening.cmake)
    include(cmake/RaspberryPiHardening.cmake)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# Prevent installation of Drogon dependencies by setting BUILD_* options before declaring the dependency
set(BUILD_EXAMPLES OFF CACHE BOOL "Build Drogon examples" FORCE)
set(BUILD_CTL ON CACHE BOOL "Build drogon_ctl utility" FORCE)  # Needed for compiling CSP templates
set(BUILD_ORM OFF CACHE BOOL "Build ORM" FORCE)
set(BUILD_BROTLI OFF CACHE BOOL "Build brotli support" FORCE)
set(BUILD_YAML_CONFIG OFF CACHE BOOL "Build yaml config support" FORCE)
# Set this before making Drogon available to ensure it doesn't get installed
set(CMAKE_SKIP_INSTALL_ALL_DEPENDENCY ON CACHE BOOL "Skip installation of all dependencies" FORCE)

FetchContent_Declare(drogon
 GIT_REPOSITORY https://github.com/drogonframework/drogon.git
 GIT_TAG        v1.9.10
 EXCLUDE_FROM_ALL  # Prevents installation in packages
)

# Store original flags
set(ORIGINAL_CXX_FLAGS ${CMAKE_CXX_FLAGS})
# Disable format-nonliteral warning only for Drogon, which is a third party library
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-error=format-nonliteral")

# Check if population has already been performed
FetchContent_GetProperties(drogon)
string(TOLOWER "drogon" lcName)
if(NOT ${lcName}_POPULATED)
  # Fetch the content using previously declared details
  FetchContent_Populate(drogon)

  # Set custom variables, policies, etc.
  # ...

  # Bring the populated content into the build
  add_subdirectory(${${lcName}_SOURCE_DIR} ${${lcName}_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()
# Restore original flags
set(CMAKE_CXX_FLAGS ${ORIGINAL_CXX_FLAGS})

unset(BUILD_YAML_CONFIG)
unset(BUILD_BROTLI)
unset(BUILD_ORM)
unset(BUILD_CTL)
unset(BUILD_EXAMPLES)

project(rpi-provisioner-ui)

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

add_executable(rpi-provisioner-ui)

# Add dependency on the compile_views target
add_dependencies(rpi-provisioner-ui compile_views)

target_sources(rpi-provisioner-ui
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

target_include_directories(rpi-provisioner-ui
    PRIVATE
    src/include
    ${SQLite3_INCLUDE_DIR}
    ${CSP_OUTPUT_DIR}  # Include the compiled templates
)

target_link_libraries(rpi-provisioner-ui
    PRIVATE
    ${jsoncpp_LIBRARY}
    drogon
    ${systemd_LIBRARIES}
    ${SQLite3_LIBRARY}
)

# Install directives
# Only install our executable and service file, not any of the FetchContent dependencies
install(TARGETS rpi-provisioner-ui
    RUNTIME DESTINATION /usr/bin
)

# Install systemd service file if it exists
if(EXISTS "${CMAKE_SOURCE_DIR}/rpi-provisioner-ui.service")
    install(FILES "${CMAKE_SOURCE_DIR}/rpi-provisioner-ui.service"
            DESTINATION /usr/lib/systemd/system
            PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)
endif()