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
  FetchContent_Populate(drogon)
  add_subdirectory(${${lcName}_SOURCE_DIR} ${${lcName}_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()
# Restore original flags
set(CMAKE_CXX_FLAGS ${ORIGINAL_CXX_FLAGS})

unset(BUILD_YAML_CONFIG)
unset(BUILD_BROTLI)
unset(BUILD_ORM)
unset(BUILD_CTL)
unset(BUILD_EXAMPLES)

# Add libcurl with minimal configuration
set(BUILD_CURL_EXE OFF CACHE BOOL "Set to ON to build curl executable." FORCE)
set(HTTP_ONLY ON CACHE BOOL "Set to ON to build with HTTP support only." FORCE)
set(BUILD_TESTING OFF CACHE BOOL "Set to ON to build libcurl tests." FORCE)
set(ENABLE_MANUAL OFF CACHE BOOL "Set to ON to enable manual." FORCE)
set(CURL_USE_OPENSSL ON CACHE BOOL "Set to ON to use OpenSSL for HTTPS." FORCE)
set(BUILD_SHARED_LIBS OFF CACHE BOOL "Set to OFF to build static libraries." FORCE)
# Disable all protocols except HTTP(S)
set(CURL_DISABLE_DICT ON CACHE BOOL "Set to ON to disable DICT." FORCE)
set(CURL_DISABLE_FILE ON CACHE BOOL "Set to ON to disable FILE." FORCE)
set(CURL_DISABLE_FTP ON CACHE BOOL "Set to ON to disable FTP." FORCE)
set(CURL_DISABLE_GOPHER ON CACHE BOOL "Set to ON to disable GOPHER." FORCE)
set(CURL_DISABLE_IMAP ON CACHE BOOL "Set to ON to disable IMAP." FORCE)
set(CURL_DISABLE_LDAP ON CACHE BOOL "Set to ON to disable LDAP." FORCE)
set(CURL_DISABLE_LDAPS ON CACHE BOOL "Set to ON to disable LDAPS." FORCE)
set(CURL_DISABLE_POP3 ON CACHE BOOL "Set to ON to disable POP3." FORCE)
set(CURL_DISABLE_RTSP ON CACHE BOOL "Set to ON to disable RTSP." FORCE)
set(CURL_DISABLE_SMB ON CACHE BOOL "Set to ON to disable SMB." FORCE)
set(CURL_DISABLE_SMTP ON CACHE BOOL "Set to ON to disable SMTP." FORCE)
set(CURL_DISABLE_TELNET ON CACHE BOOL "Set to ON to disable TELNET." FORCE)
set(CURL_DISABLE_TFTP ON CACHE BOOL "Set to ON to disable TFTP." FORCE)
# Disable libidn2 and libpsl
set(USE_LIBIDN2 OFF CACHE BOOL "Set to OFF to disable libidn2." FORCE)
set(CURL_USE_LIBPSL OFF CACHE BOOL "Set to OFF to disable libpsl." FORCE)
# Disable SSH2
set(CURL_USE_LIBSSH2 OFF CACHE BOOL "Set to OFF to disable libssh2." FORCE)
# Disable additional features
set(CURL_DISABLE_ALTSVC ON CACHE BOOL "Set to ON to disable alt-svc support." FORCE)
set(ENABLE_UNIX_SOCKETS OFF CACHE BOOL "Set to OFF to disable Unix domain sockets." FORCE)
set(CURL_DISABLE_COOKIES ON CACHE BOOL "Set to ON to disable cookies support." FORCE)
set(CURL_DISABLE_HSTS ON CACHE BOOL "Set to ON to disable HSTS support." FORCE)
set(CURL_DISABLE_DOH ON CACHE BOOL "Set to ON to disable DNS-over-HTTPS." FORCE)
set(CURL_DISABLE_WEBSOCKETS ON CACHE BOOL "Set to ON to disable WebSocket." FORCE)
set(CURL_DISABLE_PROXY ON CACHE BOOL "Set to ON to disable proxy support." FORCE)
set(CURL_DISABLE_GETOPTIONS ON CACHE BOOL "Set to ON to disable curl_easy_options API." FORCE)
set(CURL_DISABLE_HEADERS_API ON CACHE BOOL "Set to ON to disable headers-api support." FORCE)
set(CURL_DISABLE_SOCKETPAIR ON CACHE BOOL "Set to ON to disable use of socketpair." FORCE)
# Disable authentication methods (we only need simple HTTPS requests)
# BUG: Authentication provicers are required to build curl, due to a bug in the curl code
set(CURL_DISABLE_BASIC_AUTH ON CACHE BOOL "Set to ON to disable Basic authentication." FORCE)
set(CURL_DISABLE_BEARER_AUTH ON CACHE BOOL "Set to ON to disable Bearer authentication." FORCE)
set(CURL_DISABLE_DIGEST_AUTH ON CACHE BOOL "Set to ON to disable Digest authentication." FORCE)
set(CURL_DISABLE_KERBEROS_AUTH ON CACHE BOOL "Set to ON to disable Kerberos authentication." FORCE)
set(CURL_DISABLE_NEGOTIATE_AUTH ON CACHE BOOL "Set to ON to disable negotiate authentication." FORCE)
set(CURL_DISABLE_AWS ON CACHE BOOL "Set to ON to disable aws-sigv4." FORCE)
set(CURL_DISABLE_NTLM ON CACHE BOOL "Set to ON to disable NTLM support." FORCE)

FetchContent_Declare(curl
 GIT_REPOSITORY https://github.com/curl/curl.git
 GIT_TAG        curl-8_13_0
 PATCH_COMMAND patch -p1 < ${CMAKE_SOURCE_DIR}/cmake/curl/http-no-auth.patch
 UPDATE_DISCONNECTED 1
 EXCLUDE_FROM_ALL  # Prevents installation in packages
)

FetchContent_GetProperties(curl)
string(TOLOWER "curl" curlName)
if(NOT ${curlName}_POPULATED)
  FetchContent_Populate(curl)
  add_subdirectory(${${curlName}_SOURCE_DIR} ${${curlName}_BINARY_DIR} EXCLUDE_FROM_ALL)
endif()

# Unset curl configuration flags
unset(BUILD_CURL_EXE)
unset(HTTP_ONLY)
unset(BUILD_TESTING)
unset(ENABLE_MANUAL)
unset(CURL_USE_OPENSSL)
unset(BUILD_SHARED_LIBS)
unset(CURL_DISABLE_DICT)
unset(CURL_DISABLE_FILE)
unset(CURL_DISABLE_FTP)
unset(CURL_DISABLE_GOPHER)
unset(CURL_DISABLE_IMAP)
unset(CURL_DISABLE_LDAP)
unset(CURL_DISABLE_LDAPS)
unset(CURL_DISABLE_POP3)
unset(CURL_DISABLE_RTSP)
unset(CURL_DISABLE_SMB)
unset(CURL_DISABLE_SMTP)
unset(CURL_DISABLE_TELNET)
unset(CURL_DISABLE_TFTP)
unset(USE_LIBIDN2)
unset(CURL_USE_LIBPSL)
unset(CURL_USE_LIBSSH2)
unset(CURL_DISABLE_ALTSVC)
unset(ENABLE_UNIX_SOCKETS)
unset(CURL_DISABLE_COOKIES)
unset(CURL_DISABLE_HSTS)
unset(CURL_DISABLE_DOH)
unset(CURL_DISABLE_WEBSOCKETS)
unset(CURL_DISABLE_PROXY)
unset(CURL_DISABLE_GETOPTIONS)
unset(CURL_DISABLE_HEADERS_API)
unset(CURL_DISABLE_SOCKETPAIR)
# unset(CURL_DISABLE_BASIC_AUTH)
# unset(CURL_DISABLE_BEARER_AUTH)
# unset(CURL_DISABLE_DIGEST_AUTH)
# unset(CURL_DISABLE_KERBEROS_AUTH)
# unset(CURL_DISABLE_NEGOTIATE_AUTH)
# unset(CURL_DISABLE_AWS)
# unset(CURL_DISABLE_NTLM)

# Download the ZXing library for barcode scanning
set(ZXING_JS_URL "https://cdn.jsdelivr.net/npm/@zxing/library/umd/index.min.js")
set(ZXING_JS_PATH "${CMAKE_SOURCE_DIR}/static/js/zxing.js")

# Add a custom command to download the ZXing library at build time
add_custom_command(
    OUTPUT ${ZXING_JS_PATH}
    COMMAND ${CMAKE_COMMAND} -E echo "Downloading ZXing library from ${ZXING_JS_URL}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_SOURCE_DIR}/static/js"
    COMMAND curl --silent --show-error --output ${ZXING_JS_PATH} ${ZXING_JS_URL}
    COMMAND ${CMAKE_COMMAND} -E echo "ZXing library downloaded to ${ZXING_JS_PATH}"
    COMMENT "Downloading ZXing barcode scanning library"
    VERBATIM
)

# Create a custom target for downloading ZXing
add_custom_target(download_zxing DEPENDS ${ZXING_JS_PATH})

project(rpi-provisioner-ui)

find_package(SQLite3 REQUIRED)
find_package(jsoncpp REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(systemd REQUIRED libsystemd)
find_package(OpenSSL REQUIRED)

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

# Add zxing dependency
add_dependencies(rpi-provisioner-ui download_zxing)

target_sources(rpi-provisioner-ui
    PRIVATE
    src/main.cpp
    src/images.cpp
    src/options.cpp
    src/devices.cpp
    src/customisation.cpp
    src/services.cpp
    src/manufacturing.cpp
    src/scantool.cpp
    src/audit.cpp
    src/utils.cpp
    ${VIEW_SOURCES}
)

target_include_directories(rpi-provisioner-ui
    PRIVATE
    src/include
    ${SQLite3_INCLUDE_DIR}
    ${CSP_OUTPUT_DIR}  # Include the compiled templates
    ${curl_SOURCE_DIR}/include  # Add curl headers
)

target_link_libraries(rpi-provisioner-ui
    PRIVATE
    ${jsoncpp_LIBRARY}
    drogon
    ${systemd_LIBRARIES}
    ${SQLite3_LIBRARY}
    libcurl
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Install directives
# Only install our executable and service file, not any of the FetchContent dependencies
install(TARGETS rpi-provisioner-ui
    RUNTIME DESTINATION /usr/bin
)

# Install static files
install(DIRECTORY "${CMAKE_SOURCE_DIR}/static/"
        DESTINATION /usr/share/rpi-sb-provisioner/static
        FILES_MATCHING PATTERN "*.js"
        PERMISSIONS OWNER_READ GROUP_READ WORLD_READ)