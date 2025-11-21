cmake_minimum_required(VERSION 3.10)
project(kea_dynamic_subnet_hook CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find Kea includes
find_path(KEA_INCLUDE_DIR
    NAMES dhcp/pkt4.h
    PATHS /usr/include/kea /usr/local/include/kea
)

if(NOT KEA_INCLUDE_DIR)
    message(FATAL_ERROR "Kea headers not found")
endif()

include_directories(${KEA_INCLUDE_DIR})

# Build the hook library
add_library(kea_dynamic_subnet SHARED
    dynamic_subnet.cc
)

# Set proper library name (without 'lib' prefix for Kea hooks)
set_target_properties(kea_dynamic_subnet PROPERTIES
    PREFIX ""
    OUTPUT_NAME "dhcp_dynamic_subnet"
)

# Install to Kea hooks directory
install(TARGETS kea_dynamic_subnet
    LIBRARY DESTINATION /usr/local/lib/kea/hooks
)
