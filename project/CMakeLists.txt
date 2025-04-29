####################
#      Global      #
####################

cmake_minimum_required(VERSION 3.12)

# Set C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_CXX_EXTENSIONS OFF) # Prevent compiler-specific extensions

#####################
#      Project      #
#####################

# Define project name, version, and description
project(project VERSION 0.0.1 DESCRIPTION "Low-Latency Order Book and Matching Engine" LANGUAGES CXX)

# Enable compiler warnings and optimizations
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-Wall -Wextra -Wpedantic -O3 -march=native -flto)
endif()

########################
#   Source & Headers   #
########################

# Source files (relative to CMAKE_CURRENT_SOURCE_DIR)
set(SOURCES
    src/main.cpp
    parser/parser.cpp
    # Add other source files if any (e.g., benchmarking/benchmark.cpp)
)

# Header files (relative to CMAKE_CURRENT_SOURCE_DIR)
set(HEADERS
    include/header.h # Assuming this exists, adjust if needed
    parser/parser.h
    # Add other header files if any
)

# Find Boost (if required by other parts of your project, e.g., WebSocket++)
# find_package(Boost REQUIRED)

# --- Manually find Pcap ---
# Remove the standard find_package for Pcap
# find_package(Pcap REQUIRED)
# if(NOT Pcap_FOUND)
#     message(FATAL_ERROR "Pcap library not found...")
# endif()

# Find the pcap library file within Homebrew's lib directory
find_library(PCAP_LIBRARY NAMES pcap libpcap PATHS /opt/homebrew/lib)
if(NOT PCAP_LIBRARY)
    message(FATAL_ERROR "libpcap library not found in /opt/homebrew/lib. Please ensure libpcap is installed via Homebrew (`brew install libpcap`).")
endif()
message(STATUS "Found Pcap library: ${PCAP_LIBRARY}")
# --- End Manually find Pcap ---


# Add WebSocket++ Include Path (if needed)
# include_directories(/usr/local/include) # Adjust path if necessary

# Create the executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Link Boost (if needed)
# target_link_libraries(${PROJECT_NAME} Boost::boost)

# Link Pcap using the found library path
target_link_libraries(${PROJECT_NAME} PRIVATE ${PCAP_LIBRARY})


########################
#  Include Directories #
########################

# Ensure project includes the necessary directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/parser
    # Add Pcap include directory from Homebrew directly
    /opt/homebrew/include
    # Add other include directories (e.g., benchmarking)
    # ${CMAKE_CURRENT_SOURCE_DIR}/benchmarking
)

####################
#   Optimizations  #
####################

# Enable Link-Time Optimization (LTO) for performance
include(CheckIPOSupported)
check_ipo_supported(RESULT supported OUTPUT error)
if(supported)
    set_target_properties(${PROJECT_NAME} PROPERTIES INTERPROCEDURAL_OPTIMIZATION TRUE)
endif()

####################
#   Output Setup   #
####################

# Set the output directory for the executable
set_target_properties(${PROJECT_NAME} PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

####################
#   Dependencies   #
####################

# Add dependencies here if needed (e.g., linking external libraries)
