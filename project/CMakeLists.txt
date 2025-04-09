####################
#      Global      #
####################

cmake_minimum_required(VERSION 3.12)

# Set C++ Standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
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

# Source files (relative to "src" directory)
set(SOURCES
    src/main.cpp
)

# Header files (relative to "include" directory)
set(HEADERS
    include/header.h
)

# Automatically add all .cpp files from benchmarking/
file(GLOB BENCHMARK_SOURCES benchmarking/*.cpp)
list(APPEND SOURCES ${BENCHMARK_SOURCES})

# Automatically add all header files from include/ and benchmarking/
file(GLOB BENCHMARK_HEADERS benchmarking/*.h)
list(APPEND HEADERS ${BENCHMARK_HEADERS})

# Find Boost (required for WebSocket++)
find_package(Boost REQUIRED)

# Add WebSocket++ Include Path
include_directories(/usr/local/include)

# Create the executable
add_executable(${PROJECT_NAME} ${SOURCES} ${HEADERS})

# Link Boost (if needed)
target_link_libraries(${PROJECT_NAME} Boost::boost)


########################
#  Include Directories #
########################

# Ensure project includes the necessary directories
target_include_directories(${PROJECT_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/benchmarking
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
