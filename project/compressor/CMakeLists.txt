cmake_minimum_required(VERSION 3.10)
project(CompressorProject VERSION 1.0 LANGUAGES CXX)


set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_MAKE_PROGRAM ninja)
set(CMAKE_CXX_COMPILER clang++)

# -------------------------------------------------
enable_testing()          # turns on CTest
include(CTest)            # <-- adds the 'test' target
# -------------------------------------------------

add_library(compressor_lib
    src/compressor.cpp
    src/decompressor.cpp
)
target_include_directories(compressor_lib PUBLIC
    ${PROJECT_SOURCE_DIR}/include
)

add_executable(compression_tests tests/compression_tests.cpp)
target_link_libraries(compression_tests PRIVATE compressor_lib)

add_test(NAME CompressorRoundTrip COMMAND compression_tests)
