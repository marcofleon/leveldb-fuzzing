cmake_minimum_required(VERSION 3.10)
project(leveldb_fuzzing)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(LEVELDB_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(LEVELDB_BUILD_BENCHMARKS OFF CACHE BOOL "" FORCE)
add_subdirectory(leveldb-subtree)

add_executable(db_fuzzer db_fuzz.cpp)

target_compile_options(db_fuzzer PRIVATE 
    -g 
    -O2 
    -fsanitize=fuzzer
)
target_link_options(db_fuzzer PRIVATE 
    -fsanitize=fuzzer
)

target_link_libraries(db_fuzzer leveldb)

target_include_directories(db_fuzzer PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR} 
    ${CMAKE_CURRENT_SOURCE_DIR}/leveldb-subtree/include
)
