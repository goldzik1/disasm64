cmake_minimum_required(VERSION 3.16)
project(disasm64 CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

add_library(disasm64 STATIC
    src/prefix.cpp
    src/operand.cpp
    src/decode.cpp
    src/format_intel.cpp
    src/format_att.cpp
    src/relocate.cpp
    src/encode.cpp
    src/analysis.cpp)
target_include_directories(disasm64 PUBLIC include)

add_executable(disasm64_cli tools/disasm_cli.cpp)
target_link_libraries(disasm64_cli PRIVATE disasm64)

# C ABI shared library for FFI bindings (Python/Rust/Go/C#)
add_library(disasm64_c SHARED src/c_api.cpp)
target_link_libraries(disasm64_c PRIVATE disasm64)
target_include_directories(disasm64_c PUBLIC include)

add_executable(bench tools/bench.cpp)
target_link_libraries(bench PRIVATE disasm64)

add_executable(robust fuzz/robust.cpp)
target_link_libraries(robust PRIVATE disasm64)

add_executable(difftool tools/difftool.cpp)
target_link_libraries(difftool PRIVATE disasm64)

enable_testing()
foreach(t reader prefix decode format att ext encode relocate analysis)
    add_executable(test_${t} tests/test_${t}.cpp)
    target_link_libraries(test_${t} PRIVATE disasm64)
    target_include_directories(test_${t} PRIVATE include tests src)
    add_test(NAME ${t} COMMAND test_${t})
endforeach()

# C ABI test compiles c_api.cpp into the same binary (D64_BUILD -> no dllimport)
add_executable(test_capi tests/test_capi.cpp src/c_api.cpp)
target_link_libraries(test_capi PRIVATE disasm64)
target_include_directories(test_capi PRIVATE include tests src)
target_compile_definitions(test_capi PRIVATE D64_BUILD)
add_test(NAME capi COMMAND test_capi)

add_test(NAME robust COMMAND robust --count 300000 --seed 1)

# Single-header build (STB-style) — compiled and run to prove the amalgamation works.
add_executable(single_header examples/single_header_demo.cpp)
target_include_directories(single_header PRIVATE single_include)
add_test(NAME single_header COMMAND single_header)
