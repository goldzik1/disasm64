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
    src/relocate.cpp)
target_include_directories(disasm64 PUBLIC include)

enable_testing()
foreach(t reader prefix decode format relocate)
    add_executable(test_${t} tests/test_${t}.cpp)
    target_link_libraries(test_${t} PRIVATE disasm64)
    target_include_directories(test_${t} PRIVATE include tests src)
    add_test(NAME ${t} COMMAND test_${t})
endforeach()
