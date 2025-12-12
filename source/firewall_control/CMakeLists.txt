cmake_minimum_required(VERSION 3.28)
project(firewallctl LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXE_LINKER_FLAGS "-static")
set(THIRD_PARTY_DIR ${CMAKE_SOURCE_DIR}/../firewall/third_party)
set(CJSON_DIR ${THIRD_PARTY_DIR}/cjson)
include_directories(${CJSON_DIR})

message(STATUS "cJSON dir: ${CJSON_DIR}")

add_executable(firewallctl
    firewallctl.cpp
    ${CJSON_DIR}/cJSON.c
)

target_link_libraries(firewallctl PRIVATE pthread)