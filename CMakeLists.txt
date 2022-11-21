# Copyright 2022 The localconnect Authors. All rights reserved.


cmake_minimum_required(VERSION 3.9)

project(localconnect VERSION 1.00 LANGUAGES C CXX)

# set include
include_directories(./include)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED OFF)
set(CMAKE_C_EXTENSIONS OFF)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED OFF)
set(CMAKE_CXX_EXTENSIONS OFF)

# find thread
find_package(Threads REQUIRED)

# add excutables
add_executable(client ./src/client.cpp)
target_link_libraries(client Threads::Threads)

# add excutables
add_executable(clientdecode ./src/client.cpp)
target_compile_definitions(clientdecode PUBLIC CLIENT_DECODE)
target_link_libraries(clientdecode Threads::Threads)

# add excutables
add_executable(regsrv ./src/regsrv.cpp)
target_link_libraries(regsrv Threads::Threads)

# add excutables
add_executable(regcli ./src/regcli.cpp)
target_link_libraries(regcli Threads::Threads)


