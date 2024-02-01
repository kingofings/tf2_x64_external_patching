cmake_minimum_required(VERSION 3.28)
project(tf2_x64_external_patching C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(tf2_x64_external_patching
        main.c
)
