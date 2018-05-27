cmake_minimum_required(VERSION 3.10)
project(seth C)

set(CMAKE_C_STANDARD 11)

add_executable(seth main.c param.c param.h cmd.h ether.h ip.h sock.c)