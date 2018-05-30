cmake_minimum_required(VERSION 3.10)
project(seth C)

set(CMAKE_C_STANDARD 11)

find_package (Threads)
add_executable(seth main.c param.c param.h cmd.h ether.h ip.h sock.c ether.c icmp.h arp.c ip.c icmp.c cmd.c)
target_link_libraries (seth ${CMAKE_THREAD_LIBS_INIT})
