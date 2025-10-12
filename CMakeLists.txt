cmake_minimum_required(VERSION 3.16)
project(VideoCall)

set(CMAKE_CXX_STANDARD 17)

# Явно указываем пути которые нашел find
include_directories("/Users/ivan/vcpkg/installed/arm64-osx/include")
link_directories("/Users/ivan/vcpkg/installed/arm64-osx/lib")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(videocall main.cpp)
target_link_libraries(videocall datachannel srtp2 ssl crypto pthread)