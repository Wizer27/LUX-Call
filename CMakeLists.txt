cmake_minimum_required(VERSION 3.16)
project(VideoCall)

set(CMAKE_CXX_STANDARD 17)

# Все пути
include_directories(
    /usr/local/include
    /opt/homebrew/include
    /usr/include
    /Users/ivan/vcpkg/installed/arm64-osx/include
)

link_directories(
    /usr/local/lib
    /opt/homebrew/lib
    /usr/lib
    /Users/ivan/vcpkg/installed/arm64-osx/lib
)

# Флаги
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -std=c++17")

add_executable(videocall api.cpp)

# Только базовые библиотеки, убираем boost
target_link_libraries(videocall 
    pthread
    ssl
    crypto
    pistache
)