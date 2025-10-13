cmake_minimum_required(VERSION 3.16)
project(ChatApp)

set(CMAKE_CXX_STANDARD 17)

# Просто добавляем include путь - больше ничего не нужно!
include_directories("/Users/ivan/vcpkg/installed/arm64-osx/include")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(chatapp gen.cpp)

# НЕ нужно target_link_libraries для boost-uuid - он header-only!