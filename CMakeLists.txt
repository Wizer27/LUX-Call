cmake_minimum_required(VERSION 3.16)
project(VideoCall)

set(CMAKE_CXX_STANDARD 17)

# Явно указываем пути к Boost (замените на актуальные пути в вашей системе)
set(BOOST_ROOT "/opt/homebrew")  # для Homebrew на Apple Silicon
include_directories(
    "${BOOST_ROOT}/include"
    "/opt/homebrew/opt/openssl/include"
    "/usr/local/include"
    "/opt/homebrew/include"
)

link_directories(
    "${BOOST_ROOT}/lib"
    "/opt/homebrew/opt/openssl/lib"
    "/usr/local/lib"
    "/opt/homebrew/lib"
)

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(videocall api.cpp)

# Добавляем все необходимые библиотеки
target_link_libraries(videocall 
    ssl 
    crypto 
    pthread 
    pistache
)