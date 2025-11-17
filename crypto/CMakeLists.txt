cmake_minimum_required(VERSION 3.10)
project(MyMessenger)

# Найди пакеты
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json REQUIRED)

# Создай исполняемый файл
add_executable(crypto crypto.cpp)

# Свяжи с библиотеками
target_link_libraries(crypto PRIVATE 
    OpenSSL::SSL 
    OpenSSL::Crypto
    nlohmann_json::nlohmann_json
)

# Установи стандарт C++
set_target_properties(crypto PROPERTIES
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)