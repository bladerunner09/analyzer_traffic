project(analyzer_traffic)
cmake_minimum_required(VERSION 3.0)
#include(${CMAKE_BINARY_DIR}/conanbuildinfo.cmake)
#conan_basic_setup()
set(CMAKE_TOOLCHAIN_FILE ${CMAKE_BINARY_DIR}/conan_toolchain.cmake)
set(CMAKE_PREFIX_PATH ${CMAKE_BINARY_DIR})
find_package(PCAPPLUSPLUS REQUIRED)
find_package (glog 0.6.0 REQUIRED)

add_executable(${PROJECT_NAME} main.cpp)
target_link_libraries(${PROJECT_NAME} pcapplusplus::pcapplusplus
                                      glog::glog)