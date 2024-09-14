cmake_minimum_required(VERSION 3.23)

project(libxnet)

add_library(xnet.headers INTERFACE)
target_include_directories(xnet.headers INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(xnet.headers INTERFACE cxx_std_20)
