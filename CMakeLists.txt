cmake_minimum_required(VERSION 3.23)


project(BootServer)

set(CMAKE_LINK_LIBRARIES_ONLY_TARGETS ON)

add_library(xnet.headers INTERFACE)
target_include_directories(xnet.headers INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(xnet.headers INTERFACE cxx_std_20)

add_subdirectory(tests)
add_subdirectory(deps)

add_executable(Main
    IPListener.cc
    IPInputInterface_pcap.cc
)

target_link_libraries(Main PRIVATE
    xnet.headers
    xnet.deps.libpcap.headers
    xnet.deps.libpcap.objects
)

add_executable(Sender DHCP_sender.cc)
target_link_libraries(Sender PRIVATE
    xnet.headers
)
