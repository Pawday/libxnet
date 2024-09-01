cmake_minimum_required(VERSION 3.23)


project(BootServer)

set(CMAKE_LINK_LIBRARIES_ONLY_TARGETS ON)


add_subdirectory(deps)


add_executable(Main
    IPListener.cc
    IPSource_pcap.cc
)

target_link_libraries(Main PRIVATE 
    xnet.deps.libpcap.headers
    xnet.deps.libpcap.objects
)

add_executable(Sender DHCP_sender.cc)

set_target_properties(
    Main
    Sender
PROPERTIES
    CXX_STANDARD 23
    CXX_EXTENSIONS OFF
    CXX_STANDARD_REQUIRED ON
)
