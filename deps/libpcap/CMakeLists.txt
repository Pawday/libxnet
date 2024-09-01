add_library(xnet.deps.libpcap.headers INTERFACE)
add_library(xnet.deps.libpcap.objects OBJECT)

find_program(LEX_EXECUTABLE NAMES flex win_flex)
find_program(BISON_EXECUTABLE NAMES bison)

if(LEX_EXECUTABLE STREQUAL "LEX_EXECUTABLE-NOTFOUND")
    message(FATAL_ERROR "Neither flex nor win_flex was found.")
endif()
if(BISON_EXECUTABLE STREQUAL "BISON_EXECUTABLE-NOTFOUND")
    message(FATAL_ERROR "bison was not found.")
endif()

include(CheckFunctionExists)
include(CheckTypeSize)
include(CMakePushCheckState)


set(PCAP_SOURCE_DIR "${CMAKE_CURRENT_LIST_DIR}/src")
set(PCAP_GENEREATED_HEADERS_DIR "${CMAKE_CURRENT_BINARY_DIR}/include")


file(STRINGS ${PCAP_SOURCE_DIR}/VERSION
    PACKAGE_VERSION
    LIMIT_COUNT 1 # Read only the first line
)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/scanner.c ${PCAP_GENEREATED_HEADERS_DIR}/scanner.h
    SOURCE ${PCAP_SOURCE_DIR}/scanner.l
    COMMAND ${LEX_EXECUTABLE} -P pcap_ --header-file=${PCAP_GENEREATED_HEADERS_DIR}/scanner.h --nounput -o${CMAKE_CURRENT_BINARY_DIR}/scanner.c ${PCAP_SOURCE_DIR}/scanner.l
    DEPENDS ${PCAP_SOURCE_DIR}/scanner.l
)


set(REENTRANT_PARSER "%define api.pure")
configure_file(${PCAP_SOURCE_DIR}/grammar.y.in ${CMAKE_CURRENT_BINARY_DIR}/grammar.y @ONLY)

set(PCAP_GRAMMAR_FILE ${CMAKE_CURRENT_BINARY_DIR}/grammar.y)

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/grammar.c ${PCAP_GENEREATED_HEADERS_DIR}/grammar.h
    SOURCE ${PCAP_GRAMMAR_FILE}
    COMMAND ${BISON_EXECUTABLE} -p pcap_ --header=${PCAP_GENEREATED_HEADERS_DIR}/grammar.h -o ${CMAKE_CURRENT_BINARY_DIR}/grammar.c -d ${PCAP_GRAMMAR_FILE}
    DEPENDS ${PCAP_GRAMMAR_FILE}
)

add_custom_target(xnet.deps.libpcap.gramscan
    DEPENDS
    ${CMAKE_CURRENT_BINARY_DIR}/grammar.c
    ${CMAKE_CURRENT_BINARY_DIR}/scanner.c
)

target_include_directories(xnet.deps.libpcap.headers INTERFACE src)

list(APPEND PCAP_BASE_SOURCES
    bpf_dump.c
    bpf_filter.c
    bpf_image.c
    etherent.c
    fmtutils.c
    gencode.c
    nametoaddr.c
    optimize.c
    pcap-common.c
    pcap-util.c
    pcap.c
    savefile.c
    sf-pcapng.c
    sf-pcap.c
)


list(APPEND PCAP_BASE_SOURCES pcap-linux.c fad-getad.c)
list(TRANSFORM PCAP_BASE_SOURCES PREPEND "${PCAP_SOURCE_DIR}/")

list(APPEND PCAP_SOURCES
    ${PCAP_BASE_SOURCES}
    ${CMAKE_CURRENT_BINARY_DIR}/grammar.c
    ${CMAKE_CURRENT_BINARY_DIR}/scanner.c
)


set(OLD_CMAKE_REQUIRED_QUIET ${CMAKE_REQUIRED_QUIET})
set(CMAKE_REQUIRED_QUIET ON)
check_function_exists(strlcpy HAVE_STRLCPY)
check_function_exists(strlcat HAVE_STRLCAT)
check_function_exists(asprintf HAVE_ASPRINTF)
check_function_exists(vasprintf HAVE_VASPRINTF)
check_function_exists(strtok_r HAVE_STRTOK_R)
set(CMAKE_REQUIRED_QUIET ${OLD_CMAKE_REQUIRED_QUIET})


cmake_push_check_state()
if(WIN32)
    set(CMAKE_EXTRA_INCLUDE_FILES winsock2.h)
else(WIN32)
    set(CMAKE_EXTRA_INCLUDE_FILES unistd.h sys/socket.h)
endif(WIN32)
check_type_size("socklen_t" SOCKLEN_T)
cmake_pop_check_state()


configure_file(${PCAP_SOURCE_DIR}/cmakeconfig.h.in "${PCAP_GENEREATED_HEADERS_DIR}/config.h")
target_include_directories(xnet.deps.libpcap.objects PRIVATE
    ${PCAP_GENEREATED_HEADERS_DIR}
    ${PCAP_SOURCE_DIR}
)


target_sources(xnet.deps.libpcap.objects PRIVATE ${PCAP_SOURCES})
add_dependencies(xnet.deps.libpcap.objects xnet.deps.libpcap.gramscan)
