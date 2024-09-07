list(APPEND COMPILE_TIME_TESTS_SOURCES
    #    IPCheckSum
)

foreach(CT_TEST ${COMPILE_TIME_TESTS_SOURCES})
    set(TARGET_NAME "libxnet_ct_test_${CT_TEST}")
    add_library(${TARGET_NAME} OBJECT "${CT_TEST}CPTest.cc")
    target_link_libraries(${TARGET_NAME} PRIVATE xnet.headers)
endforeach()
