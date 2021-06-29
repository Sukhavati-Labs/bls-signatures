CMAKE_MINIMUM_REQUIRED(VERSION 3.14 FATAL_ERROR)
set (CMAKE_CXX_STANDARD 17)

project(blsgo C CXX ASM)

add_library(blsgo STATIC
        wrappers/UtilWrapper.cpp
        wrappers/UtilWrapper.h
        wrappers/PrivateKeyWrapper.h
        wrappers/PrivateKeyWrapper.cpp
        wrappers/SchemeMPLWrapper.cpp
        wrappers/SchemeMPLWrapper.h
        gobindings.h
        wrappers/BytesWrapper.cpp
        wrappers/BytesWrapper.h
        wrappers/ElementWrapper.cpp
        wrappers/ElementWrapper.h
        wrappers/GoWrapper.cpp
        wrappers/GoWrapper.h wrappers/HKDFWrapper.cpp wrappers/HKDFWrapper.h)

include_directories(
        ${INCLUDE_DIRECTORIES}
        ${CMAKE_BINARY_DIR}/_deps/relic-src/include
        ${CMAKE_BINARY_DIR}/_deps/relic-build/include
        ${relic_SOURCE_DIR}/include
        ${relic_BINARY_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/catch
)

if (GMP_FOUND)
    include_directories(${GMP_INCLUDES})
endif(GMP_FOUND)

if (SODIUM_FOUND)
    set(BLSALLOC_SODIUM "1" CACHE STRING "")
    set(SODIUM_STATIC "1" CACHE STRING "")
    target_link_libraries(blsgo blstmp relic_s sodium)
else()
    target_link_libraries(blsgo blstmp relic_s)
endif()
