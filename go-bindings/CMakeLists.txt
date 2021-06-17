CMAKE_MINIMUM_REQUIRED(VERSION 3.14 FATAL_ERROR)
set (CMAKE_CXX_STANDARD 17)

include_directories(
        ${INCLUDE_DIRECTORIES}
        ${relic_SOURCE_DIR}/include
        ${relic_BINARY_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/../contrib/catch
)

if (GMP_FOUND)
    include_directories(${GMP_INCLUDES})
endif(GMP_FOUND)

pybind11_add_module(blspy ${CMAKE_CURRENT_SOURCE_DIR}/pythonbindings.cpp)

if (SODIUM_FOUND)
    set(BLSALLOC_SODIUM "1" CACHE STRING "")
    set(SODIUM_STATIC "1" CACHE STRING "")
    target_link_libraries(blsgo PRIVATE blstmp relic_s sodium)
else()
    target_link_libraries(blsgo PRIVATE blstmp relic_s)
endif()
