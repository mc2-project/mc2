cmake_minimum_required(VERSION 3.11)

project("MC2 Client" LANGUAGES C CXX)

# Currently the `OpenEnclave` package depends on `project()`.
find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)

# ---- Fetch external packages ----
include(FetchContent)

# Fetch mc2-utils
FetchContent_Declare(
    mc2_utils_h
    GIT_REPOSITORY https://github.com/mc2-project/mc2-utils.git
)
set(FETCHCONTENT_QUIET OFF)
set(HOST ON CACHE BOOL "")
FetchContent_MakeAvailable(mc2_utils_h)

# Add necessary compiler flags and headers for spdlog dependency
add_definitions(-DSPDLOG_NO_THREAD_ID -DFMT_USE_INT128=0)
include_directories(${spdlog_SOURCE_DIR}/include)

# Fetch mc2-serialization
include(FetchContent)
FetchContent_Declare(
    mc2_serialization
    GIT_REPOSITORY https://github.com/mc2-project/mc2-serialization.git
)
set(FETCHCONTENT_QUIET OFF)
FetchContent_MakeAvailable(mc2_serialization)

# Add necessary headers for flatbuffers dependency
message(${mc2_serialization_BINARY_DIR})
include_directories(${mc2_serialization_BINARY_DIR}/flatbuffers/include/)

# Include external headers
include_directories(${CMAKE_SOURCE_DIR}/include/)

add_library(
    mc2client
    SHARED
    ${CMAKE_SOURCE_DIR}/c_api.cpp
    ${CMAKE_SOURCE_DIR}/io.cpp)
add_dependencies(mc2client spdlog mc2_serialization mc2_utils_h)
target_link_libraries(mc2client openenclave::oehost mc2_utils_h)
