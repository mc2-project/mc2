cmake_minimum_required(VERSION 3.11)
project(mc2client LANGUAGES CXX C VERSION 1.00)

project("MC2 Client" LANGUAGES C CXX)

# Currently the `OpenEnclave` package depends on `project()`.
find_package(OpenEnclave CONFIG REQUIRED)

set(CMAKE_CXX_STANDARD 11)

message(DEBUG "Downloading Flatbuffers")
include(ExternalProject)

# Download and install Flatbuffers
set(FLATBUFFERS_INSTALL_LOCATION ${CMAKE_BINARY_DIR}/flatbuffers)
ExternalProject_Add(flatbuffers
    GIT_REPOSITORY https://github.com/google/flatbuffers.git
    GIT_TAG 6f94fb51b14a1f9cc8b4fcc14744a6c334e644cb # v1.7.0
    CMAKE_ARGS -G "Unix Makefiles" -DFLATBUFFERS_BUILD_TESTS=OFF -DFLATBUFFERS_BUILD_FLATLIB=OFF -DFLATBUFFERS_BUILD_FLATHASH=OFF -DFLATBUFFERS_BUILD_FLATC=ON -DCMAKE_INSTALL_PREFIX=${FLATBUFFERS_INSTALL_LOCATION})

# Generate Flatbuffers files from schemas
set(FLATC ${CMAKE_BINARY_DIR}/flatbuffers-prefix/src/flatbuffers-build/flatc)
set(flatbuffers_schemas
    ${CMAKE_SOURCE_DIR}/flatbuffers/EncryptedBlock.fbs
    ${CMAKE_SOURCE_DIR}/flatbuffers/Rows.fbs
)

add_custom_target(flatbuffers_cpp_generation)
set(FLATBUFFERS_GENCPP_DIR ${FLATBUFFERS_INSTALL_LOCATION}/include/flatbuffers)
foreach(schema ${flatbuffers_schemas})
    get_filename_component(filename ${schema} NAME_WE)
    # For each schema, generate the corresponding C++ file
    set(generated_include ${FLATBUFFERS_GENCPP_DIR}/${filename}_generated.h)
    add_custom_command(
        OUTPUT ${generated_include}
        DEPENDS ${CMAKE_SOURCE_DIR}/flatbuffers/${filename}.fbs
        COMMAND ${FLATC} --cpp -o ${FLATBUFFERS_GENCPP_DIR} ${schema}
    )
    add_custom_target(flatbuffers_generate_${filename} DEPENDS ${generated_include})
    add_dependencies(flatbuffers_generate_${filename} flatbuffers)
    add_dependencies(flatbuffers_cpp_generation flatbuffers_generate_${filename})
endforeach()

include_directories(${FLATBUFFERS_INSTALL_LOCATION}/include/flatbuffers ${FLATBUFFERS_INSTALL_LOCATION}/include)
add_dependencies(flatbuffers_cpp_generation flatbuffers)

include_directories(${CMAKE_SOURCE_DIR}/include/)

add_library(mc2client SHARED ${CMAKE_SOURCE_DIR}/c_api.cpp ${CMAKE_SOURCE_DIR}/attestation.cpp ${CMAKE_SOURCE_DIR}/io.cpp)
add_dependencies(mc2client flatbuffers flatbuffers_cpp_generation)

target_link_libraries(mc2client mbedcrypto mbedtls openenclave::oehost)
