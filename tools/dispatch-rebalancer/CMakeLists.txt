cmake_minimum_required(VERSION 3.20)
project(dispatch_rebalancer VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

include(CTest)
find_package(Protobuf REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(folly CONFIG REQUIRED)
find_package(FBThrift REQUIRED)
find_package(highs CONFIG REQUIRED)
find_path(REBALANCER_INCLUDE_DIR
    algopt/rebalancer/interface/ProblemSolverFactory.h REQUIRED)
find_library(REBALANCER_LIBRARY NAMES rebalancer REQUIRED)

set(DISPATCH_REBALANCER_SOURCE_REVISION
    "8a3f38401a92458f47909972e17a756c3c317acc" CACHE STRING
    "Pinned engine source revision reported to clients")
set(DISPATCH_BACKEND_BUILD_ID "" CACHE STRING
    "Source-built adapter and dependency closure identity")
if(DISPATCH_BACKEND_BUILD_ID STREQUAL "")
    message(FATAL_ERROR "DISPATCH_BACKEND_BUILD_ID must identify the adapter source and dependency closure")
endif()
get_filename_component(DISPATCH_REPOSITORY_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(DISPATCH_PROTOCOL_ROOT "${DISPATCH_REPOSITORY_ROOT}/protocol")
set(DISPATCH_GENERATED_ROOT "${CMAKE_CURRENT_BINARY_DIR}/generated")
file(MAKE_DIRECTORY "${DISPATCH_GENERATED_ROOT}")

add_custom_command(
    OUTPUT
        "${DISPATCH_GENERATED_ROOT}/dispatch/worker.pb.cc"
        "${DISPATCH_GENERATED_ROOT}/dispatch/worker.pb.h"
    COMMAND protobuf::protoc
        "--proto_path=${DISPATCH_PROTOCOL_ROOT}"
        "--cpp_out=${DISPATCH_GENERATED_ROOT}"
        "${DISPATCH_PROTOCOL_ROOT}/dispatch/worker.proto"
    DEPENDS "${DISPATCH_PROTOCOL_ROOT}/dispatch/worker.proto"
    VERBATIM)

add_library(dispatch_backend STATIC
    src/compiler.cpp
    src/model.cpp
    src/worker.cpp
    "${DISPATCH_GENERATED_ROOT}/dispatch/worker.pb.cc")
target_include_directories(dispatch_backend PUBLIC
    include
    "${DISPATCH_GENERATED_ROOT}"
    "${REBALANCER_INCLUDE_DIR}"
    "${FBTHRIFT_INCLUDE_DIR}")
target_link_libraries(dispatch_backend PUBLIC
    "${REBALANCER_LIBRARY}"
    Folly::folly
    FBThrift::thriftprotocol
    FBThrift::thriftmetadata
    FBThrift::thrifttype
    FBThrift::rpcmetadata
    highs::highs
    protobuf::libprotobuf
    nlohmann_json::nlohmann_json)
target_compile_definitions(dispatch_backend PRIVATE
    DISPATCH_REBALANCER_SOURCE_REVISION="${DISPATCH_REBALANCER_SOURCE_REVISION}"
    DISPATCH_BACKEND_BUILD_ID="${DISPATCH_BACKEND_BUILD_ID}")
target_compile_definitions(dispatch_backend PUBLIC REBALANCER_OSS_BUILD)

add_executable(dispatch-rebalancer src/main.cpp)
target_link_libraries(dispatch-rebalancer PRIVATE dispatch_backend)
install(TARGETS dispatch-rebalancer RUNTIME DESTINATION bin)
install(FILES README.md LICENSE DESTINATION share/doc/dispatch-rebalancer)

if(BUILD_TESTING)
    add_executable(dispatch-backend-tests tests/backend_tests.cpp)
    target_link_libraries(dispatch-backend-tests PRIVATE dispatch_backend)
    add_test(NAME dispatch-backend-conformance COMMAND dispatch-backend-tests)
endif()
