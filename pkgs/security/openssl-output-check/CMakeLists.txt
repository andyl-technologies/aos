cmake_minimum_required(VERSION 3.16)
project(openssl_output_check LANGUAGES C)

find_package(OpenSSL 4.0 CONFIG REQUIRED)

foreach(name IN ITEMS INCLUDE RUNTIME MODULES)
  if(NOT "${OPENSSL_${name}_DIR}" STREQUAL "${EXPECTED_${name}}")
    message(FATAL_ERROR "OpenSSL ${name} directory differs from its selected output")
  endif()
endforeach()

foreach(name IN ITEMS Crypto SSL)
  string(TOUPPER "${name}" upper_name)
  get_target_property(location OpenSSL::${name} IMPORTED_LOCATION)
  if(NOT "${location}" STREQUAL "${EXPECTED_${upper_name}}")
    message(FATAL_ERROR "OpenSSL::${name} imports the wrong output")
  endif()
endforeach()

add_executable(openssl-output-probe probe.c)
target_compile_features(openssl-output-probe PRIVATE c_std_11)
target_link_libraries(openssl-output-probe PRIVATE OpenSSL::SSL OpenSSL::Crypto)
