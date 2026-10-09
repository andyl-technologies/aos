#include "dispatch/backend.h"

#include <folly/init/Init.h>
#include <folly/logging/Init.h>

#include <exception>
#include <iostream>

int main(int argc, char** argv) {
  try {
    const folly::Init initialization(&argc, &argv);
    // Diagnostics share stderr; stdout carries only framed protobuf messages.
    folly::initLoggingOrDie("ERR");
    return dispatch::backend::run_worker(std::cin, std::cout);
  } catch (const std::exception& error) {
    std::cerr << "dispatch-rebalancer: " << error.what() << '\n';
    return 1;
  }
}
