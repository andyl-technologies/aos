#include "library.h"
#include "tools/bazel/tests/fixture/generated.h"

int fixture_answer() {
    return AOS_FIXTURE_VALUE + AOS_FIXTURE_HEADER_OFFSET;
}
