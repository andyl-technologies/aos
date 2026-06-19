#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int
main(int argc, char **argv)
{
  uint64_t iterations = 20000000;
  if (argc > 1) {
    iterations = strtoull(argv[1], NULL, 10);
  }

  volatile uint64_t state = 0x0010c001ULL;
  for (uint64_t i = 0; i < iterations; i++) {
    state ^= i + 0x9e3779b97f4a7c15ULL;
    state *= 0xbf58476d1ce4e5b9ULL;
    state ^= state >> 27;
  }

  printf("CRUCIBLE_COVERAGE_WORKLOAD iterations=%" PRIu64 " state=%" PRIx64 "\n", iterations, state);
  return state == 0 ? 1 : 0;
}
