#include <math.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }

    const double input = strtod(argv[1], NULL);
    const double root = sqrt(input);
    if (root != 3.0) {
        return 3;
    }

    puts("AOS static C math passed");
    return 0;
}
