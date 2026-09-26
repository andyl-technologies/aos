#include <cmath>
#include <iostream>
#include <string>

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }

    const double input = std::stod(argv[1]);
    const double root = std::sqrt(input);
    if (root != 3.0) {
        return 3;
    }

    std::cout << "AOS static C++ math passed\n";
    return 0;
}
