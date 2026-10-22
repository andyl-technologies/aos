#include <cstdio>
#include <string>

#include "library.h"

int main() {
    std::string answer = "answer=" + std::to_string(fixture_answer());
    std::puts(answer.c_str());
}
