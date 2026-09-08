#include <algorithm>
#include <iostream>
#include <numeric>
#include <vector>

int main() {
    std::vector<int> values{4, 1, 3, 2};
    std::sort(values.begin(), values.end());

    const int total = std::accumulate(values.begin(), values.end(), 0);
    std::cout << "AOS automatic Clang C++ config passed: " << total << '\n';

    return total == 10 ? 0 : 1;
}
