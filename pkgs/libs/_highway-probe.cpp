#include <hwy/aligned_allocator.h>
#include <hwy/highway.h>

#include <cstdio>
#include <cstring>
#include <limits>

namespace hn = hwy::HWY_NAMESPACE;

int main(int argc, char **argv) {
    if (argc != 2) {
        return 2;
    }
    if (std::strcmp(argv[1], "add") == 0) {
        const hn::ScalableTag<float> lanes;
        const size_t count = hn::Lanes(lanes);
        auto *values = static_cast<float *>(hwy::AllocateAlignedBytes(count * sizeof(float)));
        if (values == nullptr || !hwy::IsAligned(values)) {
            return 3;
        }
        hn::Store(hn::Add(hn::Set(lanes, 2.0f), hn::Set(lanes, 3.0f)), lanes, values);
        for (size_t index = 0; index < count; ++index) {
            if (values[index] != 5.0f) {
                hwy::FreeAlignedBytes(values, nullptr, nullptr);
                return 4;
            }
        }
        hwy::FreeAlignedBytes(values, nullptr, nullptr);
        std::puts("Highway SIMD addition passed");
        return 0;
    }
    if (std::strcmp(argv[1], "oversize") == 0) {
        void *values = hwy::AllocateAlignedBytes(std::numeric_limits<size_t>::max());
        if (values != nullptr) {
            hwy::FreeAlignedBytes(values, nullptr, nullptr);
            return 5;
        }
        std::puts("Highway rejected oversized allocation");
        return 0;
    }
    return 2;
}
