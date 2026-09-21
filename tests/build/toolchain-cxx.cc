/* Exercises C++ headers, libc character tables, and static runtime unwinding. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <cctype>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <numeric>
#include <vector>
#include <link.h>

static int count_images(struct dl_phdr_info *image, size_t size, void *data)
{
    if (image->dlpi_phnum != 0)
        ++*static_cast<int *>(data);
    return 0;
}

struct UnwindCleanup
{
    int &calls;

    explicit UnwindCleanup(int &count) : calls(count) {}

    ~UnwindCleanup()
    {
        ++calls;
    }
};

/* Cross a real call boundary so the check requires the unwinder's frame data. */
static void __attribute__((noinline)) raise_exception(int &cleanup_calls)
{
    UnwindCleanup cleanup(cleanup_calls);
    throw 42;
}

int main()
{
    volatile int lower = 'a';
    std::vector<int> values(3, 14);

    if (PATH_MAX <= 0 || std::toupper(lower) != 'A' ||
        std::accumulate(values.begin(), values.end(), 0) != 42 ||
        std::strtol("42", 0, 10) != 42)
        return 1;

    int cleanup_calls = 0;
    try {
        raise_exception(cleanup_calls);
        return 1;
    } catch (int value) {
        if (value != 42)
            return 1;
    } catch (...) {
        return 1;
    }
    if (cleanup_calls != 1)
        return 1;

    /* Static executables still have program headers that libc must report. */
    int images = 0;
    if (dl_iterate_phdr(count_images, &images) != 0 || images == 0)
        return 1;

    return std::puts("C++ header and runtime contracts passed") < 0;
}
