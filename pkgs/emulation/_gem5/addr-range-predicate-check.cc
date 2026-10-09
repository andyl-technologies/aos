// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Andyl, Inc.
// Compares the actual pinned header before and after its predicate patch.

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <new>
#include <type_traits>
#include <utility>
#include <vector>

#include <gtest/gtest.h>
#include "base/gtest/logging.hh"

#define AddrRangeMap BaselineAddrRangeMap
#include "base/addr_range_map-baseline.hh"
#undef AddrRangeMap
#undef __BASE_ADDR_RANGE_MAP_HH__
#include "base/addr_range_map.hh"

namespace
{
bool countAllocations = false;
uint64_t allocations = 0;
}

void *operator new(std::size_t size)
{
    if (countAllocations)
        ++allocations;
    if (void *memory = std::malloc(size ? size : 1))
        return memory;
    throw std::bad_alloc();
}

void *operator new[](std::size_t size) { return ::operator new(size); }
void operator delete(void *memory) noexcept { std::free(memory); }
void operator delete[](void *memory) noexcept { std::free(memory); }
void operator delete(void *memory, std::size_t) noexcept { std::free(memory); }
void operator delete[](void *memory, std::size_t) noexcept { std::free(memory); }

namespace
{
using gem5::Addr;
using gem5::AddrRange;

// Copy-sensitive, stateful predicates must never be part of the public map API.
// The optimization applies only to the four synchronous concrete range lambdas.
struct CopySensitivePredicate
{
    unsigned *copies;
    mutable unsigned calls = 0;

    explicit CopySensitivePredicate(unsigned &count) : copies(&count) {}
    CopySensitivePredicate(const CopySensitivePredicate &other)
        : copies(other.copies), calls(other.calls)
    {
        ++*copies;
    }

    bool operator()(const AddrRange &) const { return ++calls == 1; }
};

template <typename Map, typename = void>
struct HasPublicPredicateFind : std::false_type {};

template <typename Map>
struct HasPublicPredicateFind<Map, std::void_t<decltype(
    std::declval<Map &>().find(std::declval<const AddrRange &>(),
                              std::declval<CopySensitivePredicate>()))>>
    : std::true_type {};

static_assert(!HasPublicPredicateFind<gem5::BaselineAddrRangeMap<int>>::value);
static_assert(!HasPublicPredicateFind<const gem5::BaselineAddrRangeMap<int>>::value);
static_assert(!HasPublicPredicateFind<gem5::AddrRangeMap<int>>::value);
static_assert(!HasPublicPredicateFind<const gem5::AddrRangeMap<int>>::value);

template <typename Map>
int contains(const Map &map, const AddrRange &range)
{
    const auto result = map.contains(range);
    return result == map.end() ? -1 : result->second;
}

template <typename Map>
int intersects(Map &map, const AddrRange &range)
{
    const auto result = map.intersects(range);
    return result == map.end() ? -1 : result->second;
}

TEST(AddrRangePredicate, ExactRangesBoundariesAndDynamicInvalidation)
{
    gem5::BaselineAddrRangeMap<int, 3> baseline;
    gem5::AddrRangeMap<int, 3> patched;
    const std::vector<AddrRange> ranges = {
        AddrRange(0x1000, 0x2000), AddrRange(0x4000, 0x5000),
        AddrRange(0x8000, 0x9000), AddrRange(0xc000, 0xd000),
    };
    for (unsigned index = 0; index < ranges.size(); ++index) {
        ASSERT_NE(baseline.insert(ranges[index], index), baseline.end());
        ASSERT_NE(patched.insert(ranges[index], index), patched.end());
    }

    for (Addr address = 0; address <= 0x10000; ++address) {
        for (Addr extent : {1, 8, 64, 4096}) {
            const AddrRange query(address, address + extent);
            EXPECT_EQ(contains(baseline, query), contains(patched, query));
            EXPECT_EQ(intersects(baseline, query), intersects(patched, query));
            EXPECT_EQ(contains(baseline, query), contains(patched, query));
        }
    }
    EXPECT_EQ(baseline.insert(AddrRange(0x1800, 0x4800), 9), baseline.end());
    EXPECT_EQ(patched.insert(AddrRange(0x1800, 0x4800), 9), patched.end());
    baseline.erase(baseline.contains(Addr(0x1800)));
    patched.erase(patched.contains(Addr(0x1800)));
    EXPECT_EQ(contains(baseline, AddrRange(0x1800, 0x1801)), -1);
    EXPECT_EQ(contains(patched, AddrRange(0x1800, 0x1801)), -1);
    baseline.clear();
    patched.clear();
    EXPECT_EQ(contains(baseline, AddrRange(0xc000, 0xc001)), -1);
    EXPECT_EQ(contains(patched, AddrRange(0xc000, 0xc001)), -1);
}

TEST(AddrRangePredicate, InterleavedMasksAndConstQueries)
{
    gem5::BaselineAddrRangeMap<int, 3> baseline;
    gem5::AddrRangeMap<int, 3> patched;
    const std::vector<Addr> masks = {0x44440, 0x88880, 0x111100, 0x222200};
    for (int bank = 0; bank < 16; ++bank) {
        const AddrRange range(0x80000000, 0xc0000000, masks, bank);
        ASSERT_NE(baseline.insert(range, bank), baseline.end());
        ASSERT_NE(patched.insert(range, bank), patched.end());
    }
    for (Addr offset = 0; offset < 65536; ++offset) {
        const AddrRange query(0x80000000 + offset, 0x80000001 + offset);
        EXPECT_EQ(contains(baseline, query), contains(patched, query));
    }
    for (int bank = 0; bank < 16; ++bank) {
        const AddrRange range(0x80000000, 0xc0000000, masks, bank);
        EXPECT_EQ(intersects(baseline, range), intersects(patched, range));
    }
    // Native AddrRange deliberately refuses this ambiguous intersection.
    const AddrRange unsupported(0x80000000, 0x80000001);
    EXPECT_THROW(intersects(baseline, unsupported), gem5::GTestException);
    EXPECT_THROW(intersects(patched, unsupported), gem5::GTestException);
    const AddrRange unsupportedSubset(0x80000000, 0xc0000000, masks, 0);
    EXPECT_THROW(contains(baseline, unsupportedSubset), gem5::GTestException);
    EXPECT_THROW(contains(patched, unsupportedSubset), gem5::GTestException);
}

struct Measurement
{
    uint64_t nanoseconds;
    uint64_t allocationCount;
    uint64_t checksum;
};

template <typename Map>
[[gnu::noinline]] int hotQuery(Map &map, Addr address)
{
    const auto result = map.contains(address);
    return result == map.end() ? 0 : result->second;
}

template <typename Map>
Measurement measure(Map &map)
{
    constexpr unsigned Queries = 1000000;
    (void)map.contains(Addr(0x1000));
    allocations = 0;
    uint64_t checksum = 0;
    countAllocations = true;
    const auto start = std::chrono::steady_clock::now();
    for (unsigned query = 0; query < Queries; ++query) {
        checksum += hotQuery(map, Addr(0x1000 + (query & 0x7ff)));
    }
    const auto stop = std::chrono::steady_clock::now();
    countAllocations = false;
    return {static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::nanoseconds>(
                stop - start).count()), allocations, checksum};
}

TEST(AddrRangePredicate, ActualHotRamQueriesAvoidAllocation)
{
    gem5::BaselineAddrRangeMap<int, 3> baseline;
    gem5::AddrRangeMap<int, 3> patched;
    baseline.insert(AddrRange(0x1000, 0x2000), 17);
    patched.insert(AddrRange(0x1000, 0x2000), 17);
    for (unsigned round = 0; round < 5; ++round) {
        const auto before = measure(baseline);
        const auto after = measure(patched);
        ASSERT_EQ(before.checksum, 17000000);
        ASSERT_EQ(after.checksum, before.checksum);
        EXPECT_EQ(before.allocationCount, 1000000);
        EXPECT_EQ(after.allocationCount, 0);
        std::cout << "{\"schema\":\"crucible.gem5.addr-range-microbenchmark.v1\","
                  << "\"round\":" << round
                  << ",\"queries\":1000000,\"baseline_ns\":" << before.nanoseconds
                  << ",\"patched_ns\":" << after.nanoseconds
                  << ",\"baseline_allocations\":" << before.allocationCount
                  << ",\"patched_allocations\":" << after.allocationCount
                  << ",\"whole_boot_performance_measured\":false}\n";
    }
}
} // namespace
