// SPDX-License-Identifier: MIT
// Calls the native CPUID handler; no replacement guest/model implementation.
#include <cstdint>
#include <limits>
#include <vector>

#include <gtest/gtest.h>

#include "arch/x86/cpuid.hh"

namespace gem5::X86ISA
{

namespace
{

void
assertResult(const CpuidResult &result, uint32_t a, uint32_t b,
             uint32_t d, uint32_t c)
{
    EXPECT_EQ(result.rax, a);
    EXPECT_EQ(result.rbx, b);
    EXPECT_EQ(result.rdx, d);
    EXPECT_EQ(result.rcx, c);
}

TEST(X86CpuidSubleaf, PreservesEveryConfiguredTuple)
{
    X86CPUID cpuid("GenuineIntel", "bounded CPUID test");
    std::vector<uint32_t> values;
    for (uint32_t index = 0; index < 64; ++index) {
        values.insert(values.end(), {index + 1, index + 101,
                                     index + 201, index + 301});
    }
    cpuid.addStandardFunc(ExtendedState, values);

    for (uint32_t index = 0; index < 64; ++index) {
        CpuidResult result(9, 9, 9, 9);
        ASSERT_TRUE(cpuid.doCpuid(nullptr, ExtendedState, index, result));
        assertResult(result, index + 1, index + 101, index + 201, index + 301);
    }
}

TEST(X86CpuidSubleaf, UnavailableAndOverflowingIndicesReturnZero)
{
    X86CPUID cpuid("GenuineIntel", "bounded CPUID test");
    cpuid.addStandardFunc(ExtendedState, {1, 2, 3, 4, 5, 6, 7, 8});
    const std::vector<uint32_t> indices = {
        2, 3, 63, 64, 0x1fffffff, 0x20000000, 0x3fffffff,
        0x40000000, 0x40000001, 0x7fffffff, 0x80000000,
        0xfffffffe, std::numeric_limits<uint32_t>::max(),
    };
    for (uint32_t index : indices) {
        CpuidResult result(9, 9, 9, 9);
        ASSERT_TRUE(cpuid.doCpuid(nullptr, ExtendedState, index, result));
        assertResult(result, 0, 0, 0, 0);
    }
}

TEST(X86CpuidSubleaf, PartialTrailingTupleIsUnavailable)
{
    X86CPUID cpuid("GenuineIntel", "bounded CPUID test");
    for (size_t count = 0; count < 8; ++count) {
        cpuid.addStandardFunc(ExtendedState, std::vector<uint32_t>(count, 7));
        CpuidResult result(9, 9, 9, 9);
        ASSERT_TRUE(cpuid.doCpuid(nullptr, ExtendedState,
                                 static_cast<uint32_t>(count / 4), result));
        assertResult(result, 0, 0, 0, 0);
    }
}

TEST(X86CpuidSubleaf, OrdinaryFunctionsStillIgnoreIndex)
{
    X86CPUID cpuid("GenuineIntel", "bounded CPUID test");
    cpuid.addStandardFunc(FamilyModelStepping, {11, 12, 13, 14});
    for (uint32_t index : {0U, 2U, 0x40000000U, 0xffffffffU}) {
        CpuidResult result(9, 9, 9, 9);
        ASSERT_TRUE(cpuid.doCpuid(nullptr, FamilyModelStepping, index, result));
        assertResult(result, 11, 12, 13, 14);
    }
    CpuidResult unsupported(9, 9, 9, 9);
    EXPECT_FALSE(cpuid.doCpuid(nullptr, 0x12345678, 0xffffffff, unsupported));
    assertResult(unsupported, 9, 9, 9, 9);
}

} // anonymous namespace
} // namespace gem5::X86ISA
