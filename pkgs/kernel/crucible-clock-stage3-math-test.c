/* SPDX-License-Identifier: GPL-2.0-only */
/* Executes the exact patched kernel arithmetic without requiring KVM hardware. */
#include <assert.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <linux/kvm.h>

typedef uint64_t u64;
typedef uint32_t u32;
#define U64_MAX UINT64_MAX
#include "include/linux/kvm_crucible_clock_math.h"

static uint64_t next(uint64_t *state)
{
	*state = *state * UINT64_C(6364136223846793005) + 1;
	return *state;
}

int main(void)
{
	uint64_t seed = 1;
	unsigned int iteration;

	_Static_assert(sizeof(struct kvm_crucible_clock) == 96, "controller ABI size");
	_Static_assert(offsetof(struct kvm_crucible_clock, current_ns) == 48,
		       "controller ABI time offset");
	_Static_assert(offsetof(struct kvm_crucible_clock, reserved) == 76,
		       "controller ABI reserved offset");

	assert(kvm_crucible_clock_project(0, 10, 1010, 50, 3) == 10);
	assert(kvm_crucible_clock_project(3, 10, 1010, 50, 3) == 60);
	assert(kvm_crucible_clock_project(60, 10, 1010, 50, 3) == 1010);
	assert(kvm_crucible_clock_project(UINT64_MAX, 10, 1010, 50, 3) == 1010);
	assert(kvm_crucible_clock_project(1, UINT64_MAX - 1, UINT64_MAX,
					1, 1) == UINT64_MAX);
	assert(kvm_crucible_clock_project(2, 0, UINT64_MAX, 1, 1) == 2);
	assert(kvm_crucible_clock_project(UINT64_MAX, 0, UINT64_MAX, 1, 1)
	       == UINT64_MAX);

	/* Differential wide-integer oracle checks saturation and multiplication
	 * safety over valid installed windows, including large clock coordinates.
	 */
	for (iteration = 0; iteration < 100000; iteration++) {
		u32 numerator = next(&seed) % 65535 + 1;
		u32 denominator = next(&seed) % 65535 + 1;
		u64 extent = next(&seed) % (UINT64_MAX / denominator) + 1;
		u64 start = next(&seed) % (UINT64_MAX - extent + 1);
		u64 elapsed = next(&seed);
		__uint128_t delta = (__uint128_t)elapsed * numerator / denominator;
		u64 expected = start + (delta > extent ? extent : (u64)delta);

		assert(kvm_crucible_clock_project(elapsed, start, start + extent,
						numerator, denominator) == expected);
	}
	/* An independent truth-table oracle covers retained-owner admission;
	 * original generations and exact frozen coordinates remain mandatory.
	 */
	for (iteration = 0; iteration < 64; iteration++) {
		struct kvm_crucible_begin_state state = {
			.generation = 9, .frozen_ns = 20, .requested_generation = 10,
			.start_ns = 20, .end_ns = 30, .denominator = 1,
			.active = !!(iteration & 1), .owners_busy = !!(iteration & 2),
			.acknowledged = !!(iteration & 4),
		};
		enum kvm_crucible_begin_result expected;

		if (iteration & 8)
			state.requested_generation = 9;
		if (iteration & 16)
			state.start_ns = 21;
		if (iteration & 32)
			state.end_ns = 20;
		if ((iteration & 3) || !(iteration & 4))
			expected = KVM_CRUCIBLE_BEGIN_BUSY;
		else if (iteration & 56)
			expected = KVM_CRUCIBLE_BEGIN_INVALID;
		else
			expected = KVM_CRUCIBLE_BEGIN_READY;
		assert(kvm_crucible_clock_begin_policy(&state) == expected);
	}
	{
		struct kvm_crucible_begin_state state = {
			.generation = 0, .frozen_ns = 0, .requested_generation = 1,
			.start_ns = 0, .end_ns = 1, .denominator = 1,
		};
		assert(kvm_crucible_clock_begin_policy(&state) == KVM_CRUCIBLE_BEGIN_READY);
		state.generation = UINT64_MAX;
		assert(kvm_crucible_clock_begin_policy(&state) == KVM_CRUCIBLE_BEGIN_BUSY);
		state.acknowledged = true;
		assert(kvm_crucible_clock_begin_policy(&state) == KVM_CRUCIBLE_BEGIN_INVALID);
		state.generation = 0;
		state.end_ns = UINT64_MAX >> 1;
		state.denominator = UINT32_MAX;
		assert(kvm_crucible_clock_begin_policy(&state) == KVM_CRUCIBLE_BEGIN_OVERFLOW);
	}

	/* Independent inverse projection oracle proves no timer is scheduled
	 * before its logical deadline, including near-maximum products.
	 */
	for (iteration = 0; iteration < 100000; iteration++) {
		u32 numerator = next(&seed) % UINT32_MAX + 1;
		u32 denominator = next(&seed) % UINT32_MAX + 1;
		u64 delta = next(&seed) % (UINT64_MAX / denominator) + 1;
		__uint128_t product = (__uint128_t)delta * denominator;
		u64 expected = (product + numerator - 1) / numerator;
		u64 delay = kvm_crucible_clock_host_delay(delta, numerator, denominator);
		assert(delay == expected);
		assert((__uint128_t)delay * numerator / denominator >= delta);
		if (delay)
			assert((__uint128_t)(delay - 1) * numerator / denominator < delta);
	}

	for (iteration = 0; iteration < 100000; iteration++) {
		u64 cycles = next(&seed);
		u32 khz = next(&seed) % UINT32_MAX + 1;
		__uint128_t wide = ((__uint128_t)cycles * 1000000 + khz - 1) / khz;
		u64 expected = wide > UINT64_MAX ? UINT64_MAX : (u64)wide;
		assert(kvm_crucible_clock_cycles_to_ns(cycles, khz) == expected);
	}
	for (iteration = 0; iteration < 100000; iteration++) {
		u64 position = next(&seed) >> 1;
		u64 delta = next(&seed);
		__uint128_t sum = (__uint128_t)position + delta;
		u64 maximum = UINT64_MAX >> 1;
		u64 expected = sum > maximum ? maximum : (u64)sum;

		assert(kvm_crucible_clock_deadline_add(position, delta) == expected);
	}
	assert(kvm_crucible_clock_deadline_add(UINT64_MAX >> 1, 1) == UINT64_MAX >> 1);
	assert(kvm_crucible_clock_cycles_to_ns(UINT64_MAX, 1) == UINT64_MAX);
	assert(kvm_crucible_clock_cycles_to_ns(1, 3000000) == 1);
	for (iteration = 0; iteration < 100000; iteration++) {
		u64 ns = next(&seed) >> 1;
		u32 frequency = next(&seed) % 1000000000 + 1;
		u64 expected = (__uint128_t)ns * frequency / 1000000000;

		assert(kvm_crucible_clock_counter_from_ns(ns, frequency) == expected);
	}
	for (iteration = 0; iteration < 100000; iteration++) {
		u64 cycles = next(&seed);
		u32 frequency = next(&seed) % 1000000000 + 1;
		__uint128_t wide = ((__uint128_t)cycles * 1000000000 + frequency - 1) / frequency;
		u64 expected = wide > UINT64_MAX ? UINT64_MAX : (u64)wide;

		assert(kvm_crucible_clock_counter_cycles_to_ns(cycles, frequency) == expected);
	}
	return 0;
}
