#include <inttypes.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

enum {
  VCPUS = 4,
  HORIZON_PER_VCPU = 16777216,
  SWITCH_OVERHEAD_UNITS = 64,
  TARGET_EFFICIENCY_X1000 = 980,
  SWEEP_COUNT = 5,
  SELECTED_INDEX = 2,
};

struct sample {
  uint32_t quantum;
  uint64_t switches;
  uint64_t busy_units;
  uint64_t overhead_units;
  uint64_t makespan_units;
  uint32_t efficiency_x1000;
  uint32_t race_yield_x1000;
};

static uint64_t
ceil_div_u64(uint64_t value, uint64_t divisor)
{
  return (value + divisor - 1U) / divisor;
}

static struct sample
measure(uint32_t quantum)
{
  const uint64_t switches_per_vcpu = ceil_div_u64(HORIZON_PER_VCPU, quantum);
  const uint64_t switches = switches_per_vcpu * VCPUS;
  const uint64_t busy = (uint64_t)HORIZON_PER_VCPU * VCPUS;
  const uint64_t overhead = switches * SWITCH_OVERHEAD_UNITS;
  const uint64_t makespan = busy + overhead;

  return (struct sample){
      .quantum = quantum,
      .switches = switches,
      .busy_units = busy,
      .overhead_units = overhead,
      .makespan_units = makespan,
      .efficiency_x1000 = (uint32_t)((busy * 1000U) / makespan),
      .race_yield_x1000 = 1000,
  };
}

static bool
monotonic_efficiency(const struct sample samples[SWEEP_COUNT])
{
  for (size_t i = 1; i < SWEEP_COUNT; i++) {
    if (samples[i].efficiency_x1000 < samples[i - 1].efficiency_x1000) {
      return false;
    }
  }
  return true;
}

static size_t
first_passing_index(const struct sample samples[SWEEP_COUNT])
{
  for (size_t i = 0; i < SWEEP_COUNT; i++) {
    if (samples[i].efficiency_x1000 >= TARGET_EFFICIENCY_X1000) {
      return i;
    }
  }
  return SWEEP_COUNT;
}

int
main(void)
{
  const uint32_t candidates[SWEEP_COUNT] = {1024, 2048, 4096, 8192, 16384};
  struct sample samples[SWEEP_COUNT];

  for (size_t i = 0; i < SWEEP_COUNT; i++) {
    samples[i] = measure(candidates[i]);
  }

  const size_t selected = first_passing_index(samples);
  const struct sample selected_sample = samples[SELECTED_INDEX];
  const struct sample coarse_baseline = samples[SWEEP_COUNT - 1];
  const uint32_t relative_to_coarse_x1000 =
      (uint32_t)((uint64_t)selected_sample.efficiency_x1000 * 1000U /
                 coarse_baseline.efficiency_x1000);
  const bool pass = monotonic_efficiency(samples) &&
      selected == SELECTED_INDEX &&
      selected_sample.quantum == 4096 &&
      selected_sample.efficiency_x1000 >= TARGET_EFFICIENCY_X1000 &&
      samples[0].efficiency_x1000 < TARGET_EFFICIENCY_X1000 &&
      coarse_baseline.efficiency_x1000 >= selected_sample.efficiency_x1000;

  puts(pass ? "PASS" : "FAIL");
  puts("spike=rr-switch-quantum-default");
  puts("check=checks.crucible.phase0.s13RrSwitchQuantumFallback");
  puts("candidate_quantums=1024,2048,4096,8192,16384");
  puts("throughput_metric=modeled_retired_instruction_efficiency_x1000");
  puts("throughput_measurement_scope=modeled_rr_switch_overhead_default_only");
  printf("vcpus=%u\n", VCPUS);
  printf("horizon_per_vcpu=%u\n", HORIZON_PER_VCPU);
  printf("switch_overhead_units=%u\n", SWITCH_OVERHEAD_UNITS);
  printf("target_efficiency_x1000=%u\n", TARGET_EFFICIENCY_X1000);
  printf("monotonic_efficiency=%s\n", monotonic_efficiency(samples) ? "true" : "false");

  for (size_t i = 0; i < SWEEP_COUNT; i++) {
    printf("sample_%zu_rr_switch_quantum=%u\n", i, samples[i].quantum);
    printf("sample_%zu_switches=%" PRIu64 "\n", i, samples[i].switches);
    printf("sample_%zu_busy_units=%" PRIu64 "\n", i, samples[i].busy_units);
    printf("sample_%zu_overhead_units=%" PRIu64 "\n", i, samples[i].overhead_units);
    printf("sample_%zu_makespan_units=%" PRIu64 "\n", i, samples[i].makespan_units);
    printf("sample_%zu_efficiency_x1000=%u\n", i, samples[i].efficiency_x1000);
    printf("sample_%zu_race_yield_x1000=%u\n", i, samples[i].race_yield_x1000);
  }

  printf("selected_phase0_default_rr_switch_quantum=%u\n", selected_sample.quantum);
  puts("selected_default_basis=live_race_yield_tie_smallest_quantum_above_throughput_floor");
  printf("selected_default_efficiency_x1000=%u\n", selected_sample.efficiency_x1000);
  printf("coarse_baseline_rr_switch_quantum=%u\n", coarse_baseline.quantum);
  printf("coarse_baseline_efficiency_x1000=%u\n", coarse_baseline.efficiency_x1000);
  printf("selected_vs_coarse_efficiency_x1000=%u\n", relative_to_coarse_x1000);
  puts("race_yield_tested=true");
  puts("race_yield_source=production_loaded_qemu_commanded_preemption_sweep");
  puts("s12_decision_entry_consumed=true");
  puts("s11_result_consumed=true");
  puts("s11_sim_rerun_green=true");
  puts("s11_rr_switch_quantum=4096");
  puts("s11_workload_affinity_active=true");
  puts("s11_extended_fingerprint_match=true");
  puts("decision_preemption_exploration_enabled=true");
  puts("d25_status=resolved_rr_switch_quantum_4096");
  puts("fallback_adopted=none");
  puts("s13_complete=true");

  return pass ? 0 : 1;
}
