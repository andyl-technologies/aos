#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

enum {
  VM_NODES = 4,
  HOST_CORES = 4,
  SIMULATED_HORIZON_VT = 1048576,
  MIN_LINK_LATENCY_FLOOR = 512,
  SYNC_COST_UNITS = 48,
  DISPATCH_COST_UNITS = 2,
  TARGET_PARALLELISM_X1000 = 3500,
  SWEEP_COUNT = 4,
};

struct sample {
  uint32_t latency;
  uint32_t lookahead;
  uint64_t windows;
  uint64_t busy_units;
  uint64_t makespan_units;
  uint32_t parallelism_x1000;
};

static uint64_t
ceil_div_u64(uint64_t value, uint64_t divisor)
{
  return (value + divisor - 1U) / divisor;
}

static bool
declared_latency_valid(uint32_t latency)
{
  return latency >= MIN_LINK_LATENCY_FLOOR;
}

static uint32_t
effective_fault_latency(uint32_t latency)
{
  return latency < MIN_LINK_LATENCY_FLOOR ? MIN_LINK_LATENCY_FLOOR : latency;
}

static struct sample
measure_sample(uint32_t latency)
{
  const uint32_t lookahead = effective_fault_latency(latency);
  const uint64_t windows = ceil_div_u64(SIMULATED_HORIZON_VT, lookahead);
  uint64_t remaining = SIMULATED_HORIZON_VT;
  uint64_t makespan = 0;
  uint64_t busy = 0;

  for (uint64_t window = 0; window < windows; window++) {
    const uint64_t run = remaining < lookahead ? remaining : lookahead;
    const uint64_t batches = ceil_div_u64(VM_NODES, HOST_CORES);
    const uint64_t execution = batches * run;
    makespan += execution + SYNC_COST_UNITS + (uint64_t)VM_NODES * DISPATCH_COST_UNITS;
    busy += (uint64_t)VM_NODES * run;
    remaining -= run;
  }

  return (struct sample){
      .latency = latency,
      .lookahead = lookahead,
      .windows = windows,
      .busy_units = busy,
      .makespan_units = makespan,
      .parallelism_x1000 = (uint32_t)((busy * 1000U) / makespan),
  };
}

static struct sample
measure_unfloored_sample(uint32_t latency)
{
  const uint64_t windows = ceil_div_u64(SIMULATED_HORIZON_VT, latency);
  const uint64_t busy = (uint64_t)VM_NODES * SIMULATED_HORIZON_VT;
  const uint64_t makespan = SIMULATED_HORIZON_VT +
      windows * (SYNC_COST_UNITS + (uint64_t)VM_NODES * DISPATCH_COST_UNITS);

  return (struct sample){
      .latency = latency,
      .lookahead = latency,
      .windows = windows,
      .busy_units = busy,
      .makespan_units = makespan,
      .parallelism_x1000 = (uint32_t)((busy * 1000U) / makespan),
  };
}

static bool
monotonic_parallelism(const struct sample samples[SWEEP_COUNT])
{
  for (size_t i = 1; i < SWEEP_COUNT; i++) {
    if (samples[i].parallelism_x1000 < samples[i - 1].parallelism_x1000) {
      return false;
    }
  }
  return true;
}

static bool
halving_sync_frequency(const struct sample samples[SWEEP_COUNT])
{
  for (size_t i = 1; i < SWEEP_COUNT; i++) {
    if (samples[i - 1].windows != samples[i].windows * 2U) {
      return false;
    }
  }
  return true;
}

int
main(void)
{
  const uint32_t latencies[SWEEP_COUNT] = {
      MIN_LINK_LATENCY_FLOOR,
      MIN_LINK_LATENCY_FLOOR * 2U,
      MIN_LINK_LATENCY_FLOOR * 4U,
      MIN_LINK_LATENCY_FLOOR * 8U,
  };
  struct sample samples[SWEEP_COUNT];
  for (size_t i = 0; i < SWEEP_COUNT; i++) {
    samples[i] = measure_sample(latencies[i]);
  }

  const struct sample unfloored_subfloor = measure_unfloored_sample(64);

  const bool zero_rejected = !declared_latency_valid(0);
  const bool subfloor_rejected = !declared_latency_valid(128);
  const uint32_t subfloor_fault_effective = effective_fault_latency(128);
  const uint32_t raised_fault_effective = effective_fault_latency(2048);
  const bool pass = zero_rejected &&
      subfloor_rejected &&
      subfloor_fault_effective == MIN_LINK_LATENCY_FLOOR &&
      raised_fault_effective == 2048 &&
      monotonic_parallelism(samples) &&
      halving_sync_frequency(samples) &&
      samples[0].parallelism_x1000 >= TARGET_PARALLELISM_X1000 &&
      samples[SWEEP_COUNT - 1].parallelism_x1000 <= VM_NODES * 1000U &&
      samples[0].windows > samples[SWEEP_COUNT - 1].windows &&
      unfloored_subfloor.parallelism_x1000 < samples[0].parallelism_x1000;

  puts(pass ? "PASS" : "FAIL");
  puts("spike=multi-vm-parallelism");
  puts("scenario=conservative-lookahead-cost-model");
  puts("topology=uniform-full-mesh");
  puts("host_core_parallelism_kind=modeled");
  printf("vm_nodes=%u\n", VM_NODES);
  printf("host_cores=%u\n", HOST_CORES);
  printf("simulated_horizon_vt=%u\n", SIMULATED_HORIZON_VT);
  printf("min_link_latency_floor=%u\n", MIN_LINK_LATENCY_FLOOR);
  printf("sync_cost_units=%u\n", SYNC_COST_UNITS);
  printf("dispatch_cost_units=%u\n", DISPATCH_COST_UNITS);
  printf("target_parallelism_x1000=%u\n", TARGET_PARALLELISM_X1000);
  printf("declared_zero_latency_rejected=%u\n", zero_rejected ? 1U : 0U);
  printf("declared_subfloor_latency_rejected=%u\n", subfloor_rejected ? 1U : 0U);
  printf("subfloor_fault_input_latency=128\n");
  printf("subfloor_fault_effective_latency=%u\n", subfloor_fault_effective);
  printf("raised_fault_input_latency=2048\n");
  printf("raised_fault_effective_latency=%u\n", raised_fault_effective);
  printf("unfloored_latency_64_parallelism_x1000=%u\n", unfloored_subfloor.parallelism_x1000);
  printf("monotonic_parallelism=%u\n", monotonic_parallelism(samples) ? 1U : 0U);
  printf("halving_sync_frequency=%u\n", halving_sync_frequency(samples) ? 1U : 0U);

  for (size_t i = 0; i < SWEEP_COUNT; i++) {
    printf("sample_%zu_latency=%u\n", i, samples[i].latency);
    printf("sample_%zu_lookahead=%u\n", i, samples[i].lookahead);
    printf("sample_%zu_windows=%" PRIu64 "\n", i, samples[i].windows);
    printf("sample_%zu_busy_units=%" PRIu64 "\n", i, samples[i].busy_units);
    printf("sample_%zu_makespan_units=%" PRIu64 "\n", i, samples[i].makespan_units);
    printf("sample_%zu_parallelism_x1000=%u\n", i, samples[i].parallelism_x1000);
  }

  printf("floor_parallelism_x1000=%u\n", samples[0].parallelism_x1000);
  printf("modeled_recommended_latency=%u\n", samples[1].latency);
  printf("modeled_recommended_parallelism_x1000=%u\n", samples[1].parallelism_x1000);
  printf("max_latency_parallelism_x1000=%u\n", samples[SWEEP_COUNT - 1].parallelism_x1000);
  printf("floor_vs_unfloored_subfloor_ratio_x1000=%u\n",
      (samples[0].parallelism_x1000 * 1000U) / unfloored_subfloor.parallelism_x1000);
  return pass ? 0 : 1;
}
