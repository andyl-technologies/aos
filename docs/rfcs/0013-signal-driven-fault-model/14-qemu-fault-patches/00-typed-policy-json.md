# Typed node-policy JSON contract

This document is the independent C implementation contract for every
`CRUCJSN1` field in the typed node-rule payload. It is normative for patches
0050 through 0070.

## Framing and canonical grammar

The field begins with the eight ASCII bytes `CRUCJSN1`. The remaining bytes are
one JSON value under these rules:

- UTF-8 only; no byte-order mark, whitespace, comments, trailing bytes, or
  duplicate object keys;
- fixed ASCII object keys in lexicographic byte order;
- fixed snake-case ASCII enum strings and validated ASCII object IDs;
- lowercase even-length hexadecimal strings for byte strings;
- base-10 integers only, with no leading zero except the value `0`, no positive
  sign, no negative zero, fractions, exponent notation, `NaN`, or infinity;
- lowercase `true`, `false`, and `null` only;
- arrays preserve order; set-like arrays are nonempty, strictly increasing, and
  contain no duplicates;
- no omitted optional struct members: an absent optional value is encoded as
  `null`;
- no member other than those shown below is accepted.

An object ID is 1 through 96 ASCII bytes, begins with `a` through `z`, ends in a
lowercase letter or digit, contains only lowercase letters, digits, and single
hyphens, and never contains adjacent hyphens. A hex string contains only
`0` through `9` and `a` through `f`, has even length, and remains within both
the field-specific width and the 16,777,216-byte decoded hard ceiling (the
aggregate transport payload ceiling also applies). The complete field and
payload ceilings are:

| Resource | Hard ceiling |
| --- | ---: |
| fields in one typed node payload | 128 |
| encoded command payload, including field headers and JSON framing | 33,563,728 bytes |
| hashes in one binary hash-set field | 4,096 |
| decoded bytes in one hex string | 16,777,216 bytes, further restricted by the containing field |
| vCPUs in one sorted vCPU array | 4,096 |
| register selection | 65,536 bits |
| exact instruction bytes | 32 bytes |
| instruction replay count | 256 |
| duplicate interrupt copies | 256 |
| jitter distribution or wander increments | 4,096 entries |
| any other `BoundedCount`, including boot attempts, periodic occurrence count, and interrupt-storm burst/count | 4,194,304 |

Every positive integer wrapper is in `1..=u64::MAX`. Every exact-ratio numerator
and denominator is in `1..=u64::MAX`; capacity ratios additionally require
`numerator <= denominator`. Ranges have positive length and their unsigned
start-plus-length must not overflow. Signed values use the complete `i64` range;
unsigned scalar fields use the width stated by their schema (`u16`, `u32`, or
`u64`). The QEMU parser repeats the applicable numeric, length, ordering,
payload-budget, and cross-field checks before it
creates private rule state. Parsing success alone never authorizes a mutation.

The examples show exact bytes after `CRUCJSN1`. Metavariables in angle brackets
describe values and are not literal JSON.

## Common scalar forms

| Form | Exact JSON |
| --- | --- |
| object ID | `"clock-main"` |
| hex bytes | `"00ff"` |
| positive integer wrapper | `1` |
| bounded count wrapper | `1` |
| exact ratio | `{"denominator":2,"numerator":1}` |
| optional integer | integer or `null` |
| optional object ID | string or `null` |
| sorted numeric vCPU set | `[0,2,7]` |
| sorted identity set | `["a","b"]` when embedded in JSON; top-level clock source sets use the binary hash-set field instead |

## Binary discriminants used beside JSON

| Field family | Exhaustive numeric values |
| --- | --- |
| lifecycle transition | `boot = 1`, `crash = 2`, `reset = 3`, `power_off = 4`, `power_cycle = 5`, `permanent_failure = 6` |
| state policy | `preserve = 1`, `clear = 2`, `device_reset = 3`; `device_reset` is invalid for volatile state |
| hang scope kind | `node = 1`, `vcpus = 2`, `device = 3`; must agree with the JSON scope variant |
| CPU service discipline | `work_conserving = 1`, `strict_cap = 2` |
| vCPU state | `online = 1`, `offline = 2`, `stalled = 3` |
| register mutation | `bit_flip = 1`, `stuck = 2`, `replace = 3` |
| instruction mutation | `result_corrupt = 1`, `skip = 2`, `replay = 3` |
| interrupt disposition | `drop = 1`, `delay = 2`, `duplicate = 3`, `replace = 4` |
| memory access mutation | `stuck = 1`, `read_corrupt = 2`, `lost_write = 3`, `torn_write = 4`, `poison = 5` |
| ECC kind | `corrected = 1`, `uncorrectable = 2` |
| memory region kind | `failed = 1`, `retention = 2`, `rowhammer = 3` |
| clock mutation | `offset = 1`, `drift = 2`, `jump = 3`, `freeze = 4`, `jitter = 5`, `wander = 6` |
| clock monotonicity | `allow_backward = 1`, `clamp_monotonic = 2`, `fault_on_backward = 3` |
| overdue timer | `fire_at_boundary = 1`, `drop = 2`, `reschedule_periodic = 3` |
| accelerator transition | `disappear = 1`, `reset = 2`, `reconnect = 3` |

## Lifecycle, hang, and CPU service

`NodeBootPolicy`:

```json
{"kind":"immediate"}
{"kind":"require_ready","parameters":{"exhausted":"crash","maximum_attempts":3,"ready_marker":"guest-ready","retry_delay_nanos":1000}}
```

`exhausted` is exactly `crash`, `power_off`, or `permanent_failure`.

`NodeHangScope`:

```json
{"kind":"node"}
{"kind":"vcpus","parameters":[0,2]}
{"kind":"device","parameters":"accelerator-0"}
```

The numeric vCPU array is nonempty, strictly increasing, and contains at most
4,096 entries.

`NodeWatchdogPolicy`:

```json
{"kind":"disabled"}
{"kind":"transition_after","parameters":{"timeout_nanos":1000,"transition":"reset","downtime_nanos":0,"boot_policy":{"kind":"immediate"},"volatile_state_policy":"preserve","device_state_policy":"device_reset"}}
```

The transition is exactly `boot`, `crash`, `reset`, `power_off`, `power_cycle`,
or `permanent_failure`. CPU service's selected vCPUs are encoded directly as a
sorted numeric array. `CpuServiceDiscipline` is a binary `u32`, not JSON:
`work_conserving = 1`, `strict_cap = 2`.

## Opportunity and value mutations

`NodeOccurrencePolicy`:

```json
{"kind":"every"}
{"kind":"periodic","parameters":{"count":4,"first":1,"period":10}}
```

`RegisterMutation`:

```json
{"kind":"bit_flip","parameters":{"mask":"01"}}
{"kind":"stuck","parameters":{"mask":"03","value":"02"}}
{"kind":"replace","parameters":{"value":"ff"}}
```

Masks and values are nonempty. A `stuck` mask and value have equal decoded
width. The surrounding register or result schema applies its additional exact
width constraint.

`InstructionSelector`:

```json
{"input_state_sha256":null,"instruction_bytes":null,"occurrence":{"kind":"every"},"opcode_class":7,"pc_length":4,"pc_start":4096}
```

`instruction_bytes` is `null` or 1 through 32 exact bytes. `opcode_class` is a
`u32` or `null`; `pc_length` is positive and `pc_start + pc_length` must not
overflow. `instruction_bytes` and `opcode_class` cannot both be `null`: every
selector must bind either the exact encoding, the immutable manifest class, or
both. `input_state_sha256` is `null` or exactly 32 bytes encoded as 64
hexadecimal digits. It uses the versioned
`crucible.instruction-input-state.v1` digest of canonical architecture-register
state at the instruction boundary. The selector's PC, instruction bytes and/or
opcode class independently bind instruction identity. Whole RAM and raw device
VMState hashes remain in authenticated occurrence evidence and the canonical host
fingerprint rather than this QEMU-local cross-process selector; unrelated RAM
and device bookkeeping therefore cannot destabilize a local instruction match.
This is a register precondition, not an operand-value predicate: memory or MMIO
bytes addressed by those registers are not part of this digest and may differ
without suppressing the transform. Use memory-fault or assertion surfaces when
the scenario must precondition on memory contents.
A mismatch consumes the selected occurrence, emits
`suppressed` evidence containing the expected and observed input digests, and
executes the unmodified instruction.

## Architecture exceptions and interrupt routing

`NodeException`:

```json
{"architecture":"x86_64","before_instruction":true,"fault_address":null,"maskable":false,"record":{"kind":"architecture_default"},"syndrome":0,"vector":18}
```

Architecture is exactly `x86_64` or `aarch64`. x86-64 vectors are at most 255;
AArch64 exception classes are at most 1,023. `record` is
`{"kind":"architecture_default"}`, or one matching architecture record:

```json
{"kind":"x86_machine_check","parameters":{"address":4096,"bank":0,"corrected":false,"global_status":4,"misc":null,"status":1103806595072}}
{"kind":"aarch64_ras","parameters":{"asynchronous":true,"corrected":false,"fatal":false,"disr":1,"esr":2483027968,"far":4096}}
```

For x86 machine check, vector is 18, status is nonzero, and record address equals
the outer fault address. For AArch64 RAS, record ESR and FAR equal the outer
syndrome and fault address; asynchronous delivery requires DISR. QEMU also
rejects fields outside the realized architecture manifest masks.

`InterruptRoutingPolicy`:

```json
{"priority":0,"retain_pending":true,"target_vcpus":[0,2]}
```

`target_vcpus` is nonempty, strictly increasing, and contains at most 4,096
entries.

## Memory policies

`MemoryPoisonPolicy`:

```json
{"kind":"access_error"}
{"kind":"corrected","parameters":{"xor_mask":"01"}}
{"kind":"exception","parameters":{"exception":{"architecture":"x86_64","before_instruction":true,"fault_address":4096,"maskable":false,"record":{"kind":"architecture_default"},"syndrome":0,"vector":18}}}
```

`MemoryEccVisibility`:

```json
{"kind":"telemetry_only"}
{"kind":"corrected_interrupt","parameters":{"vector":17}}
{"kind":"exception","parameters":{"architecture":"aarch64","before_instruction":false,"fault_address":4096,"maskable":false,"record":{"kind":"architecture_default"},"syndrome":1,"vector":47}}
```

`MemoryRegionProcess`:

```json
{"kind":"failed","parameters":{"policy":{"kind":"access_error"}}}
{"kind":"retention","parameters":{"decay_mask":"01","interval_nanos":1000000}}
{"kind":"rowhammer","parameters":{"flip_mask":"01","row_bytes":8192,"threshold":100000,"victim_distance":1}}
```

The process variant must match the binary region-kind discriminant. Every mask
is nonempty and every interval, row size, threshold, and victim distance is
positive.

`MemoryServiceScope`:

```json
{"kind":"node"}
{"kind":"range"}
{"kind":"controller","parameters":"memory-controller-0"}
```

The memory access-class binary bit set is `fetch = 0x01`, `cpu_load = 0x02`,
`cpu_store = 0x04`, `dma_read = 0x08`, `dma_write = 0x10`, and
`page_table_walk = 0x20`. At least one bit is set and no other bit is accepted.
The host JSON carries all six booleans explicitly. `page_table_walk` requires a
guest-physical memory target because it selects the descriptor bytes read by
the MMU, not the virtual data address that caused translation.

## Clock policies

Plain clock policy enums are encoded as JSON strings:

```json
"resume_from_frozen"
"catch_up_jump"
```

Those are the exhaustive `ClockFreezeReleasePolicy` values. Jitter is an
ordered nonempty array of at most 4,096 signed nanosecond values, each within
the binary `maximum_nanos` bound:

```json
[-5,0,5]
```

`ClockWanderProcess`:

```json
{"increments_ppb":[-10,0,10],"maximum_offset_nanos":1000,"maximum_rate_ppb":100,"step_nanos":1000000}
```

The increment array is nonempty, contains at most 4,096 entries, and every
absolute increment is at most `maximum_rate_ppb`. All three scalar bounds are
positive.

`ClockSourceTransition`:

```json
{"kind":"healthy"}
{"kind":"degraded"}
{"kind":"failed","parameters":{"behavior":"stop"}}
{"kind":"failed","parameters":{"behavior":"read_error"}}
{"kind":"fallback","parameters":{"source":"clock-backup"}}
```

`ClockSynchronizationPolicy`:

```json
{"kind":"step"}
{"kind":"slew","parameters":{"rate":{"denominator":1000,"numerator":1},"threshold_nanos":100}}
```

The slew rate and threshold are positive. `ClockMonotonicityPolicy` and
`ClockOverdueTimerPolicy` are binary `u32` fields:

| Policy | Numeric values |
| --- | --- |
| monotonicity | `allow_backward = 1`, `clamp_monotonic = 2`, `fault_on_backward = 3` |
| overdue timer | `fire_at_boundary = 1`, `drop = 2`, `reschedule_periodic = 3` |

## Accelerator policies

`AcceleratorJobSelector`:

```json
{"job_kind":"matrix-multiply","occurrence":{"kind":"every"},"queue":null}
```

`queue` is a `u32` or `null`.

`AcceleratorResultMutation`:

```json
{"mask":"03","offset":16,"value":"02"}
```

Mask and value are nonempty and have equal decoded widths. `offset` plus the
decoded width must fit the realized result schema or output buffer.

`AcceleratorThermalPower`:

```json
{"power_milliwatts":15000,"temperature_millikelvin":350000}
```

Both values are positive.

## Parser and negative-test requirements

The GPL-side parser uses the command kind, field tag, and mutation discriminant
to select exactly one shape above. It must reject `null`, `{}`, the right shape
in the wrong field, unknown/missing/duplicate members, wrong scalar types,
unknown variants, noncanonical bytes, limit violations, inconsistent optional
presence flags, and trailing data. Each policy variant has a positive vector and
at least one negative vector in the live QEMU microtests. Patch 0070's final
gate feeds every accepted host vector through the independently compiled C
parser and compares its typed re-encoding/digest with the host golden.
