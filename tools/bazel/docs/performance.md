# Build performance evidence

Family measurements compile the selected libtest artifacts and then discover
and execute their complete qualified case inventories outside the timed region.
Compile-loop measurements exclude Nix evaluation, dependency preparation, and
installation; end-to-end measurements cover those costs separately. Cargo
incremental and nonincremental/accache modes remain separate baselines.

The storage/campaign v3 raw report remains an immutable historical checkpoint.
Its nine Bazel warm/edit samples all recorded `server_before: null`, so those
timings include JVM startup. The 60-second idle timeout is consistent with
expiration during untimed case validation. The retained audit is
`../tests/evidence/store-performance-v3-server-lifetime.json`.

The family harness explicitly selects a private server and allows up to 3,600
idle seconds during measurements. Every warm or edit sample must retain the
same recorded JVM PID before and after compilation. Cold, second-worktree, and
fresh-directory samples must start without an existing JVM in their new output
base. Missing or restarted JVMs reject the measurement. The harness shuts down
every private server in its `finally` block, including after failed validation.
Ordinary launcher invocations retain the 60-second default.

The completed follow-up is retained in
[`store-performance-server-lifetime.json`](../tests/evidence/store-performance-server-lifetime.json)
with its unmodified raw report. Three repetitions cover all six Bazel scenarios:
18 measurements, each followed by 599 untimed case executions. All nine warm
and edit invocations retained the same private JVM before and after compilation;
the remaining scenarios started without an existing JVM in the selected output
base. Other builds ran on the shared host, and Cargo baselines were not rerun.
These observations qualify the lifecycle correction without establishing a
controlled timing comparison or numerical acceptance.

These lifecycle checks qualify what is being measured. They do not establish
performance acceptance, semantic compiler-option equivalence, or production
cutover budgets. Keep raw observations, exact sources and toolchain inputs,
cache state, concurrency, JVM resources, and repeated distributions alongside
any timing comparison.
