# Build concurrency and resource pressure

Some builds may fail under high resource utilization and high concurrency.
Nested build jobs, compiler codegen work, thread pools, and test processes can
consume memory or file descriptors beyond what the outer job count suggests.
A failure under those conditions does not, by itself, identify a compiler bug.

The following packages previously carried concurrency or execution limits and
are useful starting points when investigating such failures:

| Package or build | Area to watch | Validation when removing limits |
| --- | --- | --- |
| Rust 1.74 bootstrap | mrustc/minicargo C++ compilation and nested Rust bootstrap jobs | Uncapped mrustc/minicargo compilation passed; the remaining bootstrap was not rerun. |
| Intermediate and final Rust compilers | Codegen parallelism and Cargo/tool rebuilding during both build and install | Uncapped Rust 1.79 and 1.81 builds and installations passed. Earlier compiler-corruption claims were not reproduced. Other tiers were not rerun. |
| OpenJDK 7 and 8 | Nested IcedTea and javac bootstrap phases | Not rerun without the limits. |
| OpenJDK 11 | Boot JVM execution and parallel compiler requests | Uncapped build and installation passed. |
| OpenJDK 14 Darwin cross build | Interim javac and parallel image generation | Not rerun without the limit. |
| Guile | Thread wakeup pipes and descriptor usage in the thread tests | Descriptor exhaustion and an `FD_SETSIZE` abort were reproduced. The high-descriptor regression and full suite passed with 32 build jobs after fixing wakeup handling and isolating parallel port-test fixtures. |
| Bash, Perl, and their historical toolchain builds | Build parallelism, including Perl's Darwin extension build | The complete native/cross matrix was not rerun. |
| Autogen | Parallel test execution | Not rerun without the limit. |

These observations identify investigation targets, not permanent concurrency
ceilings. Preserve the failing command, inputs, logs, and available resource
information. Temporary per-command limits can help distinguish resource
exhaustion from repeatable build-graph or runtime defects.

## Shared Cargo targets across worktrees

Serializing Cargo jobs prevents concurrent writers, but does not by itself
make a shared target directory safe across different worktree sources.
Cargo's ordinary freshness checks can use relative dependency paths and
source modification times. An older worktree's files can therefore appear
fresh against artifacts built from a newer, different worktree. A compile
error referring to a field absent from the current source is one possible
symptom; a successful build or test run does not rule out stale dependencies.

Before switching a shared local target to different workspace sources, stop
its active Cargo jobs and identify every relevant local path package from that
workspace's metadata, including any nonmember path dependencies. Invalidate
those packages with the AOS-built Cargo. Check the selected package names:
Cargo's package-scoped clean removes all versions of each selected name, even
when given a qualified package ID. Keep registry dependency artifacts reusable.
Do not clean another worker's
active target, remove the whole shared cache, or change source code to match a
stale dependency. A separate target directory is another isolation option.
Re-run affected tests and binaries after establishing this freshness boundary;
results obtained before discovering a mismatch are not final qualification
evidence. Record the worktree commit, command, target directory, and logs.

This local dev-shell workflow is distinct from `aos-dev` derivation builds.
The shared Rust derivation cache holds a source lock and compares its source
identity before building, refreshing copied source modification times when
the identity changes. Direct `nix develop -c cargo ...` invocations do not
automatically run that derivation configure phase. Do not assume its freshness
protection applies to a manually shared local target. Cache maintenance and
source invalidation must remain scoped to the relevant build lane.
