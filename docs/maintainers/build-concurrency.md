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
| Guile | Thread wakeup pipes and descriptor usage in the thread tests | Descriptor exhaustion and an `FD_SETSIZE` abort were reproduced. The high-descriptor regression passes with the wakeup handling patch; the full suite has not been rerun. |
| Bash, Perl, and their historical toolchain builds | Build parallelism, including Perl's Darwin extension build | The complete native/cross matrix was not rerun. |
| Autogen | Parallel test execution | Not rerun without the limit. |

These observations identify investigation targets, not permanent concurrency
ceilings. Preserve the failing command, inputs, logs, and available resource
information. Temporary per-command limits can help distinguish resource
exhaustion from repeatable build-graph or runtime defects.
