# Shared action caching across Nix builds

## Required outcome

An implementation-only source edit changes a Nix derivation's source path and
output identity. It must not invalidate unrelated Bazel compile actions. Two
separate Nix build executions, with fresh Bazel output bases, must reuse
unchanged compilation through the shared disk action cache. This is a primary
acceptance requirement, not an optional optimization after migration.

Reuse must remain correct when the consumer has no producer output tree,
Cargo target directory, Bazel analysis state, or local incremental compiler
state. Cached and uncached executions must produce equivalent declared
artifacts. The cache accelerates an otherwise complete offline build; deleting
it cannot change the dependency graph or successful program behavior.

## Layers and ownership

| Layer | Contents and identity | Lifetime |
| --- | --- | --- |
| Nix binary cache | Complete immutable package/build outputs and closures | Existing Nix policy |
| Dependency repositories | Pinned source archives, patches, generated BUILD metadata | Immutable Nix inputs |
| Bazel action cache and CAS | Results of declared actions, keyed by commands, inputs, environment, and platform | Shared disk across compatible derivation executions and worktrees |
| Bazel output base/server | Analysis graph, execution tree, local action metadata | Private to a worktree/toolchain configuration or one sandbox invocation |
| accache | Compiler actions from non-Bazel builders | Existing separate cache and provenance roots |

Keep these identities distinct. A Nix derivation can miss while most of its
Bazel actions hit. A Bazel analysis restart need not discard compiled
artifacts. Fetching a complete Nix output is reported separately from an
action-cache hit.

## Cross-derivation action identity

The common launcher and rules enforce these conditions:

1. Use a stable workspace name and execution-root-relative source, generated,
   and output paths. Materialize the Nix source tree into that layout. Do not
   pass the changing `/nix/store/...-source` root as a compiler include prefix.
2. Keep the Nix derivation path, `$out`, build directory, worktree pathname,
   invocation ID, and cache location out of compile commands and environments
   unless the action actually needs them. Emit provenance through a separate
   reporting channel. Removing a field from the key requires removing it from
   the action's observable inputs, not merely suppressing its hash.
3. Declare the actual sources, headers, generated files, link libraries,
   scripts, and profiles for each action. Do not add the entire workspace
   digest, global source inventory, or all dependency locks as artificial
   inputs to every compile action.
4. Make the relevant compiler closure, wrappers, sysroot, assembler, linker,
   plugins, native dependencies, and their immutable identities action inputs.
   An absolute compiler pathname alone is insufficient. A selected toolchain
   identity manifest covers its Nix reference closure; concrete files remain
   declared where the rules consume them.
5. Include execution and target configuration, Rust features, ABI, CPU/ISA,
   optimization, panic, sanitizers, codegen units, LTO, and PGO inputs wherever
   they affect an action. Keep build configuration separate from cache policy.
6. Control working directories and path remapping at execution. Debug paths,
   `__FILE__`, Rust source locations, procedural macros, and build scripts must
   observe the declared logical layout. A remapping flag by itself does not
   establish that all action inputs are relocatable.

The implementation must inspect `aquery`, execution logs, and action digests
under the pinned Bazel/rules versions. Similar command lines are not proof of
cache reuse. If a rules implementation embeds an output-base path or a random
temporary path, fix that action before making it shareable. Do not normalize
away a path whose bytes affect the output.

Cache granularity follows the language rules: ordinarily a C++ translation
unit and a Rust crate/configuration. Bazel action caching does not itself
provide Cargo-style incremental reuse within a changed Rust crate. Measure
that tradeoff in the edit benchmarks before cutting over large crates.

## Relationship to accache

The current [accache backend](../../../crates/accache/accache/src/backend.rs) stores
SHA-256 CAS blobs and REAPI `ActionResult` messages in Bazel's disk-cache
layout. Its [protocol subset](../../../crates/accache/accache/src/proto.rs) and
[storage documentation](../../../crates/accache/accache/README.md) explicitly describe
a local backend, with a compiler-input inventory rather than a remote-executor
filesystem tree. There is no existing remote transport or execution service
to assume in this RFC.

Reuse its compiler-closure identity approach, invalidation fixtures, cache
inspection conventions, and operational controls. Bazel already implements
disk action caching, so it accesses its cache directly rather than launching
accache around each compiler invocation. On a Bazel cache miss, wrapping the
compiler would repeat discovery and introduce another cache lookup; any
exception requires a measured benefit and full invalidation coverage.

The shared storage format does not imply shared action keys: accache and
Bazel construct different commands and input roots. Start with the existing
separate `bazel` and `accache` storage roots. A later shared CAS may deduplicate
identical blobs, but requires verified hash, result-schema, concurrency, and
garbage-collection compatibility. It must not claim compiler-result hits
between different action-key producers.

## Mounts, concurrency, and resource limits

Retain `AOS_DEV_BAZEL_CACHE_DIR` and `sharedBazelCacheDir` as the interface for
the shared host disk cache. The Nix daemon authorizes the sandbox mount; the
builder points Bazel's disk cache at that path. The integration must not
require a host service, a mutable source directory, or a shared output base.

Keep the shared action cache enabled by default for `aos-dev` development
builds, with explicit derivation/mount inputs and the existing
`--no-bazel-cache` override. The direct-development launcher uses the same
managed cache root. Retain the distinct `--no-accache` control for non-Bazel
compilation; switching to Bazel must not silently turn local caching off.

Each Nix execution gets a private output base and action temporary directories.
Developer worktrees get separate output bases keyed by repository, worktree,
and toolchain/configuration identity. They share only the action cache and
immutable dependencies. Bound concurrent jobs and local resource estimates;
the host's large CPU count is not an instruction to exhaust its memory.

Cache initialization, ACLs, disk limits, age limits, inspection, and pruning
stay under `aos-dev cache bazel`. Validate concurrent readers/writers and
eviction against the pinned Bazel implementation. Missing or damaged entries
must either cause a safe miss or an explicit cache-integrity failure with an
uncached recovery path; they must never install partial or unverified outputs.
Shared cache data uses disk, never tmpfs, and is not copied wholesale into
each derivation.

## Hermeticity, trust, and release policy

Cache correctness depends on both complete action inputs and trusted result
producers. Digest verification detects damaged blobs; it does not prove that
a writer associated the correct output with an action. Shared developer
caches have the same trust scope as their authorized writers. Do not allow
untrusted pull-request jobs to write a cache consumed by release qualification.

Preserve the current `--release` and `--no-cache` behavior: use ordinary
production derivations with no requested shared mutable compiler/action-cache
mounts. A separate qualification builder is required when daemon-wide static
mounts would otherwise expose shared caches. Nix's authenticated package
substitution remains a distinct policy. A future trusted release action cache
would require an explicit policy change; this RFC does not silently introduce
one.

Development Nix derivations explicitly opt into the shared mount as today.
Their output paths may differ from release derivations, while equivalent
compile commands remain eligible for cross-derivation hits. Never omit an
output-path-dependent linker argument from the key just to increase reuse.
Package installation and source retention always run for the current build.

For cache-free evidence, use a fresh output base, disable disk/remote action
caches and test-result reuse, and perform a fresh Nix realization where
required. `--no-cache` cannot be interpreted as proof that a previously built
Nix output was rebuilt. Record exactly which layers were bypassed.

## Observability and future remote transport

Report dependency preparation, Nix evaluation/realization, Bazel analysis,
action execution, cache restoration, tests, and package projection separately.
Capture hit/miss counts by action mnemonic, bytes transferred, lookup time,
compiler invocations, peak memory, and elapsed time. An explanation command
compares action inputs, toolchain identity, configuration, and effective
environment, following accache's provenance model. Private environment values
are digested or omitted from reports, never printed as credentials.

Remote action caching may later use Bazel's supported cache protocol with
separate read/write credentials and trust namespaces. It is independent of
remote execution, which additionally needs a transferable toolchain/input
closure and compatible execution platforms. Local absolute Nix store paths
and accache's inventory are not that execution contract. Remote transport is
not required to deliver shared-cache reuse across local Nix builds.

The later RBE direction uses Nix derivation sandboxes for Bazel action isolation
and Terrane for mounting/synchronizing inputs and outputs, as outlined in the
[migration document](04-migration-and-evidence.md#future-distributed-execution).
This preserves the intended execution boundary without making local caching
depend on a distributed service.
