# Package builder notes

These notes are for contributors writing package recipes in the AOS
repository. They record build-system behavior that affects hermetic recipes:
dependency probing, hardening exceptions, parallelism, and fixed-output
dependency fetches. The introductory packaging walkthrough is
[Package an application for AOS](../../users/aos/package-authoring.md).

## Dependencies, hardening, and parallelism

`mkDerivation` already supplies the wrapped compiler and bootstrap tools.
List application-specific build tools, libraries, and runtime commands
explicitly. Include tools that an upstream configure script probes before the
compile even when the build phases do not invoke them directly; for example,
declare Perl in `buildDeps` when configure rejects a missing Perl interpreter.
Declare generators such as Bison even when a release archive includes generated
sources, because build rules can regenerate them after unpacking or patching.
Pass the generator through the upstream configure interface when one exists so
the build cannot silently fall back to an undeclared host command.
Make excluded optional components explicit through the upstream configure
interface. Do not rely on a missing dependency to disable a component: a CMake
helper can return after a failed probe while its parent directory continues
generating targets with `NOTFOUND` include or library paths. Assert the
component's disabled cache value after configure so an upstream default change
cannot silently expand the package feature set.
If a dependency is missing from AOS, package it from source rather than
reaching into the host or importing nixpkgs.

Select a package's named output, such as `library.dev`, when a downstream build
needs only that output's headers or package metadata. `mkDerivation` preserves
the package's `propagatedDeps` on every named output, so downstream search paths
still contain the transitive dependencies required by those headers and
`.pc` files. Declare those requirements once on the producing package; do not
repeat them on each consumer merely because the producer splits its outputs.

`mkDerivation` also enables the repository hardening profile. Keep that profile
unless an upstream representation is incompatible with one specific flag. For
example, code that deliberately uses a trailing one-element or zero-length
array as variable-length storage can trigger false `_FORTIFY_SOURCE` aborts
under `strictflexarrays3`. In that case, preserve fortify and the other
hardening checks while selecting the compatible flexible-array interpretation:

```nix
hardeningDisable = ["strictflexarrays3"];
hardeningEnable = ["strictflexarrays1"];
```

Document the upstream data layout and reproduce the actual build-time or
runtime abort before adding this exception. Do not disable all hardening to
work around one incompatible flag.

Pass `$NIX_BUILD_CORES` to build and install commands that support parallel
execution. Some bootstrap installers rebuild tools, and some build systems
forward a separate job count to nested builds; pass the configured budget to
those entry points as well.

When a compiler or generator fails, preserve its inputs, command, and build
log, then reproduce the failure before choosing a workaround. Fix missing
dependency edges or shared-output races where a reproducer demonstrates them.
Do not treat a successful retry at a lower job count as a diagnosis of compiler
corruption or as evidence for a permanent package-specific limit. See the
[build concurrency notes](build-concurrency.md) for packages
to watch under resource pressure and the available reproduction results.

## Source and dependency fetches

Extract only the named members a package consumes from a larger vendor bundle.
Some archives contain a `./` member whose mode and timestamp `tar` applies to
the existing extraction root; a sandbox executor can allow file creation there
without allowing the builder to change mount-owned root metadata. Naming the
required members avoids that unrelated metadata operation and keeps unpacking
bounded to the package's declared payload.

For a Bazel package built with `mkBazelPackage`, leave `populateBCR` enabled
when the dependency graph uses Bazel modules. Set `populateBCR = false` when
the package explicitly disables Bzlmod and resolves only a `WORKSPACE` graph.
The optional empty-workspace synchronization otherwise downloads Bazel's
built-in repositories for platforms and toolchains the target does not use;
those bytes enlarge the fixed-output dependency closure and require needless
network policy exceptions. When a pinned Git repository has a commit-identical
official mirror on an already-used origin, prefer that mirror and verify the
exact commit before changing the recipe. Keep fork-only commits on their
canonical origin rather than substituting an unaffiliated mirror. Apply the
same rule to release archives: when one upstream owns multiple official
hostnames, verify that the pinned payloads are byte-identical and select the
hostname already used by the dependency closure instead of widening its
network-origin set.

Leave Bazel action placement to the system Bazel configuration when its local
default works in the build sandbox. Do not add a global
`--spawn_strategy=standalone` package flag: command-line package flags override
the system configuration and prevent an available remote executor from
receiving actions. When nested Bazel sandboxing is unavailable and a package
needs standalone execution as its portable local fallback, use
`--spawn_strategy=remote,standalone`; Bazel then consumes a remote executor from
the system configuration when present and otherwise falls back locally. If one
action class cannot run remotely, scope its strategy by mnemonic instead of
forcing the entire build local, and document why that exception is required.

Do not retain Bazel's `host_platform`, `internal_platforms_do_not_use`, or
`local_config_*` repositories in a fixed-output dependency closure. They
describe the fetch executor rather than a source dependency. Remove those
repositories and their markers in `postFetch`; Bazel recreates them for the
executor that performs the real build.

Do not let a fixed-output dependency fetch silently fall back between native
and pure-language artifacts. When an upstream package treats a declared native
extension as optional, use its supported strict-build switch so compilation
failure stops the fetch. This makes the dependency hash describe one artifact
mode instead of whichever mode happened to build on the fetch executor.

Use equal-length store-path placeholders for binary files. A replacement with
a different byte length corrupts offsets recorded in formats such as ELF, but
a fixed-output dependency cannot retain store references. Restore the original
equal-length path before the offline build uses the artifact.

Preserve permissions while scrubbing fetched repositories. Go module caches
make their files and directories read-only to enforce content immutability, so
do not make an entire cache recursively writable just to run an in-place
rewriter. Render the transformed bytes into scratch space, make only the matched
file writable long enough to overwrite it, and restore its exact mode. This
avoids requiring write permission on the cache directory and leaves unrelated
module content untouched.

When upstream commits a Cargo lockfile and generated Bazel crate repositories,
fetch that checked-in graph without setting `CARGO_BAZEL_REPIN`. Repinning asks
rules_rust to resolve compatible versions against the current registry index,
so the result can change even when the package source revision does not. Run a
repin only while intentionally updating the source and commit the regenerated
lock and repository definitions before calculating the new dependency hash.
When a local rules_rust patch changes the repository-rule input digest without
changing the Cargo.lock-selected graph, advance the generated lock's exact
checksum in the source patch phase and assert the new value. Do not enable
repinning in production fetches merely to bypass a stale rule digest.
